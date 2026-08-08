package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	gosync "sync"
	"time"
)

// Web 会话（v4）：浏览器不再持有根 API Token。
// 登录换取随机短期 Session，存 HttpOnly + SameSite=Strict Cookie，
// JavaScript 完全接触不到；且会话只具备只读权限（白名单 GET 接口）。

const (
	sessionCookieName = "litesync_session"
	sessionTTL        = 7 * 24 * time.Hour
)

type sessionStore struct {
	mu       gosync.Mutex
	sessions map[string]time.Time // id → 过期时间（内存态；服务重启需重新登录）
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]time.Time{}}
}

func (s *sessionStore) create() string {
	b := make([]byte, 32)
	rand.Read(b) //nolint:errcheck
	id := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	// 顺手清理过期会话
	now := time.Now()
	for k, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, k)
		}
	}
	s.sessions[id] = now.Add(sessionTTL)
	return id
}

func (s *sessionStore) valid(id string) bool {
	if id == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[id]
	if !ok || time.Now().After(exp) {
		delete(s.sessions, id)
		return false
	}
	return true
}

func (s *sessionStore) revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func secureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// createSession 登录：POST /web/session，Body {"token":"..."}
func (h *handlers) createSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.Token == "" {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(h.opts.Token)) != 1 {
		time.Sleep(300 * time.Millisecond) // 轻量暴力破解减速
		writeErr(w, http.StatusUnauthorized, "invalid token")
		return
	}
	id := h.web.create()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secureRequest(r),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// destroySession 登出：DELETE /web/session
func (h *handlers) destroySession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		h.web.revoke(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// webSessionAllowed：Web 只读会话允许访问的接口白名单（仅 GET）。
// Web 出现漏洞时攻击面被限制在读取；所有写操作仍必须持根 Token。
func webSessionAllowed(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	switch r.URL.Path {
	case "/api/v1/info",
		"/api/v1/snapshot",
		"/api/v1/file",
		"/api/v1/history",
		"/api/v1/version",
		"/api/v1/vault-key":
		return true
	}
	return false
}
