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
//
// v6 增加 Admin 会话：备份管理等 ADMIN capability 需要单独的短期
// admin cookie（同样 HttpOnly），普通只读会话触碰 /api/v1/admin/* 一律 403。

const (
	sessionCookieName = "litesync_session"
	adminCookieName   = "litesync_admin"
	sessionTTL        = 7 * 24 * time.Hour
	adminTTL          = 30 * time.Minute // Admin 会话短期有效
)

type sessionInfo struct {
	expires time.Time
	admin   bool
}

type sessionStore struct {
	mu       gosync.Mutex
	sessions map[string]sessionInfo // id → 会话（内存态；服务重启需重新登录）
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]sessionInfo{}}
}

func (s *sessionStore) create(admin bool) string {
	b := make([]byte, 32)
	rand.Read(b) //nolint:errcheck
	id := hex.EncodeToString(b)
	ttl := sessionTTL
	if admin {
		ttl = adminTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// 顺手清理过期会话
	now := time.Now()
	for k, info := range s.sessions {
		if now.After(info.expires) {
			delete(s.sessions, k)
		}
	}
	s.sessions[id] = sessionInfo{expires: now.Add(ttl), admin: admin}
	return id
}

func (s *sessionStore) lookup(id string, wantAdmin bool) bool {
	if id == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.sessions[id]
	if !ok || time.Now().After(info.expires) {
		delete(s.sessions, id)
		return false
	}
	return info.admin == wantAdmin
}

func (s *sessionStore) valid(id string) bool      { return s.lookup(id, false) }
func (s *sessionStore) validAdmin(id string) bool { return s.lookup(id, true) }

func (s *sessionStore) revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func secureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secureRequest(r),
	})
}

// createSession 登录：POST /web/session，Body {"token":"...","admin":bool}
// admin=true 时同时下发只读会话与短期 admin 会话（备份管理页需要两者）。
func (h *handlers) createSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
		Admin bool   `json:"admin"`
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
	setSessionCookie(w, r, sessionCookieName, h.web.create(false), int(sessionTTL.Seconds()))
	if req.Admin {
		setSessionCookie(w, r, adminCookieName, h.web.create(true), int(adminTTL.Seconds()))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "admin": req.Admin})
}

// destroySession 登出：DELETE /web/session（同时撤销只读与 admin 会话）
func (h *handlers) destroySession(w http.ResponseWriter, r *http.Request) {
	for _, name := range []string{sessionCookieName, adminCookieName} {
		if c, err := r.Cookie(name); err == nil {
			h.web.revoke(c.Value)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// webSessionAllowed：Web 只读会话允许访问的接口白名单（仅 GET）。
// Web 出现漏洞时攻击面被限制在读取；所有写操作仍必须持根 Token 或 admin 会话。
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
