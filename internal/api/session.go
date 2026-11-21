package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	gosync "sync"
	"time"

	syncsvc "github.com/KJoner/litesync-server/internal/sync"
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

// sessionInfo 记录一个网页会话的归属（v0.18 多用户化）。
//
// tokenGeneration 是会话创建时用户的 Token 世代：Token 轮换会把 users 表里的
// 世代 +1，authGate 每次校验会话时比对——不一致即拒。这样「重置 Token 作废
// 全部会话」不依赖遍历内存 map，CLI 兜底（另一个进程）改库同样立即生效。
type sessionInfo struct {
	expires time.Time
	admin   bool // admin 提升会话（30 分钟 cookie），区别于「用户是管理员」
	userID  string
	name    string
	isAdmin bool // 用户本身是否实例管理员
	vaultID string
	// tokenGeneration：创建会话时的用户 Token 世代
	tokenGeneration int64
	// authEpoch：创建会话时的账号授权代次（ADR-019）；B / C / D / 停用之后对不上即失效
	authEpoch int64
	// oidc：统一登录建立的会话才有（v0.20 / ADR-011）——复核状态与 back-channel
	// logout 的 sid。指针共享，自带锁；API Token 网页登录的会话为 nil。
	oidc *oidcSessionState
	// authTime：本会话完成认证的时刻（敏感操作的「近期认证」判定）
	authTime time.Time
}

type sessionStore struct {
	mu       gosync.Mutex
	sessions map[string]sessionInfo // id → 会话（内存态；服务重启需重新登录）
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]sessionInfo{}}
}

func (s *sessionStore) create(info sessionInfo) string {
	b := make([]byte, 32)
	rand.Read(b) //nolint:errcheck
	id := hex.EncodeToString(b)
	ttl := sessionTTL
	if info.admin {
		ttl = adminTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// 顺手清理过期会话
	now := time.Now()
	for k, old := range s.sessions {
		if now.After(old.expires) {
			delete(s.sessions, k)
		}
	}
	info.expires = now.Add(ttl)
	s.sessions[id] = info
	return id
}

// lookup 返回会话信息；过期或提升级别不符返回 ok=false。
// 注意这里**不做** Token 世代校验——那需要查库，由 authGate 的
// sessionGenerationValid 完成（认证顺序：先内存后数据库）。
func (s *sessionStore) lookup(id string, wantAdmin bool) (sessionInfo, bool) {
	if id == "" {
		return sessionInfo{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.sessions[id]
	if !ok || time.Now().After(info.expires) {
		delete(s.sessions, id)
		return sessionInfo{}, false
	}
	if info.admin != wantAdmin {
		return sessionInfo{}, false
	}
	return info, true
}

func (s *sessionStore) revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// revokeWhere 作废所有满足条件的会话（back-channel logout 按 sid 定位）。
func (s *sessionStore) revokeWhere(match func(sessionInfo) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, info := range s.sessions {
		if match(info) {
			delete(s.sessions, id)
			n++
		}
	}
	return n
}

// adoptGeneration 把请求携带的会话迁移到新的 Token 世代与授权代次。
// 重置 Token 会作废该用户全部会话（世代 +1、代次 +1）；唯独**发起重置的这一个**要活下来，
// 否则新 Token 还没来得及展示，页面就被登出了。
func (s *sessionStore) adoptGeneration(r *http.Request, userID string, generation, authEpoch int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, name := range []string{sessionCookieName, adminCookieName} {
		c, err := r.Cookie(name)
		if err != nil {
			continue
		}
		if info, ok := s.sessions[c.Value]; ok && info.userID == userID {
			info.tokenGeneration = generation
			info.authEpoch = authEpoch
			s.sessions[c.Value] = info
		}
	}
}

// parseTrustedProxies 把 IP / CIDR 列表解析为前缀；非法条目忽略。
func parseTrustedProxies(entries []string) []netip.Prefix {
	var out []netip.Prefix
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			out = append(out, p)
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// fromTrusted：地址是否属于配置的可信反向代理（secureRequest / clientIP 共用）。
func fromTrusted(trusted []netip.Prefix, addr netip.Addr) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// secureRequest：请求是否来自 HTTPS。
// v9：X-Forwarded-Proto 只信任配置的反向代理来源（默认 loopback），
// 不再无条件相信任意客户端伪造的转发头。
func (h *handlers) secureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return fromTrusted(h.trusted, addr.Unmap())
}

// clientIP 返回请求方 IP（devices.last_ip 用，与 secureRequest 同族的转发头处理）。
//
// 方向绝不能反：只有当**直连方本身**是可信反向代理时才解析 X-Forwarded-For
//（取最右侧不属于可信代理的条目——左边的部分是客户端自报的，可以随便伪造）；
// 直连方不可信时 XFF 一律忽略，否则任何客户端都能往 last_ip 里写任意地址。
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.Unmap()
	if !fromTrusted(trusted, addr) {
		return addr.String()
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		e := strings.TrimSpace(parts[i])
		if e == "" {
			continue
		}
		// 条目可能带端口（某些代理会写 ip:port）；统一去掉
		if h, _, err := net.SplitHostPort(e); err == nil {
			e = h
		}
		a, err := netip.ParseAddr(e)
		if err != nil {
			break // 解析不了的链条不猜，退回直连地址
		}
		if a = a.Unmap(); !fromTrusted(trusted, a) {
			return a.String()
		}
	}
	return addr.String()
}

func (h *handlers) setSessionCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   h.secureRequest(r),
	})
}

// createSession 登录：POST /web/session，Body {"token":"...","admin":bool}
// admin=true 时同时下发只读会话与短期 admin 会话（备份管理页需要两者）。
//
// v0.18：Token 从「与环境变量比对」改为查 users 表（管理员与普通用户共用
// 这个入口）；普通用户请求 admin 提升一律 403——admin API 的门票只属于管理员。
func (h *handlers) createSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
		Admin bool   `json:"admin"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.Token == "" {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	// 统一登录启用且关闭了旧方式（旧管理员认领之后）：API Token 不再能换网页会话。
	// 设备与插件的 Bearer 认证不受影响——这里只关网页登录这一个入口。
	if !h.legacyLoginAllowed() {
		writeCoded(w, http.StatusForbidden, CodeLegacyLoginDisabled,
			"API token web login is disabled; sign in with your account", false)
		return
	}
	u, err := h.svc.AuthUserByToken(strings.TrimSpace(req.Token))
	if errors.Is(err, syncsvc.ErrTokenRevoked) {
		time.Sleep(300 * time.Millisecond)
		writeAPITokenRevoked(w)
		return
	}
	if err != nil {
		h.internalError(w, "session login", err)
		return
	}
	if u == nil {
		time.Sleep(300 * time.Millisecond) // 轻量暴力破解减速
		writeErr(w, http.StatusUnauthorized, "invalid token")
		return
	}
	if req.Admin && !u.IsAdmin {
		writeErr(w, http.StatusForbidden, "admin privileges required")
		return
	}
	vaultID, err := h.svc.OwnerVaultOf(u.UserID)
	if err != nil {
		h.internalError(w, "session login", err)
		return
	}
	if vaultID == "" {
		// 账号存在却没有专属 Vault：数据不一致，不发会话
		writeErr(w, http.StatusForbidden, "account has no vault")
		return
	}
	base := sessionInfo{
		userID: u.UserID, name: u.Name, isAdmin: u.IsAdmin, vaultID: vaultID,
		tokenGeneration: u.TokenGeneration, authEpoch: u.AuthEpoch, authTime: time.Now(),
	}
	h.setSessionCookie(w, r, sessionCookieName, h.web.create(base), int(sessionTTL.Seconds()))
	if req.Admin {
		elevated := base
		elevated.admin = true
		h.setSessionCookie(w, r, adminCookieName, h.web.create(elevated), int(adminTTL.Seconds()))
	}
	role := "user"
	if u.IsAdmin {
		role = "admin"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "admin": req.Admin, "role": role, "name": u.Name,
	})
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

// webSessionAllowed：Web 普通会话允许访问的接口白名单。
// Web 出现漏洞时攻击面被限制在这份清单里；其余写操作仍必须持用户 Token 或 admin 会话。
//
// v0.18 在纯只读之外放进两条账户自救操作（v11 设计 §4.3）：
//   - 重置自己的 API Token（重置端点自身还有 E2EE 重置凭证这道硬关卡）；
//   - 登记重置凭证（只能首登记或持旧值更新，会话拿不到覆盖权）。
func webSessionAllowed(r *http.Request) bool {
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/account/token-reset" {
		return true
	}
	if r.Method == http.MethodPut && r.URL.Path == "/api/v1/vault/reset-auth" {
		return true
	}
	// v0.19.x：仓库自助管理（新建/重命名/删除）进 Web——会话是用户级身份，
	// handler 侧 owner/membership 校验兜底，删除另有 confirmName 与最后一个
	// 保护。攻击面权衡与 token-reset 同级（那个能踢掉全部设备）；设备凭据
	// 依然被 routeScope 的 rootOnly 拦住（D4 最小权限不变）。
	if r.URL.Path == "/api/v1/vaults" && r.Method == http.MethodPost {
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/vaults/") &&
		(r.Method == http.MethodPatch || r.Method == http.MethodDelete) {
		return true
	}
	// v0.20 公开化：账户中心（统一身份之后网页会话就是账号身份本身）。
	// 写操作另有 Origin 同源校验（authGate），handler 侧 owner 校验兜底。
	switch {
	case r.Method == http.MethodGet && (r.URL.Path == "/api/v2/me" || r.URL.Path == "/api/v2/devices"):
		return true
	// 账号撤销的 B / C 与「最近的撤销」（ADR-019）
	case r.Method == http.MethodPost && (r.URL.Path == "/api/v2/account/logout-all" || r.URL.Path == "/api/v2/account/logout-devices"):
		return true
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/account/revocations":
		return true
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v2/account/revocations/") && strings.HasSuffix(r.URL.Path, "/retry"):
		return true
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v2/devices/"):
		return true
	// 网页建库与加密初始化（ADR-012）、从网页连接 Obsidian（ADR-014）：
	// owner 校验在 handler（ownedVaultScope）；会话写请求另有 Origin 同源校验
	case r.URL.Path == "/api/v2/vaults" && r.Method == http.MethodPost,
		strings.HasPrefix(r.URL.Path, "/api/v2/vaults/") && strings.HasSuffix(r.URL.Path, "/initialization"),
		strings.HasPrefix(r.URL.Path, "/api/v2/vaults/") && strings.HasSuffix(r.URL.Path, "/pairing-grants") && r.Method == http.MethodPost,
		r.URL.Path == "/api/v2/pairings" && r.Method == http.MethodPost,
		strings.HasPrefix(r.URL.Path, "/api/v2/pairings/") && r.Method == http.MethodDelete:
		return true
	}
	if r.Method != http.MethodGet {
		return false
	}
	switch r.URL.Path {
	case "/api/v1/info",
		"/api/v1/vaults",
		"/api/v1/snapshot",
		"/api/v1/file",
		"/api/v1/history",
		"/api/v1/version",
		"/api/v1/vault-key",
		"/api/v1/whoami",
		"/api/v1/trash", // v0.20 回收站列表（只读；恢复属于内容写入，受 OBSYNC_WEB_EDITING 闸门约束）
		"/api/v1/changes": // v0.20 网页发现其他设备的修改（只读元数据；网页身份没有设备行，确认游标是空操作）
		return true
	}
	return false
}
