package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// authGate 校验 /api/* 请求：
//   - Bearer Token（插件/CLI）→ 完整权限（含 admin）
//   - Admin 会话 Cookie（短期）→ 仅 /api/v1/admin/*（备份管理）
//   - Web 只读会话 Cookie → 仅白名单 GET 接口（webSessionAllowed）
//
// 其余路径（/health、/web/session、/share/{id}、静态资源）直接放行。
func authGate(token string, web *sessionStore, next http.Handler) http.Handler {
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, prefix) &&
			subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), want) == 1 {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/admin/") {
			// ADMIN capability：只读会话不够，必须持根 Token 或短期 admin 会话
			if c, err := r.Cookie(adminCookieName); err == nil && web.validAdmin(c.Value) {
				next.ServeHTTP(w, r)
				return
			}
			if c, err := r.Cookie(sessionCookieName); err == nil && web.valid(c.Value) {
				writeErr(w, http.StatusForbidden, "admin session required")
				return
			}
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if c, err := r.Cookie(sessionCookieName); err == nil && web.valid(c.Value) {
			if webSessionAllowed(r) {
				next.ServeHTTP(w, r)
				return
			}
			writeErr(w, http.StatusForbidden, "web session is read-only")
			return
		}
		writeErr(w, http.StatusUnauthorized, "unauthorized")
	})
}

// securityHeaders 为所有响应加安全头（CSP 是 Web 端持有明文与密钥时的第二道防线；
// 同时 img-src 限制阻断笔记内外链图片的隐私泄露）。
func securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
		"img-src 'self' blob: data:; font-src 'self'; media-src 'self' blob:; object-src 'none'; " +
		"base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}
