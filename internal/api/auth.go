package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// 认证身份（v9.2 设备级凭据）：
//   - 根 Token（.env）：全权限——首台设备注册、设备管理、备份 admin、灾难恢复；
//   - 设备 Token：最小权限 scopes（sync/share/key-admin/pairing），可单独撤销；
//   - Web 会话：只读白名单（不变）；admin 会话：仅备份管理（不变）。
type authIdentity struct {
	Root     bool
	DeviceID string
	Name     string
	Scopes   string
}

type ctxKey int

const identityKey ctxKey = 0

// identityFrom 返回请求的认证身份（authGate 之后必非 nil；公开路径为 nil）。
func identityFrom(r *http.Request) *authIdentity {
	v, _ := r.Context().Value(identityKey).(*authIdentity)
	return v
}

// routeScope 返回路径所需的设备 scope；rootOnly 表示设备 Token 一律拒绝。
// 未列出的 /api/v1/* 默认要求 sync（新增接口漏配置时收紧而不是放开）。
func routeScope(method, path string) (scope string, rootOnly bool) {
	switch {
	case strings.HasPrefix(path, "/api/v1/admin/"):
		return "", true // 备份管理：根 Token 或 admin 会话（authGate 单独处理会话）
	case path == "/api/v1/devices" && method == http.MethodPost:
		return "", true // 首台设备自注册：必须持根 Token
	case strings.HasPrefix(path, "/api/v1/devices/") && method == http.MethodDelete:
		return "", true // 设备撤销：根 Token 专属（被盗设备不能撤销其他设备）
	case path == "/api/v1/enrollments" || strings.HasPrefix(path, "/api/v1/pairing"):
		return syncsvc.ScopePairing, false
	case path == "/api/v1/share" || path == "/api/v1/shares":
		return syncsvc.ScopeShare, false
	case path == "/api/v1/vault-key" && method == http.MethodPut:
		return syncsvc.ScopeKeyAdmin, false
	case path == "/api/v1/history" && method == http.MethodDelete:
		return syncsvc.ScopeKeyAdmin, false
	case strings.HasPrefix(path, "/api/v1/e2ee/"):
		return syncsvc.ScopeKeyAdmin, false
	case path == "/api/v1/whoami":
		return "", false // 任何有效凭据均可
	default:
		return syncsvc.ScopeSync, false
	}
}

func authGate(token string, web *sessionStore, svc *syncsvc.Service, next http.Handler) http.Handler {
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, prefix) {
			bearer := auth[len(prefix):]
			// 根 Token：全权限
			if subtle.ConstantTimeCompare([]byte(bearer), want) == 1 {
				ctx := context.WithValue(r.Context(), identityKey, &authIdentity{Root: true})
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			// 设备 Token：按 scope 校验（撤销后立即失效）
			if d, err := svc.AuthDevice(bearer); err == nil && d != nil {
				scope, rootOnly := routeScope(r.Method, r.URL.Path)
				if rootOnly {
					writeErr(w, http.StatusForbidden, "root token required")
					return
				}
				if scope != "" && !syncsvc.HasScope(d.Scopes, scope) {
					writeErr(w, http.StatusForbidden, "insufficient scope: "+scope+" required")
					return
				}
				ctx := context.WithValue(r.Context(), identityKey, &authIdentity{
					DeviceID: d.DeviceID, Name: d.Name, Scopes: d.Scopes,
				})
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
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
