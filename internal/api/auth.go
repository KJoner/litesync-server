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

// scopeDeny 是「这条路径没有被明确授权过」的标记（v0.13.3 / 计划书 §7.6）。
// routeScope 返回它时，authGate 一律拒绝——包括持根 Token 的请求。
const scopeDeny = "deny"

// syncRoutes 是**明确**允许普通同步凭据访问的路径集合（默认拒绝的白名单）。
//
// 以前这里的 default 分支返回 ScopeSync，意味着任何新增的 /api/v1/ 接口在
// 有人想起来配置之前，都自动对所有设备 Token 开放。一个本该是 key-admin 或
// admin 的接口，会在上线的第一天就是全开的——而且没有任何信号提示这件事。
//
// 现在反过来：漏配置的路径直接 404 式拒绝，开发时立刻会发现，而不是等到审计。
var syncRoutes = map[string]bool{
	"/api/v1/info":     true,
	"/api/v1/changes":  true,
	"/api/v1/file":     true,
	"/api/v1/snapshot": true,
	"/api/v1/history":  true,
	"/api/v1/version":  true,
}

// routeScope 返回路径所需的设备 scope；rootOnly 表示设备 Token 一律拒绝。
//
// v0.13.3 §7.6：未列出的 /api/v1/* 一律**拒绝**（scopeDeny），
// 不再默认落到 ScopeSync。
func routeScope(method, path string) (scope string, rootOnly bool) {
	switch {
	case strings.HasPrefix(path, "/api/v1/admin/"):
		return "", true // 备份/完整性管理：根 Token 或 admin 会话（authGate 单独处理会话）
	case path == "/api/v1/devices" && method == http.MethodPost:
		return "", true // 首台设备自注册：必须持根 Token
	case strings.HasPrefix(path, "/api/v1/devices/") && method == http.MethodDelete:
		return "", true // 设备撤销：根 Token 专属（被盗设备不能撤销其他设备）
	case path == "/api/v1/devices" && method == http.MethodGet:
		// 设备清单是插件里的正常功能（显示「本设备」与其他已接入设备），
		// 列出的都是同一个用户自己的设备，因此 sync scope 足够
		return syncsvc.ScopeSync, false
	case path == "/api/v1/enrollments" || strings.HasPrefix(path, "/api/v1/pairing"):
		return syncsvc.ScopePairing, false
	case path == "/api/v1/share" || path == "/api/v1/shares":
		return syncsvc.ScopeShare, false
	case path == "/api/v1/vault-key" && method == http.MethodPut:
		return syncsvc.ScopeKeyAdmin, false
	case path == "/api/v1/vault-key" && method == http.MethodGet:
		return syncsvc.ScopeSync, false // 取密钥文档是每台设备的正常同步动作
	case path == "/api/v1/history" && method == http.MethodDelete:
		return syncsvc.ScopeKeyAdmin, false
	case strings.HasPrefix(path, "/api/v1/e2ee/"):
		return syncsvc.ScopeKeyAdmin, false
	case strings.HasPrefix(path, "/api/v1/meta/"):
		return syncsvc.ScopeKeyAdmin, false // 元数据加密状态机（v9.3）
	case path == "/api/v1/envelope/complete":
		return syncsvc.ScopeKeyAdmin, false // 信封下限提升：仓库级不可逆动作
	case path == "/api/v1/file/meta":
		return syncsvc.ScopeSync, false
	case path == "/api/v1/checkpoint" || path == "/api/v1/checkpoints":
		// 发布与读取 checkpoint 是普通同步动作：每台设备都要做
		return syncsvc.ScopeSync, false
	case path == "/api/v1/device/signing-key":
		return syncsvc.ScopeSync, false
	case path == "/api/v1/file/rename":
		return syncsvc.ScopeSync, false
	case strings.HasPrefix(path, "/api/v1/files/") && strings.HasSuffix(path, "/restore"):
		return syncsvc.ScopeSync, false
	case path == "/api/v1/whoami":
		return "", false // 任何有效凭据均可
	case syncRoutes[path]:
		return syncsvc.ScopeSync, false
	default:
		// §7.6：默认拒绝。新增接口必须在这里显式登记想要的 scope
		return scopeDeny, false
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
				if scope == scopeDeny {
					// §7.6：这条路径没有被显式授权过。拒绝而不是猜一个 scope——
					// 猜错的方向永远是「放得太开」
					writeErr(w, http.StatusForbidden, "route not authorized for device tokens")
					return
				}
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
