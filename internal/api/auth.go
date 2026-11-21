package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// 认证身份（v9.2 设备级凭据；v0.18 用户 Token 落库）：
//   - 用户 Token（users.token_hash，原「根 Token」的泛化）：对自己 Vault 的全权限——
//     设备注册与管理、账户自救；其中管理员（is_admin）额外持有 admin API 门票；
//   - 设备 Token：最小权限 scopes（sync/share/key-admin/pairing），可单独撤销；
//   - Web 会话：白名单接口（v0.18 起随会话携带用户与 Vault 归属）。
type authIdentity struct {
	// UserToken：本次身份来自用户级长期 Token（含管理员）。
	// 设备管理等「凭据级」端点只认它——被盗设备不得撤销别的设备或重置账户。
	UserToken bool
	// UserID：账号身份。用户 Token 与网页会话都会带上；设备/access token 为空
	//（设备的归属由 db.DeviceTenant 另查，请求里声称的一律不作数）。
	UserID string
	// IsAdmin：实例管理员。admin API 的唯一门票（v0.18 起不再有「根 Token」概念）。
	IsAdmin  bool
	DeviceID string
	Name     string
	Scopes   string
	// VaultID：这次请求被授权访问的租户（§10.1）。业务代码不得从请求体里取。
	VaultID string
	// ViaAccessToken：本次身份来自一张分钟级 access token 而非长期设备凭据（§10.5）。
	// 换票接口本身不接受短期票——否则一张泄露的票可以无限续期，
	// 「被动泄露后自动过期」这条性质就没了。
	ViaAccessToken bool
	// ViaOIDC：网页会话由统一登录建立（v0.20 / ADR-011）。
	ViaOIDC bool
	// Restricted：邮箱尚未验证的统一账号——可以查看，不能做消耗资源的操作
	//（建仓库、发行配对等，需求 §4.1）。
	Restricted bool
	// idTokenHint：全局退出时交给身份服务的 id_token_hint（只在本进程内存中）。
	idTokenHint string
	// authTime：网页会话完成认证的时刻（发行配对等敏感操作的「近期认证」判定）
	authTime time.Time
	// AuditDevice：没有设备凭据的身份（网页会话）在审计与写入归属里用的服务端标识，
	// 形如 "web-<userId 哈希前 12 位>"。客户端自报的 X-Device-ID 永远不作数。
	AuditDevice string
}

// webContentWrite：网页编辑需要的内容写路由（ADR-015；OBSYNC_WEB_EDITING 开启时才对会话放行）。
func webContentWrite(r *http.Request) bool {
	p := r.URL.Path
	switch {
	case p == "/api/v1/file" && (r.Method == http.MethodPut || r.Method == http.MethodDelete),
		p == "/api/v1/file/rename" && r.Method == http.MethodPost,
		strings.HasPrefix(p, "/api/v1/files/") && strings.HasSuffix(p, "/restore") && r.Method == http.MethodPost:
		return true
	}
	return false
}

func webAuditDevice(userID string) string {
	return "web-" + sha256HexStr(userID)[:12]
}

type ctxKey int

const identityKey ctxKey = 0

// identityFrom 返回请求的认证身份（authGate 之后必非 nil；公开路径为 nil）。
func identityFrom(r *http.Request) *authIdentity {
	v, _ := r.Context().Value(identityKey).(*authIdentity)
	return v
}

// scopeOf 把认证身份转成数据层的租户范围（T-1：范围只能来自认证上下文）。
//
// 身份缺失或没有 Vault 归属时返回零值 VaultScope——db 层对零值**硬拒**
// （ErrVaultScopeMissing），失败方向是拒绝而不是「退化为默认租户」。
func scopeOf(r *http.Request) db.VaultScope {
	id := identityFrom(r)
	if id == nil {
		return db.VaultScope{}
	}
	return db.ScopeFromAuth(id.VaultID)
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

// routeScope 返回路径所需的设备 scope；rootOnly 表示设备/access token 一律拒绝
//（v0.18 起语义为「用户级 Token 专属」——原「根 Token」已泛化为按用户落库的 Token）。
//
// v0.13.3 §7.6：未列出的 /api/v1/* 一律**拒绝**（scopeDeny），
// 不再默认落到 ScopeSync。
func routeScope(method, path string) (scope string, rootOnly bool) {
	switch {
	case strings.HasPrefix(path, "/api/v1/admin/"):
		return "", true // 备份/完整性管理：管理员 Token 或 admin 会话（authGate 单独处理会话）
	case path == "/api/v1/devices" && method == http.MethodPost:
		return "", true // 首台设备自注册：必须持用户 Token
	case strings.HasPrefix(path, "/api/v1/devices/") && method == http.MethodDelete:
		return "", true // 设备撤销：用户 Token 专属（被盗设备不能撤销其他设备）
	case path == "/api/v1/account/token-reset":
		return "", true // 账户 Token 重置：用户 Token 专属（被盗设备不得锁死账户）
	case path == "/api/v1/vaults" && method == http.MethodGet:
		return syncsvc.ScopeSync, false // 仓库列表：设备可列（只列自己主人名下的）
	case path == "/api/v1/vaults" && method == http.MethodPost:
		return "", true // 新建仓库：用户 Token 专属
	case strings.HasPrefix(path, "/api/v1/vaults/") && method == http.MethodDelete:
		return "", true // 删除仓库：用户 Token 专属
	case strings.HasPrefix(path, "/api/v1/vaults/") && method == http.MethodPatch:
		return "", true // 重命名仓库：用户 Token 专属
	case path == "/api/v1/vault/reset-auth":
		return syncsvc.ScopeSync, false // 重置凭证登记：解锁 E2EE 后每台设备的正常动作
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
	case path == "/api/v1/trash" && method == http.MethodGet:
		return syncsvc.ScopeSync, false // 回收站列表：与显式恢复同一 scope
	case path == "/api/v1/token":
		return "", false // 换票：任何有效的**长期**设备凭据均可（短期票另行拒绝）
	case path == "/api/v1/members" || strings.HasPrefix(path, "/api/v1/members/"):
		return syncsvc.ScopeKeyAdmin, false // 成员变更会触发密钥轮换（§10.4）
	case path == "/api/v1/audit":
		return syncsvc.ScopeKeyAdmin, false
	case path == "/api/v1/whoami":
		return "", false // 任何有效凭据均可
	// ---- v0.20 公开化 /api/v2 ----
	case path == "/api/v2/me":
		// 用户身份不走 scope；设备凭据需要 sync（看到的是其主人的账号信息，
		// 零 scope 设备什么都拿不到——越权矩阵 TestZeroScopeDeviceGetsNothing）
		return syncsvc.ScopeSync, false
	case strings.HasPrefix(path, "/api/v2/account/") || path == "/api/v2/devices" ||
		strings.HasPrefix(path, "/api/v2/devices/"):
		return "", true // 账户级操作：用户身份专属，被盗设备不得退出/撤销别的设备
	case strings.HasPrefix(path, "/api/v2/vaults/") && strings.HasSuffix(path, "/pairing-grants"):
		return syncsvc.ScopePairing, false // 插件「添加新设备」：设备凭据只能为自己绑定的仓库发行
	case path == "/api/v2/pairings" || strings.HasPrefix(path, "/api/v2/pairings/"):
		return syncsvc.ScopePairing, false
	case path == "/api/v2/vaults" || strings.HasPrefix(path, "/api/v2/vaults/"):
		return "", true // 建库与加密初始化：用户身份专属（设备不能建库，也不能动别的仓库的密钥）
	case syncRoutes[path]:
		return syncsvc.ScopeSync, false
	default:
		// §7.6：默认拒绝。新增接口必须在这里显式登记想要的 scope
		return scopeDeny, false
	}
}

// clientPlatforms 是 X-Client-Platform 允许落库的值（白名单）。
// Header 是客户端自报的任意字符串，直接落库等于把一个注入面写进 devices 表；
// 白名单外的值一律归 unknown，空值视为「未上报」（旧客户端），保留已记录的平台。
var clientPlatforms = map[string]bool{
	"windows": true, "macos": true, "linux": true,
	"ios": true, "android": true, "web": true, "unknown": true,
}

func normalizeClientPlatform(v string) string {
	if v == "" {
		return ""
	}
	if !clientPlatforms[v] {
		return "unknown"
	}
	return v
}

// vaultRequired 报告该路由是否需要一个具体仓库（v0.20：零仓库账号是正常状态）。
// 不需要仓库的：仓库列表/新建/改名/删除（目标在路径或请求体里，由 handler 按
// owner 校验）、身份查询与全部 /api/v2 账号接口。
func vaultRequired(r *http.Request) bool {
	p := r.URL.Path
	switch {
	case p == "/api/v1/vaults", strings.HasPrefix(p, "/api/v1/vaults/"),
		p == "/api/v1/whoami", strings.HasPrefix(p, "/api/v2/"),
		strings.HasPrefix(p, "/api/v1/admin/"): // 实例级运维不依附于某个仓库
		return false
	}
	return true
}

// sessionIdentity 把网页会话转成认证身份；ok=false 时响应已写好。
func (h *handlers) sessionIdentity(w http.ResponseWriter, r *http.Request, cookieID string, info sessionInfo, admin bool) (*authIdentity, bool) {
	if info.oidc != nil && h.rp != nil && !h.rp.revalidate(r.Context(), info.oidc) {
		// 身份服务明确拒绝了复核（冻结、全局退出、会话撤销）：本会话作废
		h.web.revoke(cookieID)
		writeCoded(w, http.StatusUnauthorized, CodeAuthRequired, "session ended; sign in again", false)
		return nil, false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !h.sameOrigin(r) {
		writeCoded(w, http.StatusForbidden, CodeForbidden, "cross-origin request rejected", false)
		return nil, false
	}
	chosen, okv := resolveVaultChoice(w, r, h.svc, info.userID, info.vaultID)
	if !okv {
		return nil, false
	}
	if chosen == "" && vaultRequired(r) {
		writeCoded(w, http.StatusConflict, CodeVaultRequired, "no vault selected; create or choose a vault first", false)
		return nil, false
	}
	if webContentWrite(r) {
		// 网页写入：仓库成员角色必须可写（只读成员、零仓库一律拒绝）；解锁成功≠允许写
		role, ok, err := h.svc.RoleIn(db.ScopeFromAuth(chosen), info.userID)
		if err != nil {
			h.internalError(w, "web write role", err)
			return nil, false
		}
		if !ok || !role.CanWrite() {
			writeCoded(w, http.StatusForbidden, CodeForbidden, "your role in this vault is read-only", false)
			return nil, false
		}
	}
	id := &authIdentity{UserID: info.userID, Name: info.name, IsAdmin: info.isAdmin || admin, VaultID: chosen, authTime: info.authTime,
		AuditDevice: webAuditDevice(info.userID)}
	if info.oidc != nil {
		id.ViaOIDC = true
		id.Restricted = !info.oidc.emailVerified
		info.oidc.mu.Lock()
		id.idTokenHint = info.oidc.idToken
		info.oidc.mu.Unlock()
	}
	return id, true
}

func authGate(h *handlers, next http.Handler) http.Handler {
	web, svc, trusted := h.web, h.svc, h.trusted
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || publicAPIRoute(r) {
			// /api/ 之外 = 公开；publicAPIRoute 是 /api/v2 下 secret 即认证的少数端点
			//（配对 envelope 读取、设备兑换），各自在 handler 内校验并限流
			next.ServeHTTP(w, r)
			return
		}
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, prefix) {
			// 宽容解析（v0.18 实测）：粘贴 Token 时多出的空格是常见笔误，
			// 而它的症状是一个无从排查的 401。Token 本身不含空白，trim 无歧义
			bearer := strings.TrimSpace(auth[len(prefix):])
			// 短期 access token（§10.5）：验签 + 未过期 + 设备仍有效
			if strings.HasPrefix(bearer, "lst1.") {
				claims, err := svc.VerifyAccessToken(bearer)
				if err != nil {
					// 过期与伪造分开告知：过期是客户端可以自行处理的正常状态
					//（拿长期凭据再换一张），伪造则没什么可解释的
					if errors.Is(err, syncsvc.ErrAccessTokenExpired) {
						writeErr(w, http.StatusUnauthorized, "access token expired; exchange a new one")
					} else {
						writeErr(w, http.StatusUnauthorized, "unauthorized")
					}
					return
				}
				if ok := enforceRouteScope(w, r, claims.Scopes); !ok {
					return
				}
				if ok := enforceVault(w, svc, claims.VaultID); !ok {
					return
				}
				// 换票接口不接受短期票：允许用票换票 = 无限续期
				if r.URL.Path == "/api/v1/token" {
					writeErr(w, http.StatusForbidden,
						"access tokens cannot be exchanged for new ones; use the device credential")
					return
				}
				ctx := context.WithValue(r.Context(), identityKey, &authIdentity{
					DeviceID: claims.DeviceID, Scopes: claims.Scopes,
					VaultID: claims.VaultID, ViaAccessToken: true,
				})
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			// 设备 Token：按 scope 校验（撤销后立即失效）
			clientVer := r.Header.Get("X-Client-Version")
			clientProto, _ := strconv.ParseInt(r.Header.Get("X-LiteSync-Protocol"), 10, 64) //nolint:errcheck
			platform := normalizeClientPlatform(r.Header.Get("X-Client-Platform"))
			// 设备凭据已绑定仓库：X-Vault-ID **一律忽略**（v0.19）——
			// 被盗设备不得凭一个头改变自己的访问范围
			d, derr := svc.AuthDeviceWithClient(bearer, clientVer, clientProto,
				platform, clientIP(r, trusted))
			if errors.Is(derr, syncsvc.ErrDeviceRevoked) {
				// 「曾有效、已被撤销」与「查无此凭据」分开告知：前者是 Token 重置或
				// 设备撤销的正常后果，客户端要给的是「填新 Token 重新接入」的指引
				writeCoded(w, http.StatusUnauthorized, CodeTokenRevoked,
					"device credential has been revoked; enter the new API token and reconnect", false)
				return
			}
			if derr == nil && d != nil {
				if ok := enforceRouteScope(w, r, d.Scopes); !ok {
					return
				}
				vaultID := d.VaultID
				if vaultID == "" {
					vaultID = db.DefaultVaultID
				}
				if ok := enforceVault(w, svc, vaultID); !ok {
					return
				}
				ctx := context.WithValue(r.Context(), identityKey, &authIdentity{
					DeviceID: d.DeviceID, Name: d.Name, Scopes: d.Scopes, VaultID: vaultID,
				})
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			// 用户 Token（v0.18：users.token_hash，含管理员）：对自己 Vault 全权限。
			// 不做 scope 检查（scope 是设备的最小权限机制），但 admin API 必须 is_admin。
			if u, err := svc.AuthUserByToken(bearer); err == nil && u != nil {
				if strings.HasPrefix(r.URL.Path, "/api/v1/admin/") && !u.IsAdmin {
					writeErr(w, http.StatusForbidden, "admin privileges required")
					return
				}
				vaultID, verr := svc.OwnerVaultOf(u.UserID)
				if verr != nil || vaultID == "" {
					writeErr(w, http.StatusForbidden, "account has no vault")
					return
				}
				chosen, okv := resolveVaultChoice(w, r, svc, u.UserID, vaultID)
				if !okv {
					return
				}
				vaultID = chosen
				if ok := enforceVault(w, svc, vaultID); !ok {
					return
				}
				ctx := context.WithValue(r.Context(), identityKey, &authIdentity{
					UserToken: true, UserID: u.UserID, IsAdmin: u.IsAdmin,
					Name: u.Name, VaultID: vaultID,
				})
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/admin/") {
			// ADMIN capability：普通会话不够，必须持管理员 Token 或短期 admin 会话
			if c, err := r.Cookie(adminCookieName); err == nil {
				if info, ok := web.lookup(c.Value, true); ok && sessionGenerationValid(svc, info) {
					id, okv := h.sessionIdentity(w, r, c.Value, info, true)
					if !okv {
						return
					}
					next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey, id)))
					return
				}
			}
			if c, err := r.Cookie(sessionCookieName); err == nil {
				if _, ok := web.lookup(c.Value, false); ok {
					writeErr(w, http.StatusForbidden, "admin session required")
					return
				}
			}
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if c, err := r.Cookie(sessionCookieName); err == nil {
			if info, ok := web.lookup(c.Value, false); ok && sessionGenerationValid(svc, info) {
				if webSessionAllowed(r) || (h.opts.WebEditing && webContentWrite(r)) {
					id, okv := h.sessionIdentity(w, r, c.Value, info, false)
					if !okv {
						return
					}
					next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey, id)))
					return
				}
				writeErr(w, http.StatusForbidden, "web session is read-only")
				return
			}
		}
		writeErr(w, http.StatusUnauthorized, "unauthorized")
	})
}

// resolveVaultChoice 解析 X-Vault-ID（v0.19 单用户多仓库）：
// 头为空 → 默认仓库（fallback）；非空 → membership 硬校验，非成员一律 404
//（不泄露存在性）。头只是「选择」，授权永远由服务端的成员关系裁决（T-1）。
//
// 只有**用户级身份**（用户 Token / 网页会话）走这里；设备凭据与 access token
// 已绑定仓库，X-Vault-ID 一律忽略——被盗设备不得凭一个头横向进入主人的
// 其他仓库（有测试盯着）。
//
// 返回 ok=false 时 404 响应已写好。
func resolveVaultChoice(w http.ResponseWriter, r *http.Request, svc *syncsvc.Service, userID, fallback string) (string, bool) {
	hdr := strings.TrimSpace(r.Header.Get("X-Vault-ID"))
	if hdr == "" || hdr == fallback {
		return fallback, true
	}
	ok, err := svc.UserHasVault(userID, hdr)
	if err != nil || !ok {
		writeCoded(w, http.StatusNotFound, CodeNotFound, "vault not found", false)
		return "", false
	}
	return hdr, true
}

// sessionGenerationValid 比对会话创建时的 Token 世代与用户当前世代。
//
// Token 轮换（网页或 CLI）把世代 +1，所有旧会话在这里被拒——这是「重置后
// 旧会话必须全部下线」的实现，不依赖遍历内存，跨进程（CLI 兜底）同样生效。
// 用户被禁用时 UserTokenGeneration 返回 0，同样在这里拦截。
func sessionGenerationValid(svc *syncsvc.Service, info sessionInfo) bool {
	gen, err := svc.UserTokenGeneration(info.userID)
	return err == nil && gen != 0 && gen == info.tokenGeneration
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

// enforceRouteScope 用同一套路由表判定一组 scope 是否够用；不够时已写好响应。
//
// 设备 token 与 access token 必须走**同一份**判定逻辑。两套实现意味着
// 迟早有一条路径只在其中一套里被收紧，而那条缝隙不会有人注意到。
func enforceRouteScope(w http.ResponseWriter, r *http.Request, scopes string) bool {
	need, rootOnly := routeScope(r.Method, r.URL.Path)
	switch {
	case need == scopeDeny:
		writeErr(w, http.StatusForbidden, "route not authorized for device tokens")
		return false
	case rootOnly:
		writeErr(w, http.StatusForbidden, "user token required")
		return false
	case need != "" && !syncsvc.HasScope(scopes, need):
		writeErr(w, http.StatusForbidden, "insufficient scope: "+need+" required")
		return false
	}
	return true
}

// enforceVault 校验认证身份的 Vault 归属（§10.6，v0.18 起放开多 Vault）。
//
// v0.17 以前这里要求「必须等于实例唯一 vault」；多用户后改为：凭据必须有
// 归属、该 Vault 必须存在、其 owner 未被禁用。失败方向仍然是**拒绝**而不是
// 「沿用默认 Vault」——后者会把一次漏配置变成静默的跨租户读取。
// vaultID 一律来自服务端数据（设备行 / 票据 claims / users 表），
// 请求里声称的永远不作数。
func enforceVault(w http.ResponseWriter, svc *syncsvc.Service, vaultID string) bool {
	if vaultID == "" {
		writeErr(w, http.StatusForbidden, "credential has no vault")
		return false
	}
	ok, err := svc.VaultActive(db.ScopeFromAuth(vaultID))
	if err != nil || !ok {
		writeErr(w, http.StatusForbidden, "credential belongs to an inactive vault")
		return false
	}
	return true
}
