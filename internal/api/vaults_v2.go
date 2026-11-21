package api

// /api/v2 仓库与配对（v0.20 公开化）：
//
//	POST   /api/v2/vaults                          新建仓库（pending_encryption，幂等 clientRequestId）
//	GET    /api/v2/vaults/{id}/initialization      初始化状态（无秘密）
//	POST   /api/v2/vaults/{id}/initialization      claim / commit（ADR-012）
//	POST   /api/v2/vaults/{id}/pairing-grants      发行一次性设备 grant（ADR-014）
//	POST   /api/v2/pairings                        上传绑定 grant 的配对包密文
//	DELETE /api/v2/pairings/{id}                   发行者撤销（连带作废 grant）
//	GET    /api/v2/pairings/{id}/envelope          公开：读取配对包（不消费）
//	POST   /api/v2/device-enrollments/redeem       公开：显式兑换（secret 即认证，可恢复）

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	gosync "sync"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// 新增错误码（接口约定 §0.1）
const (
	CodeVaultNotReady        = "VAULT_NOT_READY"
	CodeInitInProgress       = "INIT_IN_PROGRESS"
	CodeInitVersionMismatch  = "INIT_VERSION_MISMATCH"
	CodeIdempotencyKeyReused = "IDEMPOTENCY_KEY_REUSED"
	CodeVaultMismatch        = "VAULT_MISMATCH"
	CodePairingExpired       = "PAIRING_EXPIRED"
	CodePairingUsed          = "PAIRING_USED"
	CodePairingRevoked       = "PAIRING_REVOKED"
	CodeRateLimited          = "RATE_LIMITED"
	CodeReauthRequired       = "REAUTH_REQUIRED"
)

// grantRecentAuth：会话发行配对的「近期认证」窗口（接口约定 §5.1）。
const grantRecentAuth = 12 * time.Hour

func writeVaultNotReady(w http.ResponseWriter) {
	writeCoded(w, http.StatusConflict, CodeVaultNotReady,
		"vault encryption setup is not finished; content writes are rejected until it is", false)
}

// ownedVaultScope 校验调用者是路径中仓库的 owner；不是（或不存在）一律 404。
// 设备凭据只能操作自己绑定的那个仓库。
func (h *handlers) ownedVaultScope(w http.ResponseWriter, r *http.Request, vaultID string) (db.VaultScope, string, bool) {
	me := identityFrom(r)
	if me == nil {
		writeCoded(w, http.StatusUnauthorized, CodeAuthRequired, "unauthorized", false)
		return db.VaultScope{}, "", false
	}
	if me.DeviceID != "" {
		if me.VaultID != vaultID {
			writeCoded(w, http.StatusNotFound, CodeNotFound, "vault not found", false)
			return db.VaultScope{}, "", false
		}
		owner, err := h.svc.DeviceOwner(me.DeviceID)
		if err != nil || owner == "" {
			writeCoded(w, http.StatusNotFound, CodeNotFound, "vault not found", false)
			return db.VaultScope{}, "", false
		}
		return db.ScopeFromAuth(vaultID), owner, true
	}
	if me.UserID == "" || vaultID == "" {
		writeCoded(w, http.StatusNotFound, CodeNotFound, "vault not found", false)
		return db.VaultScope{}, "", false
	}
	scope := db.ScopeFromAuth(vaultID)
	role, ok, err := h.svc.RoleIn(scope, me.UserID)
	if err != nil {
		h.internalError(w, "vault role", err)
		return db.VaultScope{}, "", false
	}
	if !ok || role != db.RoleOwner {
		writeCoded(w, http.StatusNotFound, CodeNotFound, "vault not found", false)
		return db.VaultScope{}, "", false
	}
	return scope, me.UserID, true
}

func (h *handlers) createVaultV2(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	if me == nil || me.UserID == "" {
		writeCoded(w, http.StatusForbidden, CodeForbidden, "user session required", false)
		return
	}
	if me.Restricted {
		writeCoded(w, http.StatusForbidden, CodeEmailNotVerified, "verify your email before creating a vault", false)
		return
	}
	var req struct {
		Name            string `json:"name"`
		ClientRequestID string `json:"clientRequestId"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "invalid body", false)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 64 {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "仓库名需为 1–64 个字符", false)
		return
	}
	if !syncsvc.ValidExchangeID(req.ClientRequestID) {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "clientRequestId must be 16–64 url-safe characters", false)
		return
	}
	id, created, err := h.svc.CreateVaultV2(me.UserID, name, req.ClientRequestID, h.opts.RequireE2EENewVaults)
	switch {
	case errors.Is(err, db.ErrVaultLimit):
		h.writeVaultLimit(w, me.UserID)
		return
	case errors.Is(err, db.ErrVaultNameTaken):
		writeCoded(w, http.StatusConflict, CodeConflict, "同名仓库已存在，请换一个名字", false)
		return
	case err != nil:
		h.internalError(w, "vault create v2", err)
		return
	}
	h.writeInitStatus(w, r, db.ScopeFromAuth(id), map[string]any{"created": created, "name": name})
}

func (h *handlers) writeInitStatus(w http.ResponseWriter, _ *http.Request, scope db.VaultScope, extra map[string]any) {
	vi, keyDoc, err := h.svc.VaultInitStatus(scope)
	if err != nil || vi == nil {
		h.internalError(w, "vault init status", err)
		return
	}
	ri, err := h.svc.RepoInfo(scope)
	if err != nil {
		h.internalError(w, "vault init status", err)
		return
	}
	now := time.Now().Unix()
	actions := []string{}
	switch vi.State {
	case db.InitPendingEncryption:
		actions = []string{"initialize_e2ee", "delete_empty_vault"}
	case db.InitInitializing:
		actions = []string{"initialize_e2ee", "delete_empty_vault"}
	case db.InitReady:
		actions = []string{"open", "connect_device"}
	}
	out := map[string]any{
		"vaultId":        scope.ID(),
		"vaultIdentity":  ri.VaultID, // = v1 info.vaultId（加密 AAD 绑定）
		"initState":      vi.State,
		"initVersion":    vi.Version,
		"leaseActive":    vi.State == db.InitInitializing && vi.LeaseExpires > now,
		"keyDocPresent":  keyDoc,
		"cryptoProfile":  syncsvc.CurrentCryptoProfile(),
		"allowedActions": actions,
	}
	if vi.State == db.InitInitializing && vi.LeaseExpires > now {
		out["leaseExpiresAt"] = vi.LeaseExpires
	}
	for k, v := range extra {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handlers) vaultInitStatus(w http.ResponseWriter, r *http.Request) {
	scope, _, ok := h.ownedVaultScope(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	h.writeInitStatus(w, r, scope, nil)
}

func (h *handlers) vaultInitAction(w http.ResponseWriter, r *http.Request) {
	scope, _, ok := h.ownedVaultScope(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if me := identityFrom(r); me != nil && me.DeviceID != "" {
		writeCoded(w, http.StatusForbidden, CodeForbidden, "user session required", false)
		return
	}
	var req struct {
		Phase               string                `json:"phase"`
		OpID                string                `json:"opId"`
		ExpectedInitVersion int64                 `json:"expectedInitVersion"`
		KeyDoc              json.RawMessage       `json:"keyDoc"`
		ResetAuth           string                `json:"resetAuth"`
		CryptoProfile       syncsvc.CryptoProfile `json:"cryptoProfile"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxVaultKeySize)).Decode(&req); err != nil {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "invalid body", false)
		return
	}
	if !syncsvc.ValidExchangeID(req.OpID) {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "opId must be 16–64 url-safe characters", false)
		return
	}
	switch req.Phase {
	case "claim":
		_, err := h.svc.ClaimVaultInit(scope, req.OpID)
		if err != nil {
			h.initError(w, err)
			return
		}
		h.writeInitStatus(w, r, scope, map[string]any{"claimedBy": req.OpID})
	case "commit":
		var compact bytes.Buffer
		if len(req.KeyDoc) == 0 || json.Compact(&compact, req.KeyDoc) != nil || compact.Bytes()[0] != '{' {
			writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "keyDoc must be a JSON object", false)
			return
		}
		res, replay, err := h.svc.CommitVaultInit(scope, req.OpID, req.ExpectedInitVersion,
			compact.String(), req.CryptoProfile, req.ResetAuth)
		if err != nil {
			h.initError(w, err)
			return
		}
		res["replayed"] = replay
		writeJSON(w, http.StatusOK, res)
	default:
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "phase must be claim or commit", false)
	}
}

func (h *handlers) initError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, syncsvc.ErrInitInProgress):
		writeCoded(w, http.StatusConflict, CodeInitInProgress, "another window is setting up this vault", true)
	case errors.Is(err, syncsvc.ErrInitAlreadyReady):
		writeCoded(w, http.StatusConflict, CodeConflict,
			"vault is already initialized; unlock it with the password chosen at setup", false)
	case errors.Is(err, syncsvc.ErrInitLeaseMissing):
		writeCoded(w, http.StatusConflict, CodeInitVersionMismatch, "claim the initialization first (or the claim expired)", true)
	case errors.Is(err, syncsvc.ErrInitVersionMismatch):
		writeCoded(w, http.StatusConflict, CodeInitVersionMismatch, "initialization version mismatch; reload the status", false)
	case errors.Is(err, syncsvc.ErrIdempotencyReused):
		writeCoded(w, http.StatusConflict, CodeIdempotencyKeyReused, "opId reused with a different request", false)
	case errors.Is(err, syncsvc.ErrVaultNotEmpty):
		writeCoded(w, http.StatusConflict, CodeConflict, "only an empty vault can be initialized here", false)
	case errors.Is(err, syncsvc.ErrInvalidKeyDoc):
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, err.Error(), false)
	default:
		h.internalError(w, "vault init", err)
	}
}

// ---------------------------------------------------------------- 配对 v2

func (h *handlers) createPairingGrant(w http.ResponseWriter, r *http.Request) {
	scope, owner, ok := h.ownedVaultScope(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	me := identityFrom(r)
	if me.Restricted {
		writeCoded(w, http.StatusForbidden, CodeEmailNotVerified, "verify your email before connecting devices", false)
		return
	}
	if me.ViaOIDC && !me.authTime.IsZero() && time.Since(me.authTime) > grantRecentAuth {
		writeCoded(w, http.StatusForbidden, CodeReauthRequired, "sign in again before connecting a new device", false)
		return
	}
	g, err := h.svc.CreatePairingGrant(scope, owner, me.DeviceID)
	if errors.Is(err, syncsvc.ErrVaultNotReady) {
		writeVaultNotReady(w)
		return
	}
	if err != nil {
		h.internalError(w, "pairing grant", err)
		return
	}
	label := me.Name
	if ids, ierr := h.svc.IdentitiesOf(owner); ierr == nil && len(ids) > 0 && ids[0].DisplayName != "" {
		label = ids[0].DisplayName
	}
	trustMode := "first_trust"
	if g.HeadSequence == 0 {
		trustMode = "new_vault_genesis"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"grantId": g.GrantID, "enrollmentSecret": g.EnrollmentSecret, "expiresAt": g.ExpiresAt,
		"vault":                map[string]any{"vaultId": scope.ID(), "vaultIdentity": g.VaultIdentity, "displayName": g.VaultName},
		"accountLabel":         label,
		"protocolVersion":      ProtocolVersion,
		"requiredCapabilities": []string{"vault-bound-pairing", "redeem-v2"},
		// 服务器只能给出「首次信任 / 新库起点」：它说的 checkpoint 不能自证可信（ADR-014 I-5）
		"trust": map[string]any{"mode": trustMode, "repoEpoch": g.RepoEpoch, "headSequence": g.HeadSequence},
	})
}

func (h *handlers) createPairingV2(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	owner, err := h.requestOwner(me)
	if err != nil || owner == "" || me.VaultID == "" {
		writeCoded(w, http.StatusForbidden, CodeForbidden, "unauthorized", false)
		return
	}
	var req struct {
		GrantID    string `json:"grantId"`
		Ciphertext string `json:"ciphertext"`
		VaultID    string `json:"vaultId"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxPairingSize+1024)).Decode(&req); err != nil ||
		req.GrantID == "" || req.Ciphertext == "" || len(req.Ciphertext) > maxPairingSize {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "invalid body", false)
		return
	}
	scope := scopeOf(r)
	if req.VaultID != "" && req.VaultID != scope.ID() {
		// 会话的 X-Vault-ID 与包所属仓库不一致：按 404 处理，不让包挂到别的仓库
		writeCoded(w, http.StatusNotFound, CodeNotFound, "grant not found", false)
		return
	}
	id, expiresAt, err := h.svc.CreatePairingV2(scope, owner, req.GrantID, req.Ciphertext)
	if errors.Is(err, syncsvc.ErrGrantNotFound) {
		writeCoded(w, http.StatusNotFound, CodeNotFound, "grant not found", false)
		return
	}
	if err != nil {
		h.internalError(w, "pairing v2 create", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pairId": id, "expiresAt": expiresAt})
}

func (h *handlers) deletePairingV2(w http.ResponseWriter, r *http.Request) {
	owner, err := h.requestOwner(identityFrom(r))
	if err != nil {
		h.internalError(w, "pairing v2 delete", err)
		return
	}
	if err := h.svc.DeletePairing(scopeOf(r), owner, r.PathValue("id")); err != nil {
		h.internalError(w, "pairing v2 delete", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- 公开端点（限流）

type ipLimiter struct {
	mu     gosync.Mutex
	per    int
	window time.Duration
	hits   map[string][]time.Time
}

func newIPLimiter(per int, window time.Duration) *ipLimiter {
	return &ipLimiter{per: per, window: window, hits: map[string][]time.Time{}}
}

func (l *ipLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.hits) > 50000 { // 防止被大量来源撑爆内存：清掉过期条目
		for k, ts := range l.hits {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > l.window {
				delete(l.hits, k)
			}
		}
	}
	ts := l.hits[key]
	keep := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < l.window {
			keep = append(keep, t)
		}
	}
	if len(keep) >= l.per {
		l.hits[key] = keep
		return false
	}
	l.hits[key] = append(keep, now)
	return true
}

func (h *handlers) limited(w http.ResponseWriter, r *http.Request) bool {
	ip := clientIP(r, h.trusted)
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	if !h.publicLimiter.allow(ip) {
		w.Header().Set("Retry-After", "60")
		writeCoded(w, http.StatusTooManyRequests, CodeRateLimited, "too many requests; retry later", true)
		return true
	}
	return false
}

// pairingEnvelope GET /api/v2/pairings/{id}/envelope（公开，**不消费**）。
// 链接预览、安全扫描、刷新都不会让配对失效；只返回密文（密钥在链接 #fragment）。
func (h *handlers) pairingEnvelope(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if h.limited(w, r) {
		return
	}
	ct, expiresAt, err := h.svc.PairingEnvelope(r.PathValue("id"))
	if errors.Is(err, syncsvc.ErrPairingNotFound) {
		writeCoded(w, http.StatusNotFound, CodeNotFound, "pairing not found, expired, used or revoked", false)
		return
	}
	if err != nil {
		h.internalError(w, "pairing envelope", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ciphertext": ct, "expiresAt": expiresAt, "state": "active"})
}

// redeemEnrollment POST /api/v2/device-enrollments/redeem（公开，secret 即认证）。
func (h *handlers) redeemEnrollment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if h.limited(w, r) {
		return
	}
	var req struct {
		EnrollmentSecret string `json:"enrollmentSecret"`
		ExchangeID       string `json:"exchangeId"`
		ExpectedVaultID  string `json:"expectedVaultId"`
		Device           struct {
			Name          string `json:"name"`
			Platform      string `json:"platform"`
			ClientVersion string `json:"clientVersion"`
		} `json:"device"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil ||
		req.EnrollmentSecret == "" || !syncsvc.ValidExchangeID(req.ExchangeID) {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "invalid body", false)
		return
	}
	vaultID, err := h.svc.EnrollmentVault(req.EnrollmentSecret)
	if err != nil {
		time.Sleep(300 * time.Millisecond) // 与登录、邀请同款减速
		writeCoded(w, http.StatusNotFound, CodeNotFound, "enrollment not found", false)
		return
	}
	res, err := h.svc.RedeemEnrollment(db.ScopeFromAuth(vaultID), syncsvc.RedeemParams{
		Secret: req.EnrollmentSecret, ExchangeID: req.ExchangeID, ExpectedVaultID: req.ExpectedVaultID,
		DeviceName: req.Device.Name, Platform: normalizeClientPlatform(req.Device.Platform),
	})
	switch {
	case errors.Is(err, syncsvc.ErrEnrollmentInvalid):
		writeCoded(w, http.StatusNotFound, CodeNotFound, "enrollment not found", false)
	case errors.Is(err, syncsvc.ErrPairingUsed):
		writeCoded(w, http.StatusGone, CodePairingUsed, "this link has already been used", false)
	case errors.Is(err, syncsvc.ErrPairingExpired):
		writeCoded(w, http.StatusGone, CodePairingExpired, "this link has expired", false)
	case errors.Is(err, syncsvc.ErrPairingRevoked):
		writeCoded(w, http.StatusGone, CodePairingRevoked, "this link has been revoked", false)
	case errors.Is(err, syncsvc.ErrVaultMismatch):
		writeCoded(w, http.StatusConflict, CodeVaultMismatch, "this link belongs to a different vault", false)
	case errors.Is(err, syncsvc.ErrVaultNotReady):
		writeVaultNotReady(w)
	case err != nil:
		h.internalError(w, "enrollment redeem", err)
	default:
		writeJSON(w, http.StatusOK, res)
	}
}

// contentWriteRoute：需要仓库已完成加密初始化的写路由（readyGate 的 API 层闸门；
// 业务层的 guardWriteReady 是第二道）。
func contentWriteRoute(method, path string) bool {
	switch {
	case path == "/api/v1/file" && (method == http.MethodPut || method == http.MethodDelete),
		path == "/api/v1/file/rename" && method == http.MethodPost,
		strings.HasPrefix(path, "/api/v1/files/") && strings.HasSuffix(path, "/restore"),
		strings.HasPrefix(path, "/api/v1/meta/") && method == http.MethodPost,
		path == "/api/v1/share" && method == http.MethodPost,
		path == "/api/v1/enrollments" && method == http.MethodPost,
		path == "/api/v1/pairing" && method == http.MethodPost:
		return true
	}
	return false
}

// readyGate 在认证之后、处理器之前拦截未就绪仓库的内容写入（ADR-012 I-1）。
func readyGate(h *handlers, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if contentWriteRoute(r.Method, r.URL.Path) {
			if id := identityFrom(r); id != nil && id.VaultID != "" {
				ok, err := h.svc.VaultReady(db.ScopeFromAuth(id.VaultID))
				if err != nil {
					h.internalError(w, "vault ready", err)
					return
				}
				if !ok {
					writeVaultNotReady(w)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// publicAPIRoute：/api/ 下少数**公开**端点（secret 即认证），不经过 authGate。
func publicAPIRoute(r *http.Request) bool {
	p := r.URL.Path
	return (r.Method == http.MethodGet && strings.HasPrefix(p, "/api/v2/pairings/") && strings.HasSuffix(p, "/envelope")) ||
		(r.Method == http.MethodPost && p == "/api/v2/device-enrollments/redeem")
}

// mailWebhook POST /hooks/mail/resend：服务商回执（Svix 签名校验在 handler 内）。
func (h *handlers) mailWebhook(w http.ResponseWriter, r *http.Request) {
	if h.opts.MailWebhook == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	h.opts.MailWebhook.ServeHTTP(w, r)
}

// adminMailStatus GET /api/v1/admin/mail/status：投递计数（不含任何地址）。
func (h *handlers) adminMailStatus(w http.ResponseWriter, _ *http.Request) {
	st, err := h.svc.MailStats()
	if err != nil {
		h.internalError(w, "mail status", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"queued": st.Queued, "sending": st.Sending, "sent": st.Sent, "failed": st.Failed, "suppressed": st.Suppressed,
	})
}
