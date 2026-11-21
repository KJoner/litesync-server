package api

// 账号撤销的三种范围（v0.20.1 / ADR-019）的 HTTP 层。
//
//	A 退出此会话           POST /auth/logout（本浏览器）、身份中心 back-channel logout（sid 或只有 sub）
//	                       ——只结束网页会话，设备凭据与待领取授权不受影响（R-3）
//	B 退出本产品的全部设备  POST /api/v2/account/logout-devices
//	C 退出所有产品与设备    POST /api/v2/account/logout-all
//	                       本产品 B → 身份中心（用户本人的令牌结束他在所有浏览器的 SSO 会话）
//	                       → 另一个产品（持久化事件，同步投递一次，失败后台重试）
//	                       每一步的真实结果都如实返回；任何一步没完成，ok=false（R-5）
//	GET  /api/v2/account/revocations                    最近的撤销事件与投递状态
//	POST /api/v2/account/revocations/{eventId}/retry    重新发送（尚未送达的跨产品事件）
//
// B / C 之后本产品的全部网页会话（包括发起的这一个）都已失效；C 的响应额外带一个只能查看 / 重发
// 这一个事件的 statusToken（30 分钟），浏览器凭它在结果页上看到 pending / failed 并重新发送。

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/KJoner/litesync-server/internal/db"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// peerProductName：跨产品撤销的对方产品（ADR-019 §2.4 只定义了 LiteSync ↔ Nexus 一对）。
const peerProductName = "nexus"

// 身份中心一步的状态（ADR-019 §2.3）。
const (
	identityDone          = "done"
	identityFailed        = "failed"
	identityNotApplicable = "not-applicable"
)

func rfc3339(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

func clearSessionCookies(w http.ResponseWriter) {
	for _, name := range []string{sessionCookieName, adminCookieName} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
}

// linkedIdentity 返回账号在本实例身份中心下的 (issuer, subject)；没有绑定（或未启用统一登录）返回 ok=false。
func (h *handlers) linkedIdentity(userID string) (issuer, subject string, ok bool) {
	if h.rp == nil {
		return "", "", false
	}
	ids, err := h.svc.IdentitiesOf(userID)
	if err != nil {
		return "", "", false
	}
	for _, id := range ids {
		if id.Issuer == h.rp.opts.Issuer {
			return id.Issuer, id.Subject, true
		}
	}
	return "", "", false
}

// logoutDevices POST /api/v2/account/logout-devices：动作 B。
func (h *handlers) logoutDevices(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	if me == nil || me.UserID == "" {
		writeCoded(w, http.StatusForbidden, CodeForbidden, "需要用账号身份（网页登录或 API Token）执行", false)
		return
	}
	res, err := h.svc.RevokeAccount(syncsvc.RevokeRequest{UserID: me.UserID})
	if err != nil {
		h.internalError(w, "logout devices", err)
		return
	}
	clearSessionCookies(w)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "eventId": res.EventID, "scope": db.RevocationScopeProduct,
		"local": map[string]any{"state": "done", "revokedDevices": res.RevokedDevices, "revokedGrants": res.RevokedGrants},
	})
}

// logoutAll POST /api/v2/account/logout-all：动作 C（ADR-019 §2.3）。
func (h *handlers) logoutAll(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	if me == nil || me.UserID == "" {
		writeCoded(w, http.StatusForbidden, CodeForbidden, "需要用账号身份（网页登录或 API Token）执行", false)
		return
	}
	issuer, subject, linked := h.linkedIdentity(me.UserID)
	// 1. 本产品：B（事务内，立即生效）；跨产品事件与它同一事务写入 outbox
	res, err := h.svc.RevokeAccount(syncsvc.RevokeRequest{
		UserID: me.UserID, AllProducts: true, Reason: syncsvc.RevokeReasonUserRequest,
		PeerIssuer: issuer, PeerSubject: subject,
	})
	if err != nil {
		h.internalError(w, "logout all", err)
		return
	}
	// 2. 身份中心：用户本人的令牌结束他在所有浏览器的 SSO 会话
	if linked {
		state, errClass := h.rp.endAllSessions(r.Context(), me.oidc)
		if err := h.svc.SetRevocationIdentityResult(res.EventID, state, errClass); err != nil {
			h.opts.Logger.Error("record identity-center result failed", "event", res.EventID, "error", err)
		}
		// 3. 另一个产品：请求返回前同步投递一次（失败的留给后台重试）
		h.svc.DeliverRevocationNow(r.Context(), res.EventID)
	}
	clearSessionCookies(w)
	rec, err := h.svc.RevocationForUser(res.EventID, me.UserID)
	if err != nil || rec == nil {
		h.internalError(w, "logout all", err)
		return
	}
	out := h.revocationJSON(rec)
	if res.StatusToken != "" {
		out["statusToken"] = res.StatusToken
	}
	if ic, _ := out["identityCenter"].(map[string]any); ic != nil && ic["state"] == identityFailed && h.rp != nil && h.rp.endSess != "" {
		// 身份中心一步失败：至少可以结束**这个浏览器**的 SSO 会话（其他浏览器要到账号中心手动退出）
		v := url.Values{}
		v.Set("client_id", h.rp.opts.ClientID)
		v.Set("post_logout_redirect_uri", h.rp.opts.PublicURL+"/")
		if me.idTokenHint != "" {
			v.Set("id_token_hint", me.idTokenHint)
		}
		out["endSessionUrl"] = h.rp.endSess + "?" + v.Encode()
	}
	writeJSON(w, http.StatusOK, out)
}

// revocationJSON 把一个撤销事件变成账户中心展示的形状（只含时间、对象产品、状态与错误类别，不含令牌）。
func (h *handlers) revocationJSON(r *db.RevocationRecord) map[string]any {
	out := map[string]any{
		"eventId": r.EventID, "createdAt": rfc3339(r.CreatedAt), "scope": r.Scope, "reason": r.Reason, "origin": r.Origin,
		"local": map[string]any{"state": "done", "revokedDevices": r.RevokedDevices, "revokedGrants": r.RevokedGrants},
	}
	if r.Scope != db.RevocationScopeAllProducts || r.Origin != "litesync" {
		out["ok"] = true
		return out
	}
	ic := map[string]any{"state": r.IdentityState}
	if r.IdentityState == identityNotApplicable {
		ic["reason"] = "no-linked-identity"
	}
	if r.IdentityError != "" {
		ic["error"] = r.IdentityError
	}
	if r.IdentityState == identityFailed && h.rp != nil && h.rp.acctURL != "" {
		ic["accountConsoleUrl"] = h.rp.acctURL
	}
	out["identityCenter"] = ic
	peers := make([]map[string]any, 0, len(r.Deliveries))
	ok := r.IdentityState == identityDone || r.IdentityState == identityNotApplicable
	for _, d := range r.Deliveries {
		p := map[string]any{"product": d.Peer, "state": d.State, "attempts": d.Attempts}
		switch d.State {
		case db.DeliveryPending:
			p["nextAttemptAt"] = rfc3339(d.NextAttemptAt)
			p["expiresAt"] = rfc3339(d.ExpiresAt)
		case db.DeliveryDelivered:
			p["deliveredAt"] = rfc3339(d.DeliveredAt)
			if d.PeerResult != "" {
				p["result"] = d.PeerResult
			}
		}
		if d.LastError != "" && d.State != db.DeliveryDelivered {
			p["error"] = d.LastError
		}
		if d.State != db.DeliveryDelivered {
			ok = false
		}
		peers = append(peers, p)
	}
	if len(r.Deliveries) == 0 && r.IdentityState != identityNotApplicable {
		// 绑定了统一账号却没有可投递的对方：跨产品撤销没有配置，另一个产品没有被通知
		peers = append(peers, map[string]any{"product": peerProductName, "state": "not-configured"})
		ok = false
	}
	out["peers"] = peers
	out["ok"] = ok
	return out
}

// accountRevocations GET /api/v2/account/revocations：最近的撤销事件与投递状态。
func (h *handlers) accountRevocations(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	if me == nil || me.UserID == "" {
		writeCoded(w, http.StatusForbidden, CodeForbidden, "需要用账号身份查看", false)
		return
	}
	list, err := h.svc.ListRevocations(me.UserID, 20)
	if err != nil {
		h.internalError(w, "account revocations", err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for i := range list {
		out = append(out, h.revocationJSON(&list[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"revocations": out, "config": h.revocationConfigJSON()})
}

// revocationConfigJSON：账户中心 / 管理员需要知道的部署事实（如实提示「未配置」）。
func (h *handlers) revocationConfigJSON() map[string]any {
	return map[string]any{
		"identityCenter":     h.rp != nil,
		"peerRevocation":     h.svc.PeerRevocationConfigured(),
		"centralStatusCheck": h.central != nil,
	}
}

// ---------------------------------------------------------------- 身份中心（动作 C 第 2 步）

// 身份中心一步的错误类别（稳定字符串，账户中心据此给出中文说明）。
const (
	idErrNoUserToken   = "no-user-token"        // 会话里没有可用的 refresh token（API Token 登录、身份服务没给）
	idErrSessionEnded  = "session-expired"      // refresh 被拒：身份中心那边的会话已经结束
	idErrUnreachable   = "identity-unreachable" // 网络 / 超时 / 发现文档不可用
	idErrForbidden     = "forbidden"            // 403：client 缺少 account/manage-account 的作用域映射（配置问题）
	idErrUnauthorized  = "unauthorized"         // 401：令牌不被 Account API 接受（缺少 aud=account 等）
	idErrNotSupported  = "not-supported"        // 404 / 405：身份服务没有 Account REST API
	idErrIdentityError = "identity-error"       // 其他非预期响应
)

// endAllSessions 用该用户自己的 access token（会话里的 refresh token 先换新）调用 Keycloak
// Account REST API `DELETE {issuer}/account/sessions?current=true`，结束他在所有浏览器的
// SSO 会话（ADR-019 §2.3）。只用用户本人的 manage-account 权限；浏览器拿不到任何身份中心令牌。
//
// Keycloak 随后对每个会话向两个产品发 back-channel logout——那是动作 A，backchannelLogout
// 照常处理即可（本产品的会话此时已因 B 失效）。
func (rp *oidcRP) endAllSessions(ctx context.Context, st *oidcSessionState) (state, errClass string) {
	if st == nil {
		return identityFailed, idErrNoUserToken
	}
	st.mu.Lock()
	refresh := st.refreshToken
	st.mu.Unlock()
	if refresh == "" {
		return identityFailed, idErrNoUserToken
	}
	cctx, cancel := context.WithTimeout(rp.ctx(ctx), identityCallTimeout)
	defer cancel()
	if err := rp.ensure(cctx); err != nil {
		return identityFailed, idErrUnreachable
	}
	ts := rp.oauth.TokenSource(cctx, &oauth2.Token{RefreshToken: refresh, Expiry: time.Now().Add(-time.Second)})
	tok, err := ts.Token()
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && (re.ErrorCode == "invalid_grant" ||
			re.Response != nil && re.Response.StatusCode >= 400 && re.Response.StatusCode < 500) {
			return identityFailed, idErrSessionEnded
		}
		return identityFailed, idErrUnreachable
	}
	if tok.RefreshToken != "" {
		st.mu.Lock()
		st.refreshToken = tok.RefreshToken
		st.mu.Unlock()
	}
	req, err := http.NewRequestWithContext(cctx, http.MethodDelete,
		strings.TrimRight(rp.opts.Issuer, "/")+"/account/sessions?current=true", nil)
	if err != nil {
		return identityFailed, idErrIdentityError
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := rp.opts.HTTPClient.Do(req)
	if err != nil {
		return identityFailed, idErrUnreachable
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)) //nolint:errcheck
	switch {
	case resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK:
		return identityDone, ""
	case resp.StatusCode == http.StatusUnauthorized:
		return identityFailed, idErrUnauthorized
	case resp.StatusCode == http.StatusForbidden:
		return identityFailed, idErrForbidden
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed:
		return identityFailed, idErrNotSupported
	default:
		return identityFailed, idErrIdentityError
	}
}

// identityCallTimeout：动作 C 里身份中心一步的总时限（换令牌 + 结束会话）。
var identityCallTimeout = 6 * time.Second

// ---------------------------------------------------------------- 重新发送与进度查看

// retryRevocation POST /api/v2/account/revocations/{eventId}/retry：账号本人重新发送尚未送达的跨产品事件。
func (h *handlers) retryRevocation(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	if me == nil || me.UserID == "" {
		writeCoded(w, http.StatusForbidden, CodeForbidden, "需要用账号身份执行", false)
		return
	}
	rec, err := h.svc.RevocationForUser(r.PathValue("eventId"), me.UserID)
	if err != nil {
		h.internalError(w, "revocation retry", err)
		return
	}
	if rec == nil {
		writeCoded(w, http.StatusNotFound, CodeNotFound, "没有这条撤销记录", false)
		return
	}
	h.resendAndReport(w, r, rec, me.UserID)
}

// revocationStatus GET /api/v2/revocation-status/{eventId}（公开路径；X-Revocation-Status-Token 即认证）：
// 动作 C 之后本产品的会话都已失效，结果页凭 C 响应里的一次性凭证查看这一个事件的进度。
func (h *handlers) revocationStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if h.limited(w, r) {
		return
	}
	rec, ok := h.statusTokenRecord(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, h.revocationJSON(rec))
}

// revocationStatusResend POST /api/v2/revocation-status/{eventId}/resend：同上，重新发送。
func (h *handlers) revocationStatusResend(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if h.limited(w, r) {
		return
	}
	rec, ok := h.statusTokenRecord(w, r)
	if !ok {
		return
	}
	h.resendAndReport(w, r, rec, rec.UserID)
}

func (h *handlers) statusTokenRecord(w http.ResponseWriter, r *http.Request) (*db.RevocationRecord, bool) {
	rec, err := h.svc.RevocationByStatusToken(r.PathValue("eventId"), r.Header.Get("X-Revocation-Status-Token"))
	if err != nil {
		h.internalError(w, "revocation status", err)
		return nil, false
	}
	if rec == nil {
		// 不存在、凭证不符、已过期一律 404（不区分原因）
		writeCoded(w, http.StatusNotFound, CodeNotFound, "这个进度链接已失效：请重新登录后在「账号与设备」查看", false)
		return nil, false
	}
	return rec, true
}

func (h *handlers) resendAndReport(w http.ResponseWriter, r *http.Request, rec *db.RevocationRecord, userID string) {
	if len(rec.Deliveries) == 0 {
		writeCoded(w, http.StatusConflict, CodeConflict, "这条撤销没有需要发往另一个产品的事件（或跨产品撤销未配置）", false)
		return
	}
	if err := h.svc.RetryRevocation(r.Context(), rec.EventID); err != nil {
		if errors.Is(err, syncsvc.ErrPeerNotEnabled) {
			writeCoded(w, http.StatusConflict, CodeConflict, "跨产品撤销未配置：服务器缺少 OBSYNC_PEER_REVOCATION_URL / _SECRET", false)
			return
		}
		h.internalError(w, "revocation resend", err)
		return
	}
	fresh, err := h.svc.RevocationForUser(rec.EventID, userID)
	if err != nil || fresh == nil {
		h.internalError(w, "revocation resend", err)
		return
	}
	writeJSON(w, http.StatusOK, h.revocationJSON(fresh))
}

// ---------------------------------------------------------------- 接收端

// peerRevocationInbound POST /api/internal/v1/account-revocations（公开路径；HMAC 签名即认证，单独限流）。
//
// 200 已处理（重复投递返回同样的结果）；400 格式错误；401 签名或时间戳不符；5xx 发送方重试。
// 只能撤销、不能授予；不转发。
func (h *handlers) peerRevocationInbound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.svc.PeerRevocationConfigured() {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	ip := clientIP(r, h.trusted)
	if !h.internalLimiter.allow(ip) {
		w.Header().Set("Retry-After", "60")
		writeCoded(w, http.StatusTooManyRequests, CodeRateLimited, "too many requests; retry later", true)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10+1))
	if err != nil || len(body) > 16<<10 {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "invalid body", false)
		return
	}
	if err := h.svc.VerifyPeerRevocation(r.Header.Get("X-Revocation-Timestamp"), r.Header.Get("X-Revocation-Signature"),
		body, time.Now()); err != nil {
		h.opts.Logger.Warn("peer revocation rejected", "reason", "signature-or-timestamp")
		writeCoded(w, http.StatusUnauthorized, CodeUnauthorized, "signature or timestamp rejected", false)
		return
	}
	ev, err := syncsvc.ParsePeerEvent(body)
	if err != nil {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "malformed revocation event", false)
		return
	}
	result, err := h.svc.ApplyPeerRevocation(ev)
	if err != nil {
		h.internalError(w, "peer revocation", err)
		return
	}
	if result == syncsvc.PeerResultApplied {
		writeJSON(w, http.StatusOK, map[string]any{"applied": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"applied": false, "reason": result})
}
