package api

// 统一身份登录（v0.20 公开化 / ADR-011 / 接口约定 §1）。
//
// 本服务只是 OIDC **依赖方**（RP）：注册、密码、邮箱验证、找回全部由外部身份
// 服务（基线 Keycloak）负责。这里做的是一个服务端 BFF：
//
//	/auth/login     生成 state + nonce + PKCE verifier，state 绑定发起浏览器
//	/auth/callback  state 单次消费 → code 交换（带 verifier）→ ID Token 验签与
//	                iss/aud/azp/exp/nonce 校验 → (iss, sub) 映射本地用户 → 产品会话
//
// 浏览器拿不到任何 OIDC Token；会话 Cookie 保持 host-only + HttpOnly +
// SameSite=Strict（现状）。回调是一次跨站导航，Strict Cookie 在跨站重定向链上
// 不会被带上，所以回调不 302，而是返回一个同站跳转页（meta refresh），由它发起
// 的下一次导航是同站的。

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	gosync "sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/KJoner/litesync-server/internal/db"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

const (
	oidcBindCookie      = "litesync_oidc_bind"
	loginIntentTTL      = 10 * time.Minute
	sessionRevalidate   = 5 * time.Minute  // 会话向身份服务复核的周期（ADR-011 I-6）
	revalidateGrace     = 30 * time.Minute // 身份服务暂时不可达时的最长宽限
	maxPendingIntents   = 10000            // 内存中待完成登录的上限（防止被刷爆）
	backchannelEventKey = "http://schemas.openid.net/event/backchannel-logout"
)

// OIDCOptions 是统一登录的配置（全部来自服务端环境变量）。
type OIDCOptions struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// PublicURL：对外规范地址（无尾斜杠）。回调地址 = PublicURL + "/auth/callback"。
	PublicURL string
	// RegistrationMode：closed | invite | open。
	RegistrationMode string
	// HTTPClient：访问身份服务用的客户端（测试注入；生产默认 10 秒超时）。
	HTTPClient *http.Client
	// StatusClientID / StatusClientSecret：中心状态检查用的只读服务账号（client credentials，
	// realm-management 的 view-users；ADR-019 §2.5）。两者都非空才启用动作 D 的检查。
	StatusClientID     string
	StatusClientSecret string
	// AdminAPIURL：Keycloak 管理接口基址（…/admin/realms/{realm}）；空 = 从 Issuer 推导。
	AdminAPIURL string
}

func (o OIDCOptions) enabled() bool {
	return o.Issuer != "" && o.ClientID != "" && o.ClientSecret != "" && o.PublicURL != ""
}

// loginIntent 是一次尚未完成的登录（state 的服务端记录，单次使用）。
type loginIntent struct {
	nonce       string
	verifier    string
	returnTo    string
	bindingHash string
	linkUserID  string // 非空 = 旧账号认领（ADR-011 §1.7）
	invite      string // 邀请模式下的邀请 secret
	admin       bool   // 管理员提升：要求重新认证，成功后同时下发 admin 会话
	expires     time.Time
}

// oidcSessionState 是 OIDC 会话的复核状态（指针共享，自带锁）。
type oidcSessionState struct {
	mu            gosync.Mutex
	issuer        string
	subject       string
	sid           string
	refreshToken  string
	idToken       string
	emailVerified bool
	revalidateAt  time.Time
	lastValidated time.Time
}

type oidcRP struct {
	opts OIDCOptions
	svc  *syncsvc.Service

	initMu   gosync.Mutex
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	logoutV  *oidc.IDTokenVerifier
	oauth    *oauth2.Config
	endSess  string
	acctURL  string

	mu      gosync.Mutex
	intents map[string]*loginIntent // sha256(state) → intent
	seenJTI map[string]time.Time    // back-channel logout 防重放
}

func newOIDCRP(opts OIDCOptions, svc *syncsvc.Service) *oidcRP {
	if !opts.enabled() {
		return nil
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &oidcRP{
		opts: opts, svc: svc,
		intents: map[string]*loginIntent{},
		seenJTI: map[string]time.Time{},
	}
}

func (rp *oidcRP) ctx(parent context.Context) context.Context {
	return oidc.ClientContext(parent, rp.opts.HTTPClient)
}

// ensure 懒加载身份服务的发现文档与 JWKS（身份服务启动晚于本服务时不致命）。
func (rp *oidcRP) ensure(ctx context.Context) error {
	rp.initMu.Lock()
	defer rp.initMu.Unlock()
	if rp.provider != nil {
		return nil
	}
	p, err := oidc.NewProvider(rp.ctx(ctx), rp.opts.Issuer) // 发现文档的 issuer 必须与配置逐字一致
	if err != nil {
		return err
	}
	algs := []string{oidc.RS256, oidc.ES256} // 白名单：拒绝 none 与 HS*
	rp.verifier = p.Verifier(&oidc.Config{ClientID: rp.opts.ClientID, SupportedSigningAlgs: algs})
	// logout token 的 exp 在部分实现里可缺省：单独的校验器跳过 exp，由我们检查 iat
	rp.logoutV = p.Verifier(&oidc.Config{ClientID: rp.opts.ClientID, SupportedSigningAlgs: algs, SkipExpiryCheck: true})
	rp.oauth = &oauth2.Config{
		ClientID:     rp.opts.ClientID,
		ClientSecret: rp.opts.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  rp.opts.PublicURL + "/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	var extra struct {
		EndSession string `json:"end_session_endpoint"`
	}
	_ = p.Claims(&extra) //nolint:errcheck // 可选字段
	rp.endSess = extra.EndSession
	// Keycloak 的账号控制台（改密码、MFA、会话管理）；其他实现没有就不显示。
	// ?referrer=<client>：账号中心页头显示「回到 LiteSync」（回到 client 的 baseUrl，Keycloak 自带）。
	rp.acctURL = strings.TrimRight(rp.opts.Issuer, "/") + "/account?referrer=" + url.QueryEscape(rp.opts.ClientID)
	rp.provider = p
	return nil
}

func randomHex32() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // CSPRNG 失败时任何安全属性都无从谈起
	}
	return hex.EncodeToString(b)
}

func sha256HexStr(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// safeReturnTo 只接受本产品的相对路径（ADR-011 I-5）；其余一律回首页。
func safeReturnTo(v string) string {
	if v == "" || len(v) > 512 || !strings.HasPrefix(v, "/") ||
		strings.HasPrefix(v, "//") || strings.Contains(v, `\`) {
		return "/"
	}
	for _, c := range v {
		if c < 0x20 || c == 0x7f {
			return "/"
		}
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return "/"
	}
	// 解码后的路径同样不得以 // 开头（/%2F%2Fevil 之类的变体）
	if strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	return v
}

func (rp *oidcRP) putIntent(state string, in *loginIntent) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	now := time.Now()
	for k, v := range rp.intents {
		if now.After(v.expires) {
			delete(rp.intents, k)
		}
	}
	if len(rp.intents) >= maxPendingIntents {
		return errors.New("too many pending logins")
	}
	rp.intents[sha256HexStr(state)] = in
	return nil
}

// takeIntent 单次消费（无论后续校验成败，同一个 state 都不能再用第二次）。
func (rp *oidcRP) takeIntent(state string) *loginIntent {
	if state == "" {
		return nil
	}
	rp.mu.Lock()
	defer rp.mu.Unlock()
	k := sha256HexStr(state)
	in := rp.intents[k]
	delete(rp.intents, k)
	if in == nil || time.Now().After(in.expires) {
		return nil
	}
	return in
}

// ---------------------------------------------------------------- 页面

func writePage(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title><link rel="stylesheet" href="/styles.css"></head><body><div class="center-screen"><div class="center-card"><div class="brand">◈ LiteSync</div>%s</div></div></body></html>`,
		html.EscapeString(title), body)
}

// authErrorPage 登录没走完时的页面（UI 焕新 U4b：与账号中心主题同一套说法——「账号中心」「账号密码」，
// 两个出口：重新登录、回到 LiteSync 首页）。只改展示，认证流程与各分支的判断不变。
func authErrorPage(w http.ResponseWriter, status int, msg string) {
	writePage(w, status, "登录没有完成",
		`<h1 class="login-title">登录没有完成</h1><p>`+html.EscapeString(msg)+`</p>`+
			`<p class="muted small">一个账号可用于 LiteSync 和 Nexus。</p>`+
			`<a class="button primary block" href="/auth/login">重新登录</a><a class="button block" href="/">返回 LiteSync 首页</a>`)
}

// providerErrorText 把账号中心回调里的 error 参数（OAuth 2.0 / OIDC 标准代码）换成普通人看得懂的话；
// 不认识的代码原样附在括号里，方便排查。
func providerErrorText(code string) string {
	switch code {
	case "access_denied":
		return "你在账号中心取消了登录。"
	case "temporarily_unavailable", "server_error":
		return "账号中心暂时不可用，请稍后再试。"
	case "login_required", "interaction_required", "consent_required", "account_selection_required":
		return "需要在账号中心重新登录。"
	default:
		return "账号中心没有完成登录（" + code + "）。"
	}
}

// bouncePage 同站跳转页：Strict 会话 Cookie 在跨站重定向链上不会被携带，
// 由这一页发起的导航是同站的（见文件头注释）。
func bouncePage(w http.ResponseWriter, target string) {
	t := html.EscapeString(target)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=%s"><title>LiteSync</title></head><body><p>登录成功，正在进入 <a href="%s">LiteSync</a>…</p></body></html>`, t, t)
}

// ---------------------------------------------------------------- 处理器

// authConfig GET /auth/config（公开）：网页登录页据此决定显示哪些入口。不含任何秘密。
func (h *handlers) authConfig(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"oidc":             h.rp != nil,
		"legacyTokenLogin": h.legacyLoginAllowed(),
		"registrationMode": h.opts.OIDC.RegistrationMode,
	}
	if h.rp != nil && h.rp.ensure(r.Context()) == nil {
		out["accountConsoleUrl"] = h.rp.acctURL
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handlers) legacyLoginAllowed() bool {
	return h.rp == nil || h.opts.LegacyTokenLogin
}

// oidcLogin GET /auth/login?returnTo=&invite=&intent=register|admin
func (h *handlers) oidcLogin(w http.ResponseWriter, r *http.Request) {
	h.startOIDC(w, r, "")
}

// oidcLinkStart GET /auth/link/start?returnTo=
// 旧账号认领：必须持有已认证的旧会话（API Token 网页登录得到的），
// 回调把新的外部主体绑定到**这个**用户（ADR-011 §1.7）。
func (h *handlers) oidcLinkStart(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		authErrorPage(w, http.StatusUnauthorized, "请先用原来的方式登录，再绑定统一账号。")
		return
	}
	info, ok := h.web.lookup(c.Value, false)
	if !ok || !sessionValid(h.svc, info) {
		authErrorPage(w, http.StatusUnauthorized, "会话已失效，请先用原来的方式登录，再绑定统一账号。")
		return
	}
	h.startOIDC(w, r, info.userID)
}

func (h *handlers) startOIDC(w http.ResponseWriter, r *http.Request, linkUserID string) {
	if h.rp == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err := h.rp.ensure(r.Context()); err != nil {
		h.opts.Logger.Warn("oidc discovery failed", "error", err)
		authErrorPage(w, http.StatusServiceUnavailable, "账号中心暂时连不上，请稍后再试。笔记和已连接的设备不受影响。")
		return
	}
	q := r.URL.Query()
	state, nonce, binding := randomHex32(), randomHex32(), randomHex32()
	verifier := oauth2.GenerateVerifier()
	in := &loginIntent{
		nonce: nonce, verifier: verifier,
		returnTo:    safeReturnTo(q.Get("returnTo")),
		bindingHash: sha256HexStr(binding),
		linkUserID:  linkUserID,
		admin:       q.Get("intent") == "admin",
		expires:     time.Now().Add(loginIntentTTL),
	}
	if inv := q.Get("invite"); len(inv) == 64 && isHex(inv) {
		in.invite = inv
	}
	if err := h.rp.putIntent(state, in); err != nil {
		authErrorPage(w, http.StatusServiceUnavailable, "登录请求过多，请稍后再试。")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oidcBindCookie, Value: binding, Path: "/auth", MaxAge: int(loginIntentTTL.Seconds()),
		HttpOnly: true, Secure: h.secureRequest(r),
		// Lax：回调是从身份服务回来的跨站顶层 GET 导航，Strict 不会携带它
		SameSite: http.SameSiteLaxMode,
	})
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)}
	switch {
	case linkUserID != "" || in.admin:
		// 认领与管理员提升都要求**当场**重新认证，不接受身份服务的既有会话
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	case q.Get("intent") == "register":
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "create"))
	}
	http.Redirect(w, r, h.rp.oauth.AuthCodeURL(state, opts...), http.StatusFound)
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

type idClaims struct {
	Email             string `json:"email"`
	EmailVerified     *bool  `json:"email_verified"`
	Name              string `json:"name"`
	Nickname          string `json:"nickname"`
	PreferredUsername string `json:"preferred_username"`
	Azp               string `json:"azp"`
	Sid               string `json:"sid"`
}

// profile 取一次登录的资料快照（UI v2 / I1：用户名、昵称、邮箱各司其职）。
//
//   - 显示名：昵称（可重复、可改）→ 旧账号的 name（姓名）→ preferred_username（与改动前相同的兜底，
//     旧账号不会因此变成空名字）；email 声明从不拿来当显示名。
//   - 用户名：preferred_username 原样，只给账号页「登录用户名」展示，不从昵称推断。
//
// 这些都只是快照：身份永远只认 (issuer, subject)，昵称相同的两个人是两个账号。
func (c idClaims) profile() db.IdentityProfile {
	username := strings.TrimSpace(c.PreferredUsername)
	display := strings.TrimSpace(c.Nickname)
	if display == "" {
		display = strings.TrimSpace(c.Name)
	}
	if display == "" {
		display = username
	}
	return db.IdentityProfile{
		Email:         strings.TrimSpace(c.Email),
		EmailVerified: c.EmailVerified != nil && *c.EmailVerified,
		DisplayName:   display,
		Username:      username,
	}
}

// oidcCallback GET /auth/callback
func (h *handlers) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if h.rp == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	q := r.URL.Query()
	in := h.rp.takeIntent(q.Get("state"))
	// 绑定 Cookie 一次性：无论成败都清掉
	http.SetCookie(w, &http.Cookie{Name: oidcBindCookie, Value: "", Path: "/auth", MaxAge: -1,
		HttpOnly: true, Secure: h.secureRequest(r), SameSite: http.SameSiteLaxMode})
	if in == nil {
		authErrorPage(w, http.StatusBadRequest, "登录请求已过期或已被使用，请重新登录。")
		return
	}
	bc, err := r.Cookie(oidcBindCookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(sha256HexStr(bc.Value)), []byte(in.bindingHash)) != 1 {
		// 回调与发起不是同一个浏览器：典型的登录 CSRF（把别人的 code 塞进受害者浏览器）
		h.opts.Logger.Warn("oidc callback rejected", "reason", "browser-binding")
		authErrorPage(w, http.StatusBadRequest, "登录请求与当前浏览器不匹配，请在同一个浏览器里重新登录。")
		return
	}
	if e := q.Get("error"); e != "" {
		h.opts.Logger.Info("oidc callback error from provider", "error", e)
		authErrorPage(w, http.StatusBadRequest, providerErrorText(e))
		return
	}
	code := q.Get("code")
	if code == "" {
		authErrorPage(w, http.StatusBadRequest, "登录响应不完整，请重新登录。")
		return
	}
	ctx, cancel := context.WithTimeout(h.rp.ctx(r.Context()), 15*time.Second)
	defer cancel()
	if err := h.rp.ensure(ctx); err != nil {
		authErrorPage(w, http.StatusServiceUnavailable, "账号中心暂时连不上，请稍后再试。笔记和已连接的设备不受影响。")
		return
	}
	tok, err := h.rp.oauth.Exchange(ctx, code, oauth2.VerifierOption(in.verifier))
	if err != nil {
		h.opts.Logger.Warn("oidc callback rejected", "reason", "code-exchange", "detail", exchangeErrCode(err))
		authErrorPage(w, http.StatusBadRequest, "登录凭据无效或已过期，请重新登录。")
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		h.opts.Logger.Warn("oidc callback rejected", "reason", "missing-id-token")
		authErrorPage(w, http.StatusBadRequest, "账号中心没有返回身份信息，请重新登录。")
		return
	}
	idt, err := h.rp.verifier.Verify(ctx, rawID) // 签名、iss、aud、exp
	if err != nil {
		h.opts.Logger.Warn("oidc callback rejected", "reason", "id-token-verify")
		authErrorPage(w, http.StatusBadRequest, "身份信息校验失败，请重新登录。")
		return
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(in.nonce)) != 1 {
		h.opts.Logger.Warn("oidc callback rejected", "reason", "nonce")
		authErrorPage(w, http.StatusBadRequest, "身份信息校验失败，请重新登录。")
		return
	}
	var claims idClaims
	if err := idt.Claims(&claims); err != nil {
		authErrorPage(w, http.StatusBadRequest, "身份信息格式不正确。")
		return
	}
	// azp：多受众令牌必须由本客户端获得；出现 azp 时也必须是本客户端
	if (len(idt.Audience) > 1 || claims.Azp != "") && claims.Azp != h.rp.opts.ClientID {
		h.opts.Logger.Warn("oidc callback rejected", "reason", "azp")
		authErrorPage(w, http.StatusBadRequest, "身份信息校验失败，请重新登录。")
		return
	}
	if idt.Subject == "" {
		authErrorPage(w, http.StatusBadRequest, "身份信息缺少主体。")
		return
	}
	profile := claims.profile()

	var user *db.User
	if in.linkUserID != "" {
		user, err = h.svc.LinkOIDCIdentity(in.linkUserID, idt.Issuer, idt.Subject, profile)
		switch {
		case errors.Is(err, syncsvc.ErrIdentityTaken):
			authErrorPage(w, http.StatusConflict, "这个统一账号已经绑定到另一个 LiteSync 用户，不能重复绑定。")
			return
		case errors.Is(err, syncsvc.ErrUserAlreadyLinked):
			authErrorPage(w, http.StatusConflict, "当前用户已经绑定了另一个统一账号。")
			return
		}
	} else {
		user, _, err = h.svc.ResolveOIDCLogin(idt.Issuer, idt.Subject, profile,
			syncsvc.ParseRegistrationMode(h.rp.opts.RegistrationMode), in.invite)
		if errors.Is(err, syncsvc.ErrRegistrationClosed) {
			authErrorPage(w, http.StatusForbidden, "LiteSync 暂未开放注册。如果你收到了邀请，请使用邀请链接进入。")
			return
		}
	}
	if errors.Is(err, syncsvc.ErrAccountDisabled) {
		authErrorPage(w, http.StatusForbidden, "此账号已被停用。")
		return
	}
	if err != nil || user == nil {
		h.opts.Logger.Error("oidc login failed", "error", err)
		authErrorPage(w, http.StatusInternalServerError, "登录失败，请稍后再试。")
		return
	}
	if in.admin && !user.IsAdmin {
		authErrorPage(w, http.StatusForbidden, "当前账号不是管理员。")
		return
	}

	vaultID, err := h.svc.OwnerVaultOf(user.UserID) // 零仓库账号为空，这是正常状态
	if err != nil {
		h.internalError(w, "oidc session", err)
		return
	}
	now := time.Now()
	st := &oidcSessionState{
		issuer: idt.Issuer, subject: idt.Subject, sid: claims.Sid,
		refreshToken: tok.RefreshToken, idToken: rawID, emailVerified: profile.EmailVerified,
		revalidateAt: now.Add(sessionRevalidate), lastValidated: now,
	}
	display := profile.DisplayName
	if display == "" {
		display = user.Name
	}
	base := sessionInfo{
		userID: user.UserID, name: display, isAdmin: user.IsAdmin, vaultID: vaultID,
		tokenGeneration: user.TokenGeneration, authEpoch: user.AuthEpoch, oidc: st, authTime: now,
	}
	h.setSessionCookie(w, r, sessionCookieName, h.web.create(base), int(sessionTTL.Seconds()))
	if in.admin {
		elevated := base
		elevated.admin = true
		h.setSessionCookie(w, r, adminCookieName, h.web.create(elevated), int(adminTTL.Seconds()))
	}
	// 身份中心刚刚认证过这个人：算一次「确认启用」（ADR-019 §2.5 的宽限起点）
	h.central.markOK(user.UserID, now)
	bouncePage(w, in.returnTo)
}

// revalidate 每 ≤5 分钟用 refresh token 向身份服务复核一次会话（ADR-011 I-6）：
// 账号被冻结、在别处「退出全部」后 refresh 会失败，本会话随之失效（这是动作 A：只结束
// 网页会话；设备凭据只由 B / C / D 撤销，ADR-019 R-3）。
// 身份服务暂时不可达时给有限宽限，超过宽限同样失效。返回 valid=false = 会话应作废；
// refreshed=true = 这一次真的向身份服务确认过（中心状态检查把它算作一次「确认启用」）。
func (rp *oidcRP) revalidate(ctx context.Context, st *oidcSessionState) (valid, refreshed bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := oidcNow()
	if now.Before(st.revalidateAt) {
		return true, false
	}
	if st.refreshToken == "" {
		// 身份服务没给 refresh token：没法复核，只能按会话自身期限
		st.revalidateAt = now.Add(sessionRevalidate)
		return true, false
	}
	cctx, cancel := context.WithTimeout(rp.ctx(ctx), 5*time.Second)
	defer cancel()
	if err := rp.ensure(cctx); err != nil {
		return rp.graceLocked(st, now), false
	}
	ts := rp.oauth.TokenSource(cctx, &oauth2.Token{RefreshToken: st.refreshToken, Expiry: now.Add(-time.Second)})
	tok, err := ts.Token()
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && (re.ErrorCode == "invalid_grant" || re.ErrorCode == "unauthorized_client" ||
			re.Response != nil && re.Response.StatusCode >= 400 && re.Response.StatusCode < 500) {
			return false, false // 身份服务明确拒绝：账号冻结 / 全局退出 / 会话被撤销
		}
		return rp.graceLocked(st, now), false
	}
	if rawID, _ := tok.Extra("id_token").(string); rawID != "" {
		// 轮换回来的 ID Token 必须仍是同一个主体
		if idt, verr := rp.verifier.Verify(cctx, rawID); verr != nil || idt.Subject != st.subject {
			return false, false
		} else {
			st.idToken = rawID
		}
	}
	if tok.RefreshToken != "" {
		st.refreshToken = tok.RefreshToken
	}
	st.lastValidated = now
	st.revalidateAt = now.Add(sessionRevalidate)
	return true, true
}

func (rp *oidcRP) graceLocked(st *oidcSessionState, now time.Time) bool {
	if now.Sub(st.lastValidated) > revalidateGrace {
		return false
	}
	st.revalidateAt = now.Add(time.Minute)
	return true
}

// oidcLogout POST /auth/logout：只退出**本产品**的当前会话（身份服务的会话保留，
// 另一个产品不受影响；「退出全部」见 /api/v2/account/logout-all）。
func (h *handlers) oidcLogout(w http.ResponseWriter, r *http.Request) {
	if !h.sameOrigin(r) {
		writeCoded(w, http.StatusForbidden, CodeForbidden, "cross-origin request rejected", false)
		return
	}
	h.destroySession(w, r)
}

// backchannelLogout POST /auth/backchannel-logout（身份服务直连调用，公开）：
// 校验 logout token 后作废对应会话（OIDC Back-Channel Logout 1.0）。
//
// ADR-019：不论带 sid 还是只带 sub，这**永远只是动作 A**——身份中心的会话结束不代表用户
// 要断开全部 Obsidian。sid → 作废这一个网页会话；只有 sub → 作废本产品该用户的全部网页会话
//（会话世代 +1）。设备凭据、待领取授权一律不动（R-3）；它们只由 B / C / D 撤销。
// 动作 C 之后 Keycloak 会为每个会话发来这里，按 A 处理即可（本产品的会话已因 B 失效）。
func (h *handlers) backchannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if h.rp == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	raw := r.PostForm.Get("logout_token")
	if raw == "" || len(raw) > 16<<10 {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	ctx, cancel := context.WithTimeout(h.rp.ctx(r.Context()), 10*time.Second)
	defer cancel()
	if err := h.rp.ensure(ctx); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "identity provider unavailable")
		return
	}
	tok, err := h.rp.logoutV.Verify(ctx, raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid logout token")
		return
	}
	var c struct {
		Events map[string]json.RawMessage `json:"events"`
		Sid    string                     `json:"sid"`
		Nonce  *string                    `json:"nonce"`
		Jti    string                     `json:"jti"`
		Iat    int64                      `json:"iat"`
	}
	if err := tok.Claims(&c); err != nil || c.Nonce != nil || c.Jti == "" {
		writeErr(w, http.StatusBadRequest, "invalid logout token")
		return
	}
	if _, ok := c.Events[backchannelEventKey]; !ok {
		writeErr(w, http.StatusBadRequest, "invalid logout token")
		return
	}
	now := time.Now()
	if c.Iat == 0 || now.Sub(time.Unix(c.Iat, 0)) > 5*time.Minute || time.Unix(c.Iat, 0).After(now.Add(time.Minute)) {
		writeErr(w, http.StatusBadRequest, "stale logout token")
		return
	}
	if !tok.Expiry.IsZero() && now.After(tok.Expiry) {
		writeErr(w, http.StatusBadRequest, "expired logout token")
		return
	}
	if !h.rp.markJTI(c.Jti, now) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true}) // 重放：已处理过
		return
	}
	switch {
	case c.Sid != "":
		h.web.revokeWhere(func(info sessionInfo) bool { return info.oidc != nil && info.oidc.sid == c.Sid })
	case tok.Subject != "":
		if userID, err := h.svc.UserIDForIdentity(tok.Issuer, tok.Subject); err == nil && userID != "" {
			_ = h.svc.EndAllSessions(userID) //nolint:errcheck
		}
	default:
		writeErr(w, http.StatusBadRequest, "logout token names no session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (rp *oidcRP) markJTI(jti string, now time.Time) bool {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	for k, at := range rp.seenJTI {
		if now.Sub(at) > 10*time.Minute {
			delete(rp.seenJTI, k)
		}
	}
	if _, seen := rp.seenJTI[jti]; seen {
		return false
	}
	rp.seenJTI[jti] = now
	return true
}

// sameOrigin：浏览器写请求的 Origin 必须是本服务（Strict Cookie 之外的第二道防线）。
// 非浏览器客户端（插件、curl）不带 Origin，且它们不用 Cookie 认证——放行。
func (h *handlers) sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// 带会话 Cookie 却没有 Origin 的写请求：现代浏览器对非 GET 一定带 Origin，
		// 缺失只可能来自非浏览器客户端，而它们拿不到 HttpOnly 会话 Cookie
		return true
	}
	if h.opts.OIDC.PublicURL != "" && strings.EqualFold(origin, h.opts.OIDC.PublicURL) {
		return true
	}
	scheme := "http"
	if h.secureRequest(r) {
		scheme = "https"
	}
	return strings.EqualFold(origin, scheme+"://"+r.Host)
}

// ---------------------------------------------------------------- /api/v2 账号接口

// me GET /api/v2/me：当前主体、角色、仓库数与新手状态（零仓库账号同样可用）。
func (h *handlers) me(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	owner, err := h.requestOwner(me)
	if err != nil {
		h.internalError(w, "me", err)
		return
	}
	if owner == "" {
		writeCoded(w, http.StatusUnauthorized, CodeAuthRequired, "unauthorized", false)
		return
	}
	u, err := h.svc.UserByID(owner)
	if err != nil || u == nil {
		writeCoded(w, http.StatusUnauthorized, CodeAuthRequired, "unauthorized", false)
		return
	}
	vaults, err := h.svc.ListUserVaults(owner)
	if err != nil {
		h.internalError(w, "me", err)
		return
	}
	ids, err := h.svc.IdentitiesOf(owner)
	if err != nil {
		h.internalError(w, "me", err)
		return
	}
	display, email, verified, username := u.Name, "", !me.Restricted, ""
	if len(ids) > 0 {
		email, verified, username = ids[0].Email, ids[0].EmailVerified, ids[0].Username
		if ids[0].DisplayName != "" {
			display = ids[0].DisplayName
		}
	}
	role, perms := "user", []string{"vault:list", "vault:create", "device:list", "device:revoke"}
	if u.IsAdmin {
		role = "admin"
		perms = append(perms, "instance:admin")
	}
	if me.Restricted {
		perms = []string{"vault:list"}
	}
	onboarding := "ready"
	if len(vaults) == 0 {
		onboarding = "needs_first_vault"
	}
	kind := "token"
	switch {
	case me.DeviceID != "":
		kind = "device"
	case me.ViaOIDC:
		kind = "oidc"
	}
	account := map[string]any{
		"id": owner, "displayName": display, "email": email, "emailVerified": verified,
	}
	if username != "" {
		// 登录用户名：身份服务给的 preferred_username 快照，只用于展示（存量映射下次登录后才有）
		account["username"] = username
	}
	out := map[string]any{
		"account":     account,
		"product":     "litesync",
		"role":        role,
		"permissions": perms,
		"vaultCount":  len(vaults),
		"onboarding":  map[string]any{"state": onboarding},
		"identity":    map[string]any{"linked": len(ids) > 0},
		"session":     map[string]any{"kind": kind, "legacyLogin": h.legacyLoginAllowed()},
		"features": map[string]any{
			"oidc":             h.rp != nil,
			"registrationMode": h.opts.OIDC.RegistrationMode,
			"webEditing":       h.opts.WebEditing,
			// ADR-019：账户中心据此如实提示「跨产品撤销 / 中心状态检查未配置」
			"revocation": h.revocationConfigJSON(),
		},
	}
	if h.rp != nil && h.rp.ensure(r.Context()) == nil {
		out["accountConsoleUrl"] = h.rp.acctURL
	}
	// 用量与上限（需求 §12：达到额度之前就让用户看得到；limit 0 = 不限）
	if usage, err := h.svc.UserUsage(owner); err == nil {
		out["usage"] = usageJSON(usage)
	}
	writeJSON(w, http.StatusOK, out)
}

// accountDevices GET /api/v2/devices：账户中心的设备列表（名下全部仓库）。
func (h *handlers) accountDevices(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	if me == nil || me.UserID == "" {
		writeCoded(w, http.StatusForbidden, CodeForbidden, "user session required", false)
		return
	}
	devices, err := h.svc.ListAllUserDevices(me.UserID)
	if err != nil {
		h.internalError(w, "account devices", err)
		return
	}
	vaults, err := h.svc.ListUserVaults(me.UserID)
	if err != nil {
		h.internalError(w, "account devices", err)
		return
	}
	names := map[string]string{}
	for _, v := range vaults {
		names[v.VaultID] = v.Name
	}
	out := make([]map[string]any, 0, len(devices))
	for _, d := range devices {
		out = append(out, map[string]any{
			"id": d.DeviceID, "name": d.Name, "platform": d.Platform,
			"vaultId": d.VaultID, "vaultName": names[d.VaultID],
			"createdAt": d.CreatedAt, "lastSeenAt": d.LastSeenAt, "revoked": d.Revoked,
			"clientVersion": d.ClientVersion,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

// accountRevokeDevice DELETE /api/v2/devices/{id}：撤销自己名下的一台设备。
func (h *handlers) accountRevokeDevice(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	if me == nil || me.UserID == "" {
		writeCoded(w, http.StatusForbidden, CodeForbidden, "user session required", false)
		return
	}
	ok, err := h.svc.RevokeUserDevice(me.UserID, r.PathValue("id"))
	if err != nil {
		h.internalError(w, "account revoke device", err)
		return
	}
	if !ok {
		writeCoded(w, http.StatusNotFound, CodeNotFound, "device not found", false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

// oidcNow 是会话复核用的时钟（测试经 export_test.go 推进它，生产恒为 time.Now）。
var oidcNow = time.Now

// exchangeErrCode 只取 OAuth 错误码记日志（响应体可能含身份服务的诊断信息，不整段落盘）。
func exchangeErrCode(err error) string {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		if re.ErrorCode != "" {
			return re.ErrorCode
		}
		if re.Response != nil {
			return fmt.Sprintf("http-%d", re.Response.StatusCode)
		}
	}
	return "transport"
}
