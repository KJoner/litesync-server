package api_test

// 统一身份登录（v0.20 / ADR-011）的端到端测试；覆盖验收 ID-01、ID-03、ID-06、ID-07
// 的服务端部分（真实 Keycloak 冒烟另行记录，不以本测试冒充）。
//
// 测试内嵌一个最小的 OIDC 身份服务：发现文档、JWKS、授权码（PKCE S256 校验、
// 单次使用）、refresh token（可被撤销以模拟冻结/全局退出）。每个篡改用例只改
// 一个变量，断言「不建会话、不关联身份」，并有一条有效路径作对照。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	gosync "sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/KJoner/litesync-server/internal/api"
	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

const (
	testClientID     = "litesync-web"
	testClientSecret = "test-client-secret-not-real"
)

// ---------------------------------------------------------------- 模拟身份服务

type pendingCode struct {
	clientID, redirectURI, challenge, nonce, sub string
	claims                                       map[string]any
}

// mockAccess 是模拟身份服务签发的一张 access token（不透明字符串 → 归属与权限）。
type mockAccess struct {
	sub     string
	service bool // client credentials 签发的服务账号令牌
	// manageAccount：用户令牌带 aud=account 与 account/manage-account（Keycloak：client 的作用域映射里
	// 加了 account/manage-account 才会有，fullScopeAllowed=false）
	manageAccount bool
	// viewUsers：服务账号令牌带 realm-management/view-users（服务账号授予 + client 作用域映射都要有）
	viewUsers bool
}

// mockUser 是模拟身份服务里一个用户的状态（管理端查询 / 停用 / 删除）。
type mockUser struct {
	disabled bool
	deleted  bool
}

const (
	mockRealm          = "test"
	testStatusClientID = "litesync-status"
	testStatusSecret   = "status-client-secret-not-real"
)

type mockIdP struct {
	t      *testing.T
	srv    *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	mu     gosync.Mutex
	codes  map[string]*pendingCode
	rts    map[string]string // refresh token → sub
	ats    map[string]mockAccess
	users  map[string]*mockUser
	sids   map[string][]string // sub → 这个主体的 SSO 会话 sid（每次登录一个）
	issuer string
	// 篡改钩子：在签发 ID Token 前修改 claims（返回 false 表示用错误的密钥签名）
	tamper func(claims map[string]any) (sameKey bool)

	// ---- ADR-019：Account REST API 与只读管理端查询（行为按 Keycloak 26.8.1 实测建模） ----
	// userTokensLackManageAccount：client 没有 account/manage-account 作用域映射 → Account API 403
	userTokensLackManageAccount bool
	// serviceLacksViewUsers：服务账号没有 view-users（或没进作用域映射）→ 管理端查询 403
	serviceLacksViewUsers bool
	// adminDown：管理端接口不可达（503）；adminDelay：每次查询前等待（模拟超时）
	adminDown  bool
	adminDelay time.Duration
	adminCalls int
	// sessionsEnded：每个主体被 DELETE /account/sessions 结束过几次
	sessionsEnded map[string]int
	// backchannelURL：非空时，结束会话后像 Keycloak 一样对每个会话向依赖方发 back-channel logout
	backchannelURL  string
	backchannelSent []int // 每次回调的 HTTP 状态
}

func newMockIdP(t *testing.T) *mockIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockIdP{t: t, key: key, kid: "test-kid", codes: map[string]*pendingCode{}, rts: map[string]string{},
		ats: map[string]mockAccess{}, users: map[string]*mockUser{}, sids: map[string][]string{},
		sessionsEnded: map[string]int{}}
	realm := "/realms/" + mockRealm
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+realm+"/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"issuer":                                m.issuer,
			"authorization_endpoint":                m.issuer + "/authorize",
			"token_endpoint":                        m.issuer + "/token",
			"jwks_uri":                              m.issuer + "/jwks",
			"end_session_endpoint":                  m.issuer + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("GET "+realm+"/jwks", func(w http.ResponseWriter, _ *http.Request) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &m.key.PublicKey, KeyID: m.kid, Algorithm: "RS256", Use: "sig"}}}
		json.NewEncoder(w).Encode(set) //nolint:errcheck
	})
	mux.HandleFunc("POST "+realm+"/token", m.token)
	mux.HandleFunc("DELETE "+realm+"/account/sessions", m.accountDeleteSessions)
	mux.HandleFunc("GET /admin"+realm+"/users/{id}", m.adminGetUser)
	m.srv = httptest.NewServer(mux)
	m.issuer = m.srv.URL + realm
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockIdP) sign(claims map[string]any, useOtherKey bool) string {
	m.t.Helper()
	key := m.key
	if useOtherKey {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		key = other
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", m.kid))
	if err != nil {
		m.t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		m.t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		m.t.Fatal(err)
	}
	return out
}

func (m *mockIdP) baseClaims(sub, nonce string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": m.issuer, "sub": sub, "aud": testClientID, "azp": testClientID,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": nonce,
		"email": sub + "@example.org", "email_verified": true, "name": "测试用户 " + sub, "sid": "sid-" + sub,
	}
}

func oauthErr(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": code}) //nolint:errcheck
}

// userGoneLocked：停用或删除的用户不能再换令牌（Keycloak 同样拒绝 refresh）。
func (m *mockIdP) userGoneLocked(sub string) bool {
	u := m.users[sub]
	return u != nil && (u.disabled || u.deleted)
}

func (m *mockIdP) issueAccessLocked(a mockAccess) string {
	at := "at-" + hex.EncodeToString(randBytes(12))
	m.ats[at] = a
	return at
}

func (m *mockIdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthErr(w, "invalid_request")
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Content-Type", "application/json") // 真实身份服务都会带；缺了它 oauth2 会按表单解析
	if r.PostForm.Get("grant_type") == "client_credentials" {
		if id != testStatusClientID || secret != testStatusSecret {
			oauthErr(w, "invalid_client")
			return
		}
		at := m.issueAccessLocked(mockAccess{service: true, viewUsers: !m.serviceLacksViewUsers})
		json.NewEncoder(w).Encode(map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": 300}) //nolint:errcheck
		return
	}
	if id != testClientID || secret != testClientSecret {
		oauthErr(w, "invalid_client")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		pc := m.codes[r.PostForm.Get("code")]
		delete(m.codes, r.PostForm.Get("code")) // 授权码单次使用
		if pc == nil || pc.redirectURI != r.PostForm.Get("redirect_uri") {
			m.t.Logf("mock idp: code found=%v code=%q known=%d redirect sent=%q form=%v", pc != nil, r.PostForm.Get("code"), len(m.codes), r.PostForm.Get("redirect_uri"), r.PostForm)
			oauthErr(w, "invalid_grant")
			return
		}
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != pc.challenge {
			m.t.Logf("mock idp: pkce mismatch verifier=%q", r.PostForm.Get("code_verifier"))
			oauthErr(w, "invalid_grant") // PKCE 不符
			return
		}
		claims := m.baseClaims(pc.sub, pc.nonce)
		for k, v := range pc.claims {
			claims[k] = v
		}
		sameKey := true
		if m.tamper != nil {
			sameKey = m.tamper(claims)
		}
		if sid, _ := claims["sid"].(string); sid != "" {
			known := false
			for _, s := range m.sids[pc.sub] {
				known = known || s == sid
			}
			if !known {
				m.sids[pc.sub] = append(m.sids[pc.sub], sid)
			}
		}
		rt := "rt-" + hex.EncodeToString(randBytes(16))
		m.rts[rt] = pc.sub
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"access_token": m.issueAccessLocked(mockAccess{sub: pc.sub, manageAccount: !m.userTokensLackManageAccount}),
			"token_type":   "Bearer", "expires_in": 300,
			"refresh_token": rt, "id_token": m.sign(claims, !sameKey),
		})
	case "refresh_token":
		sub, ok := m.rts[r.PostForm.Get("refresh_token")]
		if !ok || m.userGoneLocked(sub) {
			oauthErr(w, "invalid_grant")
			return
		}
		delete(m.rts, r.PostForm.Get("refresh_token"))
		rt := "rt-" + hex.EncodeToString(randBytes(16))
		m.rts[rt] = sub
		claims := m.baseClaims(sub, "")
		delete(claims, "nonce")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"access_token": m.issueAccessLocked(mockAccess{sub: sub, manageAccount: !m.userTokensLackManageAccount}),
			"token_type":   "Bearer", "expires_in": 300,
			"refresh_token": rt, "id_token": m.sign(claims, false),
		})
	default:
		oauthErr(w, "unsupported_grant_type")
	}
}

func (m *mockIdP) bearer(r *http.Request) (mockAccess, bool) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.ats[tok]
	return a, ok
}

// accountDeleteSessions 模拟 Keycloak Account REST API `DELETE /realms/{realm}/account/sessions?current=true`
//（26.8.1 实测：用户本人令牌 + manage-account → 204；该用户全部会话结束，refresh 一律 invalid_grant，
// 并对每个会话向依赖方发 back-channel logout，logout token 带 sid、没有设备语义）。
func (m *mockIdP) accountDeleteSessions(w http.ResponseWriter, r *http.Request) {
	a, ok := m.bearer(r)
	switch {
	case !ok:
		w.WriteHeader(http.StatusUnauthorized)
		return
	case a.service || !a.manageAccount:
		w.WriteHeader(http.StatusForbidden)
		return
	}
	m.mu.Lock()
	for rt, s := range m.rts {
		if s == a.sub {
			delete(m.rts, rt)
		}
	}
	m.sessionsEnded[a.sub]++
	sids := append([]string(nil), m.sids[a.sub]...)
	delete(m.sids, a.sub)
	target := m.backchannelURL
	m.mu.Unlock()
	if target != "" {
		for _, sid := range sids {
			now := time.Now()
			tok := m.sign(map[string]any{
				"iss": m.issuer, "aud": testClientID, "sub": a.sub, "sid": sid, "typ": "Logout",
				"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": hex.EncodeToString(randBytes(8)),
				"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
			}, false)
			resp, err := http.PostForm(target, url.Values{"logout_token": {tok}})
			code := 0
			if err == nil {
				code = resp.StatusCode
				resp.Body.Close()
			}
			m.mu.Lock()
			m.backchannelSent = append(m.backchannelSent, code)
			m.mu.Unlock()
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// adminGetUser 模拟 `GET /admin/realms/{realm}/users/{sub}`（只读服务账号；启用 200 enabled:true、
// 停用 enabled:false、删除 404；令牌缺 view-users → 403——那是配置错误，不是用户被停用）。
func (m *mockIdP) adminGetUser(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.adminCalls++
	delay, down := m.adminDelay, m.adminDown
	m.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	if down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	a, ok := m.bearer(r)
	switch {
	case !ok:
		w.WriteHeader(http.StatusUnauthorized)
		return
	case !a.service || !a.viewUsers:
		w.WriteHeader(http.StatusForbidden)
		return
	}
	sub := r.PathValue("id")
	m.mu.Lock()
	u := m.users[sub]
	m.mu.Unlock()
	if u != nil && u.deleted {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"id": sub, "username": sub, "enabled": u == nil || !u.disabled}) //nolint:errcheck
}

// setUser 在身份中心里停用 / 恢复 / 删除一个用户（管理员操作的模拟）。
func (m *mockIdP) setUser(sub string, disabled, deleted bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[sub] = &mockUser{disabled: disabled, deleted: deleted}
}

// revokeAll 撤销某主体的全部 refresh token（模拟账号冻结 / 在身份服务里退出全部）。
func (m *mockIdP) revokeAll(sub string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for rt, s := range m.rts {
		if s == sub {
			delete(m.rts, rt)
		}
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b) //nolint:errcheck
	return b
}

// authorize 模拟用户在身份服务完成登录：校验授权请求参数，签发授权码，返回回调 URL。
func (m *mockIdP) authorize(t *testing.T, authURL, sub string, extra map[string]any) string {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil || !strings.HasPrefix(authURL, m.issuer+"/authorize") {
		t.Fatalf("login did not redirect to the IdP: %q", authURL)
	}
	q := u.Query()
	for k, want := range map[string]string{"response_type": "code", "client_id": testClientID, "code_challenge_method": "S256"} {
		if q.Get(k) != want {
			t.Fatalf("authorize param %s = %q, want %q", k, q.Get(k), want)
		}
	}
	for _, k := range []string{"state", "nonce", "code_challenge", "redirect_uri"} {
		if q.Get(k) == "" {
			t.Fatalf("authorize request is missing %s", k)
		}
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("scope %q lacks openid", q.Get("scope"))
	}
	code := "code-" + hex.EncodeToString(randBytes(12))
	m.mu.Lock()
	m.codes[code] = &pendingCode{clientID: testClientID, redirectURI: q.Get("redirect_uri"),
		challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), sub: sub, claims: extra}
	m.mu.Unlock()
	cb, _ := url.Parse(q.Get("redirect_uri"))
	cq := cb.Query()
	cq.Set("code", code)
	cq.Set("state", q.Get("state"))
	cb.RawQuery = cq.Encode()
	return cb.String()
}

// ---------------------------------------------------------------- 测试环境

type oidcEnv struct {
	*testEnv
	idp *mockIdP
}

func newOIDCEnv(t *testing.T, mode string, legacy bool) *oidcEnv {
	return newOIDCEnvWith(t, mode, legacy, nil)
}

// newOIDCEnvWith 允许测试调整 api.Options（中心状态检查的服务账号等）；svcSetup 在服务启动前执行
//（例如配置跨产品撤销）。
func newOIDCEnvWith(t *testing.T, mode string, legacy bool, tweak func(o *api.Options, svc *syncsvc.Service)) *oidcEnv {
	t.Helper()
	idp := newMockIdP(t)
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	store, _ := storage.New(filepath.Join(dir, "vault"))
	blobs, _ := storage.NewBlobStore(filepath.Join(dir, "blobs"))
	shares, _ := storage.NewShareStore(filepath.Join(dir, "shares"))
	logger := slog.New(slog.NewTextHandler(oidcTestLogSink(t), nil))
	svc := syncsvc.New(database, store, blobs, shares, syncsvc.Options{HistoryEnabled: true}, logger)

	ts := httptest.NewUnstartedServer(nil)
	publicURL := "http://" + ts.Listener.Addr().String()
	opts := api.Options{
		Token: testToken, MaxFileSize: 1 << 20, Version: "test", Logger: logger,
		OIDC: api.OIDCOptions{
			Issuer: idp.issuer, ClientID: testClientID, ClientSecret: testClientSecret,
			PublicURL: publicURL, RegistrationMode: mode, HTTPClient: idp.srv.Client(),
		},
		LegacyTokenLogin: legacy,
	}
	if tweak != nil {
		tweak(&opts, svc)
	}
	ts.Config.Handler = api.New(opts, svc)
	ts.Start()
	t.Cleanup(ts.Close)
	return &oidcEnv{testEnv: &testEnv{ts: ts, svc: svc, db: database}, idp: idp}
}

// browser 是一个带 Cookie 的「浏览器」：不自动跟随重定向，便于逐步检查。
type browser struct {
	t   *testing.T
	c   *http.Client
	env *oidcEnv
}

func (e *oidcEnv) newBrowser(t *testing.T) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, env: e, c: &http.Client{Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *browser) get(path string) (*http.Response, string) {
	b.t.Helper()
	target := path
	if strings.HasPrefix(path, "/") {
		target = b.env.ts.URL + path
	}
	resp, err := b.c.Get(target)
	if err != nil {
		b.t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, string(raw)
}

func (b *browser) send(method, path, origin string, body io.Reader) (*http.Response, map[string]any) {
	b.t.Helper()
	req, _ := http.NewRequest(method, b.env.ts.URL+path, body)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	json.Unmarshal(raw, &out) //nolint:errcheck
	return resp, out
}

// startLogin 走到身份服务门口，返回授权 URL。
func (b *browser) startLogin(query string) string {
	b.t.Helper()
	resp, _ := b.get("/auth/login" + query)
	if resp.StatusCode != http.StatusFound {
		b.t.Fatalf("/auth/login = %d, want 302", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

// login 完整走一遍登录；返回回调响应。
func (b *browser) login(sub string, extra map[string]any) (*http.Response, string) {
	b.t.Helper()
	return b.get(b.env.idp.authorize(b.t, b.startLogin(""), sub, extra))
}

func (b *browser) me() (int, map[string]any) {
	b.t.Helper()
	resp, body := b.send(http.MethodGet, "/api/v2/me", "", nil)
	return resp.StatusCode, body
}

// ---------------------------------------------------------------- 用例

// ID-01：统一账号首次登录 → 零仓库账号也能登录，看到「创建第一个仓库」引导；
// 需要仓库的接口明确拒绝（VAULT_REQUIRED），而不是 403「账号没有仓库」。
func TestOIDCLoginCreatesZeroVaultAccount(t *testing.T) {
	e := newOIDCEnv(t, "open", true)
	b := e.newBrowser(t)
	resp, page := b.login("alice-sub", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, `http-equiv="refresh"`) {
		t.Fatalf("callback = %d, want the same-site bounce page; body=%s", resp.StatusCode, page)
	}
	code, me := b.me()
	if code != http.StatusOK {
		t.Fatalf("/api/v2/me = %d body=%v", code, me)
	}
	if me["vaultCount"].(float64) != 0 || me["onboarding"].(map[string]any)["state"] != "needs_first_vault" {
		t.Fatalf("zero-vault onboarding expected, got %v", me)
	}
	acct := me["account"].(map[string]any)
	if acct["email"] != "alice-sub@example.org" || acct["emailVerified"] != true {
		t.Fatalf("profile snapshot wrong: %v", acct)
	}
	if me["role"] != "user" {
		t.Fatalf("a fresh account must never be admin, got role %v", me["role"])
	}
	// 仓库列表可用（空），需要仓库的接口 409 VAULT_REQUIRED
	if resp, body := b.send(http.MethodGet, "/api/v1/vaults", "", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/v1/vaults = %d %v", resp.StatusCode, body)
	}
	if resp, body := b.send(http.MethodGet, "/api/v1/snapshot", "", nil); resp.StatusCode != http.StatusConflict || body["code"] != "VAULT_REQUIRED" {
		t.Fatalf("/api/v1/snapshot for a zero-vault account = %d %v, want 409 VAULT_REQUIRED", resp.StatusCode, body)
	}

	// 再登录一次（同一主体）→ 同一个本地用户，不重复建号
	b2 := e.newBrowser(t)
	b2.login("alice-sub", nil)
	_, me2 := b2.me()
	if me2["account"].(map[string]any)["id"] != acct["id"] {
		t.Fatalf("same (iss,sub) must map to the same local user: %v vs %v", me2["account"], acct)
	}
}

// ID-03：逐项篡改，每一种都不得建立会话。
func TestOIDCCallbackRejectsTampering(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(c map[string]any) bool
	}{
		{"wrong issuer", func(c map[string]any) bool { c["iss"] = "https://evil.example"; return true }},
		{"wrong audience", func(c map[string]any) bool { c["aud"] = "someone-else"; c["azp"] = "someone-else"; return true }},
		{"azp mismatch", func(c map[string]any) bool {
			c["aud"] = []string{testClientID, "other"}
			c["azp"] = "other"
			return true
		}},
		{"nonce mismatch", func(c map[string]any) bool { c["nonce"] = "not-the-nonce"; return true }},
		{"expired", func(c map[string]any) bool { c["exp"] = time.Now().Add(-time.Hour).Unix(); return true }},
		{"signed with unknown key", func(map[string]any) bool { return false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newOIDCEnv(t, "open", true)
			e.idp.tamper = tc.tamper
			b := e.newBrowser(t)
			resp, _ := b.login("mallory", nil)
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("tampered token (%s) produced a 200 callback", tc.name)
			}
			if code, _ := b.me(); code != http.StatusUnauthorized {
				t.Fatalf("tampered token (%s) yielded a session: /api/v2/me = %d", tc.name, code)
			}
		})
	}
}

func TestOIDCCallbackStateAndBrowserBinding(t *testing.T) {
	e := newOIDCEnv(t, "open", true)

	// 1) 重放同一个回调：state 单次使用
	b := e.newBrowser(t)
	cb := e.idp.authorize(t, b.startLogin(""), "victim", nil)
	if resp, _ := b.get(cb); resp.StatusCode != http.StatusOK {
		t.Fatalf("first callback = %d", resp.StatusCode)
	}
	if resp, _ := e.newBrowser(t).get(cb); resp.StatusCode == http.StatusOK {
		t.Fatal("replayed callback (same state/code) must be rejected")
	}

	// 2) 登录 CSRF：攻击者在自己的浏览器发起登录，把回调 URL 塞给受害者
	attacker := e.newBrowser(t)
	evilCB := e.idp.authorize(t, attacker.startLogin(""), "attacker", nil)
	victim := e.newBrowser(t)
	if resp, _ := victim.get(evilCB); resp.StatusCode == http.StatusOK {
		t.Fatal("callback from another browser's login must be rejected (login CSRF)")
	}
	if code, _ := victim.me(); code != http.StatusUnauthorized {
		t.Fatalf("victim must not be signed in as the attacker, /api/v2/me = %d", code)
	}

	// 3) 伪造 state
	b3 := e.newBrowser(t)
	b3.startLogin("")
	if resp, _ := b3.get("/auth/callback?code=x&state=" + strings.Repeat("ab", 32)); resp.StatusCode == http.StatusOK {
		t.Fatal("unknown state must be rejected")
	}

	// 4) PKCE：授权码换给错误的 verifier（直接调 IdP 的 token 端点不经过我们；
	//    这里验证的是我们确实发送了 challenge 且只用一次的授权码不能复用）
	b4 := e.newBrowser(t)
	cb4 := e.idp.authorize(t, b4.startLogin(""), "pkce-user", nil)
	u, _ := url.Parse(cb4)
	e.idp.mu.Lock()
	pc := e.idp.codes[u.Query().Get("code")]
	pc.challenge = "tampered-challenge"
	e.idp.mu.Unlock()
	if resp, _ := b4.get(cb4); resp.StatusCode == http.StatusOK {
		t.Fatal("code exchange with a mismatching PKCE verifier must fail")
	}
}

func TestOIDCRegistrationModes(t *testing.T) {
	closed := newOIDCEnv(t, "closed", true)
	b := closed.newBrowser(t)
	if resp, page := b.login("newcomer", nil); resp.StatusCode != http.StatusForbidden || !strings.Contains(page, "暂未开放注册") {
		t.Fatalf("closed registration: callback = %d", resp.StatusCode)
	}
	if code, _ := b.me(); code != http.StatusUnauthorized {
		t.Fatal("closed registration must not create a session")
	}

	inv := newOIDCEnv(t, "invite", true)
	if resp, _ := inv.newBrowser(t).login("no-invite", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("invite mode without invite: callback = %d, want 403", resp.StatusCode)
	}
	secret := adminCreateInvite(t, inv.testEnv)
	bi := inv.newBrowser(t)
	cb := inv.idp.authorize(t, bi.startLogin("?invite="+secret), "invited", nil)
	if resp, _ := bi.get(cb); resp.StatusCode != http.StatusOK {
		t.Fatalf("invite mode with a valid invite: callback = %d", resp.StatusCode)
	}
	// 邀请一次性：第二个人用同一邀请被拒
	bj := inv.newBrowser(t)
	cbj := inv.idp.authorize(t, bj.startLogin("?invite="+secret), "second", nil)
	if resp, _ := bj.get(cbj); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("reused invite: callback = %d, want 403", resp.StatusCode)
	}
}

// ID-06：旧管理员认领。只有已认证的旧会话能发起；冲突不合并；
// 首个注册者不会成为管理员；同邮箱不等于同一人。
func TestOIDCLegacyAdminClaim(t *testing.T) {
	e := newOIDCEnv(t, "open", true)

	// 首个公开注册者（邮箱甚至伪装成管理员）不是管理员
	first := e.newBrowser(t)
	first.login("first-registrant", map[string]any{"email": "admin@example.org"})
	if _, me := first.me(); me["role"] != "user" {
		t.Fatalf("first public registrant got role %v", me["role"])
	}

	// 没有旧会话不能发起认领
	if resp, _ := e.newBrowser(t).get("/auth/link/start"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("link without legacy session = %d, want 401", resp.StatusCode)
	}

	// 管理员用 API Token 登录 → 认领
	admin := e.newBrowser(t)
	resp, _ := admin.send(http.MethodPost, "/web/session", "", strings.NewReader(`{"token":"`+testToken+`"}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("legacy token login = %d", resp.StatusCode)
	}
	lr, _ := admin.get("/auth/link/start")
	if lr.StatusCode != http.StatusFound || !strings.Contains(lr.Header.Get("Location"), "prompt=login") {
		t.Fatalf("link start must force re-authentication, got %d %q", lr.StatusCode, lr.Header.Get("Location"))
	}
	if r2, _ := admin.get(e.idp.authorize(t, lr.Header.Get("Location"), "admin-sub", nil)); r2.StatusCode != http.StatusOK {
		t.Fatalf("link callback = %d", r2.StatusCode)
	}

	// 之后用统一账号登录 → 进入原管理员账号（default），保留管理员身份与原仓库
	b := e.newBrowser(t)
	b.login("admin-sub", nil)
	_, me := b.me()
	if me["account"].(map[string]any)["id"] != "default" || me["role"] != "admin" || me["vaultCount"].(float64) < 1 {
		t.Fatalf("claimed identity must land on the original admin account: %v", me)
	}

	// 冲突：把已属于别人的主体再绑到管理员上 → 拒绝
	resp, _ = admin.send(http.MethodPost, "/web/session", "", strings.NewReader(`{"token":"`+testToken+`"}`))
	_ = resp
	lr2, _ := admin.get("/auth/link/start")
	if r3, page := admin.get(e.idp.authorize(t, lr2.Header.Get("Location"), "first-registrant", nil)); r3.StatusCode != http.StatusConflict {
		t.Fatalf("linking an identity owned by another user = %d (%s), want 409", r3.StatusCode, page)
	}
}

// ID-07（服务端部分）：身份服务侧冻结/全局退出后，会话在复核时失效；
// logout-all 撤销全部设备并让会话失效。
func TestOIDCRevalidationAndLogoutAll(t *testing.T) {
	e := newOIDCEnv(t, "open", true)
	b := e.newBrowser(t)
	b.login("bob-sub", nil)
	if code, _ := b.me(); code != http.StatusOK {
		t.Fatalf("me = %d", code)
	}
	// 身份服务撤销该主体全部 refresh token（冻结 / 在别处退出全部）；
	// 推进时钟不可行，这里直接让会话立即进入复核窗口
	e.idp.revokeAll("bob-sub")
	api.ForceSessionRevalidation(e.ts.Config.Handler)
	defer api.ResetOIDCClock()
	if code, body := b.me(); code != http.StatusUnauthorized || body["code"] != "AUTH_REQUIRED" {
		t.Fatalf("after IdP revocation /api/v2/me = %d %v, want 401 AUTH_REQUIRED", code, body)
	}

	// logout-all：会话失效 + 设备全部撤销
	c := e.newBrowser(t)
	c.login("carol-sub", nil)
	_, me := c.me()
	userID := me["account"].(map[string]any)["id"].(string)
	// 给 carol 一台设备（模拟插件接入）
	if _, err := e.svc.CreateUserVault(userID, "个人笔记"); err != nil {
		t.Fatal(err)
	}
	vaultID, _ := e.svc.OwnerVaultOf(userID)
	cred, err := e.svc.CreateDevice("phone", vaultID, userID)
	if err != nil {
		t.Fatal(err)
	}
	if code := whoamiStatus(t, e.testEnv, cred.Token); code != http.StatusOK {
		t.Fatalf("device whoami = %d", code)
	}
	// 跨站 logout-all 被拒（Origin 不同源）
	if resp, _ := c.send(http.MethodPost, "/api/v2/account/logout-all", "https://evil.example", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin logout-all = %d, want 403", resp.StatusCode)
	}
	resp, body := c.send(http.MethodPost, "/api/v2/account/logout-all", e.ts.URL, nil)
	local, _ := body["local"].(map[string]any)
	if resp.StatusCode != http.StatusOK || local == nil || local["revokedDevices"].(float64) != 1 {
		t.Fatalf("logout-all = %d %v", resp.StatusCode, body)
	}
	// 动作 C 的身份中心一步真的执行了（模拟身份服务的 Account REST API），且如实报告
	if ic, _ := body["identityCenter"].(map[string]any); ic == nil || ic["state"] != "done" {
		t.Fatalf("identity-center step must report its real state, got %v", body)
	}
	if code := whoamiStatus(t, e.testEnv, cred.Token); code != http.StatusUnauthorized {
		t.Fatalf("device after logout-all whoami = %d, want 401", code)
	}
	if code, _ := c.me(); code != http.StatusUnauthorized {
		t.Fatalf("session after logout-all /api/v2/me = %d, want 401", code)
	}
}

func TestOIDCBackchannelLogout(t *testing.T) {
	e := newOIDCEnv(t, "open", true)
	b := e.newBrowser(t)
	b.login("dave-sub", nil)
	if code, _ := b.me(); code != http.StatusOK {
		t.Fatal("login failed")
	}
	post := func(token string) int {
		resp, err := http.PostForm(e.ts.URL+"/auth/backchannel-logout", url.Values{"logout_token": {token}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	now := time.Now()
	good := map[string]any{
		"iss": e.idp.issuer, "aud": testClientID, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"jti": "jti-1", "sid": "sid-dave-sub",
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}
	// 带 nonce 的不是 logout token
	bad := map[string]any{}
	for k, v := range good {
		bad[k] = v
	}
	bad["nonce"] = "x"
	bad["jti"] = "jti-bad"
	if code := post(e.idp.sign(bad, false)); code != http.StatusBadRequest {
		t.Fatalf("logout token with nonce = %d, want 400", code)
	}
	if code := post(e.idp.sign(good, true)); code != http.StatusBadRequest {
		t.Fatalf("logout token signed by an unknown key = %d, want 400", code)
	}
	if code, _ := b.me(); code != http.StatusOK {
		t.Fatal("invalid logout tokens must not end the session")
	}
	if code := post(e.idp.sign(good, false)); code != http.StatusOK {
		t.Fatalf("valid logout token = %d", code)
	}
	if code, _ := b.me(); code != http.StatusUnauthorized {
		t.Fatalf("session after back-channel logout: /api/v2/me = %d, want 401", code)
	}
}

func TestLegacyTokenLoginCanBeDisabled(t *testing.T) {
	e := newOIDCEnv(t, "open", false)
	resp, body := e.newBrowser(t).send(http.MethodPost, "/web/session", "", strings.NewReader(`{"token":"`+testToken+`"}`))
	if resp.StatusCode != http.StatusForbidden || body["code"] != "LEGACY_LOGIN_DISABLED" {
		t.Fatalf("legacy login with LegacyTokenLogin=false = %d %v", resp.StatusCode, body)
	}
	// Bearer（插件、设备）不受影响
	if code := whoamiStatus(t, e.testEnv, testToken); code != http.StatusOK {
		t.Fatalf("bearer token must keep working, whoami = %d", code)
	}
}

// oidcTestLogSink：OIDC_TEST_LOG=1 时把服务端日志打到测试输出（排查用），否则丢弃。
func oidcTestLogSink(t *testing.T) io.Writer {
	if os.Getenv("OIDC_TEST_LOG") == "1" {
		return testWriter{t}
	}
	return io.Discard
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}
