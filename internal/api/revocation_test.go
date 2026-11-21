package api_test

// 账号撤销的三种范围与跨产品传播（v0.20.1 / ADR-019 §10 测试矩阵）。逐项断言 R-1…R-7：
//   - A 只结束网页会话，设备与待领取授权照常可用（R-3）；
//   - B 之后旧设备、短期票、待领取授权、已消费重放、v1 enrollment、API Token、全部网页会话一起失效，
//     另一个账号不受影响，新登录、新授权可用（R-1、R-4）；
//   - C 逐项报告本产品 / 身份中心 / 另一个产品的真实状态，pending / failed 可见、可重发（R-5、R-6）；
//   - 接收端：签名、时间窗、eventId 去重、未知身份、格式错误、不转发、单独限流；
//   - D：中心停用 / 删除 60 秒内拒绝、单飞、超时、宽限与 503、403 不当成停用、恢复不复活（R-2、R-7）；
//   - 撤销与兑换并发（SQLite 与真实 PostgreSQL 各跑一遍：scripts/test-pg.sh）。
//
// 模拟身份服务按 Keycloak 26.8.1 实测行为建模（Account REST 204、refresh invalid_grant、逐会话
// back-channel、管理端 200/404/403）。真实 Keycloak 的联合验收另行记录，不以本测试冒充。
// 覆盖 INV-12（撤销按账号与 (issuer, subject) 定位，不越过到别的账号）。

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	gosync "sync"
	"testing"
	"time"

	"github.com/KJoner/litesync-server/internal/api"
	"github.com/KJoner/litesync-server/internal/db"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

const testPeerSecret = "peer-revocation-shared-secret-for-tests-0123456789"

// ---------------------------------------------------------------- 另一个产品（接收端替身）

type fakePeer struct {
	srv      *httptest.Server
	mu       gosync.Mutex
	statuses []int // 依次返回；用完后 200
	events   []syncsvc.PeerEvent
	sigOK    []bool
	headers  []http.Header
}

func newFakePeer(t *testing.T, statuses ...int) *fakePeer {
	t.Helper()
	p := &fakePeer{statuses: statuses}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts := r.Header.Get("X-Revocation-Timestamp")
		ok := r.Method == http.MethodPost && r.URL.Path == syncsvc.PeerRevocationPath &&
			r.Header.Get("Content-Type") == "application/json" &&
			r.Header.Get("X-Revocation-Signature") == syncsvc.SignPeerRevocation(testPeerSecret, ts, body)
		var ev syncsvc.PeerEvent
		_ = json.Unmarshal(body, &ev) //nolint:errcheck
		p.mu.Lock()
		p.events = append(p.events, ev)
		p.sigOK = append(p.sigOK, ok)
		p.headers = append(p.headers, r.Header.Clone())
		status := http.StatusOK
		if len(p.statuses) > 0 {
			status, p.statuses = p.statuses[0], p.statuses[1:]
		}
		p.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			w.Write([]byte(`{"applied":true}`)) //nolint:errcheck
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakePeer) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.events)
}

// newRevocationEnv：开放注册的 OIDC 环境 + 可选跨产品撤销 + 可选中心状态检查。
// 模拟身份服务结束会话后会像 Keycloak 一样向本服务发 back-channel logout。
func newRevocationEnv(t *testing.T, peer *fakePeer, centralCheck bool) *oidcEnv {
	t.Helper()
	e := newOIDCEnvWith(t, "open", true, func(o *api.Options, svc *syncsvc.Service) {
		if centralCheck {
			o.OIDC.StatusClientID, o.OIDC.StatusClientSecret = testStatusClientID, testStatusSecret
		}
		if peer != nil {
			svc.SetPeerRevocation(syncsvc.PeerRevocationConfig{URL: peer.srv.URL, Secret: testPeerSecret})
		}
	})
	e.idp.backchannelURL = e.ts.URL + "/auth/backchannel-logout"
	return e
}

// ---------------------------------------------------------------- 小工具

// do 以同源浏览器身份发 JSON 请求（写请求必须带 Origin，见 authGate）。
func (b *browser) do(method, path string, body any, hdr map[string]string) (*http.Response, map[string]any) {
	b.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, b.env.ts.URL+path, rd)
	req.Header.Set("Origin", b.env.ts.URL)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	json.Unmarshal(raw, &out) //nolint:errcheck
	return resp, out
}

func (e *oidcEnv) loginAs(t *testing.T, sub string) (*browser, string) {
	t.Helper()
	b := e.newBrowser(t)
	if resp, page := b.login(sub, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("login %s = %d %s", sub, resp.StatusCode, page)
	}
	code, me := b.me()
	if code != http.StatusOK {
		t.Fatalf("me after login = %d %v", code, me)
	}
	return b, me["account"].(map[string]any)["id"].(string)
}

func mustVault(t *testing.T, e *oidcEnv, userID, name string) string {
	t.Helper()
	id, err := e.svc.CreateUserVault(userID, name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type issuedGrant struct{ secret, grantID string }

func (b *browser) grant(vault string) issuedGrant {
	b.t.Helper()
	resp, g := b.do(http.MethodPost, "/api/v2/vaults/"+vault+"/pairing-grants", nil, nil)
	if resp.StatusCode != http.StatusOK {
		b.t.Fatalf("pairing grant = %d %v", resp.StatusCode, g)
	}
	return issuedGrant{secret: g["enrollmentSecret"].(string), grantID: g["grantId"].(string)}
}

func (b *browser) uploadPairing(vault, grantID string) string {
	b.t.Helper()
	resp, p := b.do(http.MethodPost, "/api/v2/pairings", map[string]any{"grantId": grantID, "ciphertext": "Y2lwaGVydGV4dA==", "vaultId": vault},
		map[string]string{"X-Vault-ID": vault})
	if resp.StatusCode != http.StatusOK {
		b.t.Fatalf("upload pairing = %d %v", resp.StatusCode, p)
	}
	return p["pairId"].(string)
}

// redeemDevice 兑换一个授权并返回设备凭据（必须成功）。
func redeemDevice(t *testing.T, e *testEnv, g issuedGrant, exchange, vault string) string {
	t.Helper()
	code, body := redeem(t, e, g.secret, exchange, vault)
	if code != http.StatusOK {
		t.Fatalf("redeem = %d %v", code, body)
	}
	return body["deviceCredential"].(string)
}

func whoamiCode(t *testing.T, e *testEnv, bearer string) (int, string) {
	t.Helper()
	resp, body := bearerGet(t, e, "/api/v1/whoami", bearer)
	code, _ := body["code"].(string)
	return resp.StatusCode, code
}

func mustRevoked(t *testing.T, e *testEnv, bearer, what string) {
	t.Helper()
	if status, code := whoamiCode(t, e, bearer); status != http.StatusUnauthorized || code != "TOKEN_REVOKED" {
		t.Fatalf("%s after revocation: whoami = %d %s, want 401 TOKEN_REVOKED", what, status, code)
	}
}

func mustWork(t *testing.T, e *testEnv, bearer, what string) {
	t.Helper()
	if status, code := whoamiCode(t, e, bearer); status != http.StatusOK {
		t.Fatalf("%s must still work: whoami = %d %s", what, status, code)
	}
}

func userAuthEpoch(t *testing.T, e *testEnv, userID string) int64 {
	t.Helper()
	var n int64
	if err := e.db.QueryRow(`SELECT auth_epoch FROM users WHERE user_id = ?`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func revocationReasons(t *testing.T, e *testEnv, userID string) []string {
	t.Helper()
	rows, err := e.db.Query(`SELECT reason FROM account_revocations WHERE user_id = ? ORDER BY created_at, event_id`, userID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		rows.Scan(&r) //nolint:errcheck
		out = append(out, r)
	}
	return out
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func postBackchannel(t *testing.T, e *oidcEnv, claims map[string]any) int {
	t.Helper()
	now := time.Now()
	base := map[string]any{
		"iss": e.idp.issuer, "aud": testClientID, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"jti":    hex.EncodeToString(randBytes(8)),
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}
	for k, v := range claims {
		base[k] = v
	}
	resp, err := http.PostForm(e.ts.URL+"/auth/backchannel-logout", map[string][]string{"logout_token": {e.idp.sign(base, false)}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// ---------------------------------------------------------------- A

// 动作 A（R-3）：本浏览器退出、back-channel（带 sid / 只有 sub）都只结束网页会话。
func TestRevocationActionAOnlyEndsWebSessions(t *testing.T) {
	e := newRevocationEnv(t, nil, false)
	b1, alice := e.loginAs(t, "carol-sub")
	vault := mustVault(t, e, alice, "个人笔记")
	cred := redeemDevice(t, e.testEnv, b1.grant(vault), "exch_carol_device_001", vault)
	pending := b1.grant(vault)
	pairID := b1.uploadPairing(vault, pending.grantID)

	// 1) 本产品「退出登录」（只此浏览器）
	if resp, _ := b1.do(http.MethodPost, "/auth/logout", nil, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("/auth/logout = %d", resp.StatusCode)
	}
	if code, _ := b1.me(); code != http.StatusUnauthorized {
		t.Fatalf("after /auth/logout me = %d", code)
	}
	mustWork(t, e.testEnv, cred, "device after /auth/logout")

	// 2) back-channel 带 sid：只结束那一个网页会话
	b2, _ := e.loginAs(t, "carol-sub")
	if code := postBackchannel(t, e, map[string]any{"sid": "sid-carol-sub"}); code != http.StatusOK {
		t.Fatalf("back-channel(sid) = %d", code)
	}
	if code, _ := b2.me(); code != http.StatusUnauthorized {
		t.Fatalf("after back-channel(sid) me = %d", code)
	}
	mustWork(t, e.testEnv, cred, "device after back-channel(sid)")

	// 3) back-channel 只有 sub：本产品该用户的全部网页会话，设备仍然不动
	b3, _ := e.loginAs(t, "carol-sub")
	b4, _ := e.loginAs(t, "carol-sub")
	if code := postBackchannel(t, e, map[string]any{"sub": "carol-sub"}); code != http.StatusOK {
		t.Fatalf("back-channel(sub) = %d", code)
	}
	for i, b := range []*browser{b3, b4} {
		if code, _ := b.me(); code != http.StatusUnauthorized {
			t.Fatalf("browser %d after back-channel(sub) me = %d", i, code)
		}
	}
	mustWork(t, e.testEnv, cred, "device after back-channel(sub)")
	if code := envelopeStatus(t, e.testEnv, pairID); code != http.StatusOK {
		t.Fatalf("a pending pairing must survive action A, envelope = %d", code)
	}
	if n := userAuthEpoch(t, e.testEnv, alice); n != 0 {
		t.Fatalf("action A must never advance the auth epoch, got %d", n)
	}
	// 待领取授权仍可兑换
	redeemDevice(t, e.testEnv, pending, "exch_carol_pending_01", vault)
}

// ---------------------------------------------------------------- B

// 动作 B（R-1、R-4）：本产品此前签发的一切凭据与授权失效；另一个账号、身份中心、另一个产品不受影响。
func TestRevocationActionBRevokesEverythingInProduct(t *testing.T) {
	peer := newFakePeer(t)
	e := newRevocationEnv(t, peer, false)
	b1, alice := e.loginAs(t, "alice-sub")
	b2, _ := e.loginAs(t, "alice-sub") // 另一个浏览器
	bobB, bob := e.loginAs(t, "bob-sub")
	vault := mustVault(t, e, alice, "个人笔记")
	bobVault := mustVault(t, e, bob, "Bob 的笔记")

	// alice 的 API Token（网页重置得到；重置本身也是一次 B，发起的这个会话保留下来）
	resp, tr := b1.do(http.MethodPost, "/api/v1/account/token-reset", map[string]any{}, map[string]string{"X-Vault-ID": vault})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token reset = %d %v", resp.StatusCode, tr)
	}
	apiToken := tr["token"].(string)
	b2, _ = e.loginAs(t, "alice-sub") // 重置作废了旧的 b2；重新登录
	mustWork(t, e.testEnv, apiToken, "fresh API token")

	devCred := redeemDevice(t, e.testEnv, b1.grant(vault), "exch_alice_device_001", vault)
	_, created := e.doJSON(t, http.MethodPost, "/api/v1/devices", apiToken, map[string]any{"name": "笔记本"})
	devToken2, _ := created["deviceToken"].(string)
	mustWork(t, e.testEnv, devToken2, "device created with the API token")
	_, at := e.exchange(t, devCred, nil)
	accessToken, _ := at["accessToken"].(string)
	mustWork(t, e.testEnv, accessToken, "access token")
	pending := b1.grant(vault)
	pairID := b1.uploadPairing(vault, pending.grantID)
	replay := b1.grant(vault)
	code, first := redeem(t, e.testEnv, replay.secret, "exch_alice_replay_0001", vault)
	if code != http.StatusOK {
		t.Fatalf("redeem = %d %v", code, first)
	}
	_, enr := e.doJSON(t, http.MethodPost, "/api/v1/enrollments", devCred, map[string]any{})
	v1Secret, _ := enr["secret"].(string)
	bobCred := redeemDevice(t, e.testEnv, bobB.grant(bobVault), "exch_bob_device_0001", bobVault)

	// 动作 B
	resp, out := b1.do(http.MethodPost, "/api/v2/account/logout-devices", nil, nil)
	local, _ := out["local"].(map[string]any)
	if resp.StatusCode != http.StatusOK || out["ok"] != true || local == nil {
		t.Fatalf("logout-devices = %d %v", resp.StatusCode, out)
	}
	if local["revokedDevices"].(float64) != 3 || local["revokedGrants"].(float64) != 2 {
		t.Fatalf("B must report the real counts (3 devices; the pending v2 grant + the v1 enrollment), got %v", local)
	}

	// 本产品内此前签发的一切都失效
	for i, b := range []*browser{b1, b2} {
		if code, _ := b.me(); code != http.StatusUnauthorized {
			t.Fatalf("web session %d after B: me = %d", i, code)
		}
	}
	mustRevoked(t, e.testEnv, devCred, "redeemed device")
	mustRevoked(t, e.testEnv, devToken2, "device created from the API token")
	mustRevoked(t, e.testEnv, accessToken, "in-flight access token")
	mustRevoked(t, e.testEnv, apiToken, "API token")
	if code := envelopeStatus(t, e.testEnv, pairID); code != http.StatusNotFound {
		t.Fatalf("pending pairing envelope after B = %d, want 404", code)
	}
	if code, b := redeem(t, e.testEnv, pending.secret, "exch_alice_after_b_01", vault); code != http.StatusGone || b["code"] != "PAIRING_REVOKED" {
		t.Fatalf("pending grant redeem after B = %d %v, want 410 PAIRING_REVOKED", code, b)
	}
	if code, b := redeem(t, e.testEnv, replay.secret, "exch_alice_replay_0001", vault); code != http.StatusGone || b["deviceCredential"] != nil {
		t.Fatalf("replay of a consumed grant after B = %d %v, want 410 without any credential", code, b)
	}
	if r, _ := e.doJSON(t, http.MethodPost, "/enroll", "", map[string]any{"secret": v1Secret, "name": "x"}); r.StatusCode != http.StatusNotFound {
		t.Fatalf("v1 enrollment after B = %d, want 404", r.StatusCode)
	}

	// 另一个账号不受影响；身份中心与另一个产品不在 B 的范围
	if code, _ := bobB.me(); code != http.StatusOK {
		t.Fatalf("bob's session after alice's B = %d", code)
	}
	mustWork(t, e.testEnv, bobCred, "bob's device")
	if n := e.idp.sessionsEnded["alice-sub"]; n != 0 {
		t.Fatalf("B must not touch identity-center sessions, ended %d", n)
	}
	if n := peer.count(); n != 0 {
		t.Fatalf("B must not notify the other product, sent %d", n)
	}

	// 新登录、新授权可用
	b3, _ := e.loginAs(t, "alice-sub")
	fresh := redeemDevice(t, e.testEnv, b3.grant(vault), "exch_alice_fresh_0001", vault)
	mustWork(t, e.testEnv, fresh, "device paired after B")
	if got := strings.Join(sortedStrings(revocationReasons(t, e.testEnv, alice)), ","); got != "token-reset,user-request" {
		t.Fatalf("revocation events = %v, want token-reset + user-request", got)
	}
}

// 设备凭据（被盗设备）不能执行 B / C；跨站请求被拒。
func TestRevocationRequiresAccountIdentity(t *testing.T) {
	e := newRevocationEnv(t, nil, false)
	b, alice := e.loginAs(t, "mia-sub")
	vault := mustVault(t, e, alice, "个人笔记")
	cred := redeemDevice(t, e.testEnv, b.grant(vault), "exch_mia_device_0001", vault)
	for _, path := range []string{"/api/v2/account/logout-devices", "/api/v2/account/logout-all"} {
		if r, _ := e.doJSON(t, http.MethodPost, path, cred, nil); r.StatusCode != http.StatusForbidden {
			t.Fatalf("device credential on %s = %d, want 403", path, r.StatusCode)
		}
		if r, _ := b.send(http.MethodPost, path, "https://evil.example", nil); r.StatusCode != http.StatusForbidden {
			t.Fatalf("cross-origin %s = %d, want 403", path, r.StatusCode)
		}
	}
	mustWork(t, e.testEnv, cred, "device")
	if code, _ := b.me(); code != http.StatusOK {
		t.Fatalf("session must survive rejected attempts, me = %d", code)
	}
}

// ---------------------------------------------------------------- C

// 动作 C（R-5、R-6）：三步依次执行，每一步的真实状态都如实返回。
func TestRevocationActionCReportsEveryStep(t *testing.T) {
	peer := newFakePeer(t)
	e := newRevocationEnv(t, peer, false)
	b1, alice := e.loginAs(t, "dora-sub")
	b2, _ := e.loginAs(t, "dora-sub")
	bobB, bob := e.loginAs(t, "bob-sub")
	vault := mustVault(t, e, alice, "个人笔记")
	cred := redeemDevice(t, e.testEnv, b1.grant(vault), "exch_dora_device_001", vault)
	bobVault := mustVault(t, e, bob, "Bob")
	bobCred := redeemDevice(t, e.testEnv, bobB.grant(bobVault), "exch_bob_device_0002", bobVault)

	resp, out := b1.do(http.MethodPost, "/api/v2/account/logout-all", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout-all = %d %v", resp.StatusCode, out)
	}
	local := out["local"].(map[string]any)
	ic := out["identityCenter"].(map[string]any)
	peers := out["peers"].([]any)
	if out["ok"] != true || local["state"] != "done" || local["revokedDevices"].(float64) != 1 || ic["state"] != "done" || len(peers) != 1 {
		t.Fatalf("C must report local / identity center / peers, got %v", out)
	}
	p0 := peers[0].(map[string]any)
	if p0["product"] != "nexus" || p0["state"] != "delivered" || p0["result"] != "applied" || p0["attempts"].(float64) != 1 {
		t.Fatalf("peer delivery = %v", p0)
	}
	if tok, _ := out["statusToken"].(string); len(tok) != 64 {
		t.Fatalf("C must hand back a one-off status token, got %q", out["statusToken"])
	}
	if out["endSessionUrl"] != nil {
		t.Fatal("endSessionUrl is only a fallback when the identity-center step failed")
	}

	// 身份中心：用户本人的令牌结束了他在所有浏览器的会话（模拟 Keycloak：refresh 一律 invalid_grant）
	if n := e.idp.sessionsEnded["dora-sub"]; n != 1 {
		t.Fatalf("identity-center sessions ended %d times, want 1", n)
	}
	e.idp.mu.Lock()
	sent := append([]int(nil), e.idp.backchannelSent...)
	e.idp.mu.Unlock()
	if len(sent) == 0 {
		t.Fatal("the IdP should have sent back-channel logouts after ending the sessions")
	}
	for _, c := range sent {
		if c != http.StatusOK {
			t.Fatalf("back-channel logouts after C must be handled as action A (200), got %v", sent)
		}
	}

	// 另一个产品收到一条签名正确、字段与 ADR §2.4 一致的事件
	if peer.count() != 1 || !peer.sigOK[0] {
		t.Fatalf("peer events = %d (signature ok %v)", peer.count(), peer.sigOK)
	}
	ev := peer.events[0]
	if ev.V != 1 || len(ev.EventID) != 32 || ev.EventID != out["eventId"] || ev.Issuer != e.idp.issuer || ev.Subject != "dora-sub" ||
		ev.Scope != "all-products-all-devices" || ev.Reason != "user-request" || ev.Origin != "litesync" {
		t.Fatalf("peer event = %+v", ev)
	}
	if _, err := time.Parse(time.RFC3339, ev.OccurredAt); err != nil {
		t.Fatalf("occurredAt %q is not RFC 3339", ev.OccurredAt)
	}
	ts, _ := strconv.ParseInt(peer.headers[0].Get("X-Revocation-Timestamp"), 10, 64)
	if d := time.Since(time.Unix(ts, 0)); d < 0 || d > time.Minute {
		t.Fatalf("X-Revocation-Timestamp %d is not the send time", ts)
	}

	// 本产品：会话、设备全部失效；另一个账号不受影响
	if code, _ := b2.me(); code != http.StatusUnauthorized {
		t.Fatalf("other browser after C: me = %d", code)
	}
	mustRevoked(t, e.testEnv, cred, "device")
	if code, _ := bobB.me(); code != http.StatusOK {
		t.Fatalf("bob after dora's C: me = %d", code)
	}
	mustWork(t, e.testEnv, bobCred, "bob's device")

	// 结果页凭一次性凭证看同样的状态；凭证不对一律 404
	status := func(token string) (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v2/revocation-status/"+out["eventId"].(string), nil)
		req.Header.Set("X-Revocation-Status-Token", token)
		return func() (int, map[string]any) { r, b := e.do(t, req); return r.StatusCode, b }()
	}
	if code, st := status(out["statusToken"].(string)); code != http.StatusOK || st["ok"] != true {
		t.Fatalf("status with token = %d %v", code, st)
	}
	if code, _ := status(strings.Repeat("0", 64)); code != http.StatusNotFound {
		t.Fatalf("status with a wrong token = %d, want 404", code)
	}
	// 重新登录后在账户中心看得到这条记录
	b3, _ := e.loginAs(t, "dora-sub")
	if resp, list := b3.do(http.MethodGet, "/api/v2/account/revocations", nil, nil); resp.StatusCode != http.StatusOK ||
		len(list["revocations"].([]any)) != 1 || list["revocations"].([]any)[0].(map[string]any)["ok"] != true {
		t.Fatalf("account revocations = %d %v", resp.StatusCode, list)
	}
	// 别人不能重发、不能看到
	if resp, _ := bobB.do(http.MethodPost, "/api/v2/account/revocations/"+out["eventId"].(string)+"/retry", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("bob retrying dora's event = %d, want 404", resp.StatusCode)
	}
}

// 另一个产品暂时不可达：pending 如实可见，后台按退避重试；结果页可以「重新发送」。
func TestRevocationActionCPeerPendingRetryAndResend(t *testing.T) {
	peer := newFakePeer(t, http.StatusServiceUnavailable, http.StatusServiceUnavailable)
	e := newRevocationEnv(t, peer, false)
	b1, _ := e.loginAs(t, "ella-sub")
	_, out := b1.do(http.MethodPost, "/api/v2/account/logout-all", nil, nil)
	p0 := out["peers"].([]any)[0].(map[string]any)
	if out["ok"] != false || p0["state"] != "pending" || p0["attempts"].(float64) != 1 || p0["error"] != "http-503" || p0["nextAttemptAt"] == "" {
		t.Fatalf("an unreachable peer must be reported as pending (never as done), got %v", out)
	}
	if ic := out["identityCenter"].(map[string]any); ic["state"] != "done" {
		t.Fatalf("identity center = %v", ic)
	}
	eventID, token := out["eventId"].(string), out["statusToken"].(string)
	// 退避：还没到期的不重发
	if n := e.svc.RunRevocationDeliveries(t.Context()); n != 0 {
		t.Fatalf("a delivery inside its backoff must not be retried, attempted %d", n)
	}
	// 到期后台重试（第二次仍 503 → attempts 2，仍 pending）
	if _, err := e.db.Exec(`UPDATE revocation_deliveries SET next_attempt_at = 0 WHERE event_id = ?`, eventID); err != nil {
		t.Fatal(err)
	}
	if n := e.svc.RunRevocationDeliveries(t.Context()); n != 1 {
		t.Fatalf("due delivery attempted %d", n)
	}
	var state string
	var attempts int
	e.db.QueryRow(`SELECT delivery_state, attempts FROM revocation_deliveries WHERE event_id = ?`, eventID).Scan(&state, &attempts) //nolint:errcheck
	if state != "pending" || attempts != 2 {
		t.Fatalf("after a second 503: %s / %d", state, attempts)
	}
	// 结果页「重新发送」（会话已失效，凭一次性凭证）：这一次对方恢复 → delivered
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v2/revocation-status/"+eventID+"/resend", nil)
	req.Header.Set("X-Revocation-Status-Token", token)
	resp, st := e.do(t, req)
	if resp.StatusCode != http.StatusOK || st["ok"] != true || st["peers"].([]any)[0].(map[string]any)["state"] != "delivered" {
		t.Fatalf("resend = %d %v", resp.StatusCode, st)
	}
	if peer.count() != 3 {
		t.Fatalf("peer saw %d attempts, want 3", peer.count())
	}
	// 每次重试发送的是同一个事件（同一 eventId；接收方据此去重）
	for _, ev := range peer.events {
		if ev.EventID != eventID {
			t.Fatalf("retries must resend the same event, got %v", ev.EventID)
		}
	}
}

// 签名被对方拒绝（401）：记为 failed、不重试；修好后可以从账户中心手动重发。
func TestRevocationActionCSignatureRejectedFailsWithoutRetry(t *testing.T) {
	peer := newFakePeer(t, http.StatusUnauthorized)
	e := newRevocationEnv(t, peer, false)
	b1, _ := e.loginAs(t, "finn-sub")
	_, out := b1.do(http.MethodPost, "/api/v2/account/logout-all", nil, nil)
	p0 := out["peers"].([]any)[0].(map[string]any)
	if out["ok"] != false || p0["state"] != "failed" || p0["error"] != "signature-rejected" {
		t.Fatalf("a 401 from the peer must be a final failure, got %v", out)
	}
	if _, err := e.db.Exec(`UPDATE revocation_deliveries SET next_attempt_at = 0`); err != nil {
		t.Fatal(err)
	}
	if n := e.svc.RunRevocationDeliveries(t.Context()); n != 0 {
		t.Fatalf("a failed delivery must not be retried automatically, attempted %d", n)
	}
	// 运维修好密钥之后，用户重新登录，在账户中心重新发送
	b2, _ := e.loginAs(t, "finn-sub")
	resp, st := b2.do(http.MethodPost, "/api/v2/account/revocations/"+out["eventId"].(string)+"/retry", nil, nil)
	if resp.StatusCode != http.StatusOK || st["ok"] != true {
		t.Fatalf("manual retry = %d %v", resp.StatusCode, st)
	}
}

// 身份中心一步失败（client 缺 manage-account 作用域映射 → 403）：如实报告、给出账号中心地址，ok=false。
func TestRevocationActionCIdentityCenterFailureIsReported(t *testing.T) {
	peer := newFakePeer(t)
	e := newRevocationEnv(t, peer, false)
	e.idp.userTokensLackManageAccount = true
	b1, _ := e.loginAs(t, "gwen-sub")
	_, out := b1.do(http.MethodPost, "/api/v2/account/logout-all", nil, nil)
	ic := out["identityCenter"].(map[string]any)
	if out["ok"] != false || ic["state"] != "failed" || ic["error"] != "forbidden" || ic["accountConsoleUrl"] != e.idp.issuer+"/account" {
		t.Fatalf("identity-center failure must be reported with the account console URL, got %v", out)
	}
	if es, _ := out["endSessionUrl"].(string); !strings.HasPrefix(es, e.idp.issuer+"/logout?") {
		t.Fatalf("on identity-center failure the response offers this browser's end-session URL, got %q", es)
	}
	if e.idp.sessionsEnded["gwen-sub"] != 0 {
		t.Fatal("a rejected Account API call must not count as ended sessions")
	}
	// 本产品与另一个产品两步不受影响
	if local := out["local"].(map[string]any); local["state"] != "done" {
		t.Fatalf("local = %v", local)
	}
	if p0 := out["peers"].([]any)[0].(map[string]any); p0["state"] != "delivered" {
		t.Fatalf("peer = %v", p0)
	}
}

// 没有配置跨产品撤销：如实显示「未配置」，ok=false；没有绑定统一账号的旧账号：C 只有本产品一步。
func TestRevocationActionCWithoutPeerOrIdentity(t *testing.T) {
	e := newRevocationEnv(t, nil, false)
	b1, _ := e.loginAs(t, "hugo-sub")
	_, out := b1.do(http.MethodPost, "/api/v2/account/logout-all", nil, nil)
	p0 := out["peers"].([]any)[0].(map[string]any)
	if out["ok"] != false || p0["state"] != "not-configured" || p0["product"] != "nexus" {
		t.Fatalf("an unconfigured peer must be shown as not-configured, got %v", out)
	}

	// 旧管理员（API Token，没有绑定统一账号）：身份中心与另一个产品都不适用
	resp, out := e.doJSON(t, http.MethodPost, "/api/v2/account/logout-all", testToken, nil)
	ic := out["identityCenter"].(map[string]any)
	if resp.StatusCode != http.StatusOK || out["ok"] != true || ic["state"] != "not-applicable" || len(out["peers"].([]any)) != 0 {
		t.Fatalf("C for an unlinked account = %d %v", resp.StatusCode, out)
	}
	// API Token 也在「全部凭据」之内（R-1/R-4）：运维用 `obsync token reset` 换发
	mustRevoked(t, e.testEnv, testToken, "admin API token")
}

// ---------------------------------------------------------------- 接收端

func signedPost(t *testing.T, e *testEnv, body []byte, ts, sig string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+syncsvc.PeerRevocationPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if ts != "" {
		req.Header.Set("X-Revocation-Timestamp", ts)
	}
	if sig != "" {
		req.Header.Set("X-Revocation-Signature", sig)
	}
	resp, out := e.do(t, req)
	return resp.StatusCode, out
}

func peerEventBody(t *testing.T, issuer, subject string, mutate func(map[string]any)) []byte {
	t.Helper()
	ev := map[string]any{
		"v": 1, "eventId": hex.EncodeToString(randBytes(16)), "issuer": issuer, "subject": subject,
		"scope": "all-products-all-devices", "reason": "user-request", "origin": "nexus",
		"occurredAt": time.Now().UTC().Format(time.RFC3339),
	}
	if mutate != nil {
		mutate(ev)
	}
	raw, _ := json.Marshal(ev)
	return raw
}

func TestPeerRevocationReceiver(t *testing.T) {
	peer := newFakePeer(t)
	e := newRevocationEnv(t, peer, false)
	b, alice := e.loginAs(t, "ivan-sub")
	vault := mustVault(t, e, alice, "个人笔记")
	cred := redeemDevice(t, e.testEnv, b.grant(vault), "exch_ivan_device_001", vault)
	bobB, bob := e.loginAs(t, "bob-sub")
	bobVault := mustVault(t, e, bob, "Bob")
	bobCred := redeemDevice(t, e.testEnv, bobB.grant(bobVault), "exch_bob_device_0003", bobVault)
	now := strconv.FormatInt(time.Now().Unix(), 10)
	send := func(body []byte, ts string) (int, map[string]any) {
		return signedPost(t, e.testEnv, body, ts, syncsvc.SignPeerRevocation(testPeerSecret, ts, body))
	}

	body := peerEventBody(t, e.idp.issuer, "ivan-sub", nil)
	if code, out := send(body, now); code != http.StatusOK || out["applied"] != true {
		t.Fatalf("valid event = %d %v", code, out)
	}
	if code, _ := b.me(); code != http.StatusUnauthorized {
		t.Fatalf("web session after a peer event = %d", code)
	}
	mustRevoked(t, e.testEnv, cred, "device after a peer event")
	if code, _ := bobB.me(); code != http.StatusOK {
		t.Fatalf("bob after ivan's peer event = %d", code)
	}
	mustWork(t, e.testEnv, bobCred, "bob's device")
	epoch := userAuthEpoch(t, e.testEnv, alice)

	// eventId 去重：重复投递返回同样的结果，不再撤销一次
	if code, out := send(body, now); code != http.StatusOK || out["applied"] != true {
		t.Fatalf("duplicate delivery = %d %v", code, out)
	}
	if userAuthEpoch(t, e.testEnv, alice) != epoch {
		t.Fatal("a duplicate event must not revoke again")
	}
	// 找不到这个身份：200 unknown-identity（对方没有这个人，也就没有要撤销的东西）
	if code, out := send(peerEventBody(t, e.idp.issuer, "nobody-here", nil), now); code != http.StatusOK ||
		out["applied"] != false || out["reason"] != "unknown-identity" {
		t.Fatalf("unknown identity = %d %v", code, out)
	}
	// 同一个 subject、不同 issuer：不是同一个人
	if code, out := send(peerEventBody(t, "https://other-issuer.example/realms/x", "bob-sub", nil), now); code != http.StatusOK || out["applied"] != false {
		t.Fatalf("foreign issuer = %d %v", code, out)
	}
	mustWork(t, e.testEnv, bobCred, "bob's device after a foreign-issuer event")

	// 401：签名不对、时间戳超出 5 分钟、缺头；签名覆盖的是原始请求体
	fresh := peerEventBody(t, e.idp.issuer, "bob-sub", nil)
	for name, tc := range map[string]struct{ ts, sig string }{
		"forged signature":  {now, "v1=" + strings.Repeat("ab", 32)},
		"stale timestamp":   {strconv.FormatInt(time.Now().Add(-6*time.Minute).Unix(), 10), ""},
		"future timestamp":  {strconv.FormatInt(time.Now().Add(6*time.Minute).Unix(), 10), ""},
		"missing headers":   {"", ""},
		"wrong version":     {now, "v2=" + strings.Repeat("ab", 32)},
		"signature of body": {now, syncsvc.SignPeerRevocation(testPeerSecret, now, peerEventBody(t, e.idp.issuer, "bob-sub", nil))},
	} {
		sig := tc.sig
		if sig == "" && tc.ts != "" {
			sig = syncsvc.SignPeerRevocation(testPeerSecret, tc.ts, fresh)
		}
		if code, _ := signedPost(t, e.testEnv, fresh, tc.ts, sig); code != http.StatusUnauthorized {
			t.Fatalf("%s = %d, want 401", name, code)
		}
	}
	mustWork(t, e.testEnv, bobCred, "bob's device after rejected events")

	// 400：签名正确但格式不对
	for name, m := range map[string]func(map[string]any){
		"version 2":       func(v map[string]any) { v["v"] = 2 },
		"bad event id":    func(v map[string]any) { v["eventId"] = "not-hex" },
		"other scope":     func(v map[string]any) { v["scope"] = "product-devices" },
		"looping origin":  func(v map[string]any) { v["origin"] = "litesync" },
		"missing subject": func(v map[string]any) { delete(v, "subject") },
		"bad occurred at": func(v map[string]any) { v["occurredAt"] = "yesterday" },
	} {
		if code, _ := send(peerEventBody(t, e.idp.issuer, "bob-sub", m), now); code != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400", name, code)
		}
	}
	if code, _ := send([]byte("not json"), now); code != http.StatusBadRequest {
		t.Fatalf("non-JSON body = %d, want 400", code)
	}
	mustWork(t, e.testEnv, bobCred, "bob's device after malformed events")

	// 接收方不转发（两个产品各自只配对方，避免环路）
	var n int
	e.db.QueryRow(`SELECT COUNT(*) FROM revocation_deliveries`).Scan(&n) //nolint:errcheck
	if n != 0 || peer.count() != 0 {
		t.Fatalf("a received event must never be forwarded (deliveries %d, peer saw %d)", n, peer.count())
	}

	// 单独限流：同一来源短时间大量请求 → 429
	limited := false
	for i := 0; i < 200 && !limited; i++ {
		code, _ := signedPost(t, e.testEnv, []byte("{}"), now, "v1=00")
		limited = code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("the internal revocation endpoint must be rate limited")
	}
}

// 没有配置共享密钥：接收端关闭（404），不泄露任何信息。
func TestPeerRevocationReceiverClosedWithoutSecret(t *testing.T) {
	e := newRevocationEnv(t, nil, false)
	body := peerEventBody(t, e.idp.issuer, "x", nil)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	if code, _ := signedPost(t, e.testEnv, body, ts, syncsvc.SignPeerRevocation(testPeerSecret, ts, body)); code != http.StatusNotFound {
		t.Fatalf("receiver without a secret = %d, want 404", code)
	}
}

// ---------------------------------------------------------------- D

// 中心停用 / 删除（R-7、R-2）：60 秒内（加一次检查耗时）拒绝；同账号并发只查一次；恢复不复活。
func TestCentralStatusCheckDisableAndDelete(t *testing.T) {
	e := newRevocationEnv(t, nil, true)
	b, frank := e.loginAs(t, "frank-sub")
	vault := mustVault(t, e, frank, "个人笔记")
	cred := redeemDevice(t, e.testEnv, b.grant(vault), "exch_frank_device_01", vault)

	// 登录本身算一次确认：60 秒内不查身份中心
	e.idp.mu.Lock()
	calls := e.idp.adminCalls
	e.idp.mu.Unlock()
	mustWork(t, e.testEnv, cred, "device right after login")
	if e.idp.adminCalls != calls {
		t.Fatal("a fresh login counts as a successful check; no lookup within 60 s")
	}

	e.idp.setUser("frank-sub", true, false) // 管理员在身份中心停用
	mustWork(t, e.testEnv, cred, "device within the 60 s window")
	restore := api.ShiftCentralClock(61 * time.Second)
	mustRevoked(t, e.testEnv, cred, "device after central disable")
	restore()
	if code, _ := b.me(); code != http.StatusUnauthorized {
		t.Fatalf("web session after central disable = %d", code)
	}
	if got := revocationReasons(t, e.testEnv, frank); len(got) != 1 || got[0] != "central-disabled" {
		t.Fatalf("revocation events = %v, want [central-disabled]", got)
	}

	// 恢复（R-2）：旧凭据不复活；重新登录、重新连接后可用
	e.idp.setUser("frank-sub", false, false)
	mustRevoked(t, e.testEnv, cred, "old device after re-enable")
	b2, _ := e.loginAs(t, "frank-sub")
	fresh := redeemDevice(t, e.testEnv, b2.grant(vault), "exch_frank_fresh_001", vault)
	mustWork(t, e.testEnv, fresh, "device paired after re-enable")

	// 删除（404）→ account-deleted
	bg, gina := e.loginAs(t, "gina-sub")
	gv := mustVault(t, e, gina, "G")
	gcred := redeemDevice(t, e.testEnv, bg.grant(gv), "exch_gina_device_001", gv)
	e.idp.setUser("gina-sub", false, true)
	restore = api.ShiftCentralClock(61 * time.Second)
	mustRevoked(t, e.testEnv, gcred, "device after central delete")
	restore()
	if got := revocationReasons(t, e.testEnv, gina); len(got) != 1 || got[0] != "account-deleted" {
		t.Fatalf("revocation events = %v, want [account-deleted]", got)
	}
}

// 同一账号并发请求只查一次（单飞）；查询超时按「不可达」处理，不阻塞超过时限。
func TestCentralStatusCheckSingleFlightAndTimeout(t *testing.T) {
	e := newRevocationEnv(t, nil, true)
	b, holly := e.loginAs(t, "holly-sub")
	vault := mustVault(t, e, holly, "个人笔记")
	cred := redeemDevice(t, e.testEnv, b.grant(vault), "exch_holly_device_01", vault)

	e.idp.mu.Lock()
	e.idp.adminDelay = 300 * time.Millisecond
	before := e.idp.adminCalls
	e.idp.mu.Unlock()
	restore := api.ShiftCentralClock(61 * time.Second)
	var wg gosync.WaitGroup
	codes := make([]int, 10)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/whoami", nil)
			req.Header.Set("Authorization", "Bearer "+cred)
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				codes[i] = resp.StatusCode
				resp.Body.Close()
			}
		}(i)
	}
	wg.Wait()
	restore()
	e.idp.mu.Lock()
	got := e.idp.adminCalls - before
	e.idp.mu.Unlock()
	for _, c := range codes {
		if c != http.StatusOK {
			t.Fatalf("concurrent requests = %v", codes)
		}
	}
	if got != 1 {
		t.Fatalf("concurrent requests for one account must look up once, got %d lookups", got)
	}

	// 超时：管理端 1 秒才响应、时限 150 ms → 按不可达处理（宽限内放行），请求不被拖住
	restoreT := api.SetCentralCheckTimeout(150 * time.Millisecond)
	defer restoreT()
	e.idp.mu.Lock()
	e.idp.adminDelay = time.Second
	e.idp.mu.Unlock()
	restore = api.ShiftCentralClock(3 * time.Minute)
	start := time.Now()
	mustWork(t, e.testEnv, cred, "device when the lookup times out (within grace)")
	if d := time.Since(start); d > 900*time.Millisecond {
		t.Fatalf("a timed-out lookup held the request for %v", d)
	}
	restore()
}

// 身份中心不可达：15 分钟宽限内放行；超过宽限设备 503 IDENTITY_UNAVAILABLE（可重试），网页会话放行；
// 不可达从不等于停用（代次不前进）。
func TestCentralStatusCheckUnavailableGrace(t *testing.T) {
	e := newRevocationEnv(t, nil, true)
	b, ivy := e.loginAs(t, "ivy-sub")
	vault := mustVault(t, e, ivy, "个人笔记")
	cred := redeemDevice(t, e.testEnv, b.grant(vault), "exch_ivy_device_0001", vault)
	e.idp.mu.Lock()
	e.idp.adminDown = true
	e.idp.mu.Unlock()

	restore := api.ShiftCentralClock(61 * time.Second)
	mustWork(t, e.testEnv, cred, "device inside the 15-minute grace")
	restore()
	restore = api.ShiftCentralClock(16 * time.Minute)
	resp, body := bearerGet(t, e.testEnv, "/api/v1/whoami", cred)
	if resp.StatusCode != http.StatusServiceUnavailable || body["code"] != "IDENTITY_UNAVAILABLE" || body["retryable"] != true ||
		resp.Header.Get("Retry-After") == "" {
		t.Fatalf("beyond the grace a device gets 503 IDENTITY_UNAVAILABLE, got %d %v", resp.StatusCode, body)
	}
	if code, _ := b.me(); code != http.StatusOK {
		t.Fatalf("web sessions follow the ADR-011 revalidation grace, me = %d", code)
	}
	restore()
	if n := userAuthEpoch(t, e.testEnv, ivy); n != 0 {
		t.Fatalf("an unreachable identity center must never revoke (epoch %d)", n)
	}
	// 恢复可达：下一次检查成功即放行
	e.idp.mu.Lock()
	e.idp.adminDown = false
	e.idp.mu.Unlock()
	restore = api.ShiftCentralClock(16*time.Minute + 2*time.Minute)
	mustWork(t, e.testEnv, cred, "device after the identity center is back")
	restore()
}

// 403（服务账号缺 view-users / 作用域映射）是配置错误，不是「用户被停用」。
func TestCentralStatusCheckForbiddenIsNotDisabled(t *testing.T) {
	e := newRevocationEnv(t, nil, true)
	e.idp.serviceLacksViewUsers = true
	b, jack := e.loginAs(t, "jack-sub")
	vault := mustVault(t, e, jack, "个人笔记")
	cred := redeemDevice(t, e.testEnv, b.grant(vault), "exch_jack_device_001", vault)
	restore := api.ShiftCentralClock(61 * time.Second)
	mustWork(t, e.testEnv, cred, "device when the lookup is forbidden (within grace)")
	restore()
	restore = api.ShiftCentralClock(16 * time.Minute)
	if resp, body := bearerGet(t, e.testEnv, "/api/v1/whoami", cred); resp.StatusCode != http.StatusServiceUnavailable || body["code"] != "IDENTITY_UNAVAILABLE" {
		t.Fatalf("a forbidden lookup beyond the grace = %d %v, want 503 (never a revocation)", resp.StatusCode, body)
	}
	restore()
	if n := userAuthEpoch(t, e.testEnv, jack); n != 0 {
		t.Fatalf("403 must not be treated as a disabled user (epoch %d)", n)
	}
}

// ---------------------------------------------------------------- 管理员停用 / Token 重置

// 产品内管理员停用 = 动作 B；重新启用只恢复登录资格，不复活旧凭据（§2.1、R-2）。
func TestAdminDisableIsActionB(t *testing.T) {
	e := newRevocationEnv(t, nil, false)
	b, lena := e.loginAs(t, "lena-sub")
	vault := mustVault(t, e, lena, "个人笔记")
	cred := redeemDevice(t, e.testEnv, b.grant(vault), "exch_lena_device_001", vault)
	pending := b.grant(vault)
	if r, _ := e.doJSON(t, http.MethodPost, "/api/v1/admin/users/"+lena+"/disable", testToken, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("disable = %d", r.StatusCode)
	}
	if code, _ := b.me(); code != http.StatusUnauthorized {
		t.Fatalf("session after disable = %d", code)
	}
	mustRevoked(t, e.testEnv, cred, "device after admin disable")
	if code, body := redeem(t, e.testEnv, pending.secret, "exch_lena_pending_01", vault); code != http.StatusGone {
		t.Fatalf("redeem while disabled = %d %v", code, body)
	}
	if resp, page := e.newBrowser(t).login("lena-sub", nil); resp.StatusCode != http.StatusForbidden || !strings.Contains(page, "停用") {
		t.Fatalf("login while disabled = %d", resp.StatusCode)
	}
	if r, _ := e.doJSON(t, http.MethodPost, "/api/v1/admin/users/"+lena+"/enable", testToken, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("enable = %d", r.StatusCode)
	}
	mustRevoked(t, e.testEnv, cred, "old device after re-enable")
	if code, _ := redeem(t, e.testEnv, pending.secret, "exch_lena_pending_02", vault); code != http.StatusGone {
		t.Fatalf("old pending grant after re-enable = %d, want 410", code)
	}
	b2, _ := e.loginAs(t, "lena-sub")
	mustWork(t, e.testEnv, redeemDevice(t, e.testEnv, b2.grant(vault), "exch_lena_fresh_0001", vault), "device paired after re-enable")
	if got := revocationReasons(t, e.testEnv, lena); len(got) != 1 || got[0] != "admin-disable" {
		t.Fatalf("revocation events = %v", got)
	}
}

// Token 重置也是 B：未领取的连接链接、其他网页会话一起失效；发起的会话保留。
func TestTokenResetRevokesPendingGrantsKeepsInitiator(t *testing.T) {
	e := newRevocationEnv(t, nil, false)
	b1, mona := e.loginAs(t, "mona-sub")
	b2, _ := e.loginAs(t, "mona-sub")
	vault := mustVault(t, e, mona, "个人笔记")
	pending := b1.grant(vault)
	resp, tr := b1.do(http.MethodPost, "/api/v1/account/token-reset", map[string]any{}, map[string]string{"X-Vault-ID": vault})
	if resp.StatusCode != http.StatusOK || tr["revokedGrants"] != float64(1) {
		t.Fatalf("token reset = %d %v", resp.StatusCode, tr)
	}
	if code, _ := b1.me(); code != http.StatusOK {
		t.Fatalf("the initiating session must survive the reset, me = %d", code)
	}
	if code, _ := b2.me(); code != http.StatusUnauthorized {
		t.Fatalf("other sessions must end, me = %d", code)
	}
	if code, _ := redeem(t, e.testEnv, pending.secret, "exch_mona_pending_01", vault); code != http.StatusGone {
		t.Fatalf("a pre-reset grant must not redeem, got %d", code)
	}
	mustWork(t, e.testEnv, tr["token"].(string), "the new API token")
	// 发起的会话还能继续发行授权（新代次）
	redeemDevice(t, e.testEnv, b1.grant(vault), "exch_mona_fresh_0001", vault)
}

// ---------------------------------------------------------------- 撤销与兑换并发

// R-4：撤销与兑换并发时，撤销完成之后这个账号在本产品里没有任何有效凭据——即使某个兑换抢先
// 写入了一台设备，它记的是旧代次，校验时失败。SQLite 与真实 PostgreSQL 各跑一遍。
func TestRevocationRacesRedeem(t *testing.T) {
	e := newPublicTestEnv(t)
	// 公开端点按 IP 限流 30 次 / 分钟：3 轮 × (4 次并发兑换 + 4 次撤销后兑换) = 24 次
	for round := 0; round < 3; round++ {
		tok, resp, _ := registerUser(t, e, adminCreateInvite(t, e), fmt.Sprintf("racer%d", round))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("register = %d", resp.StatusCode)
		}
		vault := createReadyVault(t, e, tok, fmt.Sprintf("race-vault-%d", round))
		var grants []string
		for i := 0; i < 4; i++ {
			grants = append(grants, grant(t, e, tok, vault)["enrollmentSecret"].(string))
		}
		var userID string
		e.db.QueryRow(`SELECT user_id FROM users WHERE name = ?`, fmt.Sprintf("racer%d", round)).Scan(&userID) //nolint:errcheck

		start := make(chan struct{})
		var wg gosync.WaitGroup
		var mu gosync.Mutex
		var creds []string
		var revokeStatus int
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, _ := e.doJSON(t, http.MethodPost, "/api/v2/account/logout-devices", tok, nil)
			revokeStatus = r.StatusCode
		}()
		for i, secret := range grants {
			wg.Add(1)
			go func(i int, secret string) {
				defer wg.Done()
				<-start
				raw, _ := json.Marshal(map[string]any{"enrollmentSecret": secret, "exchangeId": fmt.Sprintf("exch_race_%d_%04d", round, i), "expectedVaultId": vault})
				resp, err := http.Post(e.ts.URL+"/api/v2/device-enrollments/redeem", "application/json", bytes.NewReader(raw))
				if err != nil {
					t.Error(err)
					return
				}
				defer resp.Body.Close()
				var out map[string]any
				json.NewDecoder(resp.Body).Decode(&out) //nolint:errcheck
				switch resp.StatusCode {
				case http.StatusOK:
					mu.Lock()
					creds = append(creds, out["deviceCredential"].(string))
					mu.Unlock()
				case http.StatusGone:
				default:
					t.Errorf("redeem during revocation = %d %v", resp.StatusCode, out)
				}
			}(i, secret)
		}
		close(start)
		wg.Wait()
		if revokeStatus != http.StatusOK {
			t.Fatalf("round %d: revoke = %d", round, revokeStatus)
		}
		for _, c := range creds {
			mustRevoked(t, e, c, fmt.Sprintf("round %d device redeemed concurrently with the revocation", round))
		}
		var live int
		if err := e.db.QueryRow(`SELECT COUNT(*) FROM devices d JOIN users u ON u.user_id = d.user_id
			WHERE d.user_id = ? AND d.revoked = 0 AND d.auth_epoch = u.auth_epoch`, userID).Scan(&live); err != nil {
			t.Fatal(err)
		}
		if live != 0 {
			t.Fatalf("round %d: %d devices still hold the current auth epoch after the revocation", round, live)
		}
		// 撤销之后剩下的授权一个也兑换不了
		for i, secret := range grants {
			if code, _ := redeem(t, e, secret, fmt.Sprintf("exch_after_%d_%04d", round, i), vault); code == http.StatusOK {
				t.Fatalf("round %d: grant %d redeemed after the revocation", round, i)
			}
		}
	}
}

// 「判定发生在校验时」的确定性版本：兑换在撤销之前读到授权（代次 n），撤销先提交（n+1），
// 兑换随后插入的设备带着 n——它在第一次校验时就失败（不依赖任何锁的时序）。
func TestRevocationEpochCheckedAtValidation(t *testing.T) {
	e := newPublicTestEnv(t)
	tok, _, _ := registerUser(t, e, adminCreateInvite(t, e), "late")
	var userID, vaultID string
	e.db.QueryRow(`SELECT user_id FROM users WHERE name = 'late'`).Scan(&userID) //nolint:errcheck
	vaultID, _ = e.svc.OwnerVaultOf(userID)
	before := userAuthEpoch(t, e, userID)
	if r, _ := e.doJSON(t, http.MethodPost, "/api/v2/account/logout-devices", tok, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("revoke = %d", r.StatusCode)
	}
	// 模拟「撤销前读到授权」的那个兑换：用旧代次直接插入设备
	if err := db.InsertDevice(e.db, &db.Device{DeviceID: "late0000device01", Name: "late", TokenHash: sha256Hex([]byte("late-device-token")),
		Scopes: "sync", CreatedAt: time.Now().Unix(), VaultID: vaultID, UserID: userID, AuthEpoch: before}); err != nil {
		t.Fatal(err)
	}
	mustRevoked(t, e, "late-device-token", "a device inserted with the pre-revocation epoch")

	// 同理：撤销之前通过校验的旧会话在撤销提交之后才写入的授权（带旧代次、没有 revoked 标记）
	// 也换不出设备——兑换核对的是代次，不是 revoked 标记
	lateSecret := strings.Repeat("7", 64)
	now := time.Now().Unix()
	if err := db.InsertEnrollment(e.db, "late0000grant001", sha256Hex([]byte(lateSecret)), "sync,share,key-admin,pairing",
		now, now+300, vaultID, userID, before); err != nil {
		t.Fatal(err)
	}
	if code, body := redeem(t, e, lateSecret, "exch_late_grant_0001", vaultID); code != http.StatusGone || body["code"] != "PAIRING_REVOKED" {
		t.Fatalf("a grant carrying the pre-revocation epoch = %d %v, want 410 PAIRING_REVOKED", code, body)
	}
	if r, _ := e.doJSON(t, http.MethodPost, "/enroll", "", map[string]any{"secret": lateSecret, "name": "x"}); r.StatusCode != http.StatusNotFound {
		t.Fatalf("v1 enroll with a pre-revocation grant = %d, want 404", r.StatusCode)
	}
}
