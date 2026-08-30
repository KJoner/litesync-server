package api_test

// API Token 重置（v0.18 / v11 设计 §4）的行为测试：
//   - 重置事务的作废矩阵：旧 Token 全线失效、设备凭据撤销（TOKEN_REVOKED）、
//     旧网页会话被踢、发起会话存活；
//   - E2EE 重置凭证门禁：已登记后无凭证/错凭证一律 403（RESET_AUTH_MISMATCH），
//     这是「拿到 Token 的攻击者不能抢先重置」的关键性质（v11 设计 §3.1）；
//   - 重置凭证登记规则：首登记、幂等、持旧值更新，会话拿不到覆盖权；
//   - 设备凭据不得触碰重置端点（被盗设备不能锁死账户）。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func loginWith(t *testing.T, e *testEnv, token string, admin bool) []*http.Cookie {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"token": token, "admin": admin})
	resp, err := http.Post(e.ts.URL+"/web/session", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	return resp.Cookies()
}

func withCookies(req *http.Request, cookies []*http.Cookie) *http.Request {
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

func resetToken(t *testing.T, e *testEnv, bearer string, cookies []*http.Cookie, resetAuth string) (*http.Response, map[string]any) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"resetAuth": resetAuth})
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/account/token-reset", bytes.NewReader(payload))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	withCookies(req, cookies)
	return e.do(t, req)
}

func bearerGet(t *testing.T, e *testEnv, path, bearer string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return e.do(t, req)
}

// TestTokenResetRevokesEverything：重置的作废矩阵（v11 设计 §3.4）。
func TestTokenResetRevokesEverything(t *testing.T) {
	e := newTestEnv(t, 1<<20)

	// 一台已接入的设备（模拟插件把用户 Token 换成设备凭据后的常态）
	devBody, _ := json.Marshal(map[string]any{"name": "laptop"})
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/devices", bytes.NewReader(devBody))
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, body := e.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create device = %d", resp.StatusCode)
	}
	deviceToken, _ := body["deviceToken"].(string)
	if deviceToken == "" {
		t.Fatal("no device token")
	}

	// 一个将要被踢下线的旧网页会话
	oldCookies := loginWith(t, e, testToken, false)

	// 用旧 Token 发起重置（未登记重置凭证 → 放行，但 resetAuthEnforced=false）
	resp, body = resetToken(t, e, testToken, nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset = %d body=%v", resp.StatusCode, body)
	}
	newToken, _ := body["token"].(string)
	if !strings.HasPrefix(newToken, "lsk_") || len(newToken) != 4+64 {
		t.Fatalf("unexpected token format: %q", newToken)
	}
	if enforced, _ := body["resetAuthEnforced"].(bool); enforced {
		t.Fatal("resetAuthEnforced should be false when no credential is registered")
	}
	if n, _ := body["revokedDevices"].(float64); n != 1 {
		t.Fatalf("revokedDevices = %v, want 1", n)
	}

	// 旧 Token：Bearer 与网页登录全线 401
	if resp, _ := bearerGet(t, e, "/api/v1/info", testToken); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old bearer = %d, want 401", resp.StatusCode)
	}
	loginBody, _ := json.Marshal(map[string]any{"token": testToken})
	lresp, err := http.Post(e.ts.URL+"/web/session", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	lresp.Body.Close()
	if lresp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old token login = %d, want 401", lresp.StatusCode)
	}

	// 新 Token 生效
	if resp, _ := bearerGet(t, e, "/api/v1/info", newToken); resp.StatusCode != http.StatusOK {
		t.Fatalf("new bearer = %d, want 200", resp.StatusCode)
	}

	// 设备凭据被连带撤销，且错误码是 TOKEN_REVOKED（客户端据此给重新接入指引）
	resp, body = bearerGet(t, e, "/api/v1/info", deviceToken)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked device = %d, want 401", resp.StatusCode)
	}
	if code, _ := body["code"].(string); code != "TOKEN_REVOKED" {
		t.Fatalf("revoked device code = %q, want TOKEN_REVOKED", code)
	}

	// 旧网页会话被世代校验踢掉
	req, _ = http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/info", nil)
	withCookies(req, oldCookies)
	if resp, _ := e.do(t, req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old web session = %d, want 401", resp.StatusCode)
	}
}

// TestTokenResetKeepsInitiatingSession：经网页会话发起的重置，发起者自己不掉线。
func TestTokenResetKeepsInitiatingSession(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	cookies := loginWith(t, e, testToken, false)

	resp, body := resetToken(t, e, "", cookies, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset via session = %d body=%v", resp.StatusCode, body)
	}
	if tok, _ := body["token"].(string); !strings.HasPrefix(tok, "lsk_") {
		t.Fatalf("no new token in response: %v", body)
	}

	// 同一个会话仍然可用（adoptGeneration 把它迁到了新世代）
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/info", nil)
	withCookies(req, cookies)
	if resp, _ := e.do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("initiating session after reset = %d, want 200", resp.StatusCode)
	}
}

// TestResetAuthGate：E2EE 重置凭证是重置端点的服务端硬关卡（v11 设计 §3.1）。
func TestResetAuthGate(t *testing.T) {
	e := newTestEnv(t, 1<<20)

	putResetAuth := func(bearer, resetAuth, previous string) (*http.Response, map[string]any) {
		payload, _ := json.Marshal(map[string]any{"resetAuth": resetAuth, "previous": previous})
		req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/vault/reset-auth", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+bearer)
		return e.do(t, req)
	}

	// 未登记时 info 如实上报（客户端据此自动补登记）
	if _, body := bearerGet(t, e, "/api/v1/info", testToken); body["resetAuthConfigured"] != false {
		t.Fatalf("resetAuthConfigured = %v, want false", body["resetAuthConfigured"])
	}

	// 首次登记
	if resp, body := putResetAuth(testToken, "credential-A", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("register = %d body=%v", resp.StatusCode, body)
	}
	if _, body := bearerGet(t, e, "/api/v1/info", testToken); body["resetAuthConfigured"] != true {
		t.Fatalf("resetAuthConfigured = %v, want true", body["resetAuthConfigured"])
	}
	// 幂等重放（同一 VMK 派生值恒定）
	if resp, _ := putResetAuth(testToken, "credential-A", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("idempotent register = %d", resp.StatusCode)
	}
	// 只持 Token 覆盖成别的值：拒绝——否则拿到 Token 的攻击者可以先换凭证再重置
	resp, body := putResetAuth(testToken, "credential-EVIL", "")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("overwrite without previous = %d, want 409", resp.StatusCode)
	}
	if code, _ := body["code"].(string); code != "RESET_AUTH_MISMATCH" {
		t.Fatalf("overwrite code = %q", code)
	}
	// 持旧值更新（改密码的流程）
	if resp, _ := putResetAuth(testToken, "credential-B", "credential-A"); resp.StatusCode != http.StatusOK {
		t.Fatalf("update with previous = %d", resp.StatusCode)
	}

	// 重置：无凭证 / 错凭证一律 403 RESET_AUTH_MISMATCH
	for _, submitted := range []string{"", "credential-A"} {
		resp, body := resetToken(t, e, testToken, nil, submitted)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("reset with %q = %d, want 403", submitted, resp.StatusCode)
		}
		if code, _ := body["code"].(string); code != "RESET_AUTH_MISMATCH" {
			t.Fatalf("reset code = %q, want RESET_AUTH_MISMATCH", code)
		}
	}
	// Token 仍然有效（被拒的重置不产生任何副作用）
	if resp, _ := bearerGet(t, e, "/api/v1/info", testToken); resp.StatusCode != http.StatusOK {
		t.Fatalf("token after denied reset = %d, want 200", resp.StatusCode)
	}

	// 正确凭证：重置成功且 resetAuthEnforced=true
	resp, body = resetToken(t, e, testToken, nil, "credential-B")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset with correct credential = %d body=%v", resp.StatusCode, body)
	}
	if enforced, _ := body["resetAuthEnforced"].(bool); !enforced {
		t.Fatal("resetAuthEnforced should be true")
	}
}

// TestDeviceCredentialCannotResetToken：被盗设备不能锁死账户。
func TestDeviceCredentialCannotResetToken(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devBody, _ := json.Marshal(map[string]any{"name": "stolen"})
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/devices", bytes.NewReader(devBody))
	req.Header.Set("Authorization", "Bearer "+testToken)
	_, body := e.do(t, req)
	deviceToken, _ := body["deviceToken"].(string)

	resp, _ := resetToken(t, e, deviceToken, nil, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("device reset = %d, want 403", resp.StatusCode)
	}
	// 设备可以登记重置凭证（解锁 E2EE 后的自动补登记走的就是设备凭据）
	payload, _ := json.Marshal(map[string]any{"resetAuth": "from-device"})
	req, _ = http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/vault/reset-auth", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+deviceToken)
	if resp, _ := e.do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("device register reset-auth = %d, want 200", resp.StatusCode)
	}
}

// TestNonAdminCannotElevate：普通用户 Token 请求 admin 提升一律 403（多用户前置）。
func TestNonAdminCannotElevate(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	// 直接在库里造一个普通用户（M3 之前还没有注册入口）
	userToken := "lsk_" + strings.Repeat("ab", 32)
	if _, err := e.db.Exec(`INSERT INTO users (user_id, name, created_at, token_hash, token_generation, is_admin, disabled)
		VALUES ('u1', 'alice', 1, ?, 1, 0, 0)`, sha256Hex([]byte(userToken))); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"token": userToken, "admin": true})
	resp, err := http.Post(e.ts.URL+"/web/session", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin elevate = %d, want 403", resp.StatusCode)
	}
	// 普通用户 Token 打 admin API 同样 403
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/admin/devices", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	// u1 还没有 vault/membership：预期在 vault 归属检查前就被 admin 检查拦下
	if resp, _ := e.do(t, req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin on admin api = %d, want 403", resp.StatusCode)
	}
}

// TestBearerWhitespaceTolerance：粘贴 Token 的多余空格不再制造无从排查的 401
//（v0.18 实测：`Bearer  lsk_…` 双空格）。
func TestBearerWhitespaceTolerance(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/info", nil)
	req.Header.Set("Authorization", "Bearer  "+testToken+" ")
	if resp, _ := e.do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("padded bearer = %d, want 200", resp.StatusCode)
	}
}
