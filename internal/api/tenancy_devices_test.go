package api_test

// 设备与配对的跨租户隔离（v0.20 / 公开化基线 PRE-01、PRE-02、PRE-03；覆盖 INV-12）。
//
// 越权矩阵（tenancy_matrix_test.go）用占位 ID 探测路由，验证的是「路由要求认证」；
// 它发现不了「认证通过以后，返回的内容属于谁」。这里按**内容**断言：
//   - A 列设备只能看到 A 自己的设备（用户 Token 与设备凭据两条路径都测）；
//   - A 不能撤销 B 的设备（404），B 的设备之后照常可用；
//   - A 不能撤销 B 发行的配对包（响应与「不存在」相同），B 的配对包之后仍可被消费。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

type issuedDevice struct {
	id, token string
}

func createDeviceAs(t *testing.T, e *testEnv, userToken, name string) issuedDevice {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"name": name})
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/devices", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+userToken)
	resp, body := e.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create device %q = %d body=%v", name, resp.StatusCode, body)
	}
	id, _ := body["deviceId"].(string)
	tok, _ := body["deviceToken"].(string)
	if id == "" || tok == "" {
		t.Fatalf("create device %q: missing id/token in %v", name, body)
	}
	return issuedDevice{id: id, token: tok}
}

func listDeviceIDs(t *testing.T, e *testEnv, bearer string) map[string]bool {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, body := e.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list devices = %d body=%v", resp.StatusCode, body)
	}
	out := map[string]bool{}
	list, _ := body["devices"].([]any)
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			if id, _ := m["id"].(string); id != "" {
				out[id] = true
			}
		}
	}
	return out
}

func whoamiStatus(t *testing.T, e *testEnv, bearer string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, _ := e.do(t, req)
	return resp.StatusCode
}

func TestDeviceListIsScopedToOwner(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	aliceToken, resp, _ := registerUser(t, e, adminCreateInvite(t, e), "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register alice = %d", resp.StatusCode)
	}
	bobToken, resp, _ := registerUser(t, e, adminCreateInvite(t, e), "bob")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register bob = %d", resp.StatusCode)
	}

	adminDev := createDeviceAs(t, e, testToken, "admin-laptop")
	aliceDev := createDeviceAs(t, e, aliceToken, "alice-phone")
	bobDev := createDeviceAs(t, e, bobToken, "bob-tablet")

	for _, via := range []struct {
		name, bearer string
	}{
		{"alice user token", aliceToken},
		{"alice device credential", aliceDev.token},
	} {
		ids := listDeviceIDs(t, e, via.bearer)
		if !ids[aliceDev.id] {
			t.Fatalf("%s: own device missing from list %v", via.name, ids)
		}
		if ids[bobDev.id] || ids[adminDev.id] {
			t.Fatalf("%s: device list leaks other tenants' devices: %v", via.name, ids)
		}
	}
	// 管理员自己的列表同样只含自己的设备（全实例视图在 /api/v1/admin/devices）
	if ids := listDeviceIDs(t, e, testToken); ids[aliceDev.id] || ids[bobDev.id] || !ids[adminDev.id] {
		t.Fatalf("admin /api/v1/devices should list only admin's devices, got %v", ids)
	}
}

func TestDeviceRevokeRequiresOwnership(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	aliceToken, _, _ := registerUser(t, e, adminCreateInvite(t, e), "alice")
	bobToken, _, _ := registerUser(t, e, adminCreateInvite(t, e), "bob")
	bobDev := createDeviceAs(t, e, bobToken, "bob-tablet")
	aliceDev := createDeviceAs(t, e, aliceToken, "alice-phone")

	req, _ := http.NewRequest(http.MethodDelete, e.ts.URL+"/api/v1/devices/"+bobDev.id, nil)
	req.Header.Set("Authorization", "Bearer "+aliceToken)
	if resp, body := e.do(t, req); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("alice revoking bob's device = %d body=%v, want 404", resp.StatusCode, body)
	}
	if code := whoamiStatus(t, e, bobDev.token); code != http.StatusOK {
		t.Fatalf("bob's device must still work after a foreign revoke attempt, whoami = %d", code)
	}

	// 自己的设备照常可以撤销，撤销后立即失效
	req, _ = http.NewRequest(http.MethodDelete, e.ts.URL+"/api/v1/devices/"+aliceDev.id, nil)
	req.Header.Set("Authorization", "Bearer "+aliceToken)
	if resp, body := e.do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("alice revoking own device = %d body=%v", resp.StatusCode, body)
	}
	if code := whoamiStatus(t, e, aliceDev.token); code != http.StatusUnauthorized {
		t.Fatalf("revoked device whoami = %d, want 401", code)
	}
}

func TestPairingDeleteRequiresIssuer(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	aliceToken, _, _ := registerUser(t, e, adminCreateInvite(t, e), "alice")
	bobToken, _, _ := registerUser(t, e, adminCreateInvite(t, e), "bob")
	aliceDev := createDeviceAs(t, e, aliceToken, "alice-phone")
	bobDev := createDeviceAs(t, e, bobToken, "bob-tablet")

	payload, _ := json.Marshal(map[string]any{"ciphertext": "Ym9iLXBhaXJpbmc=", "ttlSeconds": 300})
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/pairing", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+bobDev.token)
	resp, body := e.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bob create pairing = %d body=%v", resp.StatusCode, body)
	}
	pairID, _ := body["id"].(string)

	// Alice 撤销 Bob 的配对包：响应与「不存在」相同（不泄露存在性），但不能真的删掉
	req, _ = http.NewRequest(http.MethodDelete, e.ts.URL+"/api/v1/pairing/"+pairID, nil)
	req.Header.Set("Authorization", "Bearer "+aliceDev.token)
	if resp, body := e.do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("foreign pairing delete = %d body=%v, want the same 200 as a missing id", resp.StatusCode, body)
	}
	req, _ = http.NewRequest(http.MethodPost, e.ts.URL+"/pair/"+pairID+"/consume", nil)
	if resp, body := e.do(t, req); resp.StatusCode != http.StatusOK || body["ciphertext"] != "Ym9iLXBhaXJpbmc=" {
		t.Fatalf("bob's pairing must survive alice's delete; consume = %d body=%v", resp.StatusCode, body)
	}

	// 发行者本人撤销有效
	req, _ = http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/pairing", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+bobDev.token)
	_, body = e.do(t, req)
	pairID, _ = body["id"].(string)
	req, _ = http.NewRequest(http.MethodDelete, e.ts.URL+"/api/v1/pairing/"+pairID, nil)
	req.Header.Set("Authorization", "Bearer "+bobDev.token)
	if resp, _ := e.do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("issuer delete = %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodPost, e.ts.URL+"/pair/"+pairID+"/consume", nil)
	if resp, _ := e.do(t, req); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("consume after issuer delete = %d, want 404", resp.StatusCode)
	}
}
