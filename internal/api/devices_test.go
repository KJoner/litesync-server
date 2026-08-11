package api_test

// v9.2 设备级凭据测试（审查 14）：注册生命周期、scope 矩阵、撤销即失效、
// 审计身份取服务器侧设备 ID（不信客户端自报 Header）。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func (e *testEnv) doJSON(t *testing.T, method, path, token string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, bytes.NewReader(payload))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	return e.do(t, req)
}

// 根 Token 自注册 → 设备 Token 可同步；scope 矩阵与撤销。
func TestDeviceCredentialLifecycle(t *testing.T) {
	e := newTestEnv(t, 1<<20)

	// 1. 根 Token 创建首台设备凭据
	resp, body := e.doJSON(t, http.MethodPost, "/api/v1/devices", testToken, map[string]any{"name": "MacBook"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create device = %d", resp.StatusCode)
	}
	devToken, _ := body["deviceToken"].(string)
	devID, _ := body["deviceId"].(string)
	if len(devToken) != 64 || devID == "" {
		t.Fatalf("credential = %v", body)
	}

	// 2. whoami：根 vs 设备
	if _, who := e.doJSON(t, http.MethodGet, "/api/v1/whoami", testToken, nil); who["tokenType"] != "root" {
		t.Fatalf("root whoami = %v", who)
	}
	_, who2 := e.doJSON(t, http.MethodGet, "/api/v1/whoami", devToken, nil)
	if who2["tokenType"] != "device" || who2["deviceId"] != devID {
		t.Fatalf("device whoami = %v", who2)
	}

	// 3. 设备 Token 可以完成同步全流程（info / 上传 / changes）
	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytes.NewReader([]byte("hi")))
	req.Header.Set("Authorization", "Bearer "+devToken)
	req.Header.Set("X-File-Path", "a.md")
	req.Header.Set("X-Base-Revision", "0")
	req.Header.Set("X-Content-Hash", sha256Hex([]byte("hi")))
	req.Header.Set("X-Device-ID", "spoofed-client-claim") // 自报身份必须被忽略
	if r2, _ := e.do(t, req); r2.StatusCode != http.StatusOK {
		t.Fatalf("device upload = %d", r2.StatusCode)
	}
	if r3, _ := e.doJSON(t, http.MethodGet, "/api/v1/changes?since=0", devToken, nil); r3.StatusCode != http.StatusOK {
		t.Fatalf("device changes = %d", r3.StatusCode)
	}

	// 4. 审计身份 = 服务器侧设备 ID，而不是客户端自报的 Header
	_, hist := e.doJSON(t, http.MethodGet, "/api/v1/history?path=a.md", testToken, nil)
	versions := hist["versions"].([]any)
	if versions[0].(map[string]any)["deviceId"] != devID {
		t.Fatalf("audit deviceId = %v, want %s", versions[0].(map[string]any)["deviceId"], devID)
	}

	// 5. scope 边界：设备 Token 摸备份 admin / 设备管理 → 403
	if r, _ := e.doJSON(t, http.MethodGet, "/api/v1/admin/backup/status", devToken, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("device on backup admin = %d, want 403", r.StatusCode)
	}
	if r, _ := e.doJSON(t, http.MethodDelete, "/api/v1/devices/"+devID, devToken, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("device revoking device = %d, want 403", r.StatusCode)
	}
	if r, _ := e.doJSON(t, http.MethodPost, "/api/v1/devices", devToken, map[string]any{"name": "x"}); r.StatusCode != http.StatusForbidden {
		t.Fatalf("device creating device = %d, want 403", r.StatusCode)
	}

	// 6. 设备列表（current 标记）
	_, list := e.doJSON(t, http.MethodGet, "/api/v1/devices", devToken, nil)
	devices := list["devices"].([]any)
	if len(devices) != 1 || devices[0].(map[string]any)["current"] != true {
		t.Fatalf("device list = %v", devices)
	}
	if _, hasHash := devices[0].(map[string]any)["tokenHash"]; hasHash {
		t.Fatal("device list must not expose token material")
	}

	// 7. 撤销 → 下一个请求即 401
	if r, _ := e.doJSON(t, http.MethodDelete, "/api/v1/devices/"+devID, testToken, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("root revoke = %d", r.StatusCode)
	}
	if r, _ := e.doJSON(t, http.MethodGet, "/api/v1/info", devToken, nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked device = %d, want 401", r.StatusCode)
	}
}

// 一次性注册凭据：创建（pairing scope）→ 公开 enroll → 一次性 → 过期语义。
func TestEnrollmentFlow(t *testing.T) {
	e := newTestEnv(t, 1<<20)

	// 设备（含 pairing scope）创建注册凭据
	_, cred := e.doJSON(t, http.MethodPost, "/api/v1/devices", testToken, map[string]any{"name": "first"})
	devToken := cred["deviceToken"].(string)
	resp, enr := e.doJSON(t, http.MethodPost, "/api/v1/enrollments", devToken, map[string]any{"ttlSeconds": 300})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create enrollment = %d", resp.StatusCode)
	}
	secret := enr["secret"].(string)

	// 公开 enroll（无任何 Token）
	resp2, cred2 := e.doJSON(t, http.MethodPost, "/enroll", "", map[string]any{"secret": secret, "name": "iPhone"})
	if resp2.StatusCode != http.StatusOK || cred2["deviceToken"] == nil {
		t.Fatalf("enroll = %d %v", resp2.StatusCode, cred2)
	}
	newToken := cred2["deviceToken"].(string)
	if r, _ := e.doJSON(t, http.MethodGet, "/api/v1/info", newToken, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("enrolled device info = %d", r.StatusCode)
	}

	// 一次性：同一 secret 再用 → 404；伪造 secret → 404
	if r, _ := e.doJSON(t, http.MethodPost, "/enroll", "", map[string]any{"secret": secret, "name": "again"}); r.StatusCode != http.StatusNotFound {
		t.Fatalf("reused enrollment = %d, want 404", r.StatusCode)
	}
	if r, _ := e.doJSON(t, http.MethodPost, "/enroll", "", map[string]any{"secret": "deadbeef", "name": "x"}); r.StatusCode != http.StatusNotFound {
		t.Fatalf("bogus enrollment = %d, want 404", r.StatusCode)
	}
}

// 无效 Token 一律 401（设备 Token 引入后不放松未认证拒绝）。
func TestDeviceAuthRejectsGarbage(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	if r, _ := e.doJSON(t, http.MethodGet, "/api/v1/info", "not-a-real-token", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("garbage token = %d, want 401", r.StatusCode)
	}
}
