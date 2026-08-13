package api_test

// v9.2 设备级凭据测试（审查 14）：注册生命周期、scope 矩阵、撤销即失效、
// 审计身份取服务器侧设备 ID（不信客户端自报 Header）。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	syncsvc "github.com/KJoner/litesync-server/internal/sync"
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

// --- 运维页 Devices 列表增强（v0.17）：平台 / 最近 IP ---

// adminDevice 从管理列表里取指定设备的行。
func (e *testEnv) adminDevice(t *testing.T, deviceID string) map[string]any {
	t.Helper()
	resp, body := e.doJSON(t, http.MethodGet, "/api/v1/admin/devices", testToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("列设备 = %d", resp.StatusCode)
	}
	devices, _ := body["devices"].([]any)
	for _, d := range devices {
		if m, _ := d.(map[string]any); m["id"] == deviceID {
			return m
		}
	}
	t.Fatalf("设备 %s 不在管理列表里", deviceID)
	return nil
}

// deviceGet 用设备 Token 发一个 GET 请求，附加任意 Header（平台 / XFF 上报测试用）。
func (e *testEnv) deviceGet(t *testing.T, devToken, path string, headers map[string]string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+devToken)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if resp, _ := e.do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d", path, resp.StatusCode)
	}
}

// 设备认证一次之后，平台与最近来源 IP 必须能在管理列表里查到——
// 丢设备那天，「哪台是那部手机、它最后从哪连上来」靠只有设备名的列表答不了。
func TestAdminDevicesReportPlatformAndLastIP(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, deviceID := e.enrollDevice(t, "口袋里的手机")

	// 白名单外的自报值不落库：Header 是客户端可控的任意字符串，异常值一律归 unknown
	e.deviceGet(t, devToken, "/api/v1/info", map[string]string{"X-Client-Platform": "<script>alert(1)</script>"})
	if m := e.adminDevice(t, deviceID); m["platform"] != "unknown" {
		t.Fatalf("白名单外的平台值应当归 unknown，得到 %v", m["platform"])
	}

	// 正常值：平台变化立即可见（不等 5 分钟节流），最近 IP 一并记录
	e.deviceGet(t, devToken, "/api/v1/info", map[string]string{"X-Client-Platform": "android"})
	m := e.adminDevice(t, deviceID)
	if m["platform"] != "android" {
		t.Fatalf("platform = %v, want android", m["platform"])
	}
	if m["lastIp"] != "127.0.0.1" {
		t.Fatalf("lastIp = %v, want 127.0.0.1（httptest 直连地址）", m["lastIp"])
	}
}

// last_ip 的方向绝不能反：直连方不是可信代理时 X-Forwarded-For 一律忽略——
// 否则任何拿到设备 Token 的客户端都能往 last_ip 里写任意地址。
func TestDeviceLastIPIgnoresForgedXFF(t *testing.T) {
	e := newTestEnv(t, 1<<20) // 未配置任何可信代理
	devToken, deviceID := e.enrollDevice(t, "直连设备")

	e.deviceGet(t, devToken, "/api/v1/info", map[string]string{"X-Forwarded-For": "203.0.113.66"})
	if m := e.adminDevice(t, deviceID); m["lastIp"] != "127.0.0.1" {
		t.Fatalf("不可信直连伪造的 XFF 不能写入 last_ip，得到 %v", m["lastIp"])
	}
}

// 直连方是配置过的可信代理时才解析 XFF：取最右侧不属于可信代理的条目
//（左边的部分是客户端自报的，可以随便伪造）。
func TestDeviceLastIPHonorsXFFBehindTrustedProxy(t *testing.T) {
	e := newTestEnvProxied(t, 1<<20, syncsvc.Options{}, []string{"127.0.0.1"})
	devToken, deviceID := e.enrollDevice(t, "代理后的设备")

	e.deviceGet(t, devToken, "/api/v1/info", map[string]string{"X-Forwarded-For": "198.51.100.7, 127.0.0.1"})
	if m := e.adminDevice(t, deviceID); m["lastIp"] != "198.51.100.7" {
		t.Fatalf("可信代理转发的真实来源应当被记录，得到 %v", m["lastIp"])
	}
}
