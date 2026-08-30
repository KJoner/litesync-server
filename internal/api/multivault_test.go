package api_test

// 单用户多仓库（v0.19）。覆盖：
//   - 仓库 CRUD：新建/列表/同名拒绝/上限/删除确认/最后一个保护；
//   - X-Vault-ID 选择：用户 Token 携头写入第二仓库、默认仓库互不可见；
//     他人仓库的头 → 404（不泄露存在性）；**设备凭据带伪头范围不变**；
//   - 重置门禁 any-vault：任一仓库的重置凭证都可放行重置。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func vaultReq(t *testing.T, e *testEnv, method, path, bearer, vaultHdr string, body []byte) (*http.Response, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body == nil {
		rd = bytes.NewReader([]byte{})
	} else {
		rd = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, rd)
	req.Header.Set("Authorization", "Bearer "+bearer)
	if vaultHdr != "" {
		req.Header.Set("X-Vault-ID", vaultHdr)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return e.do(t, req)
}

func uploadTo(t *testing.T, e *testEnv, bearer, vaultHdr, path string, content []byte) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytes.NewReader(content))
	req.Header.Set("Authorization", "Bearer "+bearer)
	if vaultHdr != "" {
		req.Header.Set("X-Vault-ID", vaultHdr)
	}
	req.Header.Set("X-File-Path", url.PathEscape(path))
	req.Header.Set("X-Base-Revision", "0")
	req.Header.Set("X-Content-Hash", sha256Hex(content))
	req.Header.Set("X-File-Mtime", "1700000000000")
	resp, _ := e.do(t, req)
	return resp
}

func snapshotPaths(t *testing.T, e *testEnv, bearer, vaultHdr string) string {
	t.Helper()
	_, body := vaultReq(t, e, http.MethodGet, "/api/v1/snapshot", bearer, vaultHdr, nil)
	raw, _ := json.Marshal(body)
	return string(raw)
}

func TestMultiVaultLifecycleAndIsolation(t *testing.T) {
	e := newTestEnv(t, 1<<20)

	// 初始：一个默认仓库
	resp, body := vaultReq(t, e, http.MethodGet, "/api/v1/vaults", testToken, "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list = %d", resp.StatusCode)
	}
	if n := len(body["vaults"].([]any)); n != 1 {
		t.Fatalf("initial vaults = %d, want 1", n)
	}

	// 新建第二仓库；同名 409
	payload, _ := json.Marshal(map[string]any{"name": "工作笔记"})
	resp, body = vaultReq(t, e, http.MethodPost, "/api/v1/vaults", testToken, "", payload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create = %d body=%v", resp.StatusCode, body)
	}
	second, _ := body["id"].(string)
	if !strings.HasPrefix(second, "v-") {
		t.Fatalf("vault id %q", second)
	}
	if resp, _ := vaultReq(t, e, http.MethodPost, "/api/v1/vaults", testToken, "", payload); resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate name = %d, want 409", resp.StatusCode)
	}

	// 携头写入第二仓库：默认仓库不可见、第二仓库可见（同用户跨仓库隔离）
	if resp := uploadTo(t, e, testToken, second, "工作/计划.md", []byte("second vault data")); resp.StatusCode != http.StatusOK {
		t.Fatalf("upload with header = %d", resp.StatusCode)
	}
	if s := snapshotPaths(t, e, testToken, ""); strings.Contains(s, "计划") {
		t.Fatalf("default vault leaks second vault's file: %s", s)
	}
	if s := snapshotPaths(t, e, testToken, second); !strings.Contains(s, "计划") {
		t.Fatalf("second vault missing its file: %s", s)
	}
	// info 的仓库身份随选择而不同
	_, infoDefault := vaultReq(t, e, http.MethodGet, "/api/v1/info", testToken, "", nil)
	_, infoSecond := vaultReq(t, e, http.MethodGet, "/api/v1/info", testToken, second, nil)
	if infoDefault["vaultId"] == infoSecond["vaultId"] {
		t.Fatal("vault identities must differ between selections")
	}

	// 他人 vault 头 → 404（不泄露存在性）：用注册用户的仓库试管理员的头
	otherToken, _, _ := registerUser(t, e, adminCreateInvite(t, e), "outsider")
	resp, _ = vaultReq(t, e, http.MethodGet, "/api/v1/snapshot", otherToken, second, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("foreign vault header = %d, want 404", resp.StatusCode)
	}

	// 设备凭据绑定默认仓库：带第二仓库的头**不得**改变范围
	devBody, _ := json.Marshal(map[string]any{"name": "laptop"})
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/devices", bytes.NewReader(devBody))
	req.Header.Set("Authorization", "Bearer "+testToken)
	_, dv := e.do(t, req)
	deviceToken, _ := dv["deviceToken"].(string)
	if resp := uploadTo(t, e, deviceToken, second, "越权.md", []byte("x")); resp.StatusCode != http.StatusOK {
		t.Fatalf("device upload = %d", resp.StatusCode)
	}
	if s := snapshotPaths(t, e, testToken, second); strings.Contains(s, "越权") {
		t.Fatal("device header must be ignored — file landed in the second vault")
	}
	if s := snapshotPaths(t, e, testToken, ""); !strings.Contains(s, "越权") {
		t.Fatal("device upload should land in its bound (default) vault")
	}

	// 管理列表不因多仓库重复（0.19.0-rc.1 线上实测：admin 有 2 个仓库时
	// 在 Users 页出现 2 行——LEFT JOIN memberships 每仓库一行）
	adminReq, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/admin/users", nil)
	adminReq.Header.Set("Authorization", "Bearer "+testToken)
	_, adminList := e.do(t, adminReq)
	seen := map[string]int{}
	for _, raw := range adminList["users"].([]any) {
		u := raw.(map[string]any)
		name, _ := u["name"].(string)
		seen[name]++
	}
	for name, n := range seen {
		if n > 1 {
			t.Fatalf("user %q appears %d times in admin list (multi-vault duplication)", name, n)
		}
	}

	// 重命名（v0.19.x）：成功且列表反映；撞默认仓库名 → 409；外人 → 404
	ren, _ := json.Marshal(map[string]any{"name": "项目笔记"})
	if resp, _ := vaultReq(t, e, http.MethodPatch, "/api/v1/vaults/"+second, testToken, "", ren); resp.StatusCode != http.StatusOK {
		t.Fatalf("rename = %d", resp.StatusCode)
	}
	_, afterRen := vaultReq(t, e, http.MethodGet, "/api/v1/vaults", testToken, "", nil)
	renamed := false
	for _, raw := range afterRen["vaults"].([]any) {
		v := raw.(map[string]any)
		if v["id"] == second && v["name"] == "项目笔记" {
			renamed = true
		}
	}
	if !renamed {
		t.Fatal("rename not reflected in vault list")
	}
	thirdPayload, _ := json.Marshal(map[string]any{"name": "第三库"})
	_, thirdBody := vaultReq(t, e, http.MethodPost, "/api/v1/vaults", testToken, "", thirdPayload)
	third, _ := thirdBody["id"].(string)
	clash, _ := json.Marshal(map[string]any{"name": "第三库"})
	if resp, _ := vaultReq(t, e, http.MethodPatch, "/api/v1/vaults/"+second, testToken, "", clash); resp.StatusCode != http.StatusConflict {
		t.Fatalf("rename to taken name = %d, want 409", resp.StatusCode)
	}
	delThird, _ := json.Marshal(map[string]any{"confirmName": "第三库"})
	if resp, _ := vaultReq(t, e, http.MethodDelete, "/api/v1/vaults/"+third, testToken, "", delThird); resp.StatusCode != http.StatusOK {
		t.Fatalf("cleanup third vault = %d", resp.StatusCode)
	}
	if resp, _ := vaultReq(t, e, http.MethodPatch, "/api/v1/vaults/"+second, otherToken, "", ren); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("foreign rename = %d, want 404 (no existence leak)", resp.StatusCode)
	}

	// 删除：confirmName 错 → 400；最后一个 → 409；成功 → 数据消失
	bad, _ := json.Marshal(map[string]any{"confirmName": "wrong"})
	if resp, _ := vaultReq(t, e, http.MethodDelete, "/api/v1/vaults/"+second, testToken, "", bad); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("delete wrong confirm = %d, want 400", resp.StatusCode)
	}
	okBody, _ := json.Marshal(map[string]any{"confirmName": "项目笔记"})
	if resp, _ := vaultReq(t, e, http.MethodDelete, "/api/v1/vaults/"+second, testToken, "", okBody); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
	if resp, _ := vaultReq(t, e, http.MethodGet, "/api/v1/snapshot", testToken, second, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("deleted vault header = %d, want 404", resp.StatusCode)
	}
	// 只剩一个 → 不能再删
	_, lst := vaultReq(t, e, http.MethodGet, "/api/v1/vaults", testToken, "", nil)
	only := lst["vaults"].([]any)[0].(map[string]any)
	confirmLast, _ := json.Marshal(map[string]any{"confirmName": only["name"]})
	if resp, _ := vaultReq(t, e, http.MethodDelete, "/api/v1/vaults/"+only["id"].(string), testToken, "", confirmLast); resp.StatusCode != http.StatusConflict {
		t.Fatalf("delete last vault = %d, want 409", resp.StatusCode)
	}
}

func TestResetAuthAnyVault(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	payload, _ := json.Marshal(map[string]any{"name": "second"})
	_, body := vaultReq(t, e, http.MethodPost, "/api/v1/vaults", testToken, "", payload)
	second, _ := body["id"].(string)

	// 只在**第二**仓库登记重置凭证 → 门禁即生效（enforced 是按人聚合的）
	reg, _ := json.Marshal(map[string]any{"resetAuth": "cred-of-second-vault"})
	if resp, _ := vaultReq(t, e, http.MethodPut, "/api/v1/vault/reset-auth", testToken, second, reg); resp.StatusCode != http.StatusOK {
		t.Fatalf("register on second = %d", resp.StatusCode)
	}
	// 无凭证重置 → 403
	if resp, _ := resetToken(t, e, testToken, nil, ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("reset without cred = %d, want 403", resp.StatusCode)
	}
	// 提交第二仓库的凭证 → 放行（任一仓库的密码知识都证明是主人）
	resp, rbody := resetToken(t, e, testToken, nil, "cred-of-second-vault")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset with second-vault cred = %d body=%v", resp.StatusCode, rbody)
	}
	if enforced, _ := rbody["resetAuthEnforced"].(bool); !enforced {
		t.Fatal("enforced should be true")
	}
}
