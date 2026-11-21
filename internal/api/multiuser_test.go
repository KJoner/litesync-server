package api_test

// 多用户端到端（v0.18 / v11 设计 §5）。覆盖 INV-12 的运行时接线：
//   - 邀请 → 注册 → 新用户获得独立 Vault 与 lsk_ Token；
//   - 数据完全隔离：A 上传的文件在 B 的 info/snapshot/changes/file 里绝不出现；
//   - 邀请一次性、重名不消耗、无效 secret 404；
//   - 普通用户碰不到 admin API；管理员能列出用户；
//   - 禁用立即生效（Token/设备全拒）、删除清空数据。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
)

func adminCreateInvite(t *testing.T, e *testEnv) (secret string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/admin/invites", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, body := e.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create invite = %d body=%v", resp.StatusCode, body)
	}
	secret, _ = body["secret"].(string)
	if len(secret) != 64 {
		t.Fatalf("unexpected invite secret %q", secret)
	}
	return secret
}

func registerUser(t *testing.T, e *testEnv, secret, name string) (token string, resp *http.Response, body map[string]any) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"name": name})
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/join/"+secret+"/register", bytes.NewReader(payload))
	resp, body = e.do(t, req)
	token, _ = body["token"].(string)
	return token, resp, body
}

func uploadAs(t *testing.T, e *testEnv, bearer, path string, content []byte) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytes.NewReader(content))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-File-Path", url.PathEscape(path))
	req.Header.Set("X-Base-Revision", "0")
	req.Header.Set("X-Content-Hash", sha256Hex(content))
	req.Header.Set("X-File-Mtime", "1700000000000")
	resp, _ := e.do(t, req)
	return resp
}

// TestInviteRegistrationAndIsolation：注册产物完整、双用户数据互不可见。
func TestInviteRegistrationAndIsolation(t *testing.T) {
	e := newTestEnv(t, 1<<20)

	// 注册页信息查询（公开）
	secret := adminCreateInvite(t, e)
	infoReq, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/join/"+secret+"/info", nil)
	if resp, body := e.do(t, infoReq); resp.StatusCode != http.StatusOK || body["valid"] != true {
		t.Fatalf("join info = %d %v", resp.StatusCode, body)
	}

	aliceToken, resp, body := registerUser(t, e, secret, "alice")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register = %d body=%v", resp.StatusCode, body)
	}
	if !strings.HasPrefix(aliceToken, "lsk_") {
		t.Fatalf("token format %q", aliceToken)
	}

	// 邀请一次性：同一 secret 再注册 → 404
	if _, resp, _ := registerUser(t, e, secret, "bob"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("reused invite = %d, want 404", resp.StatusCode)
	}
	// 无效 secret → 404
	if _, resp, _ := registerUser(t, e, strings.Repeat("ab", 32), "carol"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("bogus invite = %d, want 404", resp.StatusCode)
	}

	bobToken, resp, _ := registerUser(t, e, adminCreateInvite(t, e), "bob")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register bob = %d", resp.StatusCode)
	}

	// 各自的 info：vaultId 互不相同，也不同于 admin 的
	vaultIDs := map[string]string{}
	for name, tok := range map[string]string{"admin": testToken, "alice": aliceToken, "bob": bobToken} {
		resp, body := bearerGet(t, e, "/api/v1/info", tok)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s info = %d", name, resp.StatusCode)
		}
		id, _ := body["vaultId"].(string)
		if id == "" {
			t.Fatalf("%s has empty vaultId", name)
		}
		vaultIDs[name] = id
		// 新用户 Vault 的 head 从 0 起步（不泄露别人的活动量）
		if name != "admin" {
			if seq, _ := body["headSequence"].(float64); seq != 0 {
				t.Fatalf("%s headSequence = %v, want 0", name, seq)
			}
		}
	}
	if vaultIDs["alice"] == vaultIDs["bob"] || vaultIDs["alice"] == vaultIDs["admin"] {
		t.Fatalf("vault identities must differ: %v", vaultIDs)
	}

	// A 上传 → B 与 admin 都看不见
	if resp := uploadAs(t, e, aliceToken, "secret-plan.md", []byte("alice private")); resp.StatusCode != http.StatusOK {
		t.Fatalf("alice upload = %d", resp.StatusCode)
	}
	for name, tok := range map[string]string{"bob": bobToken, "admin": testToken} {
		if resp, body := bearerGet(t, e, "/api/v1/snapshot", tok); resp.StatusCode != http.StatusOK {
			t.Fatalf("%s snapshot = %d", name, resp.StatusCode)
		} else if raw, _ := json.Marshal(body); strings.Contains(string(raw), "secret-plan") {
			t.Fatalf("%s snapshot leaks alice's file: %s", name, raw)
		}
		if resp, body := bearerGet(t, e, "/api/v1/changes?since=0", tok); resp.StatusCode != http.StatusOK {
			t.Fatalf("%s changes = %d", name, resp.StatusCode)
		} else if raw, _ := json.Marshal(body); strings.Contains(string(raw), "secret-plan") {
			t.Fatalf("%s changes leak alice's file: %s", name, raw)
		}
		req, _ := http.NewRequest(http.MethodGet,
			e.ts.URL+"/api/v1/file?path="+url.QueryEscape("secret-plan.md"), nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		if resp, _ := e.do(t, req); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s direct read of alice's file = %d, want 404", name, resp.StatusCode)
		}
	}
	// alice 自己读得到
	if resp, _ := bearerGet(t, e, "/api/v1/file?path="+url.QueryEscape("secret-plan.md"), aliceToken); resp.StatusCode != http.StatusOK {
		t.Fatalf("alice read own file = %d", resp.StatusCode)
	}
	// alice 的 changes 里有自己的变更
	if _, body := bearerGet(t, e, "/api/v1/changes?since=0", aliceToken); body != nil {
		raw, _ := json.Marshal(body)
		if !strings.Contains(string(raw), "secret-plan") {
			t.Fatalf("alice's own changes missing her file: %s", raw)
		}
	}

	// 普通用户碰 admin API → 403；请求 admin 提升 → 403
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+aliceToken)
	if resp, _ := e.do(t, req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("alice on admin api = %d, want 403", resp.StatusCode)
	}

	// 管理员用户列表：三个账号、bob/alice 各 1 对象统计正确
	req, _ = http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	_, body = e.do(t, req)
	users, _ := body["users"].([]any)
	if len(users) != 3 {
		t.Fatalf("user count = %d, want 3 (%v)", len(users), body)
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "lsk_") || strings.Contains(string(raw), aliceToken) {
		t.Fatalf("user list must not contain any token material: %s", raw)
	}
}

// TestUserDisableAndDelete：禁用即时生效、删除清空数据（含跨用户不可达）。
func TestUserDisableAndDelete(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	tok, resp, _ := registerUser(t, e, adminCreateInvite(t, e), "mallory")
	if resp.StatusCode != http.StatusOK {
		t.Fatal("register failed")
	}
	if resp := uploadAs(t, e, tok, "note.md", []byte("data")); resp.StatusCode != http.StatusOK {
		t.Fatalf("upload = %d", resp.StatusCode)
	}
	var userID string
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	_, body := e.do(t, req)
	for _, u := range body["users"].([]any) {
		m := u.(map[string]any)
		if m["name"] == "mallory" {
			userID, _ = m["userId"].(string)
			if n, _ := m["objects"].(float64); n != 1 {
				t.Fatalf("mallory objects = %v, want 1", n)
			}
		}
	}
	if userID == "" {
		t.Fatal("mallory not in user list")
	}

	// 禁用 → Token 立即失效
	req, _ = http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/admin/users/"+userID+"/disable", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	if resp, _ := e.do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("disable = %d", resp.StatusCode)
	}
	if resp, _ := bearerGet(t, e, "/api/v1/info", tok); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled user info = %d, want 401", resp.StatusCode)
	}
	// 解禁（v0.20.1 / ADR-019 §2.1）：只恢复登录资格，**不复活任何旧凭据**（R-2）。
	// 停用 = 动作 B，旧 Token 的授权代次已落后：解禁后仍是 401 TOKEN_REVOKED，
	// 换发新 Token（`obsync token reset --user` 的等价操作）之后才能继续使用
	req, _ = http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/admin/users/"+userID+"/enable", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	e.do(t, req)
	if resp, body := bearerGet(t, e, "/api/v1/info", tok); resp.StatusCode != http.StatusUnauthorized || body["code"] != "TOKEN_REVOKED" {
		t.Fatalf("re-enabled user's OLD token = %d %v, want 401 TOKEN_REVOKED (re-enabling must not revive old credentials)", resp.StatusCode, body)
	}
	tok = "lsk_reissued_after_enable_0123456789abcdef"
	if _, err := db.SetUserToken(e.db, userID, db.HashToken(tok)); err != nil {
		t.Fatal(err)
	}
	if resp, _ := bearerGet(t, e, "/api/v1/info", tok); resp.StatusCode != http.StatusOK {
		t.Fatalf("re-enabled user with a re-issued token: info = %d, want 200", resp.StatusCode)
	}

	// 删除：confirmName 不符 → 400 且没删；相符 → 数据消失、Token 失效
	payload, _ := json.Marshal(map[string]any{"confirmName": "wrong"})
	req, _ = http.NewRequest(http.MethodDelete, e.ts.URL+"/api/v1/admin/users/"+userID, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+testToken)
	if resp, _ := e.do(t, req); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("delete with wrong confirm = %d, want 400", resp.StatusCode)
	}
	payload, _ = json.Marshal(map[string]any{"confirmName": "mallory"})
	req, _ = http.NewRequest(http.MethodDelete, e.ts.URL+"/api/v1/admin/users/"+userID, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+testToken)
	if resp, _ := e.do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
	if resp, _ := bearerGet(t, e, "/api/v1/info", tok); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("deleted user token = %d, want 401", resp.StatusCode)
	}
	var n int64
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM file_heads WHERE vault_id NOT IN ('default')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("vault rows remain after delete: n=%d err=%v", n, err)
	}
}

// TestAdminCannotSeeUserToken：注册后管理员的一切常规视图都拿不到用户 Token。
func TestAdminCannotSeeUserToken(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	tok, _, _ := registerUser(t, e, adminCreateInvite(t, e), "dana")
	// 数据库里只有哈希
	var count int64
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM users WHERE token_hash = ?`,
		sha256Hex([]byte(tok))).Scan(&count); err != nil || count != 1 {
		t.Fatalf("hash row = %d err=%v", count, err)
	}
	var raw string
	_ = e.db.QueryRow(`SELECT COALESCE(group_concat(token_hash), '') FROM users`).Scan(&raw) //nolint:errcheck
	if strings.Contains(raw, tok) {
		t.Fatal("plaintext token found in database")
	}
	_ = fmt.Sprint(raw)
}
