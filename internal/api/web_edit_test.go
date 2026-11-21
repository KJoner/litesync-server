package api_test

// 网页写端的服务端闸门（v0.20 / ADR-015）：覆盖验收 ED-01 的服务端部分与 TN-01（会话写入归属）；INV-12。
//   - 默认关闭：会话不能写（需求 §14：写功能独立门槛开放）；
//   - 开启后：同源会话可写；跨站 Origin 拒绝；只读成员拒绝；
//   - 写入归属取服务端生成的网页标识，客户端自报的 X-Device-ID 不作数。

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KJoner/litesync-server/internal/api"
	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

func newWebEditEnv(t *testing.T, editing bool) *testEnv {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	store, _ := storage.New(filepath.Join(dir, "vault"))
	blobs, _ := storage.NewBlobStore(filepath.Join(dir, "blobs"))
	shares, _ := storage.NewShareStore(filepath.Join(dir, "shares"))
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := syncsvc.New(database, store, blobs, shares, syncsvc.Options{HistoryEnabled: true, HistoryMaxPerFile: 100}, logger)
	ts := httptest.NewServer(api.New(api.Options{Token: testToken, MaxFileSize: 1 << 20, Version: "test", Logger: logger, WebEditing: editing}, svc))
	t.Cleanup(ts.Close)
	return &testEnv{ts: ts, svc: svc, db: database}
}

// tokenSession 用 API Token 换网页会话，返回带 Cookie 的客户端。
func tokenSession(t *testing.T, e *testEnv, token string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	res, err := c.Post(e.ts.URL+"/web/session", "application/json", strings.NewReader(`{"token":"`+token+`"}`))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("token session: %v %v", err, res.StatusCode)
	}
	res.Body.Close()
	return c
}

func sessionPut(t *testing.T, c *http.Client, e *testEnv, origin, path string, content []byte, extra map[string]string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytes.NewReader(content))
	req.Header.Set("X-File-Path", url.PathEscape(path))
	req.Header.Set("X-Base-Revision", "0")
	req.Header.Set("X-Content-Hash", sha256Hex(content))
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

func TestWebSessionWritesAreOffByDefault(t *testing.T) {
	e := newWebEditEnv(t, false)
	c := tokenSession(t, e, testToken)
	if code := sessionPut(t, c, e, e.ts.URL, "a.md", []byte("hi"), nil); code != http.StatusForbidden {
		t.Fatalf("session write with web editing disabled = %d, want 403", code)
	}
}

func TestWebSessionWritesWhenEnabled(t *testing.T) {
	e := newWebEditEnv(t, true)
	c := tokenSession(t, e, testToken)
	if code := sessionPut(t, c, e, "https://evil.example", "a.md", []byte("hi"), nil); code != http.StatusForbidden {
		t.Fatalf("cross-origin session write = %d, want 403", code)
	}
	if code := sessionPut(t, c, e, e.ts.URL, "a.md", []byte("hi"), map[string]string{"X-Device-ID": "forged-device"}); code != http.StatusOK {
		t.Fatalf("same-origin session write = %d, want 200", code)
	}
	var device string
	if err := e.db.QueryRow(`SELECT COALESCE(device_id,'') FROM object_versions ORDER BY id DESC LIMIT 1`).Scan(&device); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(device, "web-") || device == "forged-device" {
		t.Fatalf("web write attributed to %q; must be the server-side web identity, never the client header", device)
	}

	// 只读成员：能登录、能读，不能写
	readerToken, resp, _ := registerUser(t, e, adminCreateInvite(t, e), "reader")
	if resp.StatusCode != http.StatusOK {
		t.Fatal("register reader")
	}
	u, err := e.svc.AuthUserByToken(readerToken)
	if err != nil || u == nil {
		t.Fatal("reader user lookup")
	}
	if err := db.UpsertMembership(e.db, &db.Membership{UserID: u.UserID, VaultID: db.DefaultVaultID, Role: db.RoleReader}); err != nil {
		t.Fatal(err)
	}
	rc := tokenSession(t, e, readerToken)
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/snapshot", nil)
	req.Header.Set("X-Vault-ID", db.DefaultVaultID)
	if res, err := rc.Do(req); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("reader read = %v %v", err, res.StatusCode)
	}
	if code := sessionPut(t, rc, e, e.ts.URL, "b.md", []byte("x"), map[string]string{"X-Vault-ID": db.DefaultVaultID}); code != http.StatusForbidden {
		t.Fatalf("read-only member web write = %d, want 403", code)
	}
}

// 回收站（v0.20 / 需求 §7.2「删除回收」）：删除后出现在 /api/v1/trash，显式恢复后消失；
// 别的用户既看不到也无法用 X-Vault-ID 越权读取。覆盖 INV-05（恢复不重置身份）与 TN-01。
func TestTrashListsTombstonesAndIsScoped(t *testing.T) {
	e := newWebEditEnv(t, true)
	resp, body := e.upload(t, "回收/计划.md", 0, []byte("v1"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload = %d", resp.StatusCode)
	}
	fileID, _ := body["fileId"].(string)
	rev := int64(body["revision"].(float64))
	if resp, _ := e.delete(t, "回收/计划.md", rev); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
	resp, body = e.doJSON(t, http.MethodGet, "/api/v1/trash", testToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("trash = %d", resp.StatusCode)
	}
	items, _ := body["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("trash items = %d, want 1: %v", len(items), body)
	}
	it := items[0].(map[string]any)
	if it["fileId"] != fileID || it["path"] != "回收/计划.md" || it["restorable"] != true || int64(it["deletionRevision"].(float64)) != rev+1 {
		t.Fatalf("trash item = %v", it)
	}
	// 网页会话（回收站页面的真实调用方）同样能读到列表
	sc := tokenSession(t, e, testToken)
	if res, err := sc.Get(e.ts.URL + "/api/v1/trash"); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("web session GET /api/v1/trash = %v %v", err, res.StatusCode)
	} else {
		res.Body.Close()
	}

	// 另一个用户：自己的回收站里没有；拿着 Alice 的仓库 ID 来读 → 404（不泄露存在性）
	bobToken, r2, _ := registerUser(t, e, adminCreateInvite(t, e), "bob")
	if r2.StatusCode != http.StatusOK {
		t.Fatal("register bob")
	}
	resp, body = e.doJSON(t, http.MethodGet, "/api/v1/trash", bobToken, nil)
	if resp.StatusCode == http.StatusOK {
		if items, _ := body["items"].([]any); len(items) != 0 {
			t.Fatalf("bob sees alice's trash: %v", body)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/trash", nil)
	req.Header.Set("Authorization", "Bearer "+bobToken)
	req.Header.Set("X-Vault-ID", db.DefaultVaultID)
	if resp, _ := e.do(t, req); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("bob reading alice's trash via X-Vault-ID = %d, want 404", resp.StatusCode)
	}

	// 显式恢复：revision 连续、fileId 不变，回收站随之清空
	resp, body = e.restore(t, fileID, map[string]any{
		"expectedTombstoneRevision": rev + 1, "contentGeneration": 2, "pseudonym": "回收/计划.md",
	})
	if resp.StatusCode != http.StatusOK || body["fileId"] != fileID || int64(body["revision"].(float64)) != rev+2 {
		t.Fatalf("restore = %d %v", resp.StatusCode, body)
	}
	_, body = e.doJSON(t, http.MethodGet, "/api/v1/trash", testToken, nil)
	if items, _ := body["items"].([]any); len(items) != 0 {
		t.Fatalf("trash after restore = %v", body)
	}
}

// 网页发现其他设备的修改（v0.20）：会话可以读本仓库的 changes 游标；
// 拿别人的仓库 ID 来读 → 404（不泄露存在性）。覆盖 TN-01 / TN-03 的 LiteSync 部分。
func TestWebSessionCanPollChangesOfOwnVaultOnly(t *testing.T) {
	e := newWebEditEnv(t, false) // 只读会话也要能发现变更
	if resp, _ := e.upload(t, "变更/a.md", 0, []byte("v1")); resp.StatusCode != http.StatusOK {
		t.Fatalf("upload = %d", resp.StatusCode)
	}
	c := tokenSession(t, e, testToken)
	res, err := c.Get(e.ts.URL + "/api/v1/changes?since=0&limit=1")
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("web session GET /api/v1/changes = %v %v", err, res.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	res.Body.Close()
	if ch, _ := body["changes"].([]any); len(ch) != 1 {
		t.Fatalf("changes = %v", body)
	}
	bobToken, r2, _ := registerUser(t, e, adminCreateInvite(t, e), "bob")
	if r2.StatusCode != http.StatusOK {
		t.Fatal("register bob")
	}
	bc := tokenSession(t, e, bobToken)
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/changes?since=0", nil)
	req.Header.Set("X-Vault-ID", db.DefaultVaultID)
	if res, err := bc.Do(req); err != nil || res.StatusCode != http.StatusNotFound {
		t.Fatalf("bob polling alice's vault changes = %v %v, want 404", err, res.StatusCode)
	} else {
		res.Body.Close()
	}
}
