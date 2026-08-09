package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"obsync/internal/api"
	"obsync/internal/backup"
	"obsync/internal/db"
	"obsync/internal/storage"
	syncsvc "obsync/internal/sync"
)

// newBackupTestServer 构建带真实 backup.Manager 的测试服务器
//（restic 二进制不存在，但 status/config 接口不依赖它）。
func newBackupTestServer(t *testing.T) *httptest.Server {
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
	svc := syncsvc.New(database, store, blobs, shares, syncsvc.Options{}, logger)

	bkp := backup.New(database, svc, backup.NewRunner(filepath.Join(dir, "no-such-restic")),
		dir, "test", filepath.Join(dir, "key", "backup-config.key"), logger)

	handler := api.New(api.Options{
		Token: testToken, MaxFileSize: 1 << 20, Version: "test", Logger: logger, Backup: bkp,
	}, svc)
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

// webLogin 登录并返回 cookie（admin=true 时包含 admin 会话）。
func webLogin(t *testing.T, ts *httptest.Server, admin bool) []*http.Cookie {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"token": testToken, "admin": admin})
	resp, err := http.Post(ts.URL+"/web/session", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	return resp.Cookies()
}

func adminReq(t *testing.T, ts *httptest.Server, method, path string, cookies []*http.Cookie, bearer string, body string) *http.Response {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, ts.URL+path, rd)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAdminAuthMatrix(t *testing.T) {
	ts := newBackupTestServer(t)
	const statusPath = "/api/v1/admin/backup/status"

	// 无认证 → 401
	resp := adminReq(t, ts, "GET", statusPath, nil, "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no auth: status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 只读会话 → 403（admin session required）
	roCookies := webLogin(t, ts, false)
	resp = adminReq(t, ts, "GET", statusPath, roCookies, "", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("readonly cookie: status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 只读会话仍能访问白名单 GET
	resp = adminReq(t, ts, "GET", "/api/v1/info", roCookies, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readonly whitelist broken: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// admin 登录 → 下发 admin cookie → 访问成功
	adCookies := webLogin(t, ts, true)
	hasAdmin := false
	for _, c := range adCookies {
		if c.Name == "litesync_admin" {
			hasAdmin = true
		}
	}
	if !hasAdmin {
		t.Fatal("admin login did not set litesync_admin cookie")
	}
	resp = adminReq(t, ts, "GET", statusPath, adCookies, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin cookie: status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 根 Token → 完整权限
	resp = adminReq(t, ts, "GET", statusPath, nil, testToken, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bearer: status = %d", resp.StatusCode)
	}
	var st backup.Status
	json.NewDecoder(resp.Body).Decode(&st) //nolint:errcheck
	resp.Body.Close()
	if !st.KeyAvailable {
		t.Fatalf("key should be available: %+v", st)
	}
}

func TestAdminConfigNeverReturnsSecrets(t *testing.T) {
	ts := newBackupTestServer(t)

	// 写入配置（含 secrets）
	cfgBody := `{"accountId":"acct1","bucket":"bkt","accessKeyId":"AK123","secretAccessKey":"SEKRET","resticPassword":"RPWD"}`
	resp := adminReq(t, ts, "PUT", "/api/v1/admin/backup/config", nil, testToken, cfgBody)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body) //nolint:errcheck
		t.Fatalf("put config: %d %s", resp.StatusCode, raw)
	}
	raw, _ := io.ReadAll(resp.Body) //nolint:errcheck
	resp.Body.Close()
	for _, secret := range []string{"SEKRET", "RPWD"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("PUT response leaked secret: %s", raw)
		}
	}

	// GET config：绝不返回 secret，只有 configured 标记
	resp = adminReq(t, ts, "GET", "/api/v1/admin/backup/config", nil, testToken, "")
	raw, _ = io.ReadAll(resp.Body) //nolint:errcheck
	resp.Body.Close()
	for _, secret := range []string{"SEKRET", "RPWD"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("GET config leaked secret: %s", raw)
		}
	}
	var v backup.View
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if !v.SecretKeyConfigured || !v.ResticPasswordConfigured || v.Bucket != "bkt" {
		t.Fatalf("bad view: %+v", v)
	}

	// 空 secret 更新 → 保持原值（configured 标记不变）
	resp = adminReq(t, ts, "PUT", "/api/v1/admin/backup/config", nil, testToken,
		`{"bucket":"bkt2","secretAccessKey":"","resticPassword":""}`)
	raw, _ = io.ReadAll(resp.Body) //nolint:errcheck
	resp.Body.Close()
	json.Unmarshal(raw, &v) //nolint:errcheck
	if v.Bucket != "bkt2" || !v.SecretKeyConfigured || !v.ResticPasswordConfigured {
		t.Fatalf("empty secrets must keep old values: %+v", v)
	}
}

func TestAdminSessionExpiryIsShort(t *testing.T) {
	ts := newBackupTestServer(t)
	cookies := webLogin(t, ts, true)
	for _, c := range cookies {
		if c.Name == "litesync_admin" && c.MaxAge > 3600 {
			t.Fatalf("admin cookie TTL too long: %d", c.MaxAge)
		}
		if c.Name == "litesync_admin" && !c.HttpOnly {
			t.Fatal("admin cookie must be HttpOnly")
		}
	}
}
