package api_test

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"obsync/internal/api"
	"obsync/internal/db"
	"obsync/internal/storage"
	syncsvc "obsync/internal/sync"
)

const testToken = "test-token-0123456789abcdef0123456789abcdef"

type testEnv struct {
	ts       *httptest.Server
	vaultDir string
	blobDir  string
	svc      *syncsvc.Service
	db       *sql.DB
}

func newTestEnv(t *testing.T, maxFileSize int64) *testEnv {
	return newTestEnvOpts(t, maxFileSize, syncsvc.Options{
		HistoryEnabled:    true,
		HistoryDays:       90,
		HistoryMaxPerFile: 100,
	})
}

func newTestEnvOpts(t *testing.T, maxFileSize int64, opts syncsvc.Options) *testEnv {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "sync.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	vaultDir := filepath.Join(dir, "vault")
	store, err := storage.New(vaultDir)
	if err != nil {
		t.Fatalf("init storage: %v", err)
	}
	blobDir := filepath.Join(dir, "blobs")
	blobs, err := storage.NewBlobStore(blobDir)
	if err != nil {
		t.Fatalf("init blob store: %v", err)
	}
	shares, err := storage.NewShareStore(filepath.Join(dir, "shares"))
	if err != nil {
		t.Fatalf("init share store: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := syncsvc.New(database, store, blobs, shares, opts, logger)
	handler := api.New(api.Options{
		Token:       testToken,
		MaxFileSize: maxFileSize,
		Version:     "test",
		Logger:      logger,
	}, svc)
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return &testEnv{ts: ts, vaultDir: vaultDir, blobDir: blobDir, svc: svc, db: database}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (e *testEnv) do(t *testing.T, req *http.Request) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	var body map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 && resp.Header.Get("Content-Type") != "application/octet-stream" {
		json.Unmarshal(raw, &body) //nolint:errcheck
	}
	return resp, body
}

func (e *testEnv) upload(t *testing.T, path string, baseRevision int64, content []byte) (*http.Response, map[string]any) {
	t.Helper()
	return e.uploadWithHash(t, path, baseRevision, content, sha256Hex(content))
}

func (e *testEnv) uploadWithHash(t *testing.T, path string, baseRevision int64, content []byte, hash string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytes.NewReader(content))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-File-Path", url.PathEscape(path))
	req.Header.Set("X-Base-Revision", fmt.Sprint(baseRevision))
	req.Header.Set("X-Content-Hash", hash)
	req.Header.Set("X-File-Mtime", "1700000000000")
	return e.do(t, req)
}

func (e *testEnv) download(t *testing.T, path string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/file?path="+url.QueryEscape(path), nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("download %s: %v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func (e *testEnv) delete(t *testing.T, path string, baseRevision int64) (*http.Response, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"path": path, "baseRevision": baseRevision})
	req, _ := http.NewRequest(http.MethodDelete, e.ts.URL+"/api/v1/file", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	return e.do(t, req)
}

func (e *testEnv) changes(t *testing.T, query string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/changes"+query, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	return e.do(t, req)
}

// --- 认证 ---

func TestHealthNoAuth(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	resp, err := http.Get(e.ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health = %d, want 200", resp.StatusCode)
	}
}

func TestAuth(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"correct token", "Bearer " + testToken, http.StatusOK},
		{"wrong token", "Bearer wrong-token", http.StatusUnauthorized},
		{"missing token", "", http.StatusUnauthorized},
		{"malformed header", testToken, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/info", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			resp, _ := e.do(t, req)
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

// --- 上传 / 下载 ---

func TestUploadDownloadFlow(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	content := []byte("# Hello\n")

	// 新文件上传
	resp, body := e.upload(t, "Notes/hello.md", 0, content)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload = %d, body %v", resp.StatusCode, body)
	}
	if body["revision"].(float64) != 1 {
		t.Fatalf("revision = %v, want 1", body["revision"])
	}

	// 下载并校验内容与 Header
	dresp, data := e.download(t, "Notes/hello.md")
	if dresp.StatusCode != http.StatusOK {
		t.Fatalf("download = %d", dresp.StatusCode)
	}
	if !bytes.Equal(data, content) {
		t.Fatalf("content mismatch: %q", data)
	}
	if dresp.Header.Get("X-Revision") != "1" {
		t.Fatalf("X-Revision = %q, want 1", dresp.Header.Get("X-Revision"))
	}
	if dresp.Header.Get("X-Content-Hash") != sha256Hex(content) {
		t.Fatal("X-Content-Hash mismatch")
	}
	if dresp.Header.Get("X-File-Mtime") != "1700000000000" {
		t.Fatalf("X-File-Mtime = %q", dresp.Header.Get("X-File-Mtime"))
	}

	// 磁盘上确实存在
	if _, err := os.Stat(filepath.Join(e.vaultDir, "Notes", "hello.md")); err != nil {
		t.Fatalf("file not on disk: %v", err)
	}

	// 修改（baseRevision=1）
	content2 := []byte("# Hello v2\n")
	resp2, body2 := e.upload(t, "Notes/hello.md", 1, content2)
	if resp2.StatusCode != http.StatusOK || body2["revision"].(float64) != 2 {
		t.Fatalf("modify = %d, revision %v", resp2.StatusCode, body2["revision"])
	}

	// 错误的 baseRevision → 409，且响应携带服务器当前状态
	resp3, body3 := e.upload(t, "Notes/hello.md", 1, []byte("# stale edit\n"))
	if resp3.StatusCode != http.StatusConflict {
		t.Fatalf("stale upload = %d, want 409", resp3.StatusCode)
	}
	if body3["revision"].(float64) != 2 || body3["hash"].(string) != sha256Hex(content2) {
		t.Fatalf("conflict body = %v", body3)
	}
	// 冲突不能覆盖服务器内容
	_, data3 := e.download(t, "Notes/hello.md")
	if !bytes.Equal(data3, content2) {
		t.Fatal("conflict overwrote server content")
	}
}

func TestSameHashUploadIsIdempotent(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	content := []byte("same content")
	e.upload(t, "a.md", 0, content)

	_, before := e.changes(t, "")
	// 相同内容重复上传（即使 baseRevision 已过期）也应幂等成功
	resp, body := e.upload(t, "a.md", 0, content)
	if resp.StatusCode != http.StatusOK || body["revision"].(float64) != 1 {
		t.Fatalf("idempotent upload = %d, revision %v", resp.StatusCode, body["revision"])
	}
	_, after := e.changes(t, "")
	if before["latestSequence"].(float64) != after["latestSequence"].(float64) {
		t.Fatal("idempotent upload must not create a new change")
	}
}

func TestUploadHashMismatch(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	resp, _ := e.uploadWithHash(t, "bad.md", 0, []byte("real content"), sha256Hex([]byte("claimed different")))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("hash mismatch = %d, want 400", resp.StatusCode)
	}
	// 不应留下正式文件
	if _, err := os.Stat(filepath.Join(e.vaultDir, "bad.md")); !os.IsNotExist(err) {
		t.Fatal("mismatched upload must not leave a file on disk")
	}
}

func TestUploadTooLarge(t *testing.T) {
	e := newTestEnv(t, 16) // 限制 16 字节
	resp, _ := e.upload(t, "big.bin", 0, bytes.Repeat([]byte("x"), 64))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("too large = %d, want 413", resp.StatusCode)
	}
}

func TestUnicodePath(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	path := "笔记/你好 世界.md"
	content := []byte("中文内容测试")
	resp, _ := e.upload(t, path, 0, content)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unicode upload = %d", resp.StatusCode)
	}
	dresp, data := e.download(t, path)
	if dresp.StatusCode != http.StatusOK || !bytes.Equal(data, content) {
		t.Fatalf("unicode download = %d, content %q", dresp.StatusCode, data)
	}
}

// --- 删除 ---

func TestDeleteFlow(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	content := []byte("to be deleted")
	e.upload(t, "Notes/del.md", 0, content)

	// 旧 revision 删除 → 409
	resp, _ := e.delete(t, "Notes/del.md", 99)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale delete = %d, want 409", resp.StatusCode)
	}

	// 正常删除
	resp2, body2 := e.delete(t, "Notes/del.md", 1)
	if resp2.StatusCode != http.StatusOK || body2["revision"].(float64) != 2 {
		t.Fatalf("delete = %d, revision %v", resp2.StatusCode, body2["revision"])
	}
	// 磁盘文件已移除
	if _, err := os.Stat(filepath.Join(e.vaultDir, "Notes", "del.md")); !os.IsNotExist(err) {
		t.Fatal("file still on disk after delete")
	}
	// 下载 → 404 且提示 deleted
	dresp, raw := e.download(t, "Notes/del.md")
	if dresp.StatusCode != http.StatusNotFound {
		t.Fatalf("download deleted = %d, want 404", dresp.StatusCode)
	}
	var nf map[string]any
	json.Unmarshal(raw, &nf) //nolint:errcheck
	if nf["deleted"] != true {
		t.Fatalf("404 body should mark deleted: %v", nf)
	}

	// 重复删除 → 幂等成功
	resp3, body3 := e.delete(t, "Notes/del.md", 1)
	if resp3.StatusCode != http.StatusOK || body3["revision"].(float64) != 2 {
		t.Fatalf("repeat delete = %d, revision %v", resp3.StatusCode, body3["revision"])
	}

	// 删除不存在的文件 → 404
	resp4, _ := e.delete(t, "Notes/never-existed.md", 0)
	if resp4.StatusCode != http.StatusNotFound {
		t.Fatalf("delete missing = %d, want 404", resp4.StatusCode)
	}

	// 删除后重新创建：baseRevision=0 或 tombstone revision 均可
	resp5, body5 := e.upload(t, "Notes/del.md", 0, []byte("recreated"))
	if resp5.StatusCode != http.StatusOK || body5["revision"].(float64) != 3 {
		t.Fatalf("recreate = %d, revision %v", resp5.StatusCode, body5["revision"])
	}
}

// --- Changes ---

func TestChangesSequence(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "a.md", 0, []byte("a"))          // seq 1: upsert a
	e.upload(t, "b.md", 0, []byte("b"))          // seq 2: upsert b
	e.upload(t, "a.md", 1, []byte("a2"))         // seq 3: upsert a rev2
	e.delete(t, "b.md", 1)                       // seq 4: delete b
	e.upload(t, "img.png", 0, []byte{0x89, 'P'}) // seq 5: upsert img.png

	resp, body := e.changes(t, "?since=0")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("changes = %d", resp.StatusCode)
	}
	if body["latestSequence"].(float64) != 5 || body["hasMore"].(bool) {
		t.Fatalf("latestSequence/hasMore = %v/%v", body["latestSequence"], body["hasMore"])
	}
	list := body["changes"].([]any)
	if len(list) != 5 {
		t.Fatalf("len(changes) = %d, want 5", len(list))
	}
	// sequence 严格递增
	prev := float64(0)
	for _, item := range list {
		c := item.(map[string]any)
		if c["sequence"].(float64) <= prev {
			t.Fatal("sequence not strictly increasing")
		}
		prev = c["sequence"].(float64)
	}
	// 校验第 4 条是 delete b.md
	c4 := list[3].(map[string]any)
	if c4["action"] != "delete" || c4["path"] != "b.md" || c4["revision"].(float64) != 2 {
		t.Fatalf("change 4 = %v", c4)
	}

	// since 过滤
	_, body2 := e.changes(t, "?since=3")
	if len(body2["changes"].([]any)) != 2 {
		t.Fatalf("since=3 returned %d changes, want 2", len(body2["changes"].([]any)))
	}

	// limit 分页
	_, body3 := e.changes(t, "?since=0&limit=2")
	if len(body3["changes"].([]any)) != 2 || !body3["hasMore"].(bool) {
		t.Fatalf("limit=2: len=%d hasMore=%v", len(body3["changes"].([]any)), body3["hasMore"])
	}
}

// --- 路径安全 ---

func TestPathTraversal(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	bad := []string{
		"../secret",
		"../../etc/passwd",
		"a/../b",
		"/absolute/path",
		"C:\\Windows\\system32",
		"a\\b.md",
		"./a.md",
		"a//b.md",
		"a/./b.md",
		"..",
		".",
		"notes/../../x",
	}
	for _, p := range bad {
		t.Run(p, func(t *testing.T) {
			resp, _ := e.upload(t, p, 0, []byte("x"))
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("upload %q = %d, want 400", p, resp.StatusCode)
			}
			dresp, _ := e.download(t, p)
			if dresp.StatusCode != http.StatusBadRequest {
				t.Fatalf("download %q = %d, want 400", p, dresp.StatusCode)
			}
			delResp, _ := e.delete(t, p, 0)
			if delResp.StatusCode != http.StatusBadRequest {
				t.Fatalf("delete %q = %d, want 400", p, delResp.StatusCode)
			}
		})
	}
}

// URL encoded traversal：Header 中的 %2e%2e%2f 解码后必须同样被拒绝
func TestEncodedTraversal(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	content := []byte("x")
	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytes.NewReader(content))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-File-Path", "%2e%2e%2f%2e%2e%2fetc%2fpasswd")
	req.Header.Set("X-Base-Revision", "0")
	req.Header.Set("X-Content-Hash", sha256Hex(content))
	resp, _ := e.do(t, req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("encoded traversal = %d, want 400", resp.StatusCode)
	}
}

// --- Info ---

func TestInfo(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "a.md", 0, []byte("a"))
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/info", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, body := e.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("info = %d", resp.StatusCode)
	}
	if body["version"] != "test" || body["latestSequence"].(float64) != 1 {
		t.Fatalf("info body = %v", body)
	}
}
