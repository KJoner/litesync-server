package api_test

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	syncsvc "obsync/internal/sync"
)

func (e *testEnv) history(t *testing.T, path string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/history?path="+url.QueryEscape(path), nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	return e.do(t, req)
}

func (e *testEnv) version(t *testing.T, path string, revision int64) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet,
		e.ts.URL+"/api/v1/version?path="+url.QueryEscape(path)+"&revision="+itoa(revision), nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("version %s@%d: %v", path, revision, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func blobPath(dir, hash string) string {
	return filepath.Join(dir, hash[:2], hash)
}

// 每次上传/删除都应产生不可变版本；旧版本内容可按 revision 取回。
func TestVersionHistoryFlow(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	v1 := []byte("version one")
	v2 := []byte("version two")

	e.upload(t, "Notes/h.md", 0, v1)
	e.upload(t, "Notes/h.md", 1, v2)
	e.delete(t, "Notes/h.md", 2)

	resp, body := e.history(t, "Notes/h.md")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("history = %d", resp.StatusCode)
	}
	versions := body["versions"].([]any)
	if len(versions) != 3 {
		t.Fatalf("len(versions) = %d, want 3", len(versions))
	}
	// 降序：rev3 delete, rev2 upsert, rev1 upsert
	top := versions[0].(map[string]any)
	if top["revision"].(float64) != 3 || top["action"] != "delete" {
		t.Fatalf("top version = %v", top)
	}
	mid := versions[1].(map[string]any)
	if mid["revision"].(float64) != 2 || mid["action"] != "upsert" || mid["hash"] != sha256Hex(v2) {
		t.Fatalf("mid version = %v", mid)
	}

	// 取回历史版本内容
	vresp, data := e.version(t, "Notes/h.md", 1)
	if vresp.StatusCode != http.StatusOK || !bytes.Equal(data, v1) {
		t.Fatalf("version 1 = %d, %q", vresp.StatusCode, data)
	}
	if vresp.Header.Get("X-Content-Hash") != sha256Hex(v1) || vresp.Header.Get("X-Action") != "upsert" {
		t.Fatal("version headers wrong")
	}

	// delete 版本没有内容 → 404；不存在的 revision → 404
	if resp, _ := e.version(t, "Notes/h.md", 3); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("delete version = %d, want 404", resp.StatusCode)
	}
	if resp, _ := e.version(t, "Notes/h.md", 99); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown revision = %d, want 404", resp.StatusCode)
	}

	// 文件删除后历史仍在，重新创建继续线性追加
	e.upload(t, "Notes/h.md", 0, []byte("resurrected"))
	_, body2 := e.history(t, "Notes/h.md")
	if len(body2["versions"].([]any)) != 4 {
		t.Fatal("history must survive delete + recreate")
	}
}

// merge / restore 动作应被记录到版本历史。
func TestVersionActions(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "a.md", 0, []byte("base"))

	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytes.NewReader([]byte("merged")))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-File-Path", "a.md")
	req.Header.Set("X-Base-Revision", "1")
	req.Header.Set("X-Content-Hash", sha256Hex([]byte("merged")))
	req.Header.Set("X-Action", "merge")
	req.Header.Set("X-Device-ID", "device-test")
	resp, _ := e.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("merge upload = %d", resp.StatusCode)
	}

	_, body := e.history(t, "a.md")
	top := body["versions"].([]any)[0].(map[string]any)
	if top["action"] != "merge" || top["deviceId"] != "device-test" {
		t.Fatalf("merge version = %v", top)
	}

	// 非法 action → 400
	req2, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytes.NewReader([]byte("x")))
	req2.Header.Set("Authorization", "Bearer "+testToken)
	req2.Header.Set("X-File-Path", "a.md")
	req2.Header.Set("X-Base-Revision", "2")
	req2.Header.Set("X-Content-Hash", sha256Hex([]byte("x")))
	req2.Header.Set("X-Action", "hack")
	resp2, _ := e.do(t, req2)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid action = %d, want 400", resp2.StatusCode)
	}
}

// 相同内容跨路径共享同一个 blob（内容寻址去重）。
func TestBlobDedup(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	content := []byte("shared bytes")
	hash := sha256Hex(content)

	e.upload(t, "one.md", 0, content)
	e.upload(t, "two.md", 0, content)

	if _, err := os.Stat(blobPath(e.blobDir, hash)); err != nil {
		t.Fatalf("blob missing: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(e.blobDir, hash[:2]))
	if len(entries) != 1 {
		t.Fatalf("expected 1 blob, got %d", len(entries))
	}
}

// retention：超过 MaxPerFile 的旧版本被裁剪，无引用的 blob 被 GC；共享 blob 保留。
func TestHistoryRetention(t *testing.T) {
	e := newTestEnvOpts(t, 1<<20, syncsvc.Options{
		HistoryEnabled:    true,
		HistoryDays:       0,
		HistoryMaxPerFile: 2,
	})
	c1, c2, c3 := []byte("content 1"), []byte("content 2"), []byte("content 3")

	// c1 同时被另一个文件引用，裁剪后 blob 必须保留
	e.upload(t, "keeper.md", 0, c1)

	e.upload(t, "r.md", 0, c1)
	e.upload(t, "r.md", 1, c2)
	e.upload(t, "r.md", 2, c3)

	_, body := e.history(t, "r.md")
	versions := body["versions"].([]any)
	if len(versions) != 2 {
		t.Fatalf("len(versions) = %d, want 2 (retention)", len(versions))
	}
	if versions[0].(map[string]any)["revision"].(float64) != 3 ||
		versions[1].(map[string]any)["revision"].(float64) != 2 {
		t.Fatalf("wrong versions kept: %v", versions)
	}
	// rev1 已裁剪 → 404
	if resp, _ := e.version(t, "r.md", 1); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("pruned version = %d, want 404", resp.StatusCode)
	}
	// c1 blob 仍被 keeper.md 引用 → 保留；c2/c3 blob 仍被引用 → 保留
	if _, err := os.Stat(blobPath(e.blobDir, sha256Hex(c1))); err != nil {
		t.Fatal("shared blob must survive pruning")
	}

	// keeper.md 更新两次把 c1 的最后引用挤出 → blob 应被 GC
	e.upload(t, "keeper.md", 1, []byte("k2"))
	e.upload(t, "keeper.md", 2, []byte("k3"))
	e.upload(t, "keeper.md", 3, []byte("k4"))
	if _, err := os.Stat(blobPath(e.blobDir, sha256Hex(c1))); !os.IsNotExist(err) {
		t.Fatal("unreferenced blob must be garbage collected")
	}
}

// 关闭历史后：不写版本记录，history 返回空列表。
// （v4 起 HEAD 本身就存在 blob store，因此 blob 仍会存在——单份存储。）
func TestHistoryDisabled(t *testing.T) {
	e := newTestEnvOpts(t, 1<<20, syncsvc.Options{HistoryEnabled: false})
	content := []byte("no history")
	e.upload(t, "n.md", 0, content)

	_, body := e.history(t, "n.md")
	if len(body["versions"].([]any)) != 0 {
		t.Fatal("history must be empty when disabled")
	}
	if resp, _ := e.version(t, "n.md", 1); resp.StatusCode != http.StatusNotFound {
		t.Fatal("version must 404 when disabled")
	}
	// HEAD blob 存在（唯一内容存储），且下载正常
	if _, err := os.Stat(blobPath(e.blobDir, sha256Hex(content))); err != nil {
		t.Fatal("HEAD blob must exist (single storage)")
	}
	dresp, data := e.download(t, "n.md")
	if dresp.StatusCode != http.StatusOK || !bytes.Equal(data, content) {
		t.Fatal("download must serve from blob store")
	}
}

// v1 升级场景：已有 files 记录（revision 5）但无版本历史 → Backfill 补记当前版本。
func TestBackfillVersions(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	content := []byte("legacy content")
	hash := sha256Hex(content)

	// 模拟 v1 遗留状态：直接写 vault 文件 + files 行，无版本记录
	if err := os.MkdirAll(e.vaultDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.vaultDir, "old.md"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	e.insertLegacyFile(t, "old.md", hash, int64(len(content)), 5)

	if err := e.svc.BackfillVersions(); err != nil {
		t.Fatal(err)
	}
	_, body := e.history(t, "old.md")
	versions := body["versions"].([]any)
	if len(versions) != 1 {
		t.Fatalf("backfill: len(versions) = %d, want 1", len(versions))
	}
	vresp, data := e.version(t, "old.md", 5)
	if vresp.StatusCode != http.StatusOK || !bytes.Equal(data, content) {
		t.Fatalf("backfilled version fetch = %d", vresp.StatusCode)
	}
	// 幂等：再跑一次不产生重复
	if err := e.svc.BackfillVersions(); err != nil {
		t.Fatal(err)
	}
	_, body2 := e.history(t, "old.md")
	if len(body2["versions"].([]any)) != 1 {
		t.Fatal("backfill must be idempotent")
	}
}

// 历史接口同样需要认证。
func TestHistoryAuth(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/history?path=a.md", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("history without token = %d, want 401", resp.StatusCode)
	}
}

// 版本接口路径安全。
func TestVersionPathSafety(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	if resp, _ := e.version(t, "../secret", 1); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("traversal version = %d, want 400", resp.StatusCode)
	}
	resp, _ := e.history(t, "../secret")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("traversal history = %d, want 400", resp.StatusCode)
	}
}

// insertLegacyFile 直接向 files 表插入一行（模拟 v1 数据），绕过版本记录。
func (e *testEnv) insertLegacyFile(t *testing.T, path, hash string, size, revision int64) {
	t.Helper()
	now := time.Now().Unix()
	if _, err := e.db.Exec(
		`INSERT INTO files (path, content_hash, size, mtime, revision, deleted, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 0, ?, ?)`,
		path, hash, size, now*1000, revision, now, now,
	); err != nil {
		t.Fatal(err)
	}
}
