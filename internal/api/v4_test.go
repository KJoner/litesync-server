package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"testing"
	"time"

	syncsvc "obsync/internal/sync"
)

// ---------- Web 只读会话 ----------

func webClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

func TestWebSessionReadonly(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "a.md", 0, []byte("hello"))
	client := webClient(t)

	// 错误 token → 401
	badBody, _ := json.Marshal(map[string]string{"token": "wrong"})
	resp, err := client.Post(e.ts.URL+"/web/session", "application/json", bytes.NewReader(badBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login = %d, want 401", resp.StatusCode)
	}

	// 正确 token → 设置 HttpOnly Cookie
	okBody, _ := json.Marshal(map[string]string{"token": testToken})
	resp2, err := client.Post(e.ts.URL+"/web/session", "application/json", bytes.NewReader(okBody))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("login = %d", resp2.StatusCode)
	}
	var cookie *http.Cookie
	for _, c := range resp2.Cookies() {
		if c.Name == "litesync_session" {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie must be HttpOnly + SameSite=Strict: %+v", cookie)
	}

	// 会话可以读（白名单 GET）
	for _, path := range []string{"/api/v1/info", "/api/v1/snapshot", "/api/v1/file?path=a.md", "/api/v1/history?path=a.md"} {
		r, err := client.Get(e.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("session GET %s = %d, want 200", path, r.StatusCode)
		}
	}

	// 会话不能写（403，Web 会话只读）
	putReq, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytes.NewReader([]byte("x")))
	putReq.Header.Set("X-File-Path", "hack.md")
	putReq.Header.Set("X-Base-Revision", "0")
	putReq.Header.Set("X-Content-Hash", sha256Hex([]byte("x")))
	r2, err := client.Do(putReq)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusForbidden {
		t.Fatalf("session PUT = %d, want 403", r2.StatusCode)
	}
	// 会话也不能碰分享管理与历史清理
	delReq, _ := http.NewRequest(http.MethodDelete, e.ts.URL+"/api/v1/history?path=a.md&beforeRevision=99", nil)
	r3, _ := client.Do(delReq)
	r3.Body.Close()
	if r3.StatusCode != http.StatusForbidden {
		t.Fatalf("session DELETE history = %d, want 403", r3.StatusCode)
	}

	// 登出后读也失效
	logoutReq, _ := http.NewRequest(http.MethodDelete, e.ts.URL+"/web/session", nil)
	r4, _ := client.Do(logoutReq)
	r4.Body.Close()
	r5, _ := client.Get(e.ts.URL + "/api/v1/info")
	r5.Body.Close()
	if r5.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout = %d, want 401", r5.StatusCode)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	resp, err := http.Get(e.ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" || !bytes.Contains([]byte(csp), []byte("default-src 'none'")) {
		t.Fatalf("missing CSP: %q", csp)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff")
	}
	if resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("missing referrer policy")
	}
}

// ---------- changes 裁剪与 resync ----------

func TestChangesPruneAndResync(t *testing.T) {
	e := newTestEnvOpts(t, 1<<20, syncsvc.Options{
		HistoryEnabled: true,
		ChangesMax:     3, // 只保留最近 3 条
	})
	for i := 0; i < 6; i++ {
		e.upload(t, "n.md", int64(i), []byte{byte('a' + i)}) // seq 1..6
	}
	e.svc.RunMaintenance()

	// 新游标正常增量
	_, body := e.changes(t, "?since=3")
	if body["resyncRequired"] == true {
		t.Fatal("since=3 (watermark) must not require resync")
	}
	if len(body["changes"].([]any)) != 3 {
		t.Fatalf("since=3 changes = %d, want 3", len(body["changes"].([]any)))
	}

	// 旧游标 → resyncRequired + minSequence 水位线
	_, body2 := e.changes(t, "?since=1")
	if body2["resyncRequired"] != true {
		t.Fatalf("since=1 must require resync: %v", body2)
	}
	if body2["minSequence"].(float64) != 3 {
		t.Fatalf("minSequence = %v, want 3", body2["minSequence"])
	}
	// snapshot 可用于对账
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/snapshot", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, sbody := e.do(t, req)
	if resp.StatusCode != http.StatusOK || sbody["sequence"].(float64) != 6 {
		t.Fatalf("snapshot after prune: %v", sbody)
	}
}

// ---------- Maintenance：历史全量保留 / 附件分类 / 字节预算 / 孤儿 blob / 过期分享 ----------

func TestMaintenanceHistorySweep(t *testing.T) {
	e := newTestEnvOpts(t, 1<<20, syncsvc.Options{
		HistoryEnabled:        true,
		HistoryMaxPerFile:     100, // md 宽松
		HistoryAttachmentMax:  2,   // 附件最多 2 个版本
	})
	// 附件传 4 个版本 → 维护后只剩 2
	for i := 0; i < 4; i++ {
		e.upload(t, "img.png", int64(i), bytes.Repeat([]byte{byte(i)}, 8))
	}
	// markdown 传 4 个版本 → 保留全部
	for i := 0; i < 4; i++ {
		e.upload(t, "note.md", int64(i), []byte{byte('a' + i)})
	}
	e.svc.RunMaintenance()

	_, aBody := e.history(t, "img.png")
	if n := len(aBody["versions"].([]any)); n != 2 {
		t.Fatalf("attachment versions after sweep = %d, want 2", n)
	}
	_, mBody := e.history(t, "note.md")
	if n := len(mBody["versions"].([]any)); n != 4 {
		t.Fatalf("markdown versions = %d, want 4", n)
	}
}

func TestMaintenanceHistoryBudget(t *testing.T) {
	e := newTestEnvOpts(t, 1<<20, syncsvc.Options{
		HistoryEnabled:  true,
		HistoryMaxBytes: 100, // 非 HEAD 历史最多 100 字节
	})
	// 每版本 64 字节 × 4 版本 → 非 HEAD 历史 192 字节 → 需要裁到 ≤100
	for i := 0; i < 4; i++ {
		e.upload(t, "big.md", int64(i), bytes.Repeat([]byte{byte('a' + i)}, 64))
	}
	e.svc.RunMaintenance()

	_, body := e.history(t, "big.md")
	versions := body["versions"].([]any)
	// HEAD 永远保留；非 HEAD 只能剩 1 个（64 ≤ 100 < 128）
	if len(versions) != 2 {
		t.Fatalf("versions after budget = %d, want 2", len(versions))
	}
	if versions[0].(map[string]any)["revision"].(float64) != 4 {
		t.Fatal("HEAD version must survive budget pruning")
	}
}

func TestMaintenanceOrphanBlobsAndShares(t *testing.T) {
	e := newTestEnv(t, 1<<20)

	// 孤儿 blob：磁盘上有、数据库无引用、时间够老 → 清理
	orphanHash := sha256Hex([]byte("orphan-data"))
	dir := filepath.Join(e.blobDir, orphanHash[:2])
	os.MkdirAll(dir, 0o700)
	orphanPath := filepath.Join(dir, orphanHash)
	os.WriteFile(orphanPath, []byte("orphan-data"), 0o600)
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(orphanPath, old, old)

	// 被引用的 blob 不能删
	content := []byte("kept content")
	e.upload(t, "keep.md", 0, content)
	keptPath := blobPath(e.blobDir, sha256Hex(content))
	os.Chtimes(keptPath, old, old)

	// 过期分享（已过期但没人访问过）→ 密文被清
	resp, body := e.createShare(t, "s.md", time.Now().Unix()+1, []byte("cipher"))
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}
	shareID := body["id"].(string)
	// 过期判断是秒级（now > expiresAt）：等待 >2s 才能保证跨过临界秒，避免 flaky
	time.Sleep(2500 * time.Millisecond)

	e.svc.RunMaintenance()

	if _, err := os.Stat(orphanPath); !os.IsNotExist(err) {
		t.Fatal("orphan blob must be removed")
	}
	if _, err := os.Stat(keptPath); err != nil {
		t.Fatal("referenced blob must survive")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(e.blobDir), "shares", shareID)); !os.IsNotExist(err) {
		t.Fatal("expired share ciphertext must be removed")
	}
	// 下载仍正常（HEAD blob 是唯一存储且被保护）
	dresp, data := e.download(t, "keep.md")
	if dresp.StatusCode != http.StatusOK || !bytes.Equal(data, content) {
		t.Fatal("download broken after maintenance")
	}
}

// ---------- HEAD → blob 迁移（旧部署升级） ----------

func TestMigrateHeadToBlobs(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	content := []byte("legacy head content")
	hash := sha256Hex(content)

	// 模拟 v0.4 之前的状态：内容在 vault 目录 + files 行，blob 不存在
	os.MkdirAll(e.vaultDir, 0o700)
	if err := os.WriteFile(filepath.Join(e.vaultDir, "old.md"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	e.insertLegacyFile(t, "old.md", hash, int64(len(content)), 3)

	if err := e.svc.MigrateHeadToBlobs(); err != nil {
		t.Fatal(err)
	}
	// blob 已建立，vault 物理文件已删除
	if _, err := os.Stat(blobPath(e.blobDir, hash)); err != nil {
		t.Fatal("blob must exist after migration")
	}
	if _, err := os.Stat(filepath.Join(e.vaultDir, "old.md")); !os.IsNotExist(err) {
		t.Fatal("vault file must be absorbed")
	}
	// 下载从 blob 服务
	dresp, data := e.download(t, "old.md")
	if dresp.StatusCode != http.StatusOK || !bytes.Equal(data, content) {
		t.Fatalf("download after migration = %d", dresp.StatusCode)
	}
	// 幂等
	if err := e.svc.MigrateHeadToBlobs(); err != nil {
		t.Fatal(err)
	}
}
