package api_test

// v9.3 三期：元数据加密——迁移生命周期、明文路径抹除、meta-encrypted 态强制项、
// 改名（元数据更新）CAS 与碰撞。

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

const (
	metaEncA = "TFNNMS1mYWtlLW1ldGEtQQ==" // 伪 LSM1 密文（服务器 opaque）
	metaEncB = "TFNNMS1mYWtlLW1ldGEtQg=="
	canonA   = "1111111111111111111111111111111111111111111111111111111111111111"
	canonB   = "2222222222222222222222222222222222222222222222222222222222222222"
)

func (e *testEnv) postMeta(t *testing.T, action string, body map[string]any) (*http.Response, map[string]any) {
	t.Helper()
	return e.doJSON(t, http.MethodPost, "/api/v1/meta/"+action, testToken, body)
}

func (e *testEnv) uploadWithMeta(t *testing.T, path string, baseRevision int64, content []byte, fileID, metaEnc, canonicalHash string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytesReader(content))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-File-Path", path)
	req.Header.Set("X-Base-Revision", itoa(baseRevision))
	req.Header.Set("X-Content-Hash", sha256Hex(content))
	if fileID != "" {
		req.Header.Set("X-File-Id", fileID)
	}
	req.Header.Set("X-Meta-Enc", metaEnc)
	req.Header.Set("X-Canonical-Hash", canonicalHash)
	return e.do(t, req)
}

// 完整迁移生命周期 + 明文抹除验证。
func TestMetaMigrationLifecycle(t *testing.T) {
	e := newTestEnv(t, 1<<20)

	// 准备：两个 LSE3 文件 + E2EE encrypted 态
	e.upload(t, "笔记/日记.md", 0, lse3Payload(1, 1, "diary"))
	e.upload(t, "b.md", 0, lse3Payload(1, 1, "b"))
	if r, _ := e.postE2ee(t, "begin"); r.StatusCode != http.StatusOK {
		t.Fatal("e2ee begin")
	}
	if r, _ := e.postE2ee(t, "complete"); r.StatusCode != http.StatusOK {
		t.Fatal("e2ee complete")
	}

	// meta begin 前置：必须 encrypted（新环境直接 begin 会因 plaintext 被拒——
	// 上面已完成，因此这里成功）
	if r, body := e.postMeta(t, "begin", nil); r.StatusCode != http.StatusOK || body["metaState"] != "migrating" {
		t.Fatalf("meta begin = %d %v", r.StatusCode, body)
	}

	before := e.snapshotFiles(t)
	idA := before["笔记/日记.md"]["fileId"].(string)

	// 迁移文件 A：真实路径 → 伪名
	r1, mig := e.doJSON(t, http.MethodPost, "/api/v1/meta/migrate", testToken,
		map[string]any{"fromPath": "笔记/日记.md", "metaEnc": metaEncA, "canonicalHash": canonA})
	if r1.StatusCode != http.StatusOK || mig["toPath"] != idA {
		t.Fatalf("migrate A = %d %v", r1.StatusCode, mig)
	}
	// 幂等重放
	if r, _ := e.doJSON(t, http.MethodPost, "/api/v1/meta/migrate", testToken,
		map[string]any{"fromPath": idA, "metaEnc": metaEncA, "canonicalHash": canonA}); r.StatusCode != http.StatusOK {
		t.Fatalf("idempotent migrate = %d", r.StatusCode)
	}

	// complete 前有未迁移文件 → 拒绝
	if r, _ := e.postMeta(t, "complete", map[string]any{"confirmErase": true}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("complete with unmigrated files = %d, want 400", r.StatusCode)
	}

	// 迁移 B 后：无 confirmErase → 400；带确认 → 完成
	idB := before["b.md"]["fileId"].(string)
	e.doJSON(t, http.MethodPost, "/api/v1/meta/migrate", testToken,
		map[string]any{"fromPath": "b.md", "metaEnc": metaEncB, "canonicalHash": canonB})
	if r, _ := e.postMeta(t, "complete", nil); r.StatusCode != http.StatusBadRequest {
		t.Fatal("complete without confirmErase must 400")
	}
	r2, st := e.postMeta(t, "complete", map[string]any{"confirmErase": true})
	if r2.StatusCode != http.StatusOK || st["metaState"] != "encrypted" {
		t.Fatalf("meta complete = %d %v", r2.StatusCode, st)
	}

	// 抹除验证 ①：快照只含伪名 + 加密元数据，明文路径消失
	after := e.snapshotFiles(t)
	if len(after) != 2 {
		t.Fatalf("snapshot files = %d, want 2", len(after))
	}
	if _, ok := after["笔记/日记.md"]; ok {
		t.Fatal("plaintext path must be gone from snapshot")
	}
	if after[idA]["metaEnc"] != metaEncA || after[idB]["metaEnc"] != metaEncB {
		t.Fatalf("snapshot metaEnc missing: %v", after)
	}
	// 抹除验证 ②：changes 全量裁剪——旧游标必须 resync（旧 changes 里的明文路径消失）
	_, cbody := e.changes(t, "?since=0")
	if cbody["resyncRequired"] != true {
		t.Fatal("old cursors must be forced to snapshot resync after erasure")
	}
	// 抹除验证 ③：伪名可下载且带 meta 头；info 反映状态
	dresp, _ := e.download(t, idA)
	if dresp.StatusCode != http.StatusOK || dresp.Header.Get("X-Meta-Enc") != metaEncA {
		t.Fatalf("download pseudonym = %d metaEnc %q", dresp.StatusCode, dresp.Header.Get("X-Meta-Enc"))
	}
	if info := e.info(t); info["metaState"] != "encrypted" {
		t.Fatalf("info metaState = %v", info["metaState"])
	}

	// meta-encrypted 强制项：明文路径上传 → 400；伪名建档缺 meta → 400；
	// 伪名 + meta + LSE3 → 200
	if r, _ := e.upload(t, "new-plain.md", 0, lse3Payload(1, 1, "x")); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("plaintext path upload in meta mode = %d, want 400", r.StatusCode)
	}
	newID := "aaaa567890abcdef0123456789abcdef"
	if r, _ := e.upload(t, newID, 0, lse3Payload(1, 1, "y")); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("pseudonym create without meta = %d, want 400", r.StatusCode)
	}
	r4, _ := e.uploadWithMeta(t, newID, 0, lse3Payload(1, 1, "y"), newID, metaEncB2(), canonHex("33"))
	if r4.StatusCode != http.StatusOK {
		t.Fatalf("pseudonym create with meta = %d, want 200", r4.StatusCode)
	}

	// 改名 = 元数据更新：CAS 错 → 412；对 → 200 且 changes 带 metaGeneration；
	// 与现有 canonical 冲突 → 422
	if r, _ := e.doJSON(t, http.MethodPut, "/api/v1/file/meta", testToken,
		map[string]any{"path": idA, "baseMetaGeneration": 99, "metaEnc": metaEncB2(), "canonicalHash": canonHex("44")}); r.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("meta CAS mismatch = %d, want 412", r.StatusCode)
	}
	r5, upd := e.doJSON(t, http.MethodPut, "/api/v1/file/meta", testToken,
		map[string]any{"path": idA, "baseMetaGeneration": 1, "metaEnc": metaEncB2(), "canonicalHash": canonHex("44")})
	if r5.StatusCode != http.StatusOK || upd["metaGeneration"].(float64) != 2 {
		t.Fatalf("meta rename = %d %v", r5.StatusCode, upd)
	}
	_, cb2 := e.changes(t, "?since="+itoa(int64(upd["sequence"].(float64))-1))
	list := cb2["changes"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["metaGeneration"].(float64) != 2 {
		t.Fatalf("rename change = %v", list)
	}
	if r, _ := e.doJSON(t, http.MethodPut, "/api/v1/file/meta", testToken,
		map[string]any{"path": idB, "baseMetaGeneration": 1, "metaEnc": metaEncB2(), "canonicalHash": canonHex("44")}); r.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("rename onto taken name = %d, want 422", r.StatusCode)
	}

	// 路径式 MOVE 在 meta 态被拒
	if r, _ := e.move(t, idA, "whatever.md", 1); r.StatusCode != http.StatusConflict {
		t.Fatalf("path move in meta mode = %d, want 409", r.StatusCode)
	}
}

// abort：混合态保留、无破坏，可重新 begin 续迁。
func TestMetaMigrationAbort(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "a.md", 0, lse3Payload(1, 1, "a"))
	e.upload(t, "b.md", 0, lse3Payload(1, 1, "b"))
	e.postE2ee(t, "begin")
	e.postE2ee(t, "complete")
	e.postMeta(t, "begin", nil)

	snap := e.snapshotFiles(t)
	idA := snap["a.md"]["fileId"].(string)
	e.doJSON(t, http.MethodPost, "/api/v1/meta/migrate", testToken,
		map[string]any{"fromPath": "a.md", "metaEnc": metaEncA, "canonicalHash": canonA})

	if r, body := e.postMeta(t, "abort", nil); r.StatusCode != http.StatusOK || body["metaState"] != "plain" {
		t.Fatalf("abort = %d %v", r.StatusCode, body)
	}
	// 混合态：已迁移的伪名行与未迁移的明文行都可下载
	if r, _ := e.download(t, idA); r.StatusCode != http.StatusOK {
		t.Fatal("migrated pseudonym must remain readable after abort")
	}
	if r, _ := e.download(t, "b.md"); r.StatusCode != http.StatusOK {
		t.Fatal("unmigrated plaintext path must remain readable after abort")
	}
	// migrate 在 plain 态被拒；重新 begin 后继续
	if r, _ := e.doJSON(t, http.MethodPost, "/api/v1/meta/migrate", testToken,
		map[string]any{"fromPath": "b.md", "metaEnc": metaEncB, "canonicalHash": canonB}); r.StatusCode != http.StatusConflict {
		t.Fatalf("migrate after abort = %d, want 409", r.StatusCode)
	}
	e.postMeta(t, "begin", nil)
	if r, _ := e.doJSON(t, http.MethodPost, "/api/v1/meta/migrate", testToken,
		map[string]any{"fromPath": "b.md", "metaEnc": metaEncB, "canonicalHash": canonB}); r.StatusCode != http.StatusOK {
		t.Fatalf("resume migrate = %d", r.StatusCode)
	}
}

// begin 的前置：E2EE 必须已 encrypted；非 LSE3 内容拒绝迁移。
func TestMetaMigrationPreconditions(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "plain.md", 0, []byte("plaintext content"))

	// E2EE 还是 plaintext → meta begin 拒绝
	if r, _ := e.postMeta(t, "begin", nil); r.StatusCode != http.StatusConflict {
		t.Fatalf("meta begin without e2ee = %d, want 409", r.StatusCode)
	}

	// 换 LSE2 内容进 encrypted 态 → migrate 因非 LSE3 拒绝
	lse2 := append([]byte("LSE2"), []byte("\x00\x00\x00\x01iv-ct")...)
	e.upload(t, "plain.md", 1, lse2)
	e.postE2ee(t, "begin")
	e.postE2ee(t, "complete")
	e.postMeta(t, "begin", nil)
	if r, _ := e.doJSON(t, http.MethodPost, "/api/v1/meta/migrate", testToken,
		map[string]any{"fromPath": "plain.md", "metaEnc": metaEncA, "canonicalHash": canonA}); r.StatusCode != http.StatusConflict {
		t.Fatalf("migrate LSE2 content = %d, want 409 (envelope upgrade required)", r.StatusCode)
	}
}

func metaEncB2() string { return "TFNNMS1mYWtlLW1ldGEtQzI=" }

func canonHex(prefix string) string {
	out := ""
	for len(out) < 64 {
		out += prefix
	}
	return out[:64]
}
