package api_test

// v9.3 三期：元数据加密——迁移生命周期、meta-encrypted 态强制项、
// 改名（元数据更新）CAS 与碰撞。
//
// v0.12.1（LS-121-S02）：complete 不再删除 tombstone。仓库里只要还有携带
// 明文路径的删除记录，complete 一律被拒（409 TOMBSTONE_PLAINTEXT），迁移
// 停在可回退的 migrating 态——「擦除明文」绝不能以丢失删除屏障为代价。

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

// forceMetaEncrypted 直接把仓库切到 meta-encrypted 态。
//
// v0.12.1 起 complete 无法在存在明文 tombstone 时完成，因此正常流程到不了
// encrypted；但**已经在 v0.12.0 完成迁移的仓库**仍处于该状态，其强制项与
// 改名语义必须继续被测试覆盖。这里模拟的正是那种既有仓库。
func (e *testEnv) forceMetaEncrypted(t *testing.T) {
	t.Helper()
	if _, err := e.db.Exec(`UPDATE repo_state SET meta_state = 'encrypted' WHERE id = 1`); err != nil {
		t.Fatalf("force meta_state: %v", err)
	}
}

// 完整迁移生命周期：begin → 逐文件伪名化（幂等）→ complete 的两道拒绝。
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

	// meta begin 前置：必须 encrypted（上面已完成，因此这里成功）
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
	// 迁移后伪名可下载且带 meta 头
	if dresp, _ := e.download(t, idA); dresp.StatusCode != http.StatusOK ||
		dresp.Header.Get("X-Meta-Enc") != metaEncA {
		t.Fatalf("download pseudonym = %d", dresp.StatusCode)
	}

	// complete 拒绝 ①：还有未迁移的明文路径文件
	if r, _ := e.postMeta(t, "complete", map[string]any{"confirmErase": true}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("complete with unmigrated files = %d, want 400", r.StatusCode)
	}

	// 迁移 B 后：无 confirmErase → 400
	e.doJSON(t, http.MethodPost, "/api/v1/meta/migrate", testToken,
		map[string]any{"fromPath": "b.md", "metaEnc": metaEncB, "canonicalHash": canonB})
	if r, _ := e.postMeta(t, "complete", nil); r.StatusCode != http.StatusBadRequest {
		t.Fatal("complete without confirmErase must 400")
	}

	// complete 拒绝 ②（v0.12.1 / LS-121-S02）：全部伪名化后仍被拒——
	// 迁移本身在旧的真实路径上留下了 tombstone，抹掉它们就等于丢失删除屏障
	r2, body2 := e.postMeta(t, "complete", map[string]any{"confirmErase": true})
	if r2.StatusCode != http.StatusConflict || body2["code"] != "TOMBSTONE_PLAINTEXT" {
		t.Fatalf("complete with plaintext tombstones = %d %v, want 409 TOMBSTONE_PLAINTEXT", r2.StatusCode, body2)
	}

	// 状态停在 migrating（可回退），删除屏障与 changes 都还在
	if info := e.info(t); info["metaState"] != "migrating" {
		t.Fatalf("metaState = %v, want migrating（complete 被拒后不得推进状态）", info["metaState"])
	}
	if _, cbody := e.changes(t, "?since=0"); cbody["resyncRequired"] == true {
		t.Fatal("complete 被拒时不得裁剪 changes")
	}
	// 删除屏障仍在：旧路径上的 base 0 重建被 tombstone 挡住（INV-06）
	if r, cb := e.upload(t, "b.md", 0, lse3Payload(1, 9, "resurrect")); r.StatusCode != http.StatusConflict ||
		cb["deleted"] != true {
		t.Fatalf("tombstone must still block base-0 recreate: %d %v", r.StatusCode, cb)
	}
}

// meta-encrypted 既有仓库（v0.12.0 迁移完成）的强制项与改名语义。
func TestMetaEncryptedEnforcement(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "a.md", 0, lse3Payload(1, 1, "a"))
	e.upload(t, "b.md", 0, lse3Payload(1, 1, "b"))
	e.postE2ee(t, "begin")
	e.postE2ee(t, "complete")
	e.postMeta(t, "begin", nil)

	snap := e.snapshotFiles(t)
	idA, idB := snap["a.md"]["fileId"].(string), snap["b.md"]["fileId"].(string)
	e.doJSON(t, http.MethodPost, "/api/v1/meta/migrate", testToken,
		map[string]any{"fromPath": "a.md", "metaEnc": metaEncA, "canonicalHash": canonA})
	e.doJSON(t, http.MethodPost, "/api/v1/meta/migrate", testToken,
		map[string]any{"fromPath": "b.md", "metaEnc": metaEncB, "canonicalHash": canonB})
	e.forceMetaEncrypted(t)

	if info := e.info(t); info["metaState"] != "encrypted" {
		t.Fatalf("info metaState = %v", info["metaState"])
	}
	// 快照只含伪名 + 加密元数据
	after := e.snapshotFiles(t)
	if _, ok := after["a.md"]; ok {
		t.Fatal("plaintext path must be gone from snapshot")
	}
	if after[idA]["metaEnc"] != metaEncA || after[idB]["metaEnc"] != metaEncB {
		t.Fatalf("snapshot metaEnc missing: %v", after)
	}

	// 强制项：明文路径上传 → 400；伪名建档缺 meta → 400；伪名 + meta + LSE3 → 200
	if r, _ := e.upload(t, "new-plain.md", 0, lse3Payload(1, 1, "x")); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("plaintext path upload in meta mode = %d, want 400", r.StatusCode)
	}
	newID := "aaaa567890abcdef0123456789abcdef"
	if r, _ := e.upload(t, newID, 0, lse3Payload(1, 1, "y")); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("pseudonym create without meta = %d, want 400", r.StatusCode)
	}
	if r, _ := e.uploadWithMeta(t, newID, 0, lse3Payload(1, 1, "y"), newID, metaEncB2(), canonHex("33")); r.StatusCode != http.StatusOK {
		t.Fatalf("pseudonym create with meta = %d, want 200", r.StatusCode)
	}

	// 改名 = 元数据更新：CAS 错 → 412；对 → 200 且 changes 带 metaGeneration；
	// 与现有 canonical 冲突 → 422
	if r, body := e.doJSON(t, http.MethodPut, "/api/v1/file/meta", testToken,
		map[string]any{"path": idA, "baseMetaGeneration": 99, "metaEnc": metaEncB2(), "canonicalHash": canonHex("44")}); r.StatusCode != http.StatusPreconditionFailed ||
		body["code"] != "STALE_META_GENERATION" {
		t.Fatalf("meta CAS mismatch = %d %v, want 412 STALE_META_GENERATION", r.StatusCode, body)
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
	if r, body := e.doJSON(t, http.MethodPut, "/api/v1/file/meta", testToken,
		map[string]any{"path": idB, "baseMetaGeneration": 1, "metaEnc": metaEncB2(), "canonicalHash": canonHex("44")}); r.StatusCode != http.StatusUnprocessableEntity ||
		body["code"] != "CANONICAL_COLLISION" {
		t.Fatalf("rename onto taken name = %d %v, want 422 CANONICAL_COLLISION", r.StatusCode, body)
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
	if r, body := e.doJSON(t, http.MethodPost, "/api/v1/meta/migrate", testToken,
		map[string]any{"fromPath": "plain.md", "metaEnc": metaEncA, "canonicalHash": canonA}); r.StatusCode != http.StatusConflict ||
		body["code"] != "PLAINTEXT_REJECTED" {
		t.Fatalf("migrate LSE2 content = %d %v, want 409 PLAINTEXT_REJECTED", r.StatusCode, body)
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
