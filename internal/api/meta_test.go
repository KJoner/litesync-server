package api_test

// 元数据加密测试（协议 v6 / ADR-002 / ADR-003）。
//
// 与 v5 的关键差异（这些正是本文件要锁住的性质）：
//   - 迁移是**一次元数据更新**：revision / contentGeneration / blob 不动，
//     **不产生任何 tombstone**——v0.12.1 的「迁移必然留下明文 tombstone
//     因而永远无法 complete」死结随之消失
//   - tombstone 做**格式转换**而不是删除，删除屏障完整保留（INV-06）
//   - 新增 verifying 态：验证与不可逆擦除分离，验证失败时数据一个字节都没动
//   - complete 前跑 11 项验证器，失败返回**完整清单**

import (
	"bytes"
	"encoding/json"
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

func (e *testEnv) metaStatus(t *testing.T) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/meta/status", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	_, body := e.do(t, req)
	return body
}

func (e *testEnv) migrateObject(t *testing.T, path, metaEnc, canon string) (*http.Response, map[string]any) {
	t.Helper()
	return e.doJSON(t, http.MethodPost, "/api/v1/meta/migrate", testToken,
		map[string]any{"fromPath": path, "metaEnc": metaEnc, "canonicalHash": canon})
}

func (e *testEnv) uploadWithMeta(t *testing.T, path string, baseRevision int64, content []byte, fileID, metaEnc, canonicalHash string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytesReader(content))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-File-Path", path)
	req.Header.Set("X-Base-Revision", itoa(baseRevision))
	req.Header.Set("X-Content-Hash", sha256Hex(content))
	req.Header.Set("X-Format-Epoch", itoa(int64(e.formatEpoch(t))))
	if fileID != "" {
		req.Header.Set("X-File-Id", fileID)
	}
	req.Header.Set("X-Meta-Enc", metaEnc)
	req.Header.Set("X-Canonical-Hash", canonicalHash)
	return e.do(t, req)
}

func (e *testEnv) formatEpoch(t *testing.T) int {
	t.Helper()
	return int(e.info(t)["formatEpoch"].(float64))
}

// enterEncryptedRepo 把仓库带到「E2EE encrypted + 信封下限 LSE3」——
// 这是元数据迁移的前置（ADR-003 §3.2）。
func (e *testEnv) enterEncryptedRepo(t *testing.T) {
	t.Helper()
	if r, _ := e.postE2ee(t, "begin"); r.StatusCode != http.StatusOK {
		t.Fatal("e2ee begin")
	}
	if r, _ := e.postE2ee(t, "complete"); r.StatusCode != http.StatusOK {
		t.Fatal("e2ee complete")
	}
	r, b := e.doJSON(t, http.MethodPost, "/api/v1/envelope/complete", testToken, nil)
	if r.StatusCode != http.StatusOK || b["minimumEnvelopeVersion"].(float64) != 3 {
		t.Fatalf("envelope complete = %d %v", r.StatusCode, b)
	}
}

// 完整迁移生命周期：begin → 逐对象 → tombstone 转换 → verify → complete。
func TestMetaMigrationLifecycle(t *testing.T) {
	e := newTestEnv(t, 1<<20)

	e.upload(t, "笔记/日记.md", 0, lse3Payload(1, 1, "diary"))
	e.upload(t, "笔记/日记.md", 1, lse3Payload(1, 2, "diary2")) // 多个 revision
	e.upload(t, "b.md", 0, lse3Payload(1, 1, "b"))
	// 一条真实删除记录：它必须活到迁移完成之后（INV-06）
	e.upload(t, "deleted.md", 0, lse3Payload(1, 1, "gone"))
	_, delBody := e.delete(t, "deleted.md", 1)
	deletedID := delBody["fileId"].(string)

	e.enterEncryptedRepo(t)

	if r, body := e.postMeta(t, "begin", nil); r.StatusCode != http.StatusOK || body["metaState"] != "migrating" {
		t.Fatalf("meta begin = %d %v", r.StatusCode, body)
	}
	st := e.metaStatus(t)
	if st["journal"].(map[string]any)["pending"].(float64) != 3 {
		t.Fatalf("journal should hold 2 objects + 1 tombstone: %v", st["journal"])
	}

	before := e.snapshotFiles(t)
	idA := before["笔记/日记.md"]["fileId"].(string)
	revA := before["笔记/日记.md"]["revision"].(float64)
	genA := before["笔记/日记.md"]["contentGeneration"].(float64)

	// 迁移对象 A：revision / contentGeneration 必须原样保留（INV-05）
	r1, mig := e.migrateObject(t, "笔记/日记.md", metaEncA, canonA)
	if r1.StatusCode != http.StatusOK || mig["toPath"] != idA {
		t.Fatalf("migrate A = %d %v", r1.StatusCode, mig)
	}
	if mig["revision"].(float64) != revA {
		t.Fatalf("migration must not reset revision: %v → %v", revA, mig["revision"])
	}
	after := e.snapshotFiles(t)
	if after[idA]["contentGeneration"].(float64) != genA {
		t.Fatalf("migration must not reset contentGeneration: %v", after[idA])
	}
	// 幂等重放
	if r, _ := e.migrateObject(t, idA, metaEncA, canonA); r.StatusCode != http.StatusOK {
		t.Fatalf("idempotent migrate = %d", r.StatusCode)
	}
	// 关键回归：迁移**不产生 tombstone**——旧路径既不是墓碑也不再存在
	dr, raw := e.download(t, "笔记/日记.md")
	var nf map[string]any
	json.Unmarshal(raw, &nf) //nolint:errcheck
	if dr.StatusCode != http.StatusNotFound || nf["deleted"] == true {
		t.Fatalf("migration must not create a tombstone: %d %v", dr.StatusCode, nf)
	}

	// verify 前 journal 未清空 → 拒绝
	if r, b := e.postMeta(t, "verify", nil); r.StatusCode != http.StatusConflict ||
		b["code"] != "MIGRATION_INCOMPLETE" {
		t.Fatalf("verify with pending journal = %d %v, want 409 MIGRATION_INCOMPLETE", r.StatusCode, b)
	}

	e.migrateObject(t, "b.md", metaEncB, canonB)

	// tombstone 仍是明文 → verify 仍被拒
	if r, _ := e.postMeta(t, "verify", nil); r.StatusCode != http.StatusConflict {
		t.Fatal("verify must fail while a plaintext tombstone remains")
	}
	// 列出明文 tombstone 并转换（**不是删除**）
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/meta/tombstones", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	_, tb := e.do(t, req)
	list := tb["tombstones"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["fileId"] != deletedID {
		t.Fatalf("plaintext tombstones = %v", list)
	}
	if r, _ := e.postMeta(t, "migrate-tombstone", map[string]any{
		"fileId": deletedID, "canonicalHash": canonHex("55"),
	}); r.StatusCode != http.StatusOK {
		t.Fatalf("migrate tombstone = %d", r.StatusCode)
	}

	// verify → verifying
	if r, b := e.postMeta(t, "verify", nil); r.StatusCode != http.StatusOK || b["metaState"] != "verifying" {
		t.Fatalf("verify = %d %v", r.StatusCode, b)
	}
	// 无 confirmErase → 400
	if r, _ := e.postMeta(t, "complete", nil); r.StatusCode != http.StatusBadRequest {
		t.Fatal("complete without confirmErase must 400")
	}
	// complete：跑 11 项验证器 → 擦除 → encrypted
	r2, st2 := e.postMeta(t, "complete", map[string]any{"confirmErase": true})
	if r2.StatusCode != http.StatusOK || st2["metaState"] != "encrypted" {
		t.Fatalf("meta complete = %d %v", r2.StatusCode, st2)
	}
	if st2["formatEpoch"].(float64) != 2 {
		t.Fatalf("formatEpoch must advance on completion: %v", st2["formatEpoch"])
	}

	// 抹除后：快照只含伪名 + 加密元数据
	final := e.snapshotFiles(t)
	if _, ok := final["笔记/日记.md"]; ok {
		t.Fatal("plaintext path must be gone from snapshot")
	}
	if len(final) != 2 || final[idA]["metaEnc"] != metaEncA {
		t.Fatalf("snapshot after erase = %v", final)
	}
	// changes 全量裁剪 → 旧游标必须 resync
	if _, cb := e.changes(t, "?since=0"); cb["resyncRequired"] != true {
		t.Fatal("old cursors must be forced to snapshot resync after erasure")
	}
	// **删除屏障仍在**：这是 v0.12.0 丢失、v0.12.1 用「拒绝 complete」冻结、
	// v6 用格式转换真正解决的那件事（INV-06）
	if r, b := e.uploadWithMeta(t, deletedID, 0, lse3Payload(1, 9, "resurrect"),
		deletedID, metaEncB2(), canonHex("55")); r.StatusCode != http.StatusConflict || b["deleted"] != true {
		t.Fatalf("tombstone must still block recreation after erasure: %d %v", r.StatusCode, b)
	}
	// 历史完整保留：迁移前的两个 revision 仍属于同一对象
	_, hist := e.history(t, idA)
	if len(hist["versions"].([]any)) != 2 {
		t.Fatalf("history must survive metadata migration: %v", hist["versions"])
	}
}

// 验证器失败时返回完整清单，且**状态与数据都不变**（ADR-003 §3.5）。
func TestMetaCompleteValidationFailures(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "a.md", 0, lse3Payload(1, 1, "a"))
	e.upload(t, "b.md", 0, lse3Payload(1, 1, "b"))
	e.enterEncryptedRepo(t)
	e.postMeta(t, "begin", nil)

	snap := e.snapshotFiles(t)
	e.migrateObject(t, "a.md", metaEncA, canonA)
	e.migrateObject(t, "b.md", metaEncB, canonB)
	e.postMeta(t, "verify", nil)

	// 人为制造一条未伪名化的 HEAD：验证器必须发现并拒绝
	if _, err := e.db.Exec(`UPDATE file_heads SET pseudonym = 'leaked/plaintext.md' WHERE file_id = ?`,
		snap["a.md"]["fileId"].(string)); err != nil {
		t.Fatal(err)
	}
	r, body := e.postMeta(t, "complete", map[string]any{"confirmErase": true})
	if r.StatusCode != http.StatusConflict || body["code"] != "MIGRATION_VALIDATION_FAILED" {
		t.Fatalf("complete with a plaintext head = %d %v", r.StatusCode, body)
	}
	failures := body["failures"].([]any)
	if len(failures) == 0 {
		t.Fatal("validation must return the full failure list")
	}
	found := false
	for _, f := range failures {
		if f.(map[string]any)["code"] == "META_REQUIRED" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected META_REQUIRED among failures: %v", failures)
	}
	// 状态没有推进，changes 没有被裁剪——验证失败时数据一个字节都没动
	if e.info(t)["metaState"] != "verifying" {
		t.Fatal("failed validation must not advance the state machine")
	}
	if _, cb := e.changes(t, "?since=0"); cb["resyncRequired"] == true {
		t.Fatal("failed validation must not prune changes")
	}
}

// abort：混合态保留、无破坏，可重新 begin 续迁。
func TestMetaMigrationAbort(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "a.md", 0, lse3Payload(1, 1, "a"))
	e.upload(t, "b.md", 0, lse3Payload(1, 1, "b"))
	e.enterEncryptedRepo(t)
	e.postMeta(t, "begin", nil)

	snap := e.snapshotFiles(t)
	idA := snap["a.md"]["fileId"].(string)
	e.migrateObject(t, "a.md", metaEncA, canonA)

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
	if r, _ := e.migrateObject(t, "b.md", metaEncB, canonB); r.StatusCode != http.StatusConflict {
		t.Fatal("migrate after abort must be rejected")
	}
	e.postMeta(t, "begin", nil)
	if r, _ := e.migrateObject(t, "b.md", metaEncB, canonB); r.StatusCode != http.StatusOK {
		t.Fatal("resume migrate after re-begin")
	}
	// verifying 态同样可以 abort
	e.postMeta(t, "verify", nil)
	if r, b := e.postMeta(t, "abort", nil); r.StatusCode != http.StatusOK || b["metaState"] != "plain" {
		t.Fatalf("abort from verifying = %d %v", r.StatusCode, b)
	}
}

// begin 的前置：E2EE encrypted + 信封下限已是 LSE3。
func TestMetaMigrationPreconditions(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "plain.md", 0, []byte("plaintext content"))

	// E2EE 还是 plaintext → meta begin 拒绝
	if r, _ := e.postMeta(t, "begin", nil); r.StatusCode != http.StatusConflict {
		t.Fatal("meta begin without e2ee must be rejected")
	}

	// 换 LSE2 内容进 encrypted 态：信封下限只到 1 → meta begin 仍被拒
	lse2 := append([]byte("LSE2"), []byte("\x00\x00\x00\x01iv-ct")...)
	e.upload(t, "plain.md", 1, lse2)
	e.postE2ee(t, "begin")
	e.postE2ee(t, "complete")
	if r, b := e.postMeta(t, "begin", nil); r.StatusCode != http.StatusConflict ||
		b["code"] != "ENVELOPE_TOO_OLD" {
		t.Fatalf("meta begin below LSE3 floor = %d %v, want 409 ENVELOPE_TOO_OLD", r.StatusCode, b)
	}
	// envelope/complete 也会因为存在 LSE2 内容而拒绝提升下限
	if r, b := e.doJSON(t, http.MethodPost, "/api/v1/envelope/complete", testToken, nil); r.StatusCode != http.StatusConflict ||
		b["code"] != "ENVELOPE_TOO_OLD" {
		t.Fatalf("envelope complete with LSE2 head = %d %v", r.StatusCode, b)
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
