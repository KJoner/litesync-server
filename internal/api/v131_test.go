package api_test

// v0.13.1 验收测试（计划书 §5）。
//
// 覆盖：
//   §5.3 逐请求协议与 epoch 校验（repoEpoch / keyEpoch / formatEpoch / protocol）
//   §5.4 迁移租约续期与**显式**接管；owner 失联后绝不自动完成
//   §5.7 迁移期间旧设备写入、旧协议请求被拒

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// uploadAs 以指定设备身份 + 自定义 Header 上传（epoch 校验测试用）。
func (e *testEnv) uploadAs(t *testing.T, deviceID, path string, baseRevision int64, content []byte, extra map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytes.NewReader(content))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Device-ID", deviceID)
	req.Header.Set("X-File-Path", url.PathEscape(path))
	req.Header.Set("X-Base-Revision", itoa(baseRevision))
	req.Header.Set("X-Content-Hash", sha256Hex(content))
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	return e.do(t, req)
}

// §5.3：repoEpoch / keyEpoch / formatEpoch / 协议版本逐请求校验。
func TestPerRequestEpochValidation(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	info := e.info(t)
	repoEpoch := info["repoEpoch"].(string)

	// 携带正确的世代 → 放行
	if r, _ := e.uploadAs(t, "d1", "a.md", 0, []byte("a"), map[string]string{
		"X-Repo-Epoch": repoEpoch, "X-Format-Epoch": "1", "X-LiteSync-Protocol": "6",
	}); r.StatusCode != http.StatusOK {
		t.Fatalf("matching epochs = %d, want 200", r.StatusCode)
	}

	// repoEpoch 不符 → 409 REPO_EPOCH_MISMATCH。
	// 这是「服务器从备份恢复过，你的游标与 baseRevision 全都作废」的信号：
	// 放行等于让旧世代的判断覆盖恢复后的内容
	r, b := e.uploadAs(t, "d1", "b.md", 0, []byte("b"), map[string]string{
		"X-Repo-Epoch": "ffffffffffffffffffffffffffffffff",
	})
	if r.StatusCode != http.StatusConflict || b["code"] != "REPO_EPOCH_MISMATCH" {
		t.Fatalf("stale repoEpoch = %d %v, want 409 REPO_EPOCH_MISMATCH", r.StatusCode, b)
	}

	// formatEpoch 不符 → 409 FORMAT_EPOCH_MISMATCH
	if r, b := e.uploadAs(t, "d1", "c.md", 0, []byte("c"), map[string]string{
		"X-Format-Epoch": "9",
	}); r.StatusCode != http.StatusConflict || b["code"] != "FORMAT_EPOCH_MISMATCH" {
		t.Fatalf("stale formatEpoch = %d %v", r.StatusCode, b)
	}

	// 低于最低要求的协议版本 → 426 UPGRADE_REQUIRED（不管仓库处于什么状态）
	if r, b := e.uploadAs(t, "d1", "d.md", 0, []byte("d"), map[string]string{
		"X-LiteSync-Protocol": "5",
	}); r.StatusCode != http.StatusUpgradeRequired || b["code"] != "UPGRADE_REQUIRED" {
		t.Fatalf("protocol v5 write = %d %v, want 426 UPGRADE_REQUIRED", r.StatusCode, b)
	}

	// keyEpoch 不符 → 409 KEY_EPOCH_MISMATCH（仓库 keyEpoch 为 0 时不校验）
	e.postE2ee(t, "begin") // keyEpoch 0 → 1
	if r, b := e.uploadAs(t, "d1", "e.md", 0, lse3Payload(1, 1, "e"), map[string]string{
		"X-Key-Epoch": "7",
	}); r.StatusCode != http.StatusConflict || b["code"] != "KEY_EPOCH_MISMATCH" {
		t.Fatalf("stale keyEpoch = %d %v, want 409 KEY_EPOCH_MISMATCH", r.StatusCode, b)
	}
	// 正确的 keyEpoch 放行
	if r, _ := e.uploadAs(t, "d1", "e.md", 0, lse3Payload(1, 1, "e"), map[string]string{
		"X-Key-Epoch": "1",
	}); r.StatusCode != http.StatusOK {
		t.Fatalf("matching keyEpoch = %d, want 200", r.StatusCode)
	}

	// 非法格式的 X-Repo-Epoch 按「未携带」处理，不进入比较逻辑
	if r, _ := e.uploadAs(t, "d1", "f.md", 0, lse3Payload(1, 1, "f"), map[string]string{
		"X-Repo-Epoch": "not-a-hex-epoch", "X-Key-Epoch": "1",
	}); r.StatusCode != http.StatusOK {
		t.Fatalf("malformed repoEpoch header = %d, want 200 (treated as absent)", r.StatusCode)
	}
}

// §5.4：租约续期、显式接管、owner 独占推进权。
func TestMigrationLeaseAndTakeover(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "a.md", 0, lse3Payload(1, 1, "a"))
	e.enterEncryptedRepo(t)

	// owner = d1
	r, st := e.doJSONAs(t, http.MethodPost, "/api/v1/meta/begin", "d1", nil)
	if r.StatusCode != http.StatusOK || st["ownerDeviceId"] != "d1" {
		t.Fatalf("begin = %d %v", r.StatusCode, st)
	}
	migrationID := st["migrationId"].(string)
	lease0 := st["leaseExpiresAt"].(float64)

	// 另一台设备 begin → MIGRATION_LOCKED（同一 Vault 只能有一个迁移）
	if r, b := e.doJSONAs(t, http.MethodPost, "/api/v1/meta/begin", "d2", nil); r.StatusCode != http.StatusConflict ||
		b["code"] != "MIGRATION_LOCKED" {
		t.Fatalf("second device begin = %d %v, want 409 MIGRATION_LOCKED", r.StatusCode, b)
	}

	// 非 owner 推进迁移 → MIGRATION_NOT_OWNER
	if r, b := e.doJSONAs(t, http.MethodPost, "/api/v1/meta/migrate", "d2",
		map[string]any{"fromPath": "a.md", "metaEnc": metaEncA, "canonicalHash": canonA}); r.StatusCode != http.StatusConflict ||
		b["code"] != "MIGRATION_NOT_OWNER" {
		t.Fatalf("non-owner migrate = %d %v, want 409 MIGRATION_NOT_OWNER", r.StatusCode, b)
	}

	// 非 owner 续租 → 同样拒绝
	if r, b := e.doJSONAs(t, http.MethodPost, "/api/v1/meta/renew", "d2", nil); r.StatusCode != http.StatusConflict ||
		b["code"] != "MIGRATION_NOT_OWNER" {
		t.Fatalf("non-owner renew = %d %v", r.StatusCode, b)
	}

	// owner 续租 → 租约延后
	e.setLeaseExpiry(t, 1) // 人为把租约推到过去再续，确保能观察到变化
	r2, st2 := e.doJSONAs(t, http.MethodPost, "/api/v1/meta/renew", "d1", nil)
	if r2.StatusCode != http.StatusOK || st2["leaseExpiresAt"].(float64) <= 1 {
		t.Fatalf("owner renew = %d %v (lease0=%v)", r2.StatusCode, st2, lease0)
	}

	// 租约仍然有效时接管 → 拒绝
	if r, b := e.doJSONAs(t, http.MethodPost, "/api/v1/meta/takeover", "d2",
		map[string]any{"migrationId": migrationID}); r.StatusCode != http.StatusConflict ||
		b["code"] != "MIGRATION_LEASE_ACTIVE" {
		t.Fatalf("takeover with active lease = %d %v, want 409 MIGRATION_LEASE_ACTIVE", r.StatusCode, b)
	}

	// 租约过期后：接管必须**显式**且携带正确的 migrationId
	e.setLeaseExpiry(t, 1)
	if r, b := e.doJSONAs(t, http.MethodPost, "/api/v1/meta/takeover", "d2",
		map[string]any{"migrationId": "wrong-id"}); r.StatusCode != http.StatusConflict ||
		b["code"] != "MIGRATION_MISMATCH" {
		t.Fatalf("takeover with wrong id = %d %v", r.StatusCode, b)
	}
	r3, st3 := e.doJSONAs(t, http.MethodPost, "/api/v1/meta/takeover", "d2",
		map[string]any{"migrationId": migrationID})
	if r3.StatusCode != http.StatusOK || st3["ownerDeviceId"] != "d2" {
		t.Fatalf("explicit takeover = %d %v", r3.StatusCode, st3)
	}
	// migrationId 不变：接管的是同一次迁移，journal 与 cutoff 全部沿用
	if st3["migrationId"] != migrationID || st3["cutoffSequence"] != st["cutoffSequence"] {
		t.Fatalf("takeover must keep the same migration: %v", st3)
	}
	// 幂等：新 owner 再接管一次直接成功
	if r, _ := e.doJSONAs(t, http.MethodPost, "/api/v1/meta/takeover", "d2",
		map[string]any{"migrationId": migrationID}); r.StatusCode != http.StatusOK {
		t.Fatal("takeover by the current owner must be idempotent")
	}
	// 接管后 d2 才能推进
	if r, _ := e.doJSONAs(t, http.MethodPost, "/api/v1/meta/migrate", "d2",
		map[string]any{"fromPath": "a.md", "metaEnc": metaEncA, "canonicalHash": canonA}); r.StatusCode != http.StatusOK {
		t.Fatalf("new owner migrate = %d", r.StatusCode)
	}

	// **owner 失联绝不自动完成**：租约过期只是「可以被接管」，
	// 状态仍停在 migrating，绝不自动推进到 encrypted
	e.setLeaseExpiry(t, 1)
	if info := e.info(t); info["metaState"] != "migrating" {
		t.Fatalf("expired lease must not auto-complete: metaState = %v", info["metaState"])
	}
}

// §5.7：迁移期间旧设备保持在线并尝试写入。
func TestWriteFreezeDuringMigration(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "notes/a.md", 0, lse3Payload(1, 1, "a"))
	e.upload(t, "notes/b.md", 0, lse3Payload(1, 1, "b"))
	e.enterEncryptedRepo(t)
	e.doJSONAs(t, http.MethodPost, "/api/v1/meta/begin", "owner", nil)

	snap := e.snapshotFiles(t)
	idA := snap["notes/a.md"]["fileId"].(string)
	e.doJSONAs(t, http.MethodPost, "/api/v1/meta/migrate", "owner",
		map[string]any{"fromPath": "notes/a.md", "metaEnc": metaEncA, "canonicalHash": canonA})

	// 其他设备写**尚未伪名化**的对象 → 冻结（否则它会把真实路径写回服务器）
	if r, b := e.uploadAs(t, "other", "notes/b.md", 1, lse3Payload(1, 2, "b2"), nil); r.StatusCode != http.StatusConflict ||
		b["code"] != "MIGRATION_LOCKED" {
		t.Fatalf("other device writing an unmigrated object = %d %v, want 409 MIGRATION_LOCKED", r.StatusCode, b)
	}
	// 其他设备写**已伪名化**的对象 → 放行（伪名寻址不泄露任何路径）
	if r, _ := e.uploadAs(t, "other", idA, 1, lse3Payload(1, 2, "a2"), nil); r.StatusCode != http.StatusOK {
		t.Fatalf("other device writing a migrated object = %d, want 200", r.StatusCode)
	}
	// 读取始终放行——旧设备要能看到「需要升级」的提示，而不是彻底黑屏
	if r, _ := e.download(t, "notes/b.md"); r.StatusCode != http.StatusOK {
		t.Fatal("reads must stay available during migration")
	}

	// verifying 态：只有 owner 能写
	e.doJSONAs(t, http.MethodPost, "/api/v1/meta/migrate", "owner",
		map[string]any{"fromPath": "notes/b.md", "metaEnc": metaEncB, "canonicalHash": canonB})
	e.doJSONAs(t, http.MethodPost, "/api/v1/meta/verify", "owner", nil)
	if r, b := e.uploadAs(t, "other", idA, 2, lse3Payload(1, 3, "a3"), nil); r.StatusCode != http.StatusConflict ||
		b["code"] != "MIGRATION_LOCKED" {
		t.Fatalf("non-owner write during verifying = %d %v", r.StatusCode, b)
	}
}

// doJSONAs 以指定设备身份发 JSON 请求（迁移 owner 归属测试用）。
func (e *testEnv) doJSONAs(t *testing.T, method, path, deviceID string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Device-ID", deviceID)
	return e.do(t, req)
}

// setLeaseExpiry 直接改写租约到期时间（模拟 owner 失联；无需真的等 30 分钟）。
func (e *testEnv) setLeaseExpiry(t *testing.T, at int64) {
	t.Helper()
	if _, err := e.db.Exec(`UPDATE repo_state SET migration_lease_expires_at = ? WHERE id = 1`, at); err != nil {
		t.Fatal(err)
	}
}
