package api_test

// 带新内容的原子恢复（v0.20.1 / W4）与路径加密仓库的回收站（W5）。
// 覆盖 INV-05（恢复不重置身份）、INV-06（删除事实保留到恢复那一刻）、INV-07（信封不降级）、INV-12（租户隔离）。
//
// W4 的原问题：两阶段恢复的第二步失败时，服务器上留下「HEAD 声明新世代、密文仍是删除前的旧世代」
// 的对象。这里断言新协议下这个中间态根本不存在：任何失败都不改变服务器状态（墓碑原样还在），
// 成功时 HEAD 的 X-Content-Generation 与信封里的世代一致。

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/failpoint"
)

func upsertReader(e *testEnv, userID string) error {
	return db.UpsertMembership(e.db, &db.Membership{UserID: userID, VaultID: db.DefaultVaultID, Role: db.RoleReader})
}

func (e *testEnv) restoreContent(t *testing.T, fileID string, hdr map[string]string, body []byte) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/files/"+fileID+"/restore", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Content-Hash", sha256Hex(body))
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	return e.do(t, req)
}

func restoreHeaders(path string, tombRev, tombGen int64, opID string) map[string]string {
	return map[string]string{
		"X-File-Path":                     url.PathEscape(path),
		"X-Expected-Tombstone-Revision":   fmt.Sprint(tombRev),
		"X-Expected-Tombstone-Generation": fmt.Sprint(tombGen),
		"X-Operation-Id":                  opID,
	}
}

func (e *testEnv) trashItems(t *testing.T) []map[string]any {
	t.Helper()
	_, body := e.doJSON(t, http.MethodGet, "/api/v1/trash", testToken, nil)
	raw, _ := body["items"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, it := range raw {
		out = append(out, it.(map[string]any))
	}
	return out
}

// envelopeGen 读 LSE3/LSE4 信封头里的世代（与服务器、插件同一套布局）。
func envelopeGen(b []byte) int64 {
	switch {
	case len(b) >= 16 && string(b[:4]) == "LSE3":
		return int64(binary.BigEndian.Uint64(b[8:16]))
	case len(b) >= 17 && string(b[:4]) == "LSE4":
		return int64(binary.BigEndian.Uint64(b[9:17]))
	}
	return -1
}

// lsm1 造一份头部合法的 LSM1（服务器只读头部的 keyEpoch / metaGeneration，内容 opaque）。
func lsm1(keyEpoch uint32, metaGen uint64, tail string) string {
	out := []byte("LSM1")
	out = binary.BigEndian.AppendUint32(out, keyEpoch)
	out = binary.BigEndian.AppendUint64(out, metaGen)
	out = append(out, []byte("iv-and-ciphertext-"+tail)...)
	return base64.StdEncoding.EncodeToString(out)
}

// 原子恢复全流程：回收站给出删除前内容所在的版本 → 按 fileId 取回 → 新世代一次提交 →
// HEAD 与信封世代一致、revision 只前进 1、历史与变更各一条；同 operationId 重试拿回首次结果。
func TestRestoreWithContentAtomic(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "回收/a.md", 0, lse3Payload(1, 1, "v1"))
	_, up2 := e.upload(t, "回收/a.md", 1, lse3Payload(1, 2, "v2"))
	fileID := up2["fileId"].(string)
	_, del := e.delete(t, "回收/a.md", 2)
	tombRev := int64(del["revision"].(float64))

	items := e.trashItems(t)
	if len(items) != 1 || items[0]["fileId"] != fileID || items[0]["restorable"] != true ||
		items[0]["priorRevision"].(float64) != 2 || items[0]["priorGeneration"].(float64) != 2 || items[0]["contentGeneration"].(float64) != 2 {
		t.Fatalf("trash item = %v", items)
	}
	if _, ok := items[0]["metaEnc"]; ok {
		t.Fatalf("plaintext-path vault must not report metaEnc: %v", items[0])
	}

	// 按 fileId 取回删除前的内容（明文模式下原路径可能已被别的对象占用）
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/version?fileId="+fileID+"&revision=2", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	vr, _ := e.do(t, req)
	if vr.StatusCode != http.StatusOK || vr.Header.Get("X-File-Id") != fileID || vr.Header.Get("X-Content-Generation") != "2" {
		t.Fatalf("version by fileId = %d %v", vr.StatusCode, vr.Header)
	}

	newBody := lse3Payload(1, 3, "restored")
	r, body := e.restoreContent(t, fileID, restoreHeaders("回收/a.md", tombRev, 2, "op-restore-1"), newBody)
	if r.StatusCode != http.StatusOK || body["fileId"] != fileID || int64(body["revision"].(float64)) != tombRev+1 ||
		body["contentGeneration"].(float64) != 3 || body["replayed"] != false {
		t.Fatalf("restore with content = %d %v", r.StatusCode, body)
	}
	if len(e.trashItems(t)) != 0 {
		t.Fatal("restored object must leave the trash")
	}
	dr, raw := e.download(t, "回收/a.md")
	if dr.StatusCode != http.StatusOK || !bytes.Equal(raw, newBody) ||
		dr.Header.Get("X-Content-Generation") != "3" || envelopeGen(raw) != 3 || dr.Header.Get("X-Revision") != fmt.Sprint(tombRev+1) {
		t.Fatalf("HEAD after atomic restore: %d gen=%s env=%d rev=%s", dr.StatusCode, dr.Header.Get("X-Content-Generation"), envelopeGen(raw), dr.Header.Get("X-Revision"))
	}
	_, hist := e.history(t, "回收/a.md")
	versions := hist["versions"].([]any)
	if top := versions[0].(map[string]any); top["action"] != "restore" || top["hash"] != sha256Hex(newBody) {
		t.Fatalf("history head = %v", top)
	}
	_, ch := e.changes(t, "?since=0")
	list := ch["changes"].([]any)
	last := list[len(list)-1].(map[string]any)
	if last["action"] != "restore" || last["contentGeneration"].(float64) != 3 {
		t.Fatalf("change feed must carry one restore change with the new content: %v", last)
	}

	// 响应丢失后的重试：同一 operationId → 首次结果，不产生第二个 revision
	r2, body2 := e.restoreContent(t, fileID, restoreHeaders("回收/a.md", tombRev, 2, "op-restore-1"), newBody)
	if r2.StatusCode != http.StatusOK || body2["replayed"] != true || int64(body2["revision"].(float64)) != tombRev+1 {
		t.Fatalf("replay = %d %v", r2.StatusCode, body2)
	}
	if _, h2 := e.history(t, "回收/a.md"); len(h2["versions"].([]any)) != len(versions) {
		t.Fatal("replay must not add history")
	}
	// 另一个 operationId：对象已经 live → 冲突（这次的内容没有写进去，不能报成功）
	r3, b3 := e.restoreContent(t, fileID, restoreHeaders("回收/a.md", tombRev, 2, "op-restore-2"), lse3Payload(1, 4, "late"))
	if r3.StatusCode != http.StatusConflict || b3["code"] != "CONFLICT" || b3["deleted"] == true {
		t.Fatalf("restore of a live object = %d %v, want 409 CONFLICT (not deleted)", r3.StatusCode, b3)
	}
}

// 任何拒绝都不改变服务器状态：墓碑原样还在、HEAD 不存在——不会出现「旧密文 + 新世代」。
func TestRestoreWithContentRejectsWithoutSideEffects(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	_, up := e.upload(t, "拒绝/a.md", 0, lse3Payload(1, 2, "v"))
	fileID := up["fileId"].(string)
	_, del := e.delete(t, "拒绝/a.md", 1)
	tombRev := int64(del["revision"].(float64))

	cases := []struct {
		name string
		hdr  map[string]string
		body []byte
		code int
		err  string
	}{
		{"世代没有前进", restoreHeaders("拒绝/a.md", tombRev, 2, "op-a"), lse3Payload(1, 2, "same"), http.StatusConflict, "CONFLICT"},
		{"期望的墓碑 revision 过期", restoreHeaders("拒绝/a.md", tombRev-1, 2, "op-b"), lse3Payload(1, 3, "x"), http.StatusPreconditionFailed, "STALE_REVISION"},
		{"期望的墓碑世代不符", restoreHeaders("拒绝/a.md", tombRev, 1, "op-c"), lse3Payload(1, 3, "x"), http.StatusPreconditionFailed, "STALE_REVISION"},
		{"没有 operationId", restoreHeaders("拒绝/a.md", tombRev, 2, ""), lse3Payload(1, 3, "x"), http.StatusBadRequest, "INVALID_HEADER"},
		{"信封降级（LSE3 → 明文）", restoreHeaders("拒绝/a.md", tombRev, 2, "op-d"), []byte("plaintext"), http.StatusConflict, ""},
	}
	for _, c := range cases {
		r, b := e.restoreContent(t, fileID, c.hdr, c.body)
		if r.StatusCode != c.code || (c.err != "" && b["code"] != c.err) {
			t.Fatalf("%s = %d %v, want %d %s", c.name, r.StatusCode, b, c.code, c.err)
		}
	}
	// 内容 hash 与声明不符
	hdr := restoreHeaders("拒绝/a.md", tombRev, 2, "op-e")
	hdr["X-Content-Hash"] = strings.Repeat("0", 64)
	if r, b := e.restoreContent(t, fileID, hdr, lse3Payload(1, 3, "x")); r.StatusCode != http.StatusBadRequest || b["code"] != "HASH_MISMATCH" {
		t.Fatalf("hash mismatch = %d %v", r.StatusCode, b)
	}
	items := e.trashItems(t)
	if len(items) != 1 || int64(items[0]["deletionRevision"].(float64)) != tombRev || items[0]["contentGeneration"].(float64) != 2 {
		t.Fatalf("rejected restores must leave the tombstone untouched: %v", items)
	}
	if dr, _ := e.download(t, "拒绝/a.md"); dr.StatusCode != http.StatusNotFound {
		t.Fatalf("no HEAD may exist after rejected restores: %d", dr.StatusCode)
	}
}

// 提交前崩溃 → 什么都没发生；提交后、响应前崩溃 → 已生效，同一 operationId 重试拿回首次结果。
func TestRestoreWithContentCrashPoints(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	_, up := e.upload(t, "崩溃/a.md", 0, lse3Payload(1, 1, "v"))
	fileID := up["fileId"].(string)
	_, del := e.delete(t, "崩溃/a.md", 1)
	tombRev := int64(del["revision"].(float64))
	body := lse3Payload(1, 2, "restored")

	cancel := failpoint.EnableError(failpoint.DBBeforeCommit, 1)
	r, _ := e.restoreContent(t, fileID, restoreHeaders("崩溃/a.md", tombRev, 1, "op-crash"), body)
	cancel()
	if r.StatusCode < 500 {
		t.Fatalf("crash before commit should surface as 5xx, got %d", r.StatusCode)
	}
	if len(e.trashItems(t)) != 1 {
		t.Fatal("crash before commit must leave the tombstone in place")
	}
	cancel = failpoint.EnableError(failpoint.DBAfterCommit, 1)
	r, _ = e.restoreContent(t, fileID, restoreHeaders("崩溃/a.md", tombRev, 1, "op-crash"), body)
	cancel()
	if r.StatusCode < 500 {
		t.Fatalf("crash after commit should surface as 5xx, got %d", r.StatusCode)
	}
	r, b := e.restoreContent(t, fileID, restoreHeaders("崩溃/a.md", tombRev, 1, "op-crash"), body)
	if r.StatusCode != http.StatusOK || b["replayed"] != true || int64(b["revision"].(float64)) != tombRev+1 {
		t.Fatalf("retry after a lost response = %d %v", r.StatusCode, b)
	}
}

// 配额：恢复写入的是一份新密文，与普通上传同一条规则；超限时墓碑不动，放开后同样的请求成功。
func TestRestoreWithContentQuota(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	_, up := e.upload(t, "配额/a.md", 0, lse3Payload(1, 1, "v"))
	fileID := up["fileId"].(string)
	_, del := e.delete(t, "配额/a.md", 1)
	tombRev := int64(del["revision"].(float64))
	_, me := e.doJSON(t, http.MethodGet, "/api/v2/me", testToken, nil)
	used := me["usage"].(map[string]any)["bytesUsed"].(float64)
	if r, _ := e.doJSON(t, http.MethodPut, "/api/v1/admin/users/default/quota", testToken, map[string]any{"bytes": used + 10, "vaults": 0}); r.StatusCode != http.StatusOK {
		t.Fatal("set quota")
	}
	big := lse3Payload(1, 2, strings.Repeat("x", 4096))
	r, b := e.restoreContent(t, fileID, restoreHeaders("配额/a.md", tombRev, 1, "op-q"), big)
	if r.StatusCode != http.StatusRequestEntityTooLarge || b["code"] != "QUOTA_EXCEEDED" || b["retryable"] != false {
		t.Fatalf("restore over quota = %d %v", r.StatusCode, b)
	}
	if len(e.trashItems(t)) != 1 {
		t.Fatal("quota rejection must leave the tombstone in place")
	}
	e.doJSON(t, http.MethodPut, "/api/v1/admin/users/default/quota", testToken, map[string]any{"bytes": -1, "vaults": 0})
	if r, b := e.restoreContent(t, fileID, restoreHeaders("配额/a.md", tombRev, 1, "op-q"), big); r.StatusCode != http.StatusOK {
		t.Fatalf("restore after lifting quota = %d %v", r.StatusCode, b)
	}
}

// 明文模式：原位置已被新对象占用 → 422 CANONICAL_COLLISION；换一个名字恢复，身份与历史不变。
func TestRestoreWithContentToAnotherPath(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	_, up := e.upload(t, "重名/a.md", 0, lse3Payload(1, 1, "old"))
	oldID := up["fileId"].(string)
	_, del := e.delete(t, "重名/a.md", 1)
	tombRev := int64(del["revision"].(float64))
	// 删除后，同名（大小写归一后同名）的另一个对象占了原位置
	e.restoreBlocker(t, "重名/A.md")
	// 原路径已被别的对象占用时，按 fileId 仍能取回删除前的内容版本（按路径会解析到占位的那个对象）
	vreq, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/version?fileId="+oldID+"&revision=1", nil)
	vreq.Header.Set("Authorization", "Bearer "+testToken)
	if vr, _ := e.do(t, vreq); vr.StatusCode != http.StatusOK || vr.Header.Get("X-File-Id") != oldID {
		t.Fatalf("version by fileId while the name is occupied = %d %s", vr.StatusCode, vr.Header.Get("X-File-Id"))
	}
	r, b := e.restoreContent(t, oldID, restoreHeaders("重名/a.md", tombRev, 1, "op-1"), lse3Payload(1, 2, "back"))
	if r.StatusCode != http.StatusUnprocessableEntity || b["code"] != "CANONICAL_COLLISION" {
		t.Fatalf("restore onto an occupied canonical name = %d %v, want 422", r.StatusCode, b)
	}
	r, b = e.restoreContent(t, oldID, restoreHeaders("重名/a（恢复）.md", tombRev, 1, "op-2"), lse3Payload(1, 2, "back"))
	if r.StatusCode != http.StatusOK || b["fileId"] != oldID || b["path"] != "重名/a（恢复）.md" {
		t.Fatalf("restore under another name = %d %v", r.StatusCode, b)
	}
	if _, h := e.history(t, "重名/a（恢复）.md"); len(h["versions"].([]any)) != 3 {
		t.Fatalf("history continues on the restored object: %v", h["versions"])
	}
}

func (e *testEnv) restoreBlocker(t *testing.T, path string) {
	t.Helper()
	// 普通新建撞上墓碑会被防复活拦下（409 deleted）——用不同大小写的名字建，模拟「别的对象占了原位置」
	r, b := e.upload(t, path, 0, lse3Payload(1, 1, "blocker"))
	if r.StatusCode == http.StatusConflict && b["deleted"] == true {
		// 墓碑按 canonical 键拦住了同名新建：这正是 ADR-002 的防复活。改用改名把一个已有对象挪过去
		e.upload(t, "重名/占位.md", 0, lse3Payload(1, 1, "blocker"))
		if rr, rb := e.rename(t, "重名/占位.md", path, 0); rr.StatusCode != http.StatusOK {
			t.Fatalf("rename blocker onto the tombstoned name = %d %v", rr.StatusCode, rb)
		}
		return
	}
	if r.StatusCode != http.StatusOK {
		t.Fatalf("blocker upload = %d %v", r.StatusCode, b)
	}
}

// 历史清理后（删除前的内容版本已不在）：回收站如实报告不可恢复，不提供恢复入口。
func TestTrashReportsPurgedHistoryAsUnrestorable(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "清理/a.md", 0, lse3Payload(1, 1, "v1"))
	_, up := e.upload(t, "清理/a.md", 1, lse3Payload(1, 2, "v2"))
	fileID := up["fileId"].(string)
	e.delete(t, "清理/a.md", 2)
	// 直接删掉内容版本行（等价于保留策略 / 字节预算把它裁掉）
	if _, err := e.db.Exec(`DELETE FROM object_versions WHERE file_id = ? AND action != 'delete'`, fileID); err != nil {
		t.Fatal(err)
	}
	items := e.trashItems(t)
	if len(items) != 1 || items[0]["restorable"] != false {
		t.Fatalf("trash after history purge = %v, want restorable=false", items)
	}
	if _, ok := items[0]["priorRevision"]; ok {
		t.Fatalf("no prior revision may be advertised after purge: %v", items[0])
	}
}

// 路径加密仓库（W5）：墓碑保留删除前最后一份 LSM1——改名后删除留下的是改名后的那份；
// 回收站返回它；带新内容的恢复要求 LSM1 头部世代 = 墓碑世代 + 1（与服务器记账一致），
// 恢复后 HEAD 的加密元数据就是客户端新给的那份；服务器从头到尾没见过明文路径。
func TestMetaTrashKeepsEncryptedMetadata(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.enterEncryptedRepo(t)
	if r, _ := e.postMeta(t, "begin", nil); r.StatusCode != http.StatusOK {
		t.Fatal("meta begin")
	}
	if r, b := e.postMeta(t, "verify", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("meta verify = %d %v", r.StatusCode, b)
	}
	if r, b := e.postMeta(t, "complete", map[string]any{"confirmErase": true}); r.StatusCode != http.StatusOK || b["metaState"] != "encrypted" {
		t.Fatalf("meta complete = %d %v", r.StatusCode, b)
	}
	fe := int64(e.formatEpoch(t))
	ke := uint32(e.info(t)["keyEpoch"].(float64))
	fileID := strings.Repeat("ab", 16)
	created := lsm1(ke, 1, "path-v1")
	if r, b := e.uploadWithMeta(t, fileID, 0, lse3Payload(0, 1, "c"), fileID, created, canonHex("a1")); r.StatusCode != http.StatusOK {
		t.Fatalf("meta create = %d %v", r.StatusCode, b)
	}
	// 改名：LSM1 世代 2
	renamed := lsm1(ke, 2, "path-v2-renamed")
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/file/rename", strings.NewReader(fmt.Sprintf(
		`{"fromPath":%q,"toPath":%q,"baseMetaGeneration":1,"metaEnc":%q,"canonicalHash":%q}`, fileID, fileID, renamed, canonHex("a2"))))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Format-Epoch", fmt.Sprint(fe))
	rr, rb := e.do(t, req)
	if rr.StatusCode != http.StatusOK {
		t.Fatalf("meta rename = %d %v", rr.StatusCode, rb)
	}
	dreq, _ := http.NewRequest(http.MethodDelete, e.ts.URL+"/api/v1/file", strings.NewReader(fmt.Sprintf(`{"path":%q,"baseRevision":%d}`, fileID, int64(rb["revision"].(float64)))))
	dreq.Header.Set("Authorization", "Bearer "+testToken)
	dreq.Header.Set("Content-Type", "application/json")
	dreq.Header.Set("X-Format-Epoch", fmt.Sprint(fe))
	r, db := e.do(t, dreq)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("meta delete = %d %v", r.StatusCode, db)
	}
	tombRev := int64(db["revision"].(float64))
	items := e.trashItems(t)
	if len(items) != 1 || items[0]["metaEnc"] != renamed || items[0]["path"] != fileID || items[0]["metaGeneration"].(float64) != 2 {
		t.Fatalf("meta trash item must carry the renamed LSM1 and only the pseudonym: %v", items)
	}

	hdr := restoreHeaders(fileID, tombRev, 1, "op-meta-1")
	hdr["X-Format-Epoch"] = fmt.Sprint(fe)
	hdr["X-Canonical-Hash"] = canonHex("a3")
	// 没带 LSM1 → 400 META_REQUIRED；LSM1 世代不是墓碑 + 1 → 同样拒绝（HEAD 与 LSM1 世代不能对不上）
	if r, b := e.restoreContent(t, fileID, hdr, lse3Payload(0, 2, "back")); r.StatusCode != http.StatusBadRequest || b["code"] != "META_REQUIRED" {
		t.Fatalf("meta restore without LSM1 = %d %v", r.StatusCode, b)
	}
	hdr["X-Meta-Enc"] = lsm1(ke, 2, "stale-gen")
	if r, b := e.restoreContent(t, fileID, hdr, lse3Payload(0, 2, "back")); r.StatusCode != http.StatusBadRequest || b["code"] != "META_REQUIRED" {
		t.Fatalf("meta restore with a stale LSM1 generation = %d %v", r.StatusCode, b)
	}
	// 伪名必须等于 fileId
	bad := restoreHeaders("真实/路径.md", tombRev, 1, "op-meta-x")
	bad["X-Format-Epoch"] = fmt.Sprint(fe)
	bad["X-Meta-Enc"], bad["X-Canonical-Hash"] = lsm1(ke, 3, "p"), canonHex("a3")
	if r, b := e.restoreContent(t, fileID, bad, lse3Payload(0, 2, "back")); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("meta restore with a plaintext pseudonym = %d %v", r.StatusCode, b)
	}
	// LSM1 的密钥世代必须是仓库当前世代
	hdr["X-Meta-Enc"] = lsm1(ke+7, 3, "wrong-epoch")
	if r, b := e.restoreContent(t, fileID, hdr, lse3Payload(0, 2, "back")); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("meta restore with a foreign key epoch = %d %v", r.StatusCode, b)
	}
	restored := lsm1(ke, 3, "path-v3-restored")
	hdr["X-Meta-Enc"] = restored
	r, b := e.restoreContent(t, fileID, hdr, lse3Payload(0, 2, "back"))
	if r.StatusCode != http.StatusOK || b["metaGeneration"].(float64) != 3 || b["path"] != fileID {
		t.Fatalf("meta restore = %d %v", r.StatusCode, b)
	}
	final := e.snapshotFiles(t)
	if final[fileID]["metaEnc"] != restored || final[fileID]["metaGeneration"].(float64) != 3 {
		t.Fatalf("restored HEAD must carry the client's new LSM1: %v", final[fileID])
	}
}

// 网页会话的闸门（ADR-015）：带新内容的恢复属于内容写入——默认关闭；开启后只读成员拒绝、
// 跨站 Origin 拒绝；/api/v1/info 的 access 让网页在只读成员打开时就隐藏编辑入口（RC-1），
// 设备凭据的 info 响应与 0.20.0 相同（不多出 access）。
func TestWebSessionRestoreWithContentGateAndAccess(t *testing.T) {
	for _, editing := range []bool{false, true} {
		e := newWebEditEnv(t, editing)
		_, up := e.upload(t, "闸门/a.md", 0, lse3Payload(1, 1, "v"))
		fileID := up["fileId"].(string)
		_, del := e.delete(t, "闸门/a.md", 1)
		tombRev := int64(del["revision"].(float64))
		c := tokenSession(t, e, testToken)
		put := func(c *http.Client, origin, vault, op string) int {
			body := lse3Payload(1, 2, "web")
			req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/files/"+fileID+"/restore", bytes.NewReader(body))
			for k, v := range restoreHeaders("闸门/a.md", tombRev, 1, op) {
				req.Header.Set(k, v)
			}
			req.Header.Set("X-Content-Hash", sha256Hex(body))
			if origin != "" {
				req.Header.Set("Origin", origin)
			}
			if vault != "" {
				req.Header.Set("X-Vault-ID", vault)
			}
			res, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			return res.StatusCode
		}
		if !editing {
			if code := put(c, e.ts.URL, "", "op-off"); code != http.StatusForbidden {
				t.Fatalf("web restore with editing disabled = %d, want 403", code)
			}
			continue
		}
		if code := put(c, "https://evil.example", "", "op-x"); code != http.StatusForbidden {
			t.Fatalf("cross-origin web restore = %d, want 403", code)
		}
		readerToken, resp, _ := registerUser(t, e, adminCreateInvite(t, e), "reader")
		if resp.StatusCode != http.StatusOK {
			t.Fatal("register reader")
		}
		u, _ := e.svc.AuthUserByToken(readerToken)
		if err := upsertReader(e, u.UserID); err != nil {
			t.Fatal(err)
		}
		rc := tokenSession(t, e, readerToken)
		if code := put(rc, e.ts.URL, "default", "op-r"); code != http.StatusForbidden {
			t.Fatalf("read-only member web restore = %d, want 403", code)
		}
		// info.access：读者看到 canWrite=false（网页据此隐藏编辑 / 新建）；所有者 true
		infoOf := func(c *http.Client, vault string) map[string]any {
			req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/info", nil)
			if vault != "" {
				req.Header.Set("X-Vault-ID", vault)
			}
			res, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			var m map[string]any
			_ = json.NewDecoder(res.Body).Decode(&m)
			return m
		}
		if a, _ := infoOf(rc, "default")["access"].(map[string]any); a == nil || a["role"] != "reader" || a["canWrite"] != false {
			t.Fatalf("reader info.access = %v", a)
		}
		if a, _ := infoOf(c, "")["access"].(map[string]any); a == nil || a["canWrite"] != true {
			t.Fatalf("owner info.access = %v", a)
		}
		devToken, _ := e.enrollDevice(t, "plain-device")
		if _, body := e.doJSON(t, http.MethodGet, "/api/v1/info", devToken, nil); body["access"] != nil {
			t.Fatalf("device info must stay exactly as before (no access field): %v", body["access"])
		}
		if code := put(c, e.ts.URL, "", "op-ok"); code != http.StatusOK {
			t.Fatalf("same-origin owner web restore = %d, want 200", code)
		}
	}
}
