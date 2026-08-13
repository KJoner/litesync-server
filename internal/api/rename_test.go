package api_test

// 改名测试（协议 v6 / ADR-001 §3.4）。
//
// v5 的 MOVE 是「旧路径 tombstone + 新路径新行」；v6 改名是**一次元数据更新**：
// revision 与 contentGeneration 不动、身份不变、**不产生任何 tombstone**、
// 历史保持一整条。这些正是本文件要锁住的性质。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func (e *testEnv) rename(t *testing.T, from, to string, baseMetaGeneration int64) (*http.Response, map[string]any) {
	t.Helper()
	return e.doJSON(t, http.MethodPost, "/api/v1/file/rename", testToken,
		map[string]any{"fromPath": from, "toPath": to, "baseMetaGeneration": baseMetaGeneration})
}

func (e *testEnv) snapshotFiles(t *testing.T) map[string]map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/snapshot", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	_, body := e.do(t, req)
	out := map[string]map[string]any{}
	for _, f := range body["files"].([]any) {
		m := f.(map[string]any)
		out[m["path"].(string)] = m
	}
	return out
}

// 改名生命周期：身份、revision、历史与 changes 语义。
func TestRenameLifecycle(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	content := []byte("movable content")
	e.upload(t, "Notes/old.md", 0, content)
	e.upload(t, "Notes/old.md", 1, []byte("movable content v2"))

	before := e.snapshotFiles(t)
	fileID := before["Notes/old.md"]["fileId"].(string)
	if len(fileID) != 32 {
		t.Fatalf("fileId = %q", fileID)
	}

	resp, body := e.rename(t, "Notes/old.md", "Notes/new.md", 0)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rename = %d %v", resp.StatusCode, body)
	}
	// 内容没变 → revision 不动；元数据世代 +1
	if body["revision"].(float64) != 2 {
		t.Fatalf("rename must not bump revision: %v", body["revision"])
	}
	if body["metaGeneration"].(float64) != 1 {
		t.Fatalf("metaGeneration = %v, want 1", body["metaGeneration"])
	}
	if body["fileId"] != fileID {
		t.Fatalf("identity must survive rename: %v", body["fileId"])
	}

	// 新名可下载、身份不变；旧名彻底消失（**不是** tombstone）
	dresp, data := e.download(t, "Notes/new.md")
	if dresp.StatusCode != http.StatusOK || string(data) != "movable content v2" {
		t.Fatalf("download new = %d %q", dresp.StatusCode, data)
	}
	if dresp.Header.Get("X-File-Id") != fileID {
		t.Fatalf("file_id must follow content: %q != %q", dresp.Header.Get("X-File-Id"), fileID)
	}
	oresp, oraw := e.download(t, "Notes/old.md")
	if oresp.StatusCode != http.StatusNotFound {
		t.Fatalf("download old = %d, want 404", oresp.StatusCode)
	}
	// 关键回归：改名绝不能留下删除记录，否则旧名字将永远无法再被使用
	var obody map[string]any
	json.Unmarshal(oraw, &obody) //nolint:errcheck
	if obody["deleted"] == true {
		t.Fatal("rename must not create a tombstone (ADR-001 §3.4)")
	}
	if r, _ := e.upload(t, "Notes/old.md", 0, []byte("brand new file at the old name")); r.StatusCode != http.StatusOK {
		t.Fatalf("old name must be reusable after rename = %d", r.StatusCode)
	}

	// 历史保持一整条：改名前的两个 revision 仍然属于同一个对象
	_, hist := e.history(t, "Notes/new.md")
	versions := hist["versions"].([]any)
	if len(versions) != 2 {
		t.Fatalf("history must survive rename intact: %d versions", len(versions))
	}
	for _, v := range versions {
		if v.(map[string]any)["fileId"] != fileID {
			t.Fatalf("history rows must carry the object identity: %v", v)
		}
	}

	// changes 携带 fileId 与 metaGeneration：客户端据此做本地 rename 而不是重新下载
	_, cb := e.changes(t, "?since=0")
	list := cb["changes"].([]any)
	last := list[len(list)-2].(map[string]any) // 最后一条是「旧名新建」，倒数第二条是改名
	if last["fileId"] != fileID || last["metaGeneration"].(float64) != 1 {
		t.Fatalf("rename change = %v", last)
	}
	if last["hash"] != before["Notes/old.md"]["hash"] {
		t.Fatal("rename change must carry the unchanged content hash")
	}
}

// 改名的各类拒绝路径。
func TestRenameRejections(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "a.md", 0, []byte("a"))
	e.upload(t, "b.md", 0, []byte("b"))

	// metaGeneration CAS 不符 → 412
	if r, b := e.rename(t, "a.md", "c.md", 99); r.StatusCode != http.StatusPreconditionFailed ||
		b["code"] != "STALE_META_GENERATION" {
		t.Fatalf("stale rename = %d %v, want 412 STALE_META_GENERATION", r.StatusCode, b)
	}
	// 目标被占用 → 409
	if r, _ := e.rename(t, "a.md", "b.md", 0); r.StatusCode != http.StatusConflict {
		t.Fatalf("rename onto existing = %d, want 409", r.StatusCode)
	}
	// 目标与现有文件归一化后同名 → 422
	if r, b := e.rename(t, "a.md", "B.md", 0); r.StatusCode != http.StatusUnprocessableEntity ||
		b["code"] != "CANONICAL_COLLISION" {
		t.Fatalf("canonical collision = %d %v, want 422", r.StatusCode, b)
	}
	// 源不存在 → 404
	if r, _ := e.rename(t, "missing.md", "x.md", 0); r.StatusCode != http.StatusNotFound {
		t.Fatalf("rename missing = %d, want 404", r.StatusCode)
	}
	// 非法路径 → 400
	if r, _ := e.rename(t, "a.md", "../escape.md", 0); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("rename to invalid path = %d, want 400", r.StatusCode)
	}
	// 纯大小写改名允许（排除自身后不算碰撞）
	if r, _ := e.rename(t, "a.md", "A.md", 0); r.StatusCode != http.StatusOK {
		t.Fatalf("case-only rename = %d, want 200", r.StatusCode)
	}

	// 目标名上有 tombstone → 必须走显式 restore，不允许改名覆盖（INV-06）
	e.upload(t, "gone.md", 0, []byte("gone"))
	e.delete(t, "gone.md", 1)
	if r, b := e.rename(t, "b.md", "gone.md", 0); r.StatusCode != http.StatusConflict || b["deleted"] != true {
		t.Fatalf("rename onto tombstone = %d %v, want 409 deleted", r.StatusCode, b)
	}
}

// 改名的幂等性：同一 operationId 重放不产生第二条变更。
func TestRenameIdempotent(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "x.md", 0, []byte("x"))

	req1 := renameRequest(t, e, "x.md", "y.md", 0, "op-rename-1")
	r1, b1 := e.do(t, req1)
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("rename = %d %v", r1.StatusCode, b1)
	}
	// 重放同一个 operationId：返回首次结果，changes 不增加
	_, before := e.changes(t, "?since=0")
	req2 := renameRequest(t, e, "y.md", "z.md", 1, "op-rename-1")
	r2, b2 := e.do(t, req2)
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("replay = %d %v", r2.StatusCode, b2)
	}
	if b2["sequence"] != b1["sequence"] {
		t.Fatalf("replayed operation must return the original sequence: %v vs %v", b2["sequence"], b1["sequence"])
	}
	_, after := e.changes(t, "?since=0")
	if len(after["changes"].([]any)) != len(before["changes"].([]any)) {
		t.Fatal("replayed operation must not append a change")
	}
	// 对象仍在 y.md（重放没有真的改成 z.md）
	if r, _ := e.download(t, "y.md"); r.StatusCode != http.StatusOK {
		t.Fatal("replay must not move the object")
	}
}

// renameRequest 构造带幂等键的改名请求。
func renameRequest(t *testing.T, e *testEnv, from, to string, baseMetaGeneration int64, opID string) *http.Request {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"fromPath": from, "toPath": to, "baseMetaGeneration": baseMetaGeneration,
	})
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/file/rename", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Operation-Id", opID)
	return req
}

// restore 响应必须返回恢复后的 metaGeneration（0.17.0-rc.3 回归）：
// 客户端要拿它做后续改名的 CAS 基线——不返回的话，恢复后的第一次改名
// 会拿删除前的旧世代（甚至 0）去 CAS，必然 412。
func TestRestoreReturnsMetaGeneration(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "r.md", 0, []byte("v1"))
	// 先改一次名把 metaGeneration 推到 1：暴露「硬编码 0/1」的错误实现
	if r, _ := e.rename(t, "r.md", "r2.md", 0); r.StatusCode != http.StatusOK {
		t.Fatal("rename failed")
	}
	_, delBody := e.delete(t, "r2.md", 1)
	deletedID := delBody["fileId"].(string)
	tombRev := delBody["revision"].(float64)

	r, body := e.restore(t, deletedID, map[string]any{
		"expectedTombstoneRevision": tombRev, "contentGeneration": 1, "pseudonym": "r2.md",
	})
	if r.StatusCode != http.StatusOK {
		t.Fatalf("restore = %d %v", r.StatusCode, body)
	}
	metaGen, ok := body["metaGeneration"].(float64)
	if !ok || metaGen < 2 {
		t.Fatalf("restore response metaGeneration = %v, want >= 2 (tombstone value + 1)", body["metaGeneration"])
	}
	// 以返回值为 CAS 基线的改名必须成功；旧世代必须 412
	if resp, b := e.rename(t, "r2.md", "r3.md", int64(metaGen)); resp.StatusCode != http.StatusOK {
		t.Fatalf("rename with restored metaGeneration = %d %v, want 200", resp.StatusCode, b)
	}
	if resp, _ := e.rename(t, "r3.md", "r4.md", 0); resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("rename with stale metaGeneration = %d, want 412", resp.StatusCode)
	}
}
