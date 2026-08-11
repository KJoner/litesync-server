package api_test

// v9.3 原子 MOVE 测试：生命周期、file_id 继承与唯一性、changes 连续性、
// 各类拒绝路径（revision 不符 / 目标占用 / 碰撞 / E2EE / 保留名）。

import (
	"net/http"
	"testing"
)

func (e *testEnv) move(t *testing.T, from, to string, baseRevision int64) (*http.Response, map[string]any) {
	t.Helper()
	return e.doJSON(t, http.MethodPost, "/api/v1/file/move", testToken,
		map[string]any{"fromPath": from, "toPath": to, "baseRevision": baseRevision})
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

func TestMoveLifecycle(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	content := []byte("movable content")
	e.upload(t, "Notes/old.md", 0, content)

	before := e.snapshotFiles(t)
	fileID := before["Notes/old.md"]["fileId"].(string)
	if len(fileID) != 32 {
		t.Fatalf("fileId = %q", fileID)
	}

	// 原子改名
	resp, body := e.move(t, "Notes/old.md", "Notes/new.md", 1)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("move = %d %v", resp.StatusCode, body)
	}
	if body["revision"].(float64) != 1 || body["tombstoneRevision"].(float64) != 2 {
		t.Fatalf("move revisions = %v", body)
	}

	// 新路径可下载且内容一致；旧路径 404 + deleted 标记
	dresp, data := e.download(t, "Notes/new.md")
	if dresp.StatusCode != http.StatusOK || string(data) != string(content) {
		t.Fatalf("download new = %d %q", dresp.StatusCode, data)
	}
	if dresp.Header.Get("X-File-Id") != fileID {
		t.Fatalf("file_id must follow content: %q != %q", dresp.Header.Get("X-File-Id"), fileID)
	}
	oresp, _ := e.download(t, "Notes/old.md")
	if oresp.StatusCode != http.StatusNotFound {
		t.Fatalf("download old = %d, want 404", oresp.StatusCode)
	}

	// changes：delete(old) + upsert(new) 两条连续 sequence（同一事务产出）
	_, cbody := e.changes(t, "?since=1")
	list := cbody["changes"].([]any)
	if len(list) != 2 {
		t.Fatalf("changes after move = %d, want 2", len(list))
	}
	first, second := list[0].(map[string]any), list[1].(map[string]any)
	if first["action"] != "delete" || first["path"] != "Notes/old.md" ||
		second["action"] != "upsert" || second["path"] != "Notes/new.md" {
		t.Fatalf("move changes = %v / %v", first, second)
	}
	if second["sequence"].(float64) != first["sequence"].(float64)+1 {
		t.Fatal("move changes must have consecutive sequences")
	}

	// 快照：只剩新路径，fileId 继承
	after := e.snapshotFiles(t)
	if _, ok := after["Notes/old.md"]; ok {
		t.Fatal("old path must be gone from snapshot")
	}
	if after["Notes/new.md"]["fileId"] != fileID {
		t.Fatal("snapshot fileId must be inherited")
	}

	// 旧路径可用墓碑 revision 重建为全新文件（获得新 fileId）
	resp2, _ := e.upload(t, "Notes/old.md", 2, []byte("brand new"))
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("recreate old path = %d", resp2.StatusCode)
	}
	final := e.snapshotFiles(t)
	if final["Notes/old.md"]["fileId"] == fileID {
		t.Fatal("recreated file must get a fresh fileId")
	}
}

func TestMoveRejections(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "a.md", 0, []byte("a"))
	e.upload(t, "b.md", 0, []byte("b"))
	e.upload(t, "c.md", 0, []byte("c"))

	// revision 不符 → 409
	if resp, _ := e.move(t, "a.md", "x.md", 99); resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale move = %d, want 409", resp.StatusCode)
	}
	// 目标已有未删除文件 → 409
	if resp, _ := e.move(t, "a.md", "b.md", 1); resp.StatusCode != http.StatusConflict {
		t.Fatalf("move onto live target = %d, want 409", resp.StatusCode)
	}
	// 与第三个文件大小写碰撞 → 422
	if resp, _ := e.move(t, "a.md", "C.md", 1); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("move canonical collision = %d, want 422", resp.StatusCode)
	}
	// 保留名 / 原地移动 / 不存在 → 400/400/404
	if resp, _ := e.move(t, "a.md", "CON.md", 1); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("move to reserved = %d, want 400", resp.StatusCode)
	}
	if resp, _ := e.move(t, "a.md", "a.md", 1); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("move to self = %d, want 400", resp.StatusCode)
	}
	if resp, _ := e.move(t, "missing.md", "y.md", 1); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("move missing = %d, want 404", resp.StatusCode)
	}

	// 大小写改名（同一文件）→ 允许
	if resp, _ := e.move(t, "a.md", "A.md", 1); resp.StatusCode != http.StatusOK {
		t.Fatalf("case rename = %d, want 200", resp.StatusCode)
	}

	// E2EE migrating：MOVE 拒绝（密文 AAD 绑定路径，服务器移动会产出不可解密内容）
	if resp, _ := e.postE2ee(t, "begin"); resp.StatusCode != http.StatusOK {
		t.Fatal("begin failed")
	}
	if resp, _ := e.move(t, "b.md", "z.md", 1); resp.StatusCode != http.StatusConflict {
		t.Fatalf("move while migrating = %d, want 409", resp.StatusCode)
	}
}
