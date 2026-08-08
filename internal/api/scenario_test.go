package api_test

import (
	"bytes"
	"net/http"
	"testing"
)

// 模拟设备：维护自己的 lastSequence 和文件状态缓存（对应插件的 StateStore）。
type device struct {
	name         string
	lastSequence int64
	files        map[string]deviceFile // path -> 本地已知状态
}

type deviceFile struct {
	revision int64
	hash     string
	content  []byte
}

func newDevice(name string) *device {
	return &device{name: name, files: map[string]deviceFile{}}
}

// pull 拉取并应用远端变更（简化版插件 pull 逻辑：本地未修改则直接采用远端）。
func (d *device) pull(t *testing.T, e *testEnv) {
	t.Helper()
	for {
		_, body := e.changes(t, "?since="+itoa(d.lastSequence))
		changes := body["changes"].([]any)
		for _, item := range changes {
			c := item.(map[string]any)
			path := c["path"].(string)
			seq := int64(c["sequence"].(float64))
			rev := int64(c["revision"].(float64))
			switch c["action"].(string) {
			case "upsert":
				resp, data := e.download(t, path)
				if resp.StatusCode == http.StatusOK {
					d.files[path] = deviceFile{
						revision: rev,
						hash:     resp.Header.Get("X-Content-Hash"),
						content:  data,
					}
				}
			case "delete":
				delete(d.files, path)
			}
			d.lastSequence = seq
		}
		if !body["hasMore"].(bool) {
			if latest := int64(body["latestSequence"].(float64)); latest > d.lastSequence {
				d.lastSequence = latest
			}
			break
		}
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// 场景 1+2+3：A 新建 → B 获得；A 修改 → B 获得；A 删除 → B 删除。
func TestScenarioBasicPropagation(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	a, b := newDevice("A"), newDevice("B")

	// 场景 1：A 新建 hello.md
	content1 := []byte("# hello from A")
	resp, body := e.upload(t, "hello.md", 0, content1)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("A create = %d", resp.StatusCode)
	}
	a.files["hello.md"] = deviceFile{revision: 1, hash: sha256Hex(content1), content: content1}

	b.pull(t, e)
	if got, ok := b.files["hello.md"]; !ok || !bytes.Equal(got.content, content1) {
		t.Fatalf("B did not receive hello.md: %+v", got)
	}

	// 场景 2：A 修改，B 下一次同步后获得
	content2 := []byte("# hello v2")
	resp, body = e.upload(t, "hello.md", a.files["hello.md"].revision, content2)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("A modify = %d %v", resp.StatusCode, body)
	}
	a.files["hello.md"] = deviceFile{revision: 2, hash: sha256Hex(content2), content: content2}

	b.pull(t, e)
	if !bytes.Equal(b.files["hello.md"].content, content2) {
		t.Fatal("B did not receive the modification")
	}

	// 场景 3：A 删除，B 下一次同步后删除
	resp, _ = e.delete(t, "hello.md", 2)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("A delete = %d", resp.StatusCode)
	}
	delete(a.files, "hello.md")

	b.pull(t, e)
	if _, ok := b.files["hello.md"]; ok {
		t.Fatal("B still has hello.md after remote delete")
	}
}

// 场景 4：A 离线修改，B 在线修改同一文件；A 恢复后必须收到 409，不能静默覆盖。
func TestScenarioOfflineConflict(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	a, b := newDevice("A"), newDevice("B")

	base := []byte("shared base")
	e.upload(t, "note.md", 0, base)
	a.pull(t, e)
	b.pull(t, e)

	// B 在线修改（基于 revision 1）→ 服务器 revision 2
	bEdit := []byte("edit from B")
	resp, _ := e.upload(t, "note.md", b.files["note.md"].revision, bEdit)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("B edit = %d", resp.StatusCode)
	}

	// A 离线修改了同一文件，恢复网络后基于旧 revision 1 上传 → 必须 409
	aEdit := []byte("offline edit from A")
	resp, body := e.upload(t, "note.md", a.files["note.md"].revision, aEdit)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("A stale upload = %d, want 409 (must not silently overwrite)", resp.StatusCode)
	}
	// 409 响应携带服务器当前状态，供 A 执行“保留两个版本”
	if body["revision"].(float64) != 2 || body["hash"].(string) != sha256Hex(bEdit) {
		t.Fatalf("conflict body = %v", body)
	}
	// 服务器内容仍是 B 的版本
	_, data := e.download(t, "note.md")
	if !bytes.Equal(data, bEdit) {
		t.Fatal("server content was overwritten by stale upload")
	}

	// A 按插件冲突流程：本地版本另存为 conflict 文件上传，原路径采用服务器版本
	conflictPath := "note.conflict-A-20260808-001500.md"
	resp, _ = e.upload(t, conflictPath, 0, aEdit)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload conflict copy = %d", resp.StatusCode)
	}
	// B 随后能同步到两个文件：note.md（自己的版本）+ conflict 副本（A 的版本）
	b.pull(t, e)
	if !bytes.Equal(b.files["note.md"].content, bEdit) {
		t.Fatal("B lost its own edit")
	}
	if got, ok := b.files[conflictPath]; !ok || !bytes.Equal(got.content, aEdit) {
		t.Fatal("B did not receive the conflict copy — user content was lost")
	}
}

// 场景 7：客户端重复提交同一个 change，服务器结果保持一致。
func TestScenarioDuplicateSubmission(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	content := []byte("dup content")

	e.upload(t, "dup.md", 0, content)
	// 客户端未收到响应后重试：相同内容 + 过期 baseRevision
	resp, body := e.upload(t, "dup.md", 0, content)
	if resp.StatusCode != http.StatusOK || body["revision"].(float64) != 1 {
		t.Fatalf("duplicate submission = %d rev %v, want 200 rev 1", resp.StatusCode, body["revision"])
	}
	// 重复删除
	e.delete(t, "dup.md", 1)
	resp, _ = e.delete(t, "dup.md", 1)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("duplicate delete = %d, want 200", resp.StatusCode)
	}
}
