package api_test

// v9.3 二期：LSE3 信封的服务端配套——客户端预生成 fileId、
// generation 单调性（服务器读信封头，无需密钥）、E2EE 下 LSE3 HEAD 放行 MOVE、
// 历史版本返回写入时的 fileId。

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

// lse3Payload 构造带指定 keyEpoch/generation 的伪 LSE3 密文。
func lse3Payload(epoch uint32, gen uint64, tail string) []byte {
	out := make([]byte, 0, 16+len(tail))
	out = append(out, 'L', 'S', 'E', '3')
	out = binary.BigEndian.AppendUint32(out, epoch)
	out = binary.BigEndian.AppendUint64(out, gen)
	return append(out, []byte("iv-and-ciphertext-"+tail)...)
}

func (e *testEnv) uploadWithFileID(t *testing.T, path string, baseRevision int64, content []byte, fileID string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytes.NewReader(content))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-File-Path", url.PathEscape(path))
	req.Header.Set("X-Base-Revision", fmt.Sprint(baseRevision))
	req.Header.Set("X-Content-Hash", sha256Hex(content))
	if fileID != "" {
		req.Header.Set("X-File-Id", fileID)
	}
	return e.do(t, req)
}

// 客户端预生成 fileId：新文件采用；已存在文件忽略；占用/非法 → 400。
func TestClientProvidedFileID(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	const myID = "aabbccdd00112233aabbccdd00112233"

	resp, body := e.uploadWithFileID(t, "a.md", 0, []byte("a"), myID)
	if resp.StatusCode != http.StatusOK || body["fileId"] != myID {
		t.Fatalf("upload with client fileId = %d %v", resp.StatusCode, body["fileId"])
	}
	// 已存在文件：客户端再传别的 id 被忽略，身份不变
	resp2, body2 := e.uploadWithFileID(t, "a.md", 1, []byte("a2"), "ffffccdd00112233aabbccdd00112233")
	if resp2.StatusCode != http.StatusOK || body2["fileId"] != myID {
		t.Fatalf("existing file must keep fileId: %v", body2["fileId"])
	}
	// 其他新文件占用同一 id → 400
	if r, _ := e.uploadWithFileID(t, "b.md", 0, []byte("b"), myID); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicate fileId = %d, want 400", r.StatusCode)
	}
	// 非法格式 → 400
	if r, _ := e.uploadWithFileID(t, "c.md", 0, []byte("c"), "not-hex"); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid fileId = %d, want 400", r.StatusCode)
	}
}

// generation 单调性：同一 HEAD 上 gen 不增 → 409（客户端会重拉 HEAD 对齐）。
func TestLse3GenerationMonotonic(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "n.md", 0, lse3Payload(1, 2, "g2"))

	// gen 2 → gen 2：拒绝（回退/重复）
	if r, _ := e.upload(t, "n.md", 1, lse3Payload(1, 2, "g2-again")); r.StatusCode != http.StatusConflict {
		t.Fatalf("same generation = %d, want 409", r.StatusCode)
	}
	// gen 2 → gen 1：拒绝（回退重放）
	if r, _ := e.upload(t, "n.md", 1, lse3Payload(1, 1, "g1")); r.StatusCode != http.StatusConflict {
		t.Fatalf("generation rollback = %d, want 409", r.StatusCode)
	}
	// gen 3：放行
	if r, _ := e.upload(t, "n.md", 1, lse3Payload(1, 3, "g3")); r.StatusCode != http.StatusOK {
		t.Fatalf("next generation = %d, want 200", r.StatusCode)
	}
	// 非 LSE3 覆盖 LSE3（如明文模式下的回退）：单调性检查不拦（磁盘态兼容）
	if r, _ := e.upload(t, "n.md", 2, []byte("plaintext again")); r.StatusCode != http.StatusOK {
		t.Fatalf("non-LSE3 over LSE3 in plaintext state = %d, want 200", r.StatusCode)
	}
}

// E2EE 下 MOVE：LSE3 HEAD（fileId-AAD，路径不入 AAD）放行；LSE2 HEAD 拒绝。
func TestMoveUnderE2ee(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "v3.md", 0, lse3Payload(1, 1, "v3"))
	lse2 := append([]byte("LSE2"), []byte("\x00\x00\x00\x01iv-ct-v2")...)
	e.upload(t, "v2.md", 0, lse2)

	if r, _ := e.postE2ee(t, "begin"); r.StatusCode != http.StatusOK {
		t.Fatal("begin failed")
	}
	if r, _ := e.postE2ee(t, "complete"); r.StatusCode != http.StatusOK {
		t.Fatal("complete failed (all heads are LSE ciphertext)")
	}

	// LSE3 HEAD → 放行，fileId 跟随
	before := e.snapshotFiles(t)
	v3ID := before["v3.md"]["fileId"].(string)
	if r, _ := e.move(t, "v3.md", "moved.md", 1); r.StatusCode != http.StatusOK {
		t.Fatalf("move LSE3 under e2ee = %d, want 200", r.StatusCode)
	}
	after := e.snapshotFiles(t)
	if after["moved.md"]["fileId"] != v3ID {
		t.Fatal("fileId must follow content across e2ee move")
	}

	// LSE2 HEAD（AAD 绑路径）→ 拒绝
	if r, _ := e.move(t, "v2.md", "nope.md", 1); r.StatusCode != http.StatusConflict {
		t.Fatalf("move LSE2 under e2ee = %d, want 409", r.StatusCode)
	}
}

// 历史版本下载返回写入时的 fileId（LSE3 历史解密需要）。
func TestVersionFileIDHeader(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	_, body := e.upload(t, "h.md", 0, []byte("v1"))
	fileID := body["fileId"].(string)
	e.upload(t, "h.md", 1, []byte("v2"))

	vresp, _ := e.version(t, "h.md", 1)
	if vresp.StatusCode != http.StatusOK || vresp.Header.Get("X-File-Id") != fileID {
		t.Fatalf("version fileId header = %q, want %q", vresp.Header.Get("X-File-Id"), fileID)
	}
}
