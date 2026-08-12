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
	// 其他新文件占用同一 id → 409 FILE_ID_CONFLICT（v0.12.1 / LS-121-S05：
	// 身份被占用是冲突而不是「路径非法」，错误码必须能被客户端机器识别）
	r3, b3 := e.uploadWithFileID(t, "b.md", 0, []byte("b"), myID)
	if r3.StatusCode != http.StatusConflict || b3["code"] != "FILE_ID_CONFLICT" {
		t.Fatalf("duplicate fileId = %d %v, want 409 FILE_ID_CONFLICT", r3.StatusCode, b3)
	}
	// 非法格式 → 400 INVALID_HEADER（Header 层就被拦下，不再进业务）
	r4, b4 := e.uploadWithFileID(t, "c.md", 0, []byte("c"), "not-hex")
	if r4.StatusCode != http.StatusBadRequest || b4["code"] != "INVALID_HEADER" {
		t.Fatalf("invalid fileId = %d %v, want 400 INVALID_HEADER", r4.StatusCode, b4)
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
	// 信封降级冻结（v0.12.1 / LS-121-S01，INV-07）：HEAD 已是 LSE3 时，
	// 明文 / LSE1 / LSE2 覆盖一律 409 ENVELOPE_TOO_OLD——旧客户端、状态丢失
	// 的设备或重放都不能把已升级的对象拉回弱信封
	rp, bp := e.upload(t, "n.md", 2, []byte("plaintext again"))
	if rp.StatusCode != http.StatusConflict || bp["code"] != "ENVELOPE_TOO_OLD" {
		t.Fatalf("plaintext over LSE3 = %d %v, want 409 ENVELOPE_TOO_OLD", rp.StatusCode, bp)
	}
	lse1 := append([]byte("LSE1"), []byte("iv-and-ciphertext-old")...)
	if r, b := e.upload(t, "n.md", 2, lse1); r.StatusCode != http.StatusConflict || b["code"] != "ENVELOPE_TOO_OLD" {
		t.Fatalf("LSE1 over LSE3 = %d %v, want 409 ENVELOPE_TOO_OLD", r.StatusCode, b)
	}
	lse2 := append([]byte("LSE2"), []byte("\x00\x00\x00\x01iv-and-ciphertext-old")...)
	if r, b := e.upload(t, "n.md", 2, lse2); r.StatusCode != http.StatusConflict || b["code"] != "ENVELOPE_TOO_OLD" {
		t.Fatalf("LSE2 over LSE3 = %d %v, want 409 ENVELOPE_TOO_OLD", r.StatusCode, b)
	}
	// 内容未变（同 hash）时仍走幂等快速路径，不受降级检查影响
	if r, _ := e.upload(t, "n.md", 2, lse3Payload(1, 3, "g3")); r.StatusCode != http.StatusOK {
		t.Fatalf("idempotent re-upload of current head = %d, want 200", r.StatusCode)
	}
}

// E2EE 下改名（协议 v6）：改名只动元数据，与信封版本无关——LSE3 与 LSE2 都放行，
// 因为服务器根本不碰密文。这与 v5 的路径式 MOVE 不同：那时 LSE1/LSE2 的 AAD 绑路径，
// 服务器侧移动会产出无法解密的内容，所以必须拒绝。
func TestRenameUnderE2ee(t *testing.T) {
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

	before := e.snapshotFiles(t)
	v3ID := before["v3.md"]["fileId"].(string)
	if r, _ := e.rename(t, "v3.md", "moved.md", 0); r.StatusCode != http.StatusOK {
		t.Fatalf("rename LSE3 under e2ee = %d, want 200", r.StatusCode)
	}
	if e.snapshotFiles(t)["moved.md"]["fileId"] != v3ID {
		t.Fatal("fileId must follow content across rename")
	}
	// LSE2 也放行：改名不重写密文
	if r, _ := e.rename(t, "v2.md", "moved2.md", 0); r.StatusCode != http.StatusOK {
		t.Fatalf("rename LSE2 under e2ee = %d, want 200 (rename never touches ciphertext)", r.StatusCode)
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
