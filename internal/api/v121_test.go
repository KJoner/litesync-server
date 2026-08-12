package api_test

// v0.12.1 止血版验收测试（计划书 §3.3）。
//
// 覆盖：
//   LS-121-S01 LSE3 HEAD 不得被旧信封覆盖（见 lse3_test.go 的 TestLse3GenerationMonotonic）
//   LS-121-S02 complete 不再删除 tombstone（见 meta_test.go 的 TestMetaMigrationLifecycle）
//   LS-121-S03 plain 状态下 UpdateFileMeta 被拒绝
//   LS-121-S04 元数据 Header 的长度与格式上限
//   LS-121-S05 客户端问题一律 4xx + 统一 {code,message,retryable} 错误体
//
// INV: INV-06 / INV-07

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// uploadWithHeaders：可自由设置任意 Header 的上传（Header 校验测试用）。
func (e *testEnv) uploadWithHeaders(t *testing.T, path string, baseRevision int64, content []byte, extra map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytes.NewReader(content))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-File-Path", url.PathEscape(path))
	req.Header.Set("X-Base-Revision", itoa(baseRevision))
	req.Header.Set("X-Content-Hash", sha256Hex(content))
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	return e.do(t, req)
}

// 统一错误体：任何 4xx 都必须带机器可识别的 code 与 retryable 标记。
func assertErrorBody(t *testing.T, body map[string]any, wantCode string) {
	t.Helper()
	if body["code"] != wantCode {
		t.Fatalf("error code = %v, want %s (body %v)", body["code"], wantCode, body)
	}
	if _, ok := body["message"].(string); !ok {
		t.Fatalf("error body missing message: %v", body)
	}
	if _, ok := body["retryable"].(bool); !ok {
		t.Fatalf("error body missing retryable: %v", body)
	}
	// 兼容字段：0.12.0 及更早的客户端只读 error
	if _, ok := body["error"].(string); !ok {
		t.Fatalf("error body must keep legacy error field: %v", body)
	}
}

// LS-121-S03：plain 状态下不得写入元数据语义字段。
func TestUpdateFileMetaRequiresMetaState(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	_, body := e.upload(t, "a.md", 0, lse3Payload(1, 1, "a"))
	fileID := body["fileId"].(string)

	// plain 状态：即使 path 恰好是合法伪名格式，也不得挂上 metaEnc / canonical HMAC
	r, b := e.doJSON(t, http.MethodPut, "/api/v1/file/meta", testToken, map[string]any{
		"path": fileID, "baseMetaGeneration": 0, "metaEnc": metaEncA, "canonicalHash": canonA,
	})
	if r.StatusCode != http.StatusConflict {
		t.Fatalf("meta update in plain state = %d, want 409", r.StatusCode)
	}
	assertErrorBody(t, b, "META_STATE_INVALID")

	// 该文件的元数据不得被污染
	if v, ok := e.snapshotFiles(t)["a.md"]["metaEnc"]; ok && v != "" {
		t.Fatalf("plain-state repo must not carry metaEnc: %v", v)
	}

	// 进入 migrating 后才允许（此处路径尚未伪名化，因此按 404 拒绝而不是状态拒绝）
	e.postE2ee(t, "begin")
	e.postE2ee(t, "complete")
	e.postMeta(t, "begin", nil)
	if r2, _ := e.doJSON(t, http.MethodPut, "/api/v1/file/meta", testToken, map[string]any{
		"path": "ffffffffffffffffffffffffffffffff", "baseMetaGeneration": 0, "metaEnc": metaEncA, "canonicalHash": canonA,
	}); r2.StatusCode != http.StatusNotFound {
		t.Fatalf("meta update on unknown pseudonym = %d, want 404", r2.StatusCode)
	}
}

// LS-121-S04：元数据 Header 的长度与格式上限（不依赖 HTTP Server 的总上限）。
func TestMetaHeaderLimits(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	content := []byte("x")

	cases := []struct {
		name   string
		header string
		value  string
	}{
		{"meta enc too large", "X-Meta-Enc", strings.Repeat("A", (8<<10)+1)},
		{"meta enc not base64", "X-Meta-Enc", "not base64 !!"},
		{"canonical hash wrong length", "X-Canonical-Hash", strings.Repeat("a", 63)},
		{"canonical hash uppercase", "X-Canonical-Hash", strings.ToUpper(canonHex("ab"))},
		{"file id wrong length", "X-File-Id", "abc"},
		{"file id not hex", "X-File-Id", strings.Repeat("z", 32)},
		{"key epoch zero", "X-Key-Epoch", "0"},
		{"key epoch overflow", "X-Key-Epoch", "4294967296"},
		{"key epoch not numeric", "X-Key-Epoch", "1e9"},
		{"content generation overflow", "X-Content-Generation", "9007199254740992"},
		{"meta generation negative", "X-Meta-Generation", "-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, b := e.uploadWithHeaders(t, "h-"+tc.name+".md", 0, content, map[string]string{tc.header: tc.value})
			if r.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s = %d, want 400", tc.name, r.StatusCode)
			}
			assertErrorBody(t, b, "INVALID_HEADER")
		})
	}

	// 边界内的合法值放行
	if r, _ := e.uploadWithHeaders(t, "ok.md", 0, content, map[string]string{
		"X-Key-Epoch": "4294967295", "X-Content-Generation": "9007199254740991",
	}); r.StatusCode != http.StatusOK {
		t.Fatalf("valid boundary headers = %d, want 200", r.StatusCode)
	}
}

// LS-121-S05：客户端问题一律 4xx + 统一错误体，绝不 500。
func TestClientErrorsAreNotServerErrors(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	content := []byte("x")

	// 非法路径
	r1, b1 := e.upload(t, "../escape.md", 0, content)
	if r1.StatusCode != http.StatusBadRequest {
		t.Fatalf("traversal upload = %d, want 400", r1.StatusCode)
	}
	assertErrorBody(t, b1, "INVALID_PATH")

	// 非法 X-Base-Revision
	r2, b2 := e.uploadWithHeaders(t, "b.md", 0, content, map[string]string{"X-Base-Revision": "abc"})
	if r2.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad base revision = %d, want 400", r2.StatusCode)
	}
	assertErrorBody(t, b2, "INVALID_HEADER")

	// hash 不符
	r3, b3 := e.uploadWithHash(t, "c.md", 0, content, sha256Hex([]byte("other")))
	if r3.StatusCode != http.StatusBadRequest {
		t.Fatalf("hash mismatch = %d, want 400", r3.StatusCode)
	}
	assertErrorBody(t, b3, "HASH_MISMATCH")

	// 元数据接口的非法 body（canonicalHash 不是 64 hex）
	r4, b4 := e.doJSON(t, http.MethodPost, "/api/v1/meta/migrate", testToken, map[string]any{
		"fromPath": "a.md", "metaEnc": metaEncA, "canonicalHash": "short",
	})
	if r4.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad canonicalHash = %d, want 400", r4.StatusCode)
	}
	assertErrorBody(t, b4, "INVALID_BODY")

	// 下载非法路径
	r5, _ := e.download(t, "../../etc/passwd")
	if r5.StatusCode != http.StatusBadRequest {
		t.Fatalf("traversal download = %d, want 400", r5.StatusCode)
	}

	// revision 冲突仍然是可识别的 CONFLICT（与协议级 409 区分开）
	e.upload(t, "d.md", 0, content)
	r6, b6 := e.upload(t, "d.md", 99, []byte("y"))
	if r6.StatusCode != http.StatusConflict {
		t.Fatalf("stale upload = %d, want 409", r6.StatusCode)
	}
	assertErrorBody(t, b6, "CONFLICT")
	if b6["revision"] == nil || b6["hash"] == nil {
		t.Fatalf("conflict body must carry server state: %v", b6)
	}
}

// LS-121-S01：信封降级冻结在删除后重建、以及历史版本上的行为。
func TestEnvelopeDowngradeAcrossLifecycle(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "n.md", 0, lse3Payload(1, 1, "v1"))

	// 删除后重建：tombstone 上没有 LSE3 HEAD，因此不受降级检查约束
	//（重建走的是 tombstone revision 分支；仓库级 minimumEnvelopeVersion 是 v0.13.0 的工作）
	if r, _ := e.delete(t, "n.md", 1); r.StatusCode != http.StatusOK {
		t.Fatal("delete failed")
	}
	if r, _ := e.upload(t, "n.md", 2, []byte("plaintext recreate")); r.StatusCode != http.StatusOK {
		t.Fatalf("recreate after delete = %d, want 200 (v0.12.1 只冻结现有 LSE3 HEAD 的降级)", r.StatusCode)
	}

	// 活的 LSE3 HEAD 无论仓库处于哪种加密状态都不得被降级覆盖
	e.upload(t, "m.md", 0, lse3Payload(1, 1, "m1"))
	r, b := e.upload(t, "m.md", 1, []byte("downgrade attempt"))
	if r.StatusCode != http.StatusConflict {
		t.Fatalf("downgrade over live LSE3 head = %d, want 409", r.StatusCode)
	}
	assertErrorBody(t, b, "ENVELOPE_TOO_OLD")

	// 内容与 HEAD 一致（幂等重放）不受影响
	if r2, _ := e.upload(t, "m.md", 1, lse3Payload(1, 1, "m1")); r2.StatusCode != http.StatusOK {
		t.Fatalf("idempotent re-upload = %d, want 200", r2.StatusCode)
	}
}
