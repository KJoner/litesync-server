package api_test

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
)

func (e *testEnv) putVaultKey(t *testing.T, body string, replace bool) (*http.Response, map[string]any) {
	t.Helper()
	u := e.ts.URL + "/api/v1/vault-key"
	if replace {
		u += "?replace=true"
	}
	req, _ := http.NewRequest(http.MethodPut, u, bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	return e.do(t, req)
}

func (e *testEnv) getVaultKey(t *testing.T) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/vault-key", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func TestVaultKeyFlow(t *testing.T) {
	e := newTestEnv(t, 1<<20)

	// 尚未设置 → 404
	resp, _ := e.getVaultKey(t)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("empty vault-key = %d, want 404", resp.StatusCode)
	}

	// 上传（服务器视为 opaque JSON）
	doc := `{"version":1,"kdf":"pbkdf2-sha256","iterations":600000,"salt":"c2FsdA==","iv":"aXY=","wrappedKey":"d3JhcHBlZA==","enabled":false}`
	resp2, _ := e.putVaultKey(t, doc, false)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("put vault-key = %d", resp2.StatusCode)
	}

	// 原样读回
	resp3, raw := e.getVaultKey(t)
	if resp3.StatusCode != http.StatusOK || string(raw) != doc {
		t.Fatalf("get vault-key = %d, body %q", resp3.StatusCode, raw)
	}

	// 重复上传（无 replace）→ 409：防止误覆盖导致密文永久不可读
	resp4, _ := e.putVaultKey(t, `{"version":2}`, false)
	if resp4.StatusCode != http.StatusConflict {
		t.Fatalf("overwrite without replace = %d, want 409", resp4.StatusCode)
	}
	// 内容未被改动
	_, raw2 := e.getVaultKey(t)
	if string(raw2) != doc {
		t.Fatal("vault key was modified by rejected overwrite")
	}

	// 显式 replace → 允许（如标记 enabled=true）
	doc2 := `{"version":1,"enabled":true}`
	resp5, _ := e.putVaultKey(t, doc2, true)
	if resp5.StatusCode != http.StatusOK {
		t.Fatalf("replace vault-key = %d", resp5.StatusCode)
	}
	_, raw3 := e.getVaultKey(t)
	if string(raw3) != doc2 {
		t.Fatal("replace did not take effect")
	}

	// 非 JSON → 400
	resp6, _ := e.putVaultKey(t, "not json", true)
	if resp6.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-json vault-key = %d, want 400", resp6.StatusCode)
	}
}

func TestVaultKeyAuth(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/vault-key", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("vault-key without token = %d, want 401", resp.StatusCode)
	}
}

func (e *testEnv) purgeHistory(t *testing.T, path string, before int64) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete,
		e.ts.URL+"/api/v1/history?path="+url.QueryEscape(path)+"&beforeRevision="+itoa(before), nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	return e.do(t, req)
}

// E2EE 迁移场景：密文上传验证后清理明文历史。
func TestHistoryPurge(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	v1, v2 := []byte("plaintext v1"), []byte("plaintext v2")
	enc := []byte("LSE1-pretend-ciphertext")

	e.upload(t, "m.md", 0, v1)  // rev 1（明文）
	e.upload(t, "m.md", 1, v2)  // rev 2（明文）
	e.upload(t, "m.md", 2, enc) // rev 3（密文）

	// 清理 rev 3 之前的明文历史
	resp, body := e.purgeHistory(t, "m.md", 3)
	if resp.StatusCode != http.StatusOK || body["removed"].(float64) != 2 {
		t.Fatalf("purge = %d, removed %v", resp.StatusCode, body["removed"])
	}

	// 只剩密文版本；HEAD 不受影响
	_, hbody := e.history(t, "m.md")
	versions := hbody["versions"].([]any)
	if len(versions) != 1 || versions[0].(map[string]any)["revision"].(float64) != 3 {
		t.Fatalf("after purge versions = %v", versions)
	}
	dresp, data := e.download(t, "m.md")
	if dresp.StatusCode != http.StatusOK || !bytes.Equal(data, enc) {
		t.Fatal("HEAD must be unaffected by purge")
	}
	// 明文 blob 已被 GC
	if _, err := os.Stat(blobPath(e.blobDir, sha256Hex(v1))); !os.IsNotExist(err) {
		t.Fatal("plaintext blob v1 must be garbage collected")
	}

	// 幂等：再清一次 removed=0
	_, body2 := e.purgeHistory(t, "m.md", 3)
	if body2["removed"].(float64) != 0 {
		t.Fatal("purge must be idempotent")
	}

	// beforeRevision 大于 HEAD 也永远保留最新版本
	resp3, _ := e.purgeHistory(t, "m.md", 99)
	if resp3.StatusCode != http.StatusOK {
		t.Fatal(resp3.StatusCode)
	}
	_, hbody2 := e.history(t, "m.md")
	if len(hbody2["versions"].([]any)) != 1 {
		t.Fatal("newest version must always survive purge")
	}

	// 路径安全 + 参数校验
	if resp, _ := e.purgeHistory(t, "../x", 1); resp.StatusCode != http.StatusBadRequest {
		t.Fatal("traversal purge must 400")
	}
	if resp, _ := e.purgeHistory(t, "m.md", 0); resp.StatusCode != http.StatusBadRequest {
		t.Fatal("beforeRevision=0 must 400")
	}
}
