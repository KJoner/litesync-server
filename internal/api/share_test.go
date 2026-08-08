package api_test

import (
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"
)

func (e *testEnv) createShare(t *testing.T, name string, expiresAt int64, content []byte) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/share", bytes.NewReader(content))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Share-Name", name)
	if expiresAt != 0 {
		req.Header.Set("X-Share-Expires", itoa(expiresAt))
	}
	return e.do(t, req)
}

func (e *testEnv) fetchShare(t *testing.T, id string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(e.ts.URL + "/share/" + id) // 公开：无 Token
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func TestShareLifecycle(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	ciphertext := []byte("LSS1-pretend-encrypted-share-content")

	// 创建
	resp, body := e.createShare(t, "Notes/demo.md", 0, ciphertext)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create share = %d", resp.StatusCode)
	}
	id := body["id"].(string)
	if len(id) != 32 {
		t.Fatalf("share id = %q", id)
	}

	// 公开读取（无需认证）
	gresp, data := e.fetchShare(t, id)
	if gresp.StatusCode != http.StatusOK || !bytes.Equal(data, ciphertext) {
		t.Fatalf("fetch share = %d", gresp.StatusCode)
	}

	// 列表（需认证）
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/shares", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	lresp, lbody := e.do(t, req)
	if lresp.StatusCode != http.StatusOK {
		t.Fatalf("list shares = %d", lresp.StatusCode)
	}
	list := lbody["shares"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["name"] != "Notes/demo.md" {
		t.Fatalf("shares list = %v", list)
	}

	// 撤销
	dreq, _ := http.NewRequest(http.MethodDelete, e.ts.URL+"/api/v1/share?id="+id, nil)
	dreq.Header.Set("Authorization", "Bearer "+testToken)
	drresp, _ := e.do(t, dreq)
	if drresp.StatusCode != http.StatusOK {
		t.Fatalf("revoke = %d", drresp.StatusCode)
	}
	// 撤销后公开读取 404
	if r, _ := e.fetchShare(t, id); r.StatusCode != http.StatusNotFound {
		t.Fatalf("revoked share fetch = %d, want 404", r.StatusCode)
	}
	// 重复撤销 404? 已存在但 revoked → RevokeShare 幂等成功
	drresp2, _ := e.do(t, func() *http.Request {
		r, _ := http.NewRequest(http.MethodDelete, e.ts.URL+"/api/v1/share?id="+id, nil)
		r.Header.Set("Authorization", "Bearer "+testToken)
		return r
	}())
	if drresp2.StatusCode != http.StatusOK {
		t.Fatalf("repeat revoke = %d", drresp2.StatusCode)
	}
}

func TestShareExpiry(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	// 2 秒后过期（留边界余量，避免秒级截断造成偶发失败）
	resp, body := e.createShare(t, "temp.md", time.Now().Unix()+2, []byte("expiring"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create = %d", resp.StatusCode)
	}
	id := body["id"].(string)
	if r, _ := e.fetchShare(t, id); r.StatusCode != http.StatusOK {
		t.Fatalf("before expiry = %d", r.StatusCode)
	}
	time.Sleep(3 * time.Second)
	if r, _ := e.fetchShare(t, id); r.StatusCode != http.StatusNotFound {
		t.Fatalf("after expiry = %d, want 404", r.StatusCode)
	}

	// 过去的过期时间 → 400
	resp2, _ := e.createShare(t, "x", time.Now().Unix()-10, []byte("y"))
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("past expiry = %d, want 400", resp2.StatusCode)
	}
}

func TestShareSecurity(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	// 创建/列表/撤销都必须认证
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/share", bytes.NewReader([]byte("x")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth create = %d, want 401", resp.StatusCode)
	}
	// 非法 id 公开读取 → 404
	if r, _ := e.fetchShare(t, "not-a-valid-id"); r.StatusCode != http.StatusNotFound {
		t.Fatalf("invalid id = %d, want 404", r.StatusCode)
	}
	// 不存在的合法格式 id → 404
	if r, _ := e.fetchShare(t, "00112233445566778899aabbccddeeff"); r.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id = %d, want 404", r.StatusCode)
	}
}

func TestSnapshot(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "b.md", 0, []byte("b"))
	e.upload(t, "a.md", 0, []byte("a"))
	e.upload(t, "del.md", 0, []byte("d"))
	e.delete(t, "del.md", 1)

	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/snapshot", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, body := e.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("snapshot = %d", resp.StatusCode)
	}
	files := body["files"].([]any)
	if len(files) != 2 {
		t.Fatalf("snapshot files = %d, want 2 (deleted excluded)", len(files))
	}
	// 按 path 排序
	if files[0].(map[string]any)["path"] != "a.md" || files[1].(map[string]any)["path"] != "b.md" {
		t.Fatalf("snapshot order = %v", files)
	}
	if body["sequence"].(float64) != 4 {
		t.Fatalf("sequence = %v, want 4", body["sequence"])
	}

	// 未认证 → 401
	req2, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/snapshot", nil)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth snapshot = %d", resp2.StatusCode)
	}
}

// 静态 Web 资源无需认证即可访问。
func TestWebStaticServed(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	resp, err := http.Get(e.ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(raw, []byte("LiteSync")) {
		t.Fatal("index.html should contain LiteSync")
	}
}
