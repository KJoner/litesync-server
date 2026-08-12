package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// HTTP 层的跨租户泄露（v0.16.0 / 计划书 §10.6、ADR-010 §9）。
//
// 路由矩阵管的是「谁能调哪条接口」。这一组管的是另一半：
// **调用被允许的接口时，能不能顺带问出不该知道的事**。

// countingReader 记录请求体被读走了多少字节。
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// 去重不得成为存在性预言机：命中去重的上传必须和全新上传**做同样多的工作**。
//
// 这是这类漏洞最常见的形态：服务器一看「这个哈希我有」就直接返回，
// 于是「秒传」与「真传」在耗时和流量上判若两物，攻击者拿一份内容
// 试一下就知道仓库里有没有它。防线不是把响应写得一样，
// 而是**根本不短路**——请求体永远被完整读完并重新哈希。
func TestDedupDoesNotShortCircuitTheUpload(t *testing.T) {
	e := newTestEnv(t, 8<<20)
	content := bytes.Repeat([]byte("dedup-probe-"), 64*1024) // ~768KB

	upload := func(path string) (int64, int) {
		cr := &countingReader{r: bytes.NewReader(content)}
		req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", cr)
		req.ContentLength = int64(len(content))
		req.Header.Set("Authorization", "Bearer "+testToken)
		req.Header.Set("X-File-Path", url.PathEscape(path))
		req.Header.Set("X-Base-Revision", "0")
		req.Header.Set("X-Content-Hash", sha256Hex(content))
		resp, _ := e.do(t, req)
		return cr.n, resp.StatusCode
	}

	first, code1 := upload("first.md")
	if code1 != http.StatusOK {
		t.Fatalf("首次上传 = %d", code1)
	}
	// 第二次是**必然命中去重**的：同样的内容，不同的路径
	second, code2 := upload("second.md")
	if code2 != http.StatusOK {
		t.Fatalf("去重上传 = %d", code2)
	}

	if second < first {
		t.Fatalf("去重命中时只读走了 %d 字节，全新上传读走 %d —— "+
			"服务器短路了，「秒传」与「真传」可区分，存在性泄露", second, first)
	}

	// 对照：证明这套计数**能**发现短路。
	// 拿一个根本不读 body 的接口试一次，读走的字节数必须明显少于全量——
	// 没有这条，上面的断言可能只是「两次都读完了，因为客户端总会写完」。
	cr := &countingReader{r: bytes.NewReader(content)}
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/info", cr)
	req.ContentLength = int64(len(content))
	req.Header.Set("Authorization", "Bearer "+testToken)
	e.do(t, req)
	if cr.n >= int64(len(content)) {
		t.Fatal("不读 body 的接口也把 body 读完了 —— 这套计数发现不了短路，上面的断言没有意义")
	}
}

// 响应里不得出现 blobId：那是服务端的存储名字，客户端不需要，
// 而知道它就等于拿到一个可以直接拿去比对的存在性标记。
func TestResponsesNeverExposeBlobIDs(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	content := []byte("some note")
	e.upload(t, "a.md", 0, content)

	for _, path := range []string{
		"/api/v1/info", "/api/v1/changes?since=0", "/api/v1/snapshot",
		"/api/v1/history?path=a.md", "/api/v1/devices", "/api/v1/whoami",
	} {
		req, _ := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		for _, needle := range []string{`"blobId"`, `"blob_id"`} {
			if bytes.Contains(raw, []byte(needle)) {
				t.Errorf("%s 的响应里出现了 %s", path, needle)
			}
		}
	}
}

// 没有任何路由把 blob 标识当作参数：blob 只能经由「路径 + revision」取，
// 而那两条路都会先过 HEAD 的租户校验。直接按 id 取内容等于绕开校验。
func TestNoRouteAddressesBlobsDirectly(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("router.go"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`mux\.HandleFunc\("[A-Z]+ ([^"]+)"`)
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		p := strings.ToLower(m[1])
		if strings.Contains(p, "blob") || strings.Contains(p, "{hash}") ||
			strings.Contains(p, "{contenthash}") {
			t.Errorf("路由 %s 直接按 blob 寻址 —— 这会绕过 HEAD 上的租户校验", m[1])
		}
	}
}

// scope 分离要在**每一类越权动作**上分别成立，而不只是「大体上」。
// 一张收窄到 sync 的票不能碰 share、历史清理、元数据迁移、密钥写入。
func TestNarrowedTokenCannotEscalate(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, _ := e.enrollDevice(t, "laptop")
	_, body := e.exchange(t, devToken, map[string]any{"scopes": []string{"sync"}})
	narrow := body["accessToken"].(string)

	cases := []struct {
		name, method, path string
	}{
		{"share 越权", http.MethodPost, "/api/v1/share"},
		{"share 列表越权", http.MethodGet, "/api/v1/shares"},
		{"历史清理越权", http.MethodDelete, "/api/v1/history?path=a.md&beforeRevision=1"},
		{"migration 越权", http.MethodPost, "/api/v1/meta/begin"},
		{"migration 完成越权", http.MethodPost, "/api/v1/meta/complete"},
		{"keyEpoch 越权", http.MethodPut, "/api/v1/vault-key"},
		{"信封下限越权", http.MethodPost, "/api/v1/envelope/complete"},
		{"E2EE 状态机越权", http.MethodPost, "/api/v1/e2ee/begin"},
		{"成员移除越权", http.MethodDelete, "/api/v1/members/someone"},
		{"审计越权", http.MethodGet, "/api/v1/audit"},
	}
	for _, c := range cases {
		req, _ := http.NewRequest(c.method, e.ts.URL+c.path, bytes.NewReader([]byte("{}")))
		req.Header.Set("Authorization", "Bearer "+narrow)
		req.Header.Set("Content-Type", "application/json")
		resp, _ := e.do(t, req)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s：只带 sync 的票应当被拒（403），得到 %d", c.name, resp.StatusCode)
		}
	}

	// 对照：同一张票做正常同步必须成功。
	// 没有这条，上面全绿也可能只是因为这张票根本就是废的
	if code := e.probe(t, route{http.MethodGet, "/api/v1/info"}, narrow); code != http.StatusOK {
		t.Fatalf("收窄后的票应当仍能同步，得到 %d", code)
	}
}

// 并发下 tenant scope 不得串台（§10.6 race condition）。
//
// 认证结果放在 request context 里，本该逐请求独立；但只要有人把它挪到
// 某个共享结构上（缓存「当前身份」之类），高并发下就会出现
// 「A 的请求拿到 B 的范围」。这条测试专门盯这种串台。
func TestConcurrentRequestsDoNotBleedTenantScope(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	goodToken, _ := e.enrollDevice(t, "local")
	foreignToken, foreignID := e.enrollDevice(t, "foreign")
	if _, err := e.db.Exec(`UPDATE devices SET vault_id = 'other-tenant' WHERE id = ?`, foreignID); err != nil {
		t.Fatal(err)
	}

	const rounds = 60
	var wg sync.WaitGroup
	errs := make(chan string, rounds*2)
	for i := 0; i < rounds; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if code := e.probeConcurrent(e.ts.URL+"/api/v1/info", goodToken); code != http.StatusOK {
				errs <- fmt.Sprintf("本租户凭据被误拒：%d", code)
			}
		}()
		go func() {
			defer wg.Done()
			if code := e.probeConcurrent(e.ts.URL+"/api/v1/info", foreignToken); code != http.StatusForbidden {
				errs <- fmt.Sprintf("外租户凭据被放行：%d", code)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
}

// probeConcurrent 是并发安全的最小探针（不碰 *testing.T）。
func (e *testEnv) probeConcurrent(url, token string) int {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return -1
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	return resp.StatusCode
}

// whoami 不得泄露别的租户的存在：它只回答「你是谁」，
// 不回答「这台服务器上还有谁」。
func TestWhoamiRevealsNothingAboutOtherTenants(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, _ := e.enrollDevice(t, "laptop")
	if _, err := e.db.Exec(
		`INSERT INTO vaults (vault_id, owner_id, name, secret, created_at)
		 VALUES ('other-tenant', 'someone-else', 'Their Notes', x'00', 0)`); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+devToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, needle := range []string{"other-tenant", "someone-else", "Their Notes"} {
		if bytes.Contains(raw, []byte(needle)) {
			t.Fatalf("whoami 泄露了别的租户的信息：%s", raw)
		}
	}
	// 对照：它确实返回了本设备的身份，不是一个空响应
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("whoami 应当返回 JSON：%s", raw)
	}
	if len(body) == 0 {
		t.Fatal("whoami 返回空对象，上面的检查没有意义")
	}
}
