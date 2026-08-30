package api_test

import (
	"net/http"
	"testing"
)

// 静态资产必须带 ETag + Cache-Control: no-cache，且 If-None-Match 命中返回 304。
// 背景（v0.19.0-rc.2 线上实测）：资产文件名固定又不发校验头，Cloudflare 之类
// CDN 按默认 TTL 缓存，每次发版都会「网页端像旧版」。
func TestStaticAssetsETag(t *testing.T) {
	e := newTestEnv(t, 1<<20)

	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/app.js", nil)
	resp, _ := e.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /app.js = %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("Cache-Control = %q, want no-cache", cc)
	}
	tag := resp.Header.Get("ETag")
	if tag == "" {
		t.Fatal("missing ETag on /app.js")
	}

	req2, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/app.js", nil)
	req2.Header.Set("If-None-Match", tag)
	resp2, _ := e.do(t, req2)
	if resp2.StatusCode != http.StatusNotModified {
		t.Fatalf("If-None-Match revalidation = %d, want 304", resp2.StatusCode)
	}

	// 根路径（index.html）同样纳入校验体系
	req3, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/", nil)
	resp3, _ := e.do(t, req3)
	if resp3.Header.Get("ETag") == "" || resp3.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("GET / headers: ETag=%q Cache-Control=%q",
			resp3.Header.Get("ETag"), resp3.Header.Get("Cache-Control"))
	}
}
