package api

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"strings"
)

// staticWithETag 包装 Web 静态资产服务：启动时对 dist 逐文件算好强 ETag，
// 响应带 `ETag + Cache-Control: no-cache`——CDN（如 Cloudflare 的代理）与
// 浏览器仍可缓存，但每次使用前必须回源校验；版本更新立即生效，未更新则
// 304 几乎零流量。
//
// 为什么必须有：资产文件名固定（app.js 等，无版本指纹），embed.FS 又没有
// 修改时间——此前不发任何缓存校验头，CDN 按扩展名默认 TTL 缓存，
// **每次发版都会出现「网页端像旧版」**（0.19.0-rc.2 线上实测：服务器已是
// 新版而 Cloudflare 边缘还在发旧 app.js；0.17 时代同形状问题的另一半根因）。
func staticWithETag(dist fs.FS) http.Handler {
	etags := map[string]string{}
	_ = fs.WalkDir(dist, ".", func(p string, d fs.DirEntry, err error) error { //nolint:errcheck
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		raw, rerr := fs.ReadFile(dist, p)
		if rerr != nil {
			return nil
		}
		sum := sha256.Sum256(raw)
		etags["/"+p] = `"` + hex.EncodeToString(sum[:8]) + `"`
		return nil
	})
	inner := http.FileServerFS(dist)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		if tag, ok := etags[path]; ok {
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("ETag", tag)
			// 宽容匹配：If-None-Match 可能携带多个候选或 W/ 前缀
			if strings.Contains(r.Header.Get("If-None-Match"), tag) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		inner.ServeHTTP(w, r)
	})
}
