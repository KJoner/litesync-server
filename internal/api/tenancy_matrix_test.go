package api_test

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 跨租户越权矩阵（v0.16.0 / 计划书 §10.6、ADR-010 §9）。
//
// # 为什么要从路由表**自动生成**
//
// 手写一张「每个接口都试一遍」的清单，第一天是完整的，第二天就不是了：
// 新增一个接口不会让任何测试变红。这类漏洞的典型形态正是「某个新接口
// 忘了配 scope」，而手写清单恰恰盖不住新接口。
//
// 所以这里直接扫 router.go 把路由抽出来。加一条新路由，下面这些测试
// 立刻把它纳入覆盖；如果它是公开的，就必须在 publicRoutes 里显式登记——
// 逼作者当场做一次「这条真的可以公开吗」的判断。

type route struct {
	method, path string
}

// publicRoutes 是**故意**不需要认证的路径。
//
// 每一条都要能说清为什么。这份清单短，是因为它必须短——
// 每加一条就是一次攻击面扩张，值得单独审。
var publicRoutes = map[string]string{
	"GET /health":             "存活探针，不返回任何仓库信息",
	"POST /web/session":       "登录本身",
	"DELETE /web/session":     "登出",
	"POST /enroll":            "一次性 enrollment secret 即认证（新设备此刻还没有凭据）",
	"POST /pair/{id}/consume": "配对包消费：一次性 id + 短 TTL 即认证",
	"GET /p/{id}":             "配对页面：内容由一次性 id 保护",
	"GET /share/{id}":         "分享链接：密文由链接里的密钥解密，服务器不持有它",
	"GET /api/v1/whoami":      "任何有效凭据均可；无凭据时仍然 401",
	"POST /api/v1/token":      "换票：由长期设备凭据认证，authGate 内处理",
	"GET /":                   "静态资源",
}

// parseRoutes 从 router.go 抽出全部注册的路由。
func parseRoutes(t *testing.T) []route {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("router.go"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`mux\.HandleFunc\("([A-Z]+) ([^"]+)"`)
	ms := re.FindAllStringSubmatch(string(src), -1)
	if len(ms) < 20 {
		t.Fatalf("只解析出 %d 条路由——正则大概已经和 router.go 对不上了", len(ms))
	}
	out := make([]route, 0, len(ms))
	for _, m := range ms {
		out = append(out, route{method: m[1], path: m[2]})
	}
	return out
}

// concrete 把 {id} 之类的通配段换成一个具体值，好让请求真的打到处理器上。
func (r route) concrete() string {
	p := regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(r.path, "probe-value")
	return p
}

func (r route) String() string { return r.method + " " + r.path }

func (e *testEnv) probe(t *testing.T, r route, token string) int {
	t.Helper()
	req, err := http.NewRequest(r.method, e.ts.URL+r.concrete(), bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, _ := e.do(t, req)
	return resp.StatusCode
}

// 任何路由在无凭据时都不得返回 2xx。
func TestEveryRouteRejectsAnonymous(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	for _, r := range parseRoutes(t) {
		if _, ok := publicRoutes[r.String()]; ok {
			continue
		}
		code := e.probe(t, r, "")
		if code >= 200 && code < 300 {
			t.Errorf("%s 无凭据时返回 %d —— 未认证请求拿到了数据", r, code)
		}
	}
}

// 撤销的设备在**任何**路由上都必须被拒（§10.6 revoked device）。
func TestEveryRouteRejectsRevokedDevice(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, deviceID := e.enrollDevice(t, "revoked")
	if resp, _ := e.doJSON(t, http.MethodDelete, "/api/v1/devices/"+deviceID, testToken, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("撤销设备 = %d", resp.StatusCode)
	}
	for _, r := range parseRoutes(t) {
		if _, ok := publicRoutes[r.String()]; ok {
			continue
		}
		code := e.probe(t, r, devToken)
		if code >= 200 && code < 300 {
			t.Errorf("%s 对已撤销设备返回 %d", r, code)
		}
	}
}

// 属于**别的 Vault** 的凭据在任何路由上都必须被拒（§10.6 跨 Vault 读取/修改）。
//
// 今天单实例只服务一个 Vault，因此这条检查等价于「凭据必须属于本仓库」。
// 它现在就存在，是为了让多 Vault 路由落地时的失败方向是拒绝，
// 而不是安静地沿用默认 Vault 把别人的数据返回出去。
func TestEveryRouteRejectsForeignVaultCredential(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, deviceID := e.enrollDevice(t, "foreign")
	// 把这台设备改挂到另一个 Vault 上
	if _, err := e.db.Exec(`UPDATE devices SET vault_id = 'other-tenant' WHERE id = ?`, deviceID); err != nil {
		t.Fatal(err)
	}
	for _, r := range parseRoutes(t) {
		if _, ok := publicRoutes[r.String()]; ok {
			continue
		}
		code := e.probe(t, r, devToken)
		if code >= 200 && code < 300 {
			t.Errorf("%s 对外租户凭据返回 %d —— 跨租户访问", r, code)
		}
		if code != http.StatusForbidden && code != http.StatusUnauthorized {
			t.Errorf("%s 对外租户凭据应当 401/403，得到 %d", r, code)
		}
	}
}

// 没有任何 scope 的设备只能碰到「不要求 scope」的那几条路由。
//
// 这条测试真正盯的是路由表的**默认拒绝**：新增接口如果忘了登记，
// routeScope 返回 scopeDeny，这里就会看到它被拒——而不是悄悄放行。
func TestZeroScopeDeviceGetsNothing(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, deviceID := e.enrollDevice(t, "no-scope")
	// token 本身仍然有效，但这台设备一个 scope 都没有
	if _, err := e.db.Exec(`UPDATE devices SET scopes = '' WHERE id = ?`, deviceID); err != nil {
		t.Fatal(err)
	}

	// 这两条明确「不要求 scope」，因此零 scope 设备本就该能用
	allowedWithoutScope := map[string]bool{
		"GET /api/v1/whoami": true,
		"POST /api/v1/token": true,
	}
	var probed int
	for _, r := range parseRoutes(t) {
		if _, public := publicRoutes[r.String()]; public || allowedWithoutScope[r.String()] {
			continue
		}
		probed++
		code := e.probe(t, r, devToken)
		if code >= 200 && code < 300 {
			t.Errorf("%s 对零 scope 设备返回 %d —— 路由表漏配了", r, code)
		}
	}
	if probed < 20 {
		t.Fatalf("只探了 %d 条路由，覆盖面不对", probed)
	}

	// 对照：明确开放的那两条必须仍然可用。
	// 没有这条对照，上面全绿也可能只是因为「所有请求都失败了」
	if code := e.probe(t, route{http.MethodGet, "/api/v1/whoami"}, devToken); code != http.StatusOK {
		t.Fatalf("whoami 对任何有效凭据都应当可用，得到 %d", code)
	}
}

// 管理类路由对普通同步设备一律关闭：备份、完整性、设备管理、灾难恢复。
//
// 这些接口能读到整个仓库的密文与全部元数据，或者能改变全局状态。
// 一台笔记本被偷不该顺带把它们交出去。
func TestAdminRoutesAreRootOnly(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, _ := e.enrollDevice(t, "ordinary")
	_, tokenBody := e.exchange(t, devToken, nil)
	accessToken, _ := tokenBody["accessToken"].(string)

	var checked int
	for _, r := range parseRoutes(t) {
		if !strings.HasPrefix(r.path, "/api/v1/admin/") {
			continue
		}
		checked++
		for name, tok := range map[string]string{"设备 Token": devToken, "access token": accessToken} {
			code := e.probe(t, r, tok)
			if code != http.StatusForbidden && code != http.StatusUnauthorized {
				t.Errorf("%s 对%s应当拒绝，得到 %d", r, name, code)
			}
		}
	}
	if checked == 0 {
		t.Fatal("一条管理路由都没扫到——解析大概坏了")
	}
}
