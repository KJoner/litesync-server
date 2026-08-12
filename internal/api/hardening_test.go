package api

import (
	"net/http"
	"testing"
)

// v0.13.3 §7.6：HTTP 与鉴权加固。

// routeScope 的默认分支必须是**拒绝**，而不是「猜一个 sync」。
//
// 这条规则的价值不在于挡住已知攻击，而在于挡住**将来某次疏忽**：
// 新增一个 /api/v1/xxx 接口而忘了配 scope 时，旧代码会让它对所有设备
// Token 全开且毫无提示；现在它会直接被拒，开发当天就能发现。
func TestRouteScopeDefaultsToDeny(t *testing.T) {
	unlisted := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/some-future-endpoint"},
		{http.MethodPost, "/api/v1/another/new/thing"},
		{http.MethodDelete, "/api/v1/dangerous-op"},
		{http.MethodGet, "/api/v1/"},
	}
	for _, c := range unlisted {
		scope, rootOnly := routeScope(c.method, c.path)
		if rootOnly {
			continue // rootOnly 本身就是更严的形态
		}
		if scope != scopeDeny {
			t.Fatalf("%s %s 未登记却拿到了 scope %q —— 默认必须是拒绝", c.method, c.path, scope)
		}
	}
}

// 已知的同步路径必须仍然可用（默认拒绝不能把正常同步一起挡掉）。
func TestRouteScopeAllowsKnownSyncRoutes(t *testing.T) {
	allowed := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/info"},
		{http.MethodGet, "/api/v1/changes"},
		{http.MethodGet, "/api/v1/file"},
		{http.MethodPut, "/api/v1/file"},
		{http.MethodDelete, "/api/v1/file"},
		{http.MethodPost, "/api/v1/file/rename"},
		{http.MethodGet, "/api/v1/file/meta"},
		{http.MethodGet, "/api/v1/snapshot"},
		{http.MethodGet, "/api/v1/history"},
		{http.MethodGet, "/api/v1/version"},
		{http.MethodGet, "/api/v1/vault-key"},
		{http.MethodPost, "/api/v1/files/abc/restore"},
	}
	for _, c := range allowed {
		scope, rootOnly := routeScope(c.method, c.path)
		if rootOnly || scope == scopeDeny {
			t.Fatalf("%s %s 是正常同步路径，不应被拒绝（scope=%q rootOnly=%v）", c.method, c.path, scope, rootOnly)
		}
	}
}

// 管理面与密钥面必须保持在更严的档位上。
func TestRouteScopePrivilegedRoutes(t *testing.T) {
	if _, rootOnly := routeScope(http.MethodGet, "/api/v1/admin/integrity/scan"); !rootOnly {
		t.Fatal("完整性运维接口必须是 root/admin 专属")
	}
	if _, rootOnly := routeScope(http.MethodPost, "/api/v1/admin/backup/run"); !rootOnly {
		t.Fatal("备份接口必须是 root/admin 专属")
	}
	if scope, _ := routeScope(http.MethodPost, "/api/v1/meta/complete"); scope == scopeDeny || scope == "" {
		t.Fatal("迁移接口应当要求 key-admin scope")
	}
	if scope, _ := routeScope(http.MethodPost, "/api/v1/envelope/complete"); scope == scopeDeny || scope == "" {
		t.Fatal("信封下限提升是仓库级不可逆动作，必须要求 key-admin scope")
	}
}
