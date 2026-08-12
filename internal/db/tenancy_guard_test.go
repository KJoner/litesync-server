package db_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
)

// 多租户隔离的**可执行约束**（v0.16.0 / ADR-010 §5、§10.6）。
//
// ADR-010 的 T-1 说「每条查询的 vault 范围只能来自认证上下文」。
// 这句话如果只写在文档里，下一个新增的接口就会违反它，而且没人会注意到。
// 这里把它变成会失败的测试。
//
// 两条互补的防线：
//   1. 类型层：VaultScope 的字段不可导出，业务代码造不出来（编译期）；
//   2. 本测试：扫描源码，禁止业务包调用唯一的构造入口（CI 期）。

// 允许调用 db.ScopeFromAuth 的包。除此之外任何地方调用它，
// 都意味着某处在绕过认证自造 vault 范围。
var scopeConstructorAllowlist = []string{
	filepath.Join("internal", "api"), // 认证中间件在这里
	filepath.Join("internal", "db"),  // 定义处与自身测试
	filepath.Join("cmd", "obsync"),   // 运维命令：没有 HTTP 认证上下文，见下
}

func TestScopeConstructorIsNotCalledFromBusinessCode(t *testing.T) {
	root := repoRoot(t)
	callRe := regexp.MustCompile(`\bdb\.ScopeFromAuth\(`)

	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil //nolint:nilerr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil //nolint:nilerr
		}
		// 测试文件豁免：测跨租户隔离**必须**能造出两个不同的范围，
		// 否则「A 看不到 B」这类断言根本写不出来。测试里的 ScopeFromAuth
		// 授予不了任何真实访问权，它只是在构造被测场景。
		if strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		for _, allowed := range scopeConstructorAllowlist {
			if strings.HasPrefix(rel, allowed) {
				return nil
			}
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil //nolint:nilerr
		}
		if callRe.Match(data) {
			offenders = append(offenders, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf(
			"以下文件自行构造了 VaultScope，绕过了认证上下文（ADR-010 T-1）：\n  %s\n"+
				"vault 范围只能来自认证结果——自造一个等于把跨租户隔离拆掉",
			strings.Join(offenders, "\n  "))
	}
}

// 业务代码不得手写 vault_id 的 SQL 条件：那说明它在自己拼范围，
// 而不是通过 VaultScope 拿到已认证的范围。
func TestNoHandwrittenVaultIDPredicatesOutsideDB(t *testing.T) {
	root := repoRoot(t)
	sqlRe := regexp.MustCompile(`vault_id\s*=\s*[?']`)

	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil //nolint:nilerr
		}
		rel, _ := filepath.Rel(root, path)
		// db 包是这些查询的实现处；测试文件豁免
		if strings.HasPrefix(rel, filepath.Join("internal", "db")) || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil //nolint:nilerr
		}
		if sqlRe.Match(data) {
			offenders = append(offenders, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf(
			"以下文件在 db 包之外手写了 vault_id 条件：\n  %s\n"+
				"请改用带 VaultScope 参数的 db 函数——手写条件漏一次就是一个跨租户漏洞",
			strings.Join(offenders, "\n  "))
	}
}

// 零值 VaultScope 必须被所有按租户划分的查询硬拒。
//
// 「退化为默认租户」是绝对不能接受的：那会把一个「忘了取范围」的编程错误
// 变成静默的跨租户访问——而且测试还会通过。
func TestZeroScopeIsRejected(t *testing.T) {
	database := openTestDB(t)
	var zero db.VaultScope
	if zero.Valid() {
		t.Fatal("零值 VaultScope 必须是无效的")
	}

	if _, err := db.GetVault(database, zero); err != db.ErrVaultScopeMissing {
		t.Fatalf("GetVault 必须拒绝零值范围，得到 %v", err)
	}
	if _, _, err := db.RoleOf(database, zero, "u1"); err != db.ErrVaultScopeMissing {
		t.Fatalf("RoleOf 必须拒绝零值范围，得到 %v", err)
	}
	if _, err := db.ListMembers(database, zero); err != db.ErrVaultScopeMissing {
		t.Fatalf("ListMembers 必须拒绝零值范围，得到 %v", err)
	}
	if err := db.RemoveMembership(database, zero, "u1"); err != db.ErrVaultScopeMissing {
		t.Fatalf("RemoveMembership 必须拒绝零值范围，得到 %v", err)
	}
	if err := db.AppendAudit(database, zero, "a", "b", ""); err != db.ErrVaultScopeMissing {
		t.Fatalf("AppendAudit 必须拒绝零值范围，得到 %v", err)
	}
	if err := db.RecordKeyEpoch(database, zero, 2, "x"); err != db.ErrVaultScopeMissing {
		t.Fatalf("RecordKeyEpoch 必须拒绝零值范围，得到 %v", err)
	}
}

// 成员关系必须严格按 Vault 隔离：A 的成员身份不得在 B 里生效。
func TestMembershipIsScopedPerVault(t *testing.T) {
	database := openTestDB(t)
	a := db.ScopeFromAuth("vault-a")
	b := db.ScopeFromAuth("vault-b")

	for _, v := range []struct {
		id    string
		scope db.VaultScope
	}{{"vault-a", a}, {"vault-b", b}} {
		if err := db.InsertVault(database, &db.Vault{
			VaultID: v.id, OwnerID: "owner", Secret: []byte("secret-" + v.id),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpsertMembership(database, &db.Membership{
		UserID: "alice", VaultID: "vault-a", Role: db.RoleEditor,
	}); err != nil {
		t.Fatal(err)
	}

	if role, ok, err := db.RoleOf(database, a, "alice"); err != nil || !ok || role != db.RoleEditor {
		t.Fatalf("alice 在 vault-a 应当是 editor：%v %v %v", role, ok, err)
	}
	// 关键断言：同一个用户在另一个 Vault 里不是成员
	if _, ok, err := db.RoleOf(database, b, "alice"); err != nil || ok {
		t.Fatal("alice 不是 vault-b 的成员，却查到了角色——跨租户越权")
	}
	members, err := db.ListMembers(database, b)
	if err != nil || len(members) != 0 {
		t.Fatalf("vault-b 不应有任何成员：%v %v", members, err)
	}
}

// 角色能力矩阵（§10.4）。
func TestRoleCapabilities(t *testing.T) {
	cases := []struct {
		role  db.Role
		write bool
		admin bool
	}{
		{db.RoleOwner, true, true},
		{db.RoleAdmin, true, true},
		{db.RoleEditor, true, false},
		{db.RoleReader, false, false},
	}
	for _, c := range cases {
		if c.role.CanWrite() != c.write {
			t.Fatalf("%s.CanWrite() 应为 %v", c.role, c.write)
		}
		if c.role.CanAdmin() != c.admin {
			t.Fatalf("%s.CanAdmin() 应为 %v", c.role, c.admin)
		}
	}
	// reader 绝不能写：这是最容易被「顺手放开」的一条
	if db.RoleReader.CanWrite() {
		t.Fatal("reader 不得有写权限")
	}
}

// Vault secret 是 blobID 的域分隔密钥，绝不能为空——
// 空 secret 会让 HMAC 退化，跨租户去重的存在性泄露就回来了。
func TestVaultRequiresSecret(t *testing.T) {
	database := openTestDB(t)
	if err := db.InsertVault(database, &db.Vault{VaultID: "v1", OwnerID: "o"}); err == nil {
		t.Fatal("没有 secret 的 Vault 必须被拒绝")
	}
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// 本测试位于 internal/db，仓库根在上两级
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// blobID 域分隔的可执行约束（v0.16.0 / §10.3、ADR-010 §4）。
//
// 域化把「同一份内容在别的 Vault 里叫什么」变成一个只有服务端算得出的值。
// 只要有一条路径能让请求方问出这个值，或者拿到 vaultSecret，
// 被关掉的那个跨租户存在性预言机就原样回来了。

// TestVaultSecretNeverLeavesTheServer 禁止 vaultSecret 流向 HTTP 层。
//
// 判据要精确：仓库里还有别的 "secret"（一次性注册凭据、S3 的 secretAccessKey），
// 它们与本条无关。真正要盯的是 db.Vault.Secret 这一个字段——
// 拿到它就能自行算出该 Vault 里任意内容的 blobID。
func TestVaultSecretNeverLeavesTheServer(t *testing.T) {
	root := repoRoot(t)

	// 1) Vault 不是线格式类型：带上 json tag 就意味着有人打算把它整个发出去
	def, err := os.ReadFile(filepath.Join(root, "internal", "db", "tenancy.go"))
	if err != nil {
		t.Fatal(err)
	}
	vaultDef := regexp.MustCompile(`(?s)type Vault struct \{.*?\n\}`).Find(def)
	if vaultDef == nil {
		t.Fatal("找不到 db.Vault 定义")
	}
	if regexp.MustCompile("`json:").Match(vaultDef) {
		t.Fatal("db.Vault 带上了 json tag —— 它是服务端内部类型，不得被序列化发出")
	}

	// 2) HTTP 层不得触碰 secret：取 Vault、生成 secret 都不该在那里发生
	reachRe := regexp.MustCompile(`db\.GetVault\(|db\.EnsureVaultSecret\(|vaultSecret`)
	var offenders []string
	err = filepath.Walk(filepath.Join(root, "internal", "api"),
		func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil //nolint:nilerr
			}
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil //nolint:nilerr
			}
			if reachRe.Match(data) {
				rel, _ := filepath.Rel(root, path)
				offenders = append(offenders, rel)
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("HTTP 层触碰了 vaultSecret：%v —— "+
			"泄露它等于让攻击者能自行算出别的 Vault 的 blobID", offenders)
	}
}

// TestBlobIDLookupIsNotReachableFromHTTP 禁止把「内容哈希 → blobID」接到处理器上。
//
// BlobIDOf 是给运维工具和测试用的。一旦它出现在 internal/api 里，
// 请求方就能拿任意内容去问「这个 Vault 里有没有」——正是 §10.3 要消灭的能力。
func TestBlobIDLookupIsNotReachableFromHTTP(t *testing.T) {
	root := repoRoot(t)
	apiDir := filepath.Join(root, "internal", "api")
	callRe := regexp.MustCompile(`\.BlobIDOf\(|storage\.BlobIDFor\(`)

	var offenders []string
	err := filepath.Walk(apiDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil //nolint:nilerr
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil //nolint:nilerr
		}
		if callRe.Match(data) {
			rel, _ := filepath.Rel(root, path)
			offenders = append(offenders, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("HTTP 层出现了 blobID 查询：%v —— "+
			"这会让请求方能探测「本 Vault 是否已有某份内容」，存在性预言机就回来了", offenders)
	}
}

// TestBlobStorageIDIsAlwaysDomainSeparated 禁止业务代码再拿裸 contentHash 当存储 id。
func TestBlobStorageIDIsAlwaysDomainSeparated(t *testing.T) {
	root := repoRoot(t)
	// 老写法：Commit(tmp, hash, ...) 用同一个值既当文件名又当期望哈希
	legacyRe := regexp.MustCompile(`blobs\.Commit\(|\.VerifyHash\(`)

	var offenders []string
	for _, pkg := range []string{"internal/sync", "internal/api"} {
		err := filepath.Walk(filepath.Join(root, filepath.FromSlash(pkg)),
			func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
					return nil //nolint:nilerr
				}
				if strings.HasSuffix(path, "_test.go") {
					return nil
				}
				data, rerr := os.ReadFile(path)
				if rerr != nil {
					return nil //nolint:nilerr
				}
				if legacyRe.Match(data) {
					rel, _ := filepath.Rel(root, path)
					offenders = append(offenders, rel)
				}
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("仍在用「文件名即内容哈希」的老接口：%v —— "+
			"请改用 CommitAs / VerifyContent，把存储 id 与期望哈希分开传", offenders)
	}
}
