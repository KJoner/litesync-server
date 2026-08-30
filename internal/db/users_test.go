package db_test

// 用户 Token 落库与启动对账（v0.18 / v11 设计 §4.1）。
// 覆盖：EnsureAdminUser 三分支、SetUserToken 的世代语义、重置凭证登记规则。

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
)

func openUsersTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "sync.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestEnsureAdminUserReconcile(t *testing.T) {
	d := openUsersTestDB(t)
	envHash := db.HashToken("env-token-0123456789abcdef")

	// 首次启动：创建
	rec, err := db.EnsureAdminUser(d, envHash)
	if err != nil || rec != db.AdminTokenCreated {
		t.Fatalf("first = (%v, %v), want (Created, nil)", rec, err)
	}
	u, err := db.GetUser(d, db.AdminUserID)
	if err != nil || u == nil || !u.IsAdmin || u.TokenHash != envHash || u.TokenGeneration != 1 {
		t.Fatalf("admin row wrong: %+v err=%v", u, err)
	}

	// 重复启动：无变化
	if rec, err = db.EnsureAdminUser(d, envHash); err != nil || rec != db.AdminTokenUnchanged {
		t.Fatalf("second = (%v, %v), want (Unchanged, nil)", rec, err)
	}

	// 网页轮换后重启：以库为准，环境变量失效
	if _, err := db.SetUserToken(d, db.AdminUserID, db.HashToken("lsk_rotated")); err != nil {
		t.Fatal(err)
	}
	if rec, err = db.EnsureAdminUser(d, envHash); err != nil || rec != db.AdminTokenSuperseded {
		t.Fatalf("after rotate = (%v, %v), want (Superseded, nil)", rec, err)
	}
	if u, _ = db.GetUser(d, db.AdminUserID); u.TokenHash != db.HashToken("lsk_rotated") {
		t.Fatal("db hash must win over env")
	}

	// 认证按新哈希：旧 env 查不到、新的查得到
	if u, _ := db.GetUserByTokenHash(d, envHash); u != nil {
		t.Fatal("env token should no longer resolve")
	}
	if u, _ := db.GetUserByTokenHash(d, db.HashToken("lsk_rotated")); u == nil || u.UserID != db.AdminUserID {
		t.Fatal("rotated token should resolve to admin")
	}
}

func TestEnsureAdminUserAdoptsEmptyHash(t *testing.T) {
	d := openUsersTestDB(t)
	// v0.16 基座可能留下的空壳行（无 token_hash）
	if err := db.InsertUser(d, &db.User{UserID: db.AdminUserID, Name: "admin"}); err != nil {
		t.Fatal(err)
	}
	envHash := db.HashToken("seed-token-0123456789abcdef")
	rec, err := db.EnsureAdminUser(d, envHash)
	if err != nil || rec != db.AdminTokenAdopted {
		t.Fatalf("adopt = (%v, %v), want (Adopted, nil)", rec, err)
	}
	u, _ := db.GetUser(d, db.AdminUserID)
	if u.TokenHash != envHash || !u.IsAdmin {
		t.Fatalf("adopted row wrong: %+v", u)
	}
}

func TestSetUserTokenBumpsGeneration(t *testing.T) {
	d := openUsersTestDB(t)
	if _, err := db.EnsureAdminUser(d, db.HashToken("t0")); err != nil {
		t.Fatal(err)
	}
	gen, err := db.SetUserToken(d, db.AdminUserID, db.HashToken("t1"))
	if err != nil || gen != 2 {
		t.Fatalf("gen = (%d, %v), want (2, nil)", gen, err)
	}
	gen, err = db.SetUserToken(d, db.AdminUserID, db.HashToken("t2"))
	if err != nil || gen != 3 {
		t.Fatalf("gen = (%d, %v), want (3, nil)", gen, err)
	}
	// 不存在的用户：报错而不是静默 0 行
	if _, err := db.SetUserToken(d, "ghost", db.HashToken("x")); err == nil {
		t.Fatal("expected error for unknown user")
	}
}

func TestVaultResetAuthRules(t *testing.T) {
	d := openUsersTestDB(t)
	scope := db.LegacyDefaultScope()
	if _, err := db.EnsureVaultSecret(d, scope, "default"); err != nil {
		t.Fatal(err)
	}

	// 未登记：不强制，任何提交都放行
	enforced, ok, err := db.VerifyVaultResetAuth(d, scope, "")
	if err != nil || enforced || !ok {
		t.Fatalf("unregistered verify = (%v,%v,%v)", enforced, ok, err)
	}

	// 首登记 + 幂等
	if err := db.RegisterVaultResetAuth(d, scope, "keyA", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.RegisterVaultResetAuth(d, scope, "keyA", ""); err != nil {
		t.Fatalf("idempotent re-register: %v", err)
	}
	// 覆盖无 previous：拒
	if err := db.RegisterVaultResetAuth(d, scope, "keyB", ""); err != db.ErrResetAuthMismatch {
		t.Fatalf("overwrite = %v, want ErrResetAuthMismatch", err)
	}
	// 持旧值更新：允许
	if err := db.RegisterVaultResetAuth(d, scope, "keyB", "keyA"); err != nil {
		t.Fatal(err)
	}

	// 校验：错值拒、对值过、强制位如实
	if enforced, ok, _ := db.VerifyVaultResetAuth(d, scope, "keyA"); !enforced || ok {
		t.Fatalf("stale key verify = (%v,%v), want (true,false)", enforced, ok)
	}
	if enforced, ok, _ := db.VerifyVaultResetAuth(d, scope, "keyB"); !enforced || !ok {
		t.Fatalf("current key verify = (%v,%v), want (true,true)", enforced, ok)
	}
}
