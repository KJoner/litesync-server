package db_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
)

// UI v2 / I1：external_identities 新增 username（登录用户名快照）。升级上来的旧库在启动时补列，
// 存量映射原样保留（user_id、邮箱、显示名都不变），username 先是空串，下次登录时补上。
func TestIdentityUsernameColumnMigratesOldDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// 改动前的表结构与一条存量映射
	for _, stmt := range []string{
		`CREATE TABLE external_identities (
			issuer TEXT NOT NULL, subject TEXT NOT NULL, user_id TEXT NOT NULL,
			email TEXT NOT NULL DEFAULT '', email_verified INTEGER NOT NULL DEFAULT 0,
			display_name TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL,
			last_login_at INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (issuer, subject))`,
		`INSERT INTO external_identities VALUES ('https://id.example', 'sub-1', 'u-000000000001',
			'old@example.org', 1, '旧 姓名', 100, 200)`,
	} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	raw.Close()

	d, err := db.OpenSQLiteFile(path)
	if err != nil {
		t.Fatalf("opening a database from before the username column: %v", err)
	}
	defer d.Close()

	got, err := db.GetIdentity(d, "https://id.example", "sub-1")
	if err != nil || got == nil {
		t.Fatalf("existing mapping after migration: %v %v", got, err)
	}
	if got.UserID != "u-000000000001" || got.Email != "old@example.org" || got.DisplayName != "旧 姓名" || got.Username != "" {
		t.Fatalf("existing mapping changed by the migration: %+v", got)
	}

	// 下次登录刷新快照：补上用户名，映射本身不变
	if err := db.TouchIdentity(d, "https://id.example", "sub-1",
		db.IdentityProfile{Email: "old@example.org", EmailVerified: true, DisplayName: "新昵称", Username: "old@example.org"}, 300); err != nil {
		t.Fatal(err)
	}
	got, _ = db.GetIdentity(d, "https://id.example", "sub-1")
	if got.UserID != "u-000000000001" || got.Username != "old@example.org" || got.DisplayName != "新昵称" {
		t.Fatalf("after a login refresh: %+v", got)
	}
}
