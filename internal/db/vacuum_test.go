package db

// db.Vacuum 只重建 LiteSync 自己的表。
//
// 2026-11-21 CI（go-postgres 17.10）的 40P01：一个测试进程的擦除跑了不带表名的 `VACUUM FULL`（整库），在 pg_attribute
// 上等另一个测试进程尚未提交的建表事务，后者又在等 pg_attribute 的 RowExclusiveLock → deadlock detected。测试本来按
// schema 隔离，是这条整库语句穿透了隔离。这里在 PG 上断言：
//
//  1. 新建的库里每张表都是 LiteSync 自己的（Vacuum 不会漏掉任何一张）；
//  2. 只重写当前 schema 里 LiteSync 的表：同库另一个 schema 的表、同一 schema 里别的应用的表都不动；
//  3. 另一个 schema 里有未提交的建表事务时 Vacuum 不等它（整库 VACUUM FULL 会一直等到那个事务结束）。
//
// 不对应 INV 编号（测试隔离与运维安全）。
import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func openVacuumTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestVacuumRebuildsOnlyLiteSyncTables(t *testing.T) {
	a := openVacuumTestDB(t)
	own := ownTableNames()
	if len(own) < 20 || !own["file_heads"] || !own["revocation_deliveries"] {
		t.Fatalf("LiteSync table list taken from the schema DDL looks wrong: %v", own)
	}
	if !IsPostgres(a) {
		// SQLite：库文件里只有 LiteSync 的表，VACUUM 是事务性的整库重建
		rows, err := a.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var name string
			rows.Scan(&name) //nolint:errcheck
			if !own[name] {
				t.Errorf("table %q is not in LiteSync's own table list", name)
			}
		}
		rows.Close()
		if err := Vacuum(a); err != nil {
			t.Fatal(err)
		}
		return
	}

	b := openVacuumTestDB(t)
	schemaOf := func(d *sql.DB) string {
		var s string
		if err := d.QueryRow(`SELECT current_schema()`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	sa, sb := schemaOf(a), schemaOf(b)
	if sa == sb {
		t.Fatalf("two test databases share schema %s", sa)
	}

	// 1. 新建的库里每张表都是 LiteSync 自己的
	tables, err := ownTablesInCurrentSchema(b)
	if err != nil {
		t.Fatal(err)
	}
	var all int
	if err := b.QueryRow(`SELECT COUNT(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND c.relkind = 'r'`).Scan(&all); err != nil {
		t.Fatal(err)
	}
	if len(tables) != all || all < 20 {
		t.Fatalf("Vacuum would rewrite %d of the %d tables in a fresh schema", len(tables), all)
	}

	// 2. 只重写当前 schema 里 LiteSync 的表（VACUUM FULL 会换新的 relfilenode）
	if _, err := b.Exec(`CREATE TABLE other_app_notes (id BIGINT PRIMARY KEY, body TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	relfile := func(schema, table string) int64 {
		var n int64
		if err := b.QueryRow(`SELECT c.relfilenode FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = ? AND c.relname = ?`, schema, table).Scan(&n); err != nil {
			t.Fatalf("relfilenode of %s.%s: %v", schema, table, err)
		}
		return n
	}
	ownB, otherB, ownA := relfile(sb, "file_heads"), relfile(sb, "other_app_notes"), relfile(sa, "file_heads")
	if err := Vacuum(b); err != nil {
		t.Fatal(err)
	}
	if relfile(sb, "file_heads") == ownB {
		t.Fatal("LiteSync's own table was not rewritten by VACUUM FULL")
	}
	if relfile(sb, "other_app_notes") != otherB {
		t.Fatal("another application's table in the same schema was rewritten")
	}
	if relfile(sa, "file_heads") != ownA {
		t.Fatal("a table in another schema of the same database was rewritten: Vacuum is acting database-wide")
	}

	// 3. 另一个 schema 里有未提交的建表事务：Vacuum 不等它
	tx, err := a.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`CREATE TABLE vacuum_probe_open_ddl (id BIGINT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Vacuum(b) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		tx.Rollback() //nolint:errcheck
		<-done
		t.Fatal("Vacuum waited for another schema's uncommitted DDL transaction: it is acting database-wide (the CI 40P01 deadlock)")
	}
}
