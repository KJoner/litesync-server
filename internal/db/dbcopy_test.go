package db

// 跨方言复制与校验（批次 G / 迁移方案 M6、M7）的测试。
//
// 夹具是「通用填充」：对当前 schema 的**每一张表、每一列**按列类型造数据
//（含非 ASCII 文本、含 NUL 的二进制、可空列上的 NULL、显式自增 id），所以以后新增
// 的表/列会自动被这组测试覆盖，不必记得回来补夹具。
//
// 覆盖：INV-11（迁移可恢复、可重复、幂等：目标非空拒绝、已完成则只校验、源库只读）、
// INV-05（身份不随迁移重置：fileId / repo_epoch / 各世代逐字节保持，由逐表摘要与
// 每仓库摘要共同断言）、INV-02（世代单调：自增序列高水位不回退，id 永不复用）。

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// newBareSQLite：只有 schema、没有任何种子行的 SQLite 文件库。
func newBareSQLite(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bare.db")
	d, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	d.SetMaxOpenConns(1)
	if err := CreateSchemaOnly(d); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d, path
}

// freshPGTarget：一个全新的、只有 schema 的 PG schema（测试结束时删除）。
func freshPGTarget(t *testing.T) *sql.DB {
	t.Helper()
	base := testPostgresDSN()
	if base == "" {
		t.Skip("未设置 LITESYNC_TEST_PG_DSN：跳过需要真实 PostgreSQL 的跨方言用例")
	}
	raw := make([]byte, 6)
	rand.Read(raw) //nolint:errcheck
	schema := "c_" + hex.EncodeToString(raw)
	admin, err := OpenPostgresRaw(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	d, err := OpenPostgresRaw(WithSearchPath(base, schema))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Close()
		admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) //nolint:errcheck
		admin.Close()
	})
	if err := CreateSchemaOnly(d); err != nil {
		t.Fatal(err)
	}
	return d
}

type fillCol struct {
	colInfo
	nullable bool
}

func fillColumns(t *testing.T, d *sql.DB, table string) []fillCol {
	t.Helper()
	var rows *sql.Rows
	var err error
	if IsPostgres(d) {
		rows, err = d.Query(`SELECT column_name, data_type, is_nullable = 'YES' FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = ? ORDER BY ordinal_position`, table)
	} else {
		rows, err = d.Query(`SELECT name, type, "notnull" = 0 AND pk = 0 FROM pragma_table_info(?) ORDER BY cid`, table)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []fillCol
	for rows.Next() {
		var c fillCol
		var typ string
		if err := rows.Scan(&c.name, &typ, &c.nullable); err != nil {
			t.Fatal(err)
		}
		c.kind = kindOf(typ)
		out = append(out, c)
	}
	return out
}

// checkValues：带 CHECK 约束的列取一个合法值（列名在全 schema 里含义一致）。
var checkValues = map[string]string{
	"status": "queued", "kind": "object", "stage": "pending", "encryption_state": "plaintext",
	"meta_state": "plain", "object_state": "live", "action": "upsert", "role": "owner",
}

// fillGeneric 给每张表写 n 行按列类型合成的数据。
func fillGeneric(t *testing.T, d *sql.DB, n int) {
	t.Helper()
	tables, err := listTables(copySide{q: d, pg: IsPostgres(d)})
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		cols := fillColumns(t, d, table)
		names := make([]string, len(cols))
		ph := make([]string, len(cols))
		for j, c := range cols {
			names[j] = quoteIdent(c.name)
			ph[j] = "?"
		}
		stmt := `INSERT INTO ` + quoteIdent(table) + ` (` + strings.Join(names, ", ") + `) VALUES (` + strings.Join(ph, ", ") + `)`
		for i := 0; i < n; i++ {
			args := make([]any, len(cols))
			for j, c := range cols {
				switch {
				case c.nullable && i%3 == 2:
					args[j] = nil
				case c.name == "id" && c.kind == kindInt:
					args[j] = int64(i + 1)
				case checkValues[c.name] != "":
					args[j] = checkValues[c.name]
				case c.kind == kindInt:
					args[j] = int64(i*1000 + j)
				case c.kind == kindBlob:
					args[j] = []byte{0x00, 0xff, byte(i), byte(j)}
				case c.kind == kindReal:
					args[j] = float64(i) + 0.5
				default:
					args[j] = fmt.Sprintf("%s-%d-笔记/ノート", c.name, i)
				}
			}
			if _, err := d.Exec(stmt, args...); err != nil {
				t.Fatalf("fill %s row %d: %v", table, i, err)
			}
		}
	}
}

func mustCopy(t *testing.T, src, dst *sql.DB) *CopyReport {
	t.Helper()
	rep, err := CopyDatabase(src, dst)
	if err != nil {
		t.Fatalf("copy: %v (problems %v)", err, rep.Problems)
	}
	if !rep.OK || len(rep.Tables) == 0 {
		t.Fatalf("copy report not ok: %+v", rep)
	}
	for _, tr := range rep.Tables {
		if !tr.Match || tr.SourceRows != tr.TargetRows {
			t.Fatalf("table %s mismatch: %+v", tr.Table, tr)
		}
	}
	return rep
}

func TestCopyGenericSQLiteToSQLite(t *testing.T) {
	src, _ := newBareSQLite(t)
	fillGeneric(t, src, 5)
	// 自增高水位：删掉最大 id 那行，sqlite_sequence 仍记着 5
	if _, err := src.Exec(`DELETE FROM audit_events WHERE id = 5`); err != nil {
		t.Fatal(err)
	}
	dst, _ := newBareSQLite(t)
	rep := mustCopy(t, src, dst)
	if rep.TotalRows == 0 || len(rep.SourceVaults) == 0 {
		t.Fatalf("report should carry rows and per-vault summaries: %+v", rep)
	}
	if rep.TargetSeqHW["audit_events"] < 5 {
		t.Fatalf("sequence high-water regressed: %v", rep.TargetSeqHW)
	}

	// 幂等：再跑只校验
	if v, err := VerifyDatabases(src, dst); err != nil || !v.OK {
		t.Fatalf("verify-only after copy: %v %+v", err, v.Problems)
	}
	// 目标非空 → 拒绝再次导入
	if _, err := CopyDatabase(src, dst); !errors.Is(err, ErrTargetNotEmpty) {
		t.Fatalf("second copy must be refused as non-empty, got %v", err)
	}
	// id 永不复用：目标新插入的审计事件必须拿到 6
	var id int64
	if err := dst.QueryRow(`INSERT INTO audit_events (vault_id, actor, action, detail, at)
		VALUES ('v', 'a', 'x', '', 0) RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if id != 6 {
		t.Fatalf("new id after copy = %d, want 6 (id 5 was used before and must never be reused)", id)
	}
}

func TestCopyDetectsDivergence(t *testing.T) {
	src, _ := newBareSQLite(t)
	fillGeneric(t, src, 3)
	dst, _ := newBareSQLite(t)
	mustCopy(t, src, dst)
	if _, err := dst.Exec(`UPDATE file_heads SET content_generation = content_generation + 1 WHERE rowid = 1`); err != nil {
		t.Fatal(err)
	}
	rep, err := VerifyDatabases(src, dst)
	if err == nil || rep.OK {
		t.Fatal("a single changed value must fail verification")
	}
	found := false
	for _, tr := range rep.Tables {
		if tr.Table == "file_heads" && !tr.Match {
			found = true
		}
	}
	if !found {
		t.Fatalf("report must name the differing table: %+v", rep.Problems)
	}
}

func TestCopyRefusesOlderSourceSchema(t *testing.T) {
	src, _ := newBareSQLite(t)
	fillGeneric(t, src, 2)
	if _, err := src.Exec(`DROP TABLE mail_suppressions`); err != nil {
		t.Fatal(err)
	}
	dst, _ := newBareSQLite(t)
	if _, err := CopyDatabase(src, dst); !errors.Is(err, ErrSourceSchemaOlder) {
		t.Fatalf("older source must be refused with ErrSourceSchemaOlder, got %v", err)
	}
	if empty, n, err := TargetIsEmpty(dst); err != nil || !empty {
		t.Fatalf("refused copy must not write anything: %v %v", n, err)
	}
	if rep, err := DryRunCopy(src); !errors.Is(err, ErrSourceSchemaOlder) || len(rep.Problems) == 0 {
		t.Fatalf("dry-run must report the same problem: %v %+v", err, rep)
	}
}

func TestCopyLegacyV5TablesAreSkippedAndReported(t *testing.T) {
	src, _ := newBareSQLite(t)
	fillGeneric(t, src, 1)
	if _, err := src.Exec(`CREATE TABLE v5_files (path TEXT)`); err != nil {
		t.Fatal(err)
	}
	dst, _ := newBareSQLite(t)
	rep := mustCopy(t, src, dst)
	if len(rep.SkippedTables) != 1 || !strings.HasPrefix(rep.SkippedTables[0], "v5_files") {
		t.Fatalf("v5 rollback copy must be reported as skipped: %v", rep.SkippedTables)
	}
}

func TestDryRunIsReadOnly(t *testing.T) {
	src, path := newBareSQLite(t)
	fillGeneric(t, src, 4)
	src.Close()
	ro, err := OpenSQLiteReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if _, err := ro.Exec(`DELETE FROM file_heads`); err == nil {
		t.Fatal("source handle must reject writes (query_only)")
	}
	rep, err := DryRunCopy(ro)
	if err != nil || !rep.OK {
		t.Fatalf("dry-run: %v %+v", err, rep)
	}
	for _, tr := range rep.Tables {
		if tr.SourceRows != 4 {
			t.Fatalf("dry-run row count %s = %d, want 4", tr.Table, tr.SourceRows)
		}
	}
}

// 真实 PG：SQLite → PG → SQLite 往返，逐表摘要与每仓库摘要必须与原库完全一致。
func TestCopyRoundTripThroughPostgres(t *testing.T) {
	pg := freshPGTarget(t)
	src, _ := newBareSQLite(t)
	fillGeneric(t, src, 6)
	if _, err := src.Exec(`DELETE FROM audit_events WHERE id = 6`); err != nil {
		t.Fatal(err)
	}
	rep := mustCopy(t, src, pg)
	if rep.Direction != "sqlite->postgres" {
		t.Fatalf("direction = %s", rep.Direction)
	}
	if rep.TargetSeqHW["audit_events"] < 6 {
		t.Fatalf("PG identity high-water regressed: %v", rep.TargetSeqHW)
	}

	out := filepath.Join(t.TempDir(), "export.db")
	exp, err := ExportToSQLiteFile(pg, out)
	if err != nil || !exp.OK {
		t.Fatalf("export: %v %+v", err, exp)
	}
	back, err := OpenSQLiteReadOnly(out)
	if err != nil {
		t.Fatal(err)
	}
	defer back.Close()
	if v, err := VerifyDatabases(src, back); err != nil || !v.OK {
		t.Fatalf("round trip differs from the original: %v %+v", err, v.Problems)
	}

	// PG 上新分配的 id 必须越过源库的高水位（6 曾经用过）
	var id int64
	if err := pg.QueryRow(`INSERT INTO audit_events (vault_id, actor, action, detail, at)
		VALUES ('v', 'a', 'x', '', 0) RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if id <= 6 {
		t.Fatalf("PG reused id %d (<= source high-water 6)", id)
	}
}
