package db_test

// v5 → v6 数据迁移测试（ADR-001 §5 / ADR-003 §5 / ADR-002 §5）。
//
// 用真实的 v5 表结构构造样本库，覆盖 v10 计划 §4.9 dry-run 要求检查的各类情况：
// 多 revision 文件、真实删除、v5 元数据迁移遗留的假 tombstone、孤儿历史、
// 重复 fileId、以及 revision / contentGeneration 的连续性。

import (
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
	_ "modernc.org/sqlite"
)

// v5Schema 是 0.12.x 的表结构（与当时的 schema.go 一致）。
const v5Schema = `
CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL UNIQUE,
    content_hash TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    canonical_key TEXT NOT NULL DEFAULT '',
    file_id TEXT NOT NULL DEFAULT '',
    meta_enc TEXT NOT NULL DEFAULT '',
    meta_generation INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE changes (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    revision INTEGER NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('upsert','delete')),
    content_hash TEXT,
    created_at INTEGER NOT NULL,
    meta_generation INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE file_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    revision INTEGER NOT NULL,
    blob_id TEXT,
    content_hash TEXT,
    size INTEGER NOT NULL,
    mtime INTEGER NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('upsert','delete','restore','merge')),
    device_id TEXT,
    created_at INTEGER NOT NULL,
    file_id TEXT NOT NULL DEFAULT '',
    UNIQUE(path, revision)
);
CREATE TABLE vault_meta (
    key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE repo_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    repo_epoch TEXT NOT NULL,
    head_sequence INTEGER NOT NULL,
    min_retained_sequence INTEGER NOT NULL DEFAULT 0,
    encryption_state TEXT NOT NULL DEFAULT 'plaintext',
    key_epoch INTEGER NOT NULL DEFAULT 0,
    meta_state TEXT NOT NULL DEFAULT 'plain'
);
INSERT INTO repo_state (id, repo_epoch, head_sequence, min_retained_sequence, encryption_state, key_epoch)
VALUES (1, 'epoch-v5', 9, 0, 'encrypted', 2);
`

// fakeProbe 模拟 blob 存储：所有内容都是 LSE3，generation 由 hash 后缀决定。
type fakeProbe struct{ missing map[string]bool }

func (p fakeProbe) Has(h string) bool { return !p.missing[h] }

func (p fakeProbe) EnvelopeVersion(h string) int64 {
	if h == "" || p.missing[h] {
		return 0
	}
	return 3
}

func (p fakeProbe) ContentGeneration(h string) (int64, bool) {
	switch h {
	case "hash-a3":
		return 3, true
	case "hash-b1":
		return 1, true
	case "hash-del":
		return 1, true
	}
	return 0, false
}

func (p fakeProbe) KeyEpoch(h string) (int64, bool) {
	if p.EnvelopeVersion(h) == 3 {
		return 2, true
	}
	return 0, false
}

// buildV5DB 构造一个含各类边角情况的 v5 样本库。
func buildV5DB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sync.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(v5Schema); err != nil {
		t.Fatal(err)
	}

	exec := func(q string, args ...any) {
		if _, err := raw.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		idA    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		idB    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		idDel  = "dddddddddddddddddddddddddddddddd"
		idTomb = "cccccccccccccccccccccccccccccccc"
	)
	// live：编辑过 3 次的笔记（revision 必须原样保留）
	exec(`INSERT INTO files (path, content_hash, size, mtime, revision, deleted, created_at, updated_at, canonical_key, file_id)
	      VALUES ('笔记/日记.md', 'hash-a3', 30, 1700, 3, 0, 100, 300, '笔记/日记.md', ?)`, idA)
	// live：附件
	exec(`INSERT INTO files (path, content_hash, size, mtime, revision, deleted, created_at, updated_at, canonical_key, file_id)
	      VALUES ('img.png', 'hash-b1', 10, 1700, 1, 0, 110, 110, 'img.png', ?)`, idB)
	// 真实删除：tombstone 必须进台账并保留防复活锚点
	exec(`INSERT INTO files (path, content_hash, size, mtime, revision, deleted, created_at, updated_at, canonical_key, file_id)
	      VALUES ('gone.md', 'hash-del', 5, 1700, 4, 1, 120, 400, 'gone.md', ?)`, idDel)
	// v5 元数据迁移/MOVE 遗留的**假** tombstone：当时新造了 tombID，名下没有历史
	exec(`INSERT INTO files (path, content_hash, size, mtime, revision, deleted, created_at, updated_at, canonical_key, file_id)
	      VALUES ('img.png.old', 'hash-b1', 10, 1700, 2, 1, 110, 200, 'img.png.old', ?)`, idTomb)

	// 历史：A 的 3 个版本 + gone.md 的 3 个版本（含删除记录）
	for _, v := range []struct {
		path string
		rev  int64
		hash string
		act  string
	}{
		{"笔记/日记.md", 1, "hash-a1", "upsert"},
		{"笔记/日记.md", 2, "hash-a2", "upsert"},
		{"笔记/日记.md", 3, "hash-a3", "upsert"},
		{"img.png", 1, "hash-b1", "upsert"},
		{"gone.md", 3, "hash-del", "upsert"},
		{"gone.md", 4, "", "delete"},
	} {
		exec(`INSERT INTO file_versions (path, revision, blob_id, content_hash, size, mtime, action, device_id, created_at)
		      VALUES (?, ?, ?, ?, 10, 1700, ?, 'dev', 100)`, v.path, v.rev, v.hash, v.hash, v.act)
	}
	// 孤儿历史：路径在 files 里完全不存在 → 必须被报告，绝不静默丢弃
	exec(`INSERT INTO file_versions (path, revision, blob_id, content_hash, size, mtime, action, device_id, created_at)
	      VALUES ('vanished.md', 1, 'hash-x', 'hash-x', 10, 1700, 'upsert', 'dev', 100)`)

	exec(`INSERT INTO changes (sequence, path, revision, action, content_hash, created_at)
	      VALUES (9, '笔记/日记.md', 3, 'upsert', 'hash-a3', 300)`)
	return path
}

func openMigrated(t *testing.T, path string) *sql.DB {
	t.Helper()
	d, err := db.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestV6MigrationDryRun(t *testing.T) {
	path := buildV5DB(t)
	d := openMigrated(t, path)

	need, err := db.NeedsV6Migration(d)
	if err != nil || !need {
		t.Fatalf("NeedsV6Migration = %v %v, want true", need, err)
	}

	report, err := db.DryRunV6Migration(d, fakeProbe{})
	if err != nil {
		t.Fatal(err)
	}
	if report.LiveObjects != 2 {
		t.Fatalf("liveObjects = %d, want 2", report.LiveObjects)
	}
	// 两条删除记录都保留（绝不静默丢弃）。gone.md 名下有历史 → 真实删除；
	// img.png.old 名下没有任何历史 → 疑似 v5 迁移/MOVE 遗留的假删除，
	// 保留但标记 needs_review 供人工核对（ADR-002 §5）
	if report.Tombstones != 2 {
		t.Fatalf("tombstones = %d, want 2 (none may be dropped)", report.Tombstones)
	}
	if report.PseudoTombstones != 1 || report.NeedsReview != 1 {
		t.Fatalf("pseudo = %d, needsReview = %d, want 1/1", report.PseudoTombstones, report.NeedsReview)
	}
	if report.OrphanVersions != 1 {
		t.Fatalf("orphanVersions = %d, want 1 (vanished.md)", report.OrphanVersions)
	}
	// 全部内容都是 LSE3 → 信封下限推断为 3；meta_state=plain → formatEpoch 1
	if report.InferredEnvelope != db.EnvelopeLSE3 || report.InferredFormat != 1 {
		t.Fatalf("inferred envelope/format = %d/%d", report.InferredEnvelope, report.InferredFormat)
	}
	// dry-run 只读：不得改动任何东西
	if need, _ := db.NeedsV6Migration(d); !need {
		t.Fatal("dry-run must not migrate")
	}
	var n int
	d.QueryRow(`SELECT COUNT(*) FROM file_heads`).Scan(&n) //nolint:errcheck
	if n != 0 {
		t.Fatalf("dry-run wrote %d heads", n)
	}
}

func TestV6MigrationPreservesIdentityAndHistory(t *testing.T) {
	path := buildV5DB(t)
	d := openMigrated(t, path)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	report, err := db.MigrateToV6(d, fakeProbe{}, logger)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if report == nil {
		t.Fatal("migration report missing")
	}

	// ---- revision / generation 连续性（INV-05 / v10 计划 §4.2） ----
	const idA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	head, err := db.GetHead(d, idA)
	if err != nil || head == nil {
		t.Fatalf("head A = %v %v", head, err)
	}
	if head.Revision != 3 {
		t.Fatalf("migration reset revision: %d, want 3", head.Revision)
	}
	if head.ContentGeneration != 3 {
		t.Fatalf("contentGeneration = %d, want 3", head.ContentGeneration)
	}
	if head.Pseudonym != "笔记/日记.md" {
		t.Fatalf("pseudonym = %q", head.Pseudonym)
	}
	if head.EnvelopeVersion != 3 || head.KeyEpoch != 2 {
		t.Fatalf("envelope/keyEpoch = %d/%d", head.EnvelopeVersion, head.KeyEpoch)
	}

	// ---- 历史按 fileId 归属，全部保留 ----
	versions, err := db.ListVersions(d, idA)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 3 {
		t.Fatalf("history = %d versions, want 3", len(versions))
	}
	for _, v := range versions {
		if v.FileID != idA {
			t.Fatalf("history row not attributed to the object: %+v", v)
		}
	}

	// ---- 删除记录进台账，防复活锚点完整（INV-06） ----
	const idDel = "dddddddddddddddddddddddddddddddd"
	tomb, err := db.GetTombstone(d, idDel)
	if err != nil || tomb == nil {
		t.Fatalf("tombstone = %v %v", tomb, err)
	}
	if tomb.DeletionRevision != 4 {
		t.Fatalf("deletionRevision = %d, want 4", tomb.DeletionRevision)
	}
	if tomb.PriorContentHash != "hash-del" {
		t.Fatalf("priorContentHash = %q, want the pre-delete content hash", tomb.PriorContentHash)
	}
	if tomb.LastPseudonym != "gone.md" {
		t.Fatalf("lastPseudonym = %q", tomb.LastPseudonym)
	}
	if state, _ := db.ObjectState(d, idDel); state != db.ObjectDeleted {
		t.Fatalf("object state = %q, want deleted", state)
	}
	if tomb.NeedsReview {
		t.Fatal("a real deletion (with history) must not be flagged for review")
	}
	// 疑似假删除同样被保留，但带上了 needs_review 标记
	const idTomb = "cccccccccccccccccccccccccccccccc"
	suspect, err := db.GetTombstone(d, idTomb)
	if err != nil || suspect == nil {
		t.Fatalf("suspect tombstone must be kept, not dropped: %v %v", suspect, err)
	}
	if !suspect.NeedsReview {
		t.Fatal("a tombstone with no history must be flagged for review")
	}

	// ---- 仓库状态：信封下限与 schema 版本已就位 ----
	rs, err := db.GetRepoState(d, db.LegacyDefaultScope())
	if err != nil {
		t.Fatal(err)
	}
	if rs.SchemaVersion != db.SchemaVersion {
		t.Fatalf("schemaVersion = %d", rs.SchemaVersion)
	}
	if rs.MinimumEnvelopeVersion != db.EnvelopeLSE3 {
		t.Fatalf("minimumEnvelopeVersion = %d, want 3", rs.MinimumEnvelopeVersion)
	}
	// changes 作废：旧游标必须重新对账
	if rs.MinRetainedSequence < rs.HeadSequence {
		t.Fatalf("minRetainedSequence = %d, head = %d (old cursors must resync)",
			rs.MinRetainedSequence, rs.HeadSequence)
	}

	// ---- 旧表只读保留（回滚窗口），原表已让位 ----
	for _, tbl := range []string{"v5_files", "v5_changes", "v5_file_versions"} {
		if ok, _ := db.TableExists(d, tbl); !ok {
			t.Fatalf("%s must be kept for rollback", tbl)
		}
	}
	for _, tbl := range []string{"files", "changes", "file_versions"} {
		if ok, _ := db.TableExists(d, tbl); ok {
			t.Fatalf("%s must have been renamed away", tbl)
		}
	}

	// ---- 幂等：再次调用是 no-op ----
	if need, _ := db.NeedsV6Migration(d); need {
		t.Fatal("migration must not be needed twice")
	}
	again, err := db.MigrateToV6(d, fakeProbe{}, logger)
	if err != nil || again != nil {
		t.Fatalf("second migration = %v %v, want no-op", again, err)
	}

	// ---- finalize：显式确认后删除旧表 ----
	if err := db.FinalizeV6Migration(d); err != nil {
		t.Fatal(err)
	}
	if ok, _ := db.TableExists(d, "v5_files"); ok {
		t.Fatal("finalize must drop the legacy tables")
	}
}

// 迁移中断后可续跑：journal 已 done 的条目不会重做，未完成的继续。
// 覆盖 INV-11：所有迁移必须可恢复、可重复、幂等。
// 中途中断后续跑，结果必须与一次跑完等价。
func TestV6MigrationResumable(t *testing.T) {
	path := buildV5DB(t)
	d := openMigrated(t, path)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if _, err := db.MigrateToV6(d, fakeProbe{}, logger); err != nil {
		t.Fatal(err)
	}
	// 模拟「迁移跑到一半崩溃」：把 schema 版本退回去、journal 保留、
	// 旧表改回原名，然后重跑——已 done 的条目不得产生重复历史
	if _, err := d.Exec(`ALTER TABLE v5_files RENAME TO files`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`ALTER TABLE v5_file_versions RENAME TO file_versions`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`ALTER TABLE v5_changes RENAME TO changes`); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSchemaVersion(d, db.LegacyDefaultScope(), 5); err != nil {
		t.Fatal(err)
	}

	if _, err := db.MigrateToV6(d, fakeProbe{}, logger); err != nil {
		t.Fatalf("resume: %v", err)
	}
	const idA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	versions, err := db.ListVersions(d, idA)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 3 {
		t.Fatalf("resumed migration duplicated history: %d versions, want 3", len(versions))
	}
	head, _ := db.GetHead(d, idA)
	if head == nil || head.Revision != 3 {
		t.Fatalf("resumed migration changed the head: %+v", head)
	}
}

// 全新库不触发迁移。
func TestV6MigrationSkippedOnFreshDB(t *testing.T) {
	d := openMigrated(t, filepath.Join(t.TempDir(), "fresh.db"))
	if need, err := db.NeedsV6Migration(d); err != nil || need {
		t.Fatalf("fresh db needs migration = %v %v", need, err)
	}
	rs, err := db.GetRepoState(d, db.LegacyDefaultScope())
	if err != nil {
		t.Fatal(err)
	}
	if rs.SchemaVersion != db.SchemaVersion || rs.FormatEpoch != 1 {
		t.Fatalf("fresh repo state = %+v", rs)
	}
}
