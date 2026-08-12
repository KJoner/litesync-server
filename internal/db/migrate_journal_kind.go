package db

import (
	"database/sql"
	"strings"
)

// migration_journal.kind 的 CHECK 约束扩容（v0.16.0 / 计划书 §10.3）。
//
// v0.16.0 之前 kind 只允许 ('object','tombstone','version')——那时 journal 只服务
// 元数据加密迁移。blobID 域化迁移要按 **blob** 逐个记进度，因此需要 'blob'。
//
// SQLite 不能 ALTER 掉一个 CHECK，只能整表重建。CREATE TABLE IF NOT EXISTS 对
// 已存在的旧库是空操作，所以升级上来的库必须走这里，否则 blobID 迁移的第一条
// EnqueueJournal 就会撞上 CHECK 失败。
//
// 重建是安全的：journal 里只有迁移进度，没有用户内容；而且整个过程在一个事务里，
// 崩溃要么全成要么全不成。

// migrateJournalKindCheck 在旧库上重建 migration_journal 以放宽 kind 约束。
// 新库（CHECK 已含 'blob'）直接返回。
func migrateJournalKindCheck(d *sql.DB) error {
	var ddl string
	err := d.QueryRow(
		`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'migration_journal'`).Scan(&ddl)
	if err == sql.ErrNoRows {
		return nil // 表还没建（不会发生，Open 里 schema 先执行），无事可做
	}
	if err != nil {
		return err
	}
	if strings.Contains(ddl, "'blob'") {
		return nil // 已经是新约束
	}

	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	// 标准的 SQLite 表重建：建新表 → 拷数据 → 删旧表 → 改名。
	// 列顺序显式写出，不用 SELECT *——将来加列时才不会静默错位。
	const cols = `migration_id, vault_id, file_id, kind, source_format, target_format,
		stage, last_error, attempt_count, updated_at`
	if _, err := tx.Exec(`
		CREATE TABLE migration_journal_new (
		    migration_id TEXT NOT NULL,
		    vault_id TEXT NOT NULL DEFAULT 'default',
		    file_id TEXT NOT NULL,
		    kind TEXT NOT NULL CHECK (kind IN ('object','tombstone','version','blob')),
		    source_format TEXT NOT NULL DEFAULT '',
		    target_format TEXT NOT NULL DEFAULT '',
		    stage TEXT NOT NULL DEFAULT 'pending'
		        CHECK (stage IN ('pending','done','failed','skipped')),
		    last_error TEXT NOT NULL DEFAULT '',
		    attempt_count INTEGER NOT NULL DEFAULT 0,
		    updated_at INTEGER NOT NULL,
		    PRIMARY KEY (migration_id, vault_id, file_id, kind)
		)`); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO migration_journal_new (` + cols + `) SELECT ` + cols + ` FROM migration_journal`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DROP TABLE migration_journal`); err != nil {
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE migration_journal_new RENAME TO migration_journal`); err != nil {
		return err
	}
	return tx.Commit()
}
