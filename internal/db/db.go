// Package db 负责 SQLite 的打开、初始化和元数据读写。
package db

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Open 打开（必要时创建）SQLite 数据库并初始化 Schema。
// 默认 synchronous=FULL（v9）：WAL 下 NORMAL 不保证掉电后已确认事务的持久性，
// 与「已确认就绝不能丢」的红线冲突；确有性能需要时用 OpenWithSync(path, false)。
// 单用户场景：固定单连接即可，天然避免 SQLITE_BUSY。
func Open(path string) (*sql.DB, error) {
	return OpenWithSync(path, true)
}

// OpenWithSync 打开数据库；syncFull=false 时使用 synchronous=NORMAL（牺牲掉电持久性）。
func OpenWithSync(path string, syncFull bool) (*sql.DB, error) {
	d, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(1)
	d.SetConnMaxLifetime(0)
	d.SetConnMaxIdleTime(0)

	synchronous := "PRAGMA synchronous=FULL"
	if !syncFull {
		synchronous = "PRAGMA synchronous=NORMAL"
	}
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		synchronous,
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := d.Exec(pragma); err != nil {
			d.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}

	if _, err := d.Exec(schema); err != nil {
		d.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	if err := migrateColumns(d); err != nil {
		d.Close()
		return nil, fmt.Errorf("migrate columns: %w", err)
	}
	if err := initRepoState(d); err != nil {
		d.Close()
		return nil, fmt.Errorf("init repo state: %w", err)
	}
	return d, nil
}

// migrateColumns 为旧库补齐新增列（CREATE TABLE IF NOT EXISTS 不会加列）。
func migrateColumns(d *sql.DB) error {
	has, err := columnExists(d, "files", "canonical_key")
	if err != nil {
		return err
	}
	if !has {
		if _, err := d.Exec(`ALTER TABLE files ADD COLUMN canonical_key TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	_, err = d.Exec(`CREATE INDEX IF NOT EXISTS idx_files_canonical ON files(canonical_key)`)
	return err
}

func columnExists(d *sql.DB, table, column string) (bool, error) {
	rows, err := d.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}
