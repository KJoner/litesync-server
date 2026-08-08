// Package db 负责 SQLite 的打开、初始化和元数据读写。
package db

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Open 打开（必要时创建）SQLite 数据库并初始化 Schema。
// 单用户场景：固定单连接即可，天然避免 SQLITE_BUSY。
func Open(path string) (*sql.DB, error) {
	d, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(1)
	d.SetConnMaxLifetime(0)
	d.SetConnMaxIdleTime(0)

	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
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
	return d, nil
}
