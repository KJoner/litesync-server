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
	if _, err := d.Exec(`CREATE INDEX IF NOT EXISTS idx_files_canonical ON files(canonical_key)`); err != nil {
		return err
	}

	// v9.3（三阶段一期）：file_id——path 是可变展示属性，file_id 是稳定身份。
	// MOVE 之后 file_id 跟随内容走到新路径；二期 LSE3 的 AAD 将绑定它。
	hasID, err := columnExists(d, "files", "file_id")
	if err != nil {
		return err
	}
	if !hasID {
		if _, err := d.Exec(`ALTER TABLE files ADD COLUMN file_id TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if err := backfillFileIDs(d); err != nil {
		return err
	}
	if _, err := d.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_files_file_id ON files(file_id)`); err != nil {
		return err
	}

	// v9.3 二期：历史版本记录写入时的 file_id——LSE3 密文的 AAD 绑定 fileId，
	// 下载历史版本解密需要当时的身份（文件被删除重建后 id 会变）。
	// 旧行留空：LSE1/LSE2 版本的 AAD 绑定 path，无需 fileId。
	hasVID, err := columnExists(d, "file_versions", "file_id")
	if err != nil {
		return err
	}
	if !hasVID {
		if _, err := d.Exec(`ALTER TABLE file_versions ADD COLUMN file_id TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}

	// v9.3 三期：元数据加密。meta_enc = LSM1 加密的真实路径等元数据
	//（meta-encrypted 态下服务器可见的 path 只是 32-hex 伪名 = file_id）；
	// meta_generation = 元数据自身的单调世代（改名 = 元数据更新，与内容无关）；
	// changes.meta_generation 让客户端区分「内容变更」与「仅改名」。
	for _, m := range []struct{ table, column, ddl string }{
		{"files", "meta_enc", `ALTER TABLE files ADD COLUMN meta_enc TEXT NOT NULL DEFAULT ''`},
		{"files", "meta_generation", `ALTER TABLE files ADD COLUMN meta_generation INTEGER NOT NULL DEFAULT 0`},
		{"changes", "meta_generation", `ALTER TABLE changes ADD COLUMN meta_generation INTEGER NOT NULL DEFAULT 0`},
		{"repo_state", "meta_state", `ALTER TABLE repo_state ADD COLUMN meta_state TEXT NOT NULL DEFAULT 'plain'`},
	} {
		has, err := columnExists(d, m.table, m.column)
		if err != nil {
			return err
		}
		if !has {
			if _, err := d.Exec(m.ddl); err != nil {
				return err
			}
		}
	}
	return nil
}

// backfillFileIDs 为旧行生成随机 file_id（幂等；在建 UNIQUE 索引前执行）。
func backfillFileIDs(d *sql.DB) error {
	rows, err := d.Query(`SELECT path FROM files WHERE file_id = ''`)
	if err != nil {
		return err
	}
	var paths []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return err
		}
		paths = append(paths, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, p := range paths {
		id, err := NewFileID()
		if err != nil {
			return err
		}
		if _, err := d.Exec(`UPDATE files SET file_id = ? WHERE path = ?`, id, p); err != nil {
			return err
		}
	}
	return nil
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
