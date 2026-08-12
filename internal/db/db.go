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
//
// 注意：v5 → v6 的**数据**迁移不在这里执行——它需要读取 blob 信封头才能推断
// contentGeneration 与信封版本，因此由 cmd/obsync 在 storage 就绪后调用
// MigrateToV6。Open 只保证「表结构与列齐备」。
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
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := d.Exec(pragma); err != nil {
			d.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}

	if _, err := d.Exec(schema + integritySchema + gcSchema + checkpointSchema + tenancySchema + serverSecretsSchema + vaultRetentionSchema); err != nil {
		d.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	if err := migrateColumns(d); err != nil {
		d.Close()
		return nil, fmt.Errorf("migrate columns: %w", err)
	}
	if err := migrateJournalKindCheck(d); err != nil {
		d.Close()
		return nil, fmt.Errorf("migrate journal kind: %w", err)
	}
	// §10.2：repo_state 从单行实例级表改为按 Vault 划分。
	// 必须在 initRepoState 之前——后者要按 vault_id 查询。
	if err := migrateRepoStatePerVault(d); err != nil {
		d.Close()
		return nil, fmt.Errorf("migrate repo state: %w", err)
	}
	if err := initRepoState(d, LegacyDefaultScope()); err != nil {
		d.Close()
		return nil, fmt.Errorf("init repo state: %w", err)
	}
	return d, nil
}

// columnMigration 描述一次「缺列则补」的迁移。
type columnMigration struct {
	table, column, ddl string
	// legacyOnly：只对升级上来的旧库有意义（表不存在时跳过）
	legacyOnly bool
}

// migrateColumns 为旧库补齐新增列（CREATE TABLE IF NOT EXISTS 不会加列）。
//
// 分两类：
//   - v5 遗留表（files / changes / file_versions）：补齐 v5 末期的列，
//     好让 v5 → v6 迁移能完整读出它们；这些表在新库里不存在，直接跳过
//   - v6 表（repo_state / devices）：补齐 v6 新增的列
func migrateColumns(d *sql.DB) error {
	migrations := []columnMigration{
		// --- v5 遗留表（仅升级路径） ---
		{"files", "canonical_key", `ALTER TABLE files ADD COLUMN canonical_key TEXT NOT NULL DEFAULT ''`, true},
		{"files", "file_id", `ALTER TABLE files ADD COLUMN file_id TEXT NOT NULL DEFAULT ''`, true},
		{"files", "meta_enc", `ALTER TABLE files ADD COLUMN meta_enc TEXT NOT NULL DEFAULT ''`, true},
		{"files", "meta_generation", `ALTER TABLE files ADD COLUMN meta_generation INTEGER NOT NULL DEFAULT 0`, true},
		{"file_versions", "file_id", `ALTER TABLE file_versions ADD COLUMN file_id TEXT NOT NULL DEFAULT ''`, true},
		{"changes", "meta_generation", `ALTER TABLE changes ADD COLUMN meta_generation INTEGER NOT NULL DEFAULT 0`, true},

		// --- v6 新增列（ADR-003 / ADR-006） ---
		{"repo_state", "meta_state", `ALTER TABLE repo_state ADD COLUMN meta_state TEXT NOT NULL DEFAULT 'plain'`, false},
		{"repo_state", "schema_version", `ALTER TABLE repo_state ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 5`, false},
		{"repo_state", "format_epoch", `ALTER TABLE repo_state ADD COLUMN format_epoch INTEGER NOT NULL DEFAULT 1`, false},
		{"repo_state", "minimum_envelope_version", `ALTER TABLE repo_state ADD COLUMN minimum_envelope_version INTEGER NOT NULL DEFAULT 0`, false},
		{"repo_state", "meta_schema_version", `ALTER TABLE repo_state ADD COLUMN meta_schema_version INTEGER NOT NULL DEFAULT 1`, false},
		{"repo_state", "migration_id", `ALTER TABLE repo_state ADD COLUMN migration_id TEXT NOT NULL DEFAULT ''`, false},
		{"repo_state", "migration_owner_device_id", `ALTER TABLE repo_state ADD COLUMN migration_owner_device_id TEXT NOT NULL DEFAULT ''`, false},
		{"repo_state", "migration_lease_expires_at", `ALTER TABLE repo_state ADD COLUMN migration_lease_expires_at INTEGER NOT NULL DEFAULT 0`, false},
		{"repo_state", "migration_cutoff_sequence", `ALTER TABLE repo_state ADD COLUMN migration_cutoff_sequence INTEGER NOT NULL DEFAULT 0`, false},
		{"repo_state", "migration_target_format_epoch", `ALTER TABLE repo_state ADD COLUMN migration_target_format_epoch INTEGER NOT NULL DEFAULT 0`, false},
		{"repo_state", "migration_key_epoch", `ALTER TABLE repo_state ADD COLUMN migration_key_epoch INTEGER NOT NULL DEFAULT 0`, false},
		{"devices", "last_acked_sequence", `ALTER TABLE devices ADD COLUMN last_acked_sequence INTEGER NOT NULL DEFAULT 0`, false},

		// --- v0.15 新增列（§9.2 设备签名密钥） ---
		{"devices", "signing_public_key", `ALTER TABLE devices ADD COLUMN signing_public_key TEXT NOT NULL DEFAULT ''`, false},

		// --- v0.16 新增列（§10.4 成员权限与密钥轮换） ---
		// 设备必须知道自己属于哪个 (vault, user)，否则「移除成员时撤销他的设备」
		// 无从谈起。存量设备默认落在 default vault 的 owner 名下。
		{"devices", "vault_id", `ALTER TABLE devices ADD COLUMN vault_id TEXT NOT NULL DEFAULT 'default'`, false},
		{"devices", "user_id", `ALTER TABLE devices ADD COLUMN user_id TEXT NOT NULL DEFAULT ''`, false},
		// 移除成员后 Vault Key 必须由管理员设备重新封装；在那之前这里记着待办的 epoch
		{"vaults", "pending_rewrap_epoch", `ALTER TABLE vaults ADD COLUMN pending_rewrap_epoch INTEGER NOT NULL DEFAULT 0`, false},

		// --- v0.17 新增列（§15 第 3 步：迁移前必须能确认没有旧客户端） ---
		// 没有这一列，「检查设备列表，无旧客户端」这一步根本无法执行——
		// 而它是不可逆迁移的前置条件。
		{"devices", "client_version", `ALTER TABLE devices ADD COLUMN client_version TEXT NOT NULL DEFAULT ''`, false},
		{"devices", "client_protocol", `ALTER TABLE devices ADD COLUMN client_protocol INTEGER NOT NULL DEFAULT 0`, false},
	}

	for _, m := range migrations {
		exists, err := TableExists(d, m.table)
		if err != nil {
			return err
		}
		if !exists {
			if m.legacyOnly {
				continue
			}
			return fmt.Errorf("table %s missing", m.table)
		}
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

	// v5 遗留表的索引与 file_id 回填（迁移读取时需要 file_id 尽量完整）
	if exists, err := TableExists(d, "files"); err != nil {
		return err
	} else if exists {
		if err := backfillLegacyFileIDs(d); err != nil {
			return err
		}
		if _, err := d.Exec(`CREATE INDEX IF NOT EXISTS idx_files_canonical ON files(canonical_key)`); err != nil {
			return err
		}
	}
	return nil
}

// backfillLegacyFileIDs 为 v5 旧行生成随机 file_id（幂等）。
func backfillLegacyFileIDs(d *sql.DB) error {
	rows, err := d.Query(`SELECT path FROM files WHERE COALESCE(file_id, '') = ''`)
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
