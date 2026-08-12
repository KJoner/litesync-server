package db

import (
	"database/sql"
	"strings"
)

// repo_state 按 Vault 划分（v0.16.0 / 计划书 §10.2）。
//
// v0.16 之前 repo_state 是一张单行表（`id INTEGER PRIMARY KEY CHECK (id = 1)`），
// 也就是**实例级**的。多租户下这不成立，而且不成立的方式是安静的：
//
//   - 一个租户从备份恢复、旋转 repoEpoch → 所有租户的游标一起作废；
//   - 一个租户写入推高 head_sequence → 别人的客户端追一个永远追不上的游标，
//     同时从这个数字里读出「别人今天写了多少」；
//   - 一个租户开始元数据迁移 → 所有租户的写入一起被冻结。
//
// 这些都不会报错。所以必须在结构上根治，而不是靠调用方记得带条件。
//
// SQLite 改不了主键也去不掉 CHECK，只能整表重建。重建在一个事务里完成：
// 要么整体切换，要么什么都没变。

// migrateRepoStatePerVault 把单行的 repo_state 重建成按 vault_id 划分的表。
// 新库（已经有 vault_id 列）直接返回。
func migrateRepoStatePerVault(d *sql.DB) error {
	has, err := columnExists(d, "repo_state", "vault_id")
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	// 没有 vault_id：这是 v0.16 之前的单行表。取出它的全部列，
	// 原样搬到 vault_id = 'default' 那一行——存量数据本来就全挂在默认租户下。
	cols, err := tableColumns(d, "repo_state")
	if err != nil {
		return err
	}
	if len(cols) == 0 {
		return nil // 表还不存在（不会发生，Open 里 schema 先执行）
	}
	carry := make([]string, 0, len(cols))
	for _, c := range cols {
		if c == "id" {
			continue // 单行表的主键，重建后由 vault_id 取代
		}
		carry = append(carry, c)
	}
	list := strings.Join(carry, ", ")

	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec(`
		CREATE TABLE repo_state_new (
		    vault_id TEXT PRIMARY KEY DEFAULT 'default',
		    repo_epoch TEXT NOT NULL,
		    head_sequence INTEGER NOT NULL,
		    min_retained_sequence INTEGER NOT NULL DEFAULT 0,
		    encryption_state TEXT NOT NULL DEFAULT 'plaintext'
		        CHECK (encryption_state IN ('plaintext','migrating','encrypted')),
		    key_epoch INTEGER NOT NULL DEFAULT 0,
		    meta_state TEXT NOT NULL DEFAULT 'plain'
		        CHECK (meta_state IN ('plain','migrating','verifying','encrypted')),
		    schema_version INTEGER NOT NULL DEFAULT 6,
		    format_epoch INTEGER NOT NULL DEFAULT 1,
		    minimum_envelope_version INTEGER NOT NULL DEFAULT 0,
		    meta_schema_version INTEGER NOT NULL DEFAULT 1,
		    migration_id TEXT NOT NULL DEFAULT '',
		    migration_owner_device_id TEXT NOT NULL DEFAULT '',
		    migration_lease_expires_at INTEGER NOT NULL DEFAULT 0,
		    migration_cutoff_sequence INTEGER NOT NULL DEFAULT 0,
		    migration_target_format_epoch INTEGER NOT NULL DEFAULT 0,
		    migration_key_epoch INTEGER NOT NULL DEFAULT 0
		)`); err != nil {
		return err
	}
	// 只搬旧表真的有的列：v5 升上来的库可能缺后加的那几个，
	// 由新表的 DEFAULT 补齐
	if _, err := tx.Exec(
		`INSERT INTO repo_state_new (vault_id, ` + list + `)
		 SELECT '` + DefaultVaultID + `', ` + list + ` FROM repo_state`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DROP TABLE repo_state`); err != nil {
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE repo_state_new RENAME TO repo_state`); err != nil {
		return err
	}
	return tx.Commit()
}

// tableColumns 返回表的列名（表不存在时返回空切片）。
func tableColumns(d *sql.DB, table string) ([]string, error) {
	rows, err := d.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}
