package db

// 维护任务的 Vault 遍历（v0.18 / v11 设计 §5.9）。
//
// 维护（保留裁剪、changes 裁剪、scrub、GC 判定）是**实例级系统行为**，没有
// 请求上下文可取——这是 VaultScope「只能来自认证」原则的一个显式例外，
// 因此构造发生在 db 包内部（guard 测试的 allowlist 里），并且只暴露
// 「遍历全部」这一种形态：调用方拿到的是完整清单，没有挑选某个租户的入口。

// AllVaultScopes 返回实例上全部 Vault 的范围（至少包含 default）。
func AllVaultScopes(q dbtx) ([]VaultScope, error) {
	rows, err := q.Query(`SELECT vault_id FROM vaults ORDER BY vault_id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VaultScope
	seenDefault := false
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if id == DefaultVaultID {
			seenDefault = true
		}
		out = append(out, VaultScope{vaultID: id})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 尚未初始化 vaults 行的旧库：default 事实上存在（所有数据挂在它名下）
	if !seenDefault {
		out = append(out, LegacyDefaultScope())
	}
	return out, nil
}

// AnyVaultMigrating 报告是否有任何 Vault 的元数据状态处于迁移中。
// GC 的阻塞判定用：迁移在改写寻址与引用，任何一个租户在迁移，
// 全实例的「无引用」判断都不可信。
func AnyVaultMigrating(q dbtx) (bool, error) {
	var n int64
	err := q.QueryRow(`SELECT COUNT(*) FROM repo_state
		WHERE meta_state NOT IN (?, ?)`, MetaPlain, MetaEncrypted).Scan(&n)
	return n > 0, err
}

// ChangesPruneCandidate 计算某 Vault 可裁剪到的 sequence 上界（0 = 无可裁剪）。
// 两个条件取更激进者：超龄（createdBefore）或超量（keepMax 条之外）。
func ChangesPruneCandidate(q dbtx, s VaultScope, createdBefore int64, keepMax int64) (int64, error) {
	if !s.Valid() {
		return 0, ErrVaultScopeMissing
	}
	deleteUpTo := int64(0)
	if createdBefore > 0 {
		var seq int64
		if err := q.QueryRow(
			`SELECT COALESCE(MAX(sequence), 0) FROM object_changes WHERE vault_id = ? AND created_at < ?`,
			s.ID(), createdBefore).Scan(&seq); err != nil {
			return 0, err
		}
		deleteUpTo = seq
	}
	if keepMax > 0 {
		var count int64
		if err := q.QueryRow(`SELECT COUNT(*) FROM object_changes WHERE vault_id = ?`, s.ID()).Scan(&count); err != nil {
			return 0, err
		}
		if count > keepMax {
			var seq int64
			if err := q.QueryRow(
				`SELECT sequence FROM object_changes WHERE vault_id = ? ORDER BY sequence DESC LIMIT 1 OFFSET ?`,
				s.ID(), keepMax).Scan(&seq); err != nil {
				return 0, err
			}
			if seq > deleteUpTo {
				deleteUpTo = seq
			}
		}
	}
	return deleteUpTo, nil
}

// DeleteChangesUpTo 删除某 Vault sequence ≤ upTo 的变更，返回删除行数。
// 调用方必须在同一事务里推进该 Vault 的 min_retained_sequence 水位线。
func DeleteChangesUpTo(q dbtx, s VaultScope, upTo int64) (int64, error) {
	if !s.Valid() {
		return 0, ErrVaultScopeMissing
	}
	res, err := q.Exec(`DELETE FROM object_changes WHERE vault_id = ? AND sequence <= ?`, s.ID(), upTo)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return n, nil
}

// ReleaseMigrationLease 清空某 Vault 的迁移租约持有者（过期接管用）。
func ReleaseMigrationLease(q dbtx, s VaultScope) error {
	if !s.Valid() {
		return ErrVaultScopeMissing
	}
	_, err := q.Exec(
		`UPDATE repo_state SET migration_owner_device_id = '', migration_lease_expires_at = 0
		 WHERE vault_id = ?`, s.ID())
	return err
}
