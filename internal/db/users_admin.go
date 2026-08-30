package db

import (
	"database/sql"
	"fmt"
)

// 用户管理（v0.18 / v11 设计 §5.7）。仅管理员端点使用。

// UserAccount 是管理列表的一行：账号 + 专属 Vault 的概要。
// 不含任何凭据材料——Token 哈希都不出库（管理员也拿不到，见 users.go 包注释）。
type UserAccount struct {
	UserID     string
	Name       string
	IsAdmin    bool
	Disabled   bool
	CreatedAt  int64
	LastSeenAt int64
	VaultID    string
	// Vaults：名下仓库数（v0.19 多仓库）
	Vaults  int
	Devices int
	// Objects / BytesUsed：live 对象数与其内容字节和（不含历史与填充差额；
	// 管理员本来就能看磁盘，这不是新的泄露面）
	Objects   int64
	BytesUsed int64
}

// ListUserAccounts 返回全部用户及概要（管理列表）。
func ListUserAccounts(d *sql.DB) ([]UserAccount, error) {
	rows, err := d.Query(`
		SELECT u.user_id, u.name, u.is_admin, u.disabled, u.created_at, COALESCE(u.last_seen_at, 0),
		       COALESCE(m.vault_id, '')
		  FROM users u
		  LEFT JOIN memberships m ON m.user_id = u.user_id AND m.role = 'owner'
		 ORDER BY u.created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserAccount
	for rows.Next() {
		var a UserAccount
		var isAdmin, disabled int
		if err := rows.Scan(&a.UserID, &a.Name, &isAdmin, &disabled, &a.CreatedAt, &a.LastSeenAt, &a.VaultID); err != nil {
			return nil, err
		}
		a.IsAdmin = isAdmin != 0
		a.Disabled = disabled != 0
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		a := &out[i]
		if err := d.QueryRow(`SELECT COUNT(*) FROM devices WHERE user_id = ? AND revoked = 0`,
			a.UserID).Scan(&a.Devices); err != nil {
			return nil, err
		}
		// v0.19：聚合该用户全部仓库的统计（Vaults 数、总对象、总字节）
		if err := d.QueryRow(`SELECT COUNT(*) FROM memberships WHERE user_id = ? AND role = 'owner'`,
			a.UserID).Scan(&a.Vaults); err != nil {
			return nil, err
		}
		if err := d.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size), 0) FROM file_heads WHERE vault_id IN
			(SELECT vault_id FROM memberships WHERE user_id = ? AND role = 'owner')`,
			a.UserID).Scan(&a.Objects, &a.BytesUsed); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DeleteUserCascade 删除用户与其专属 Vault 的全部数据行（单事务）。
// 返回该 Vault 曾引用的全部 blobID 与分享 id——调用方在事务提交后
// 清理磁盘密文并把 blob 交给 GC 判定（blobID 已按 Vault 域化，
// 别的租户不可能引用同一个 id）。
//
// 破坏性操作：调用方（API 层）必须完成两步确认。管理员不可删除自己。
func DeleteUserCascade(d *sql.DB, userID string) (blobIDs, shareIDs []string, vaultID string, err error) {
	u, err := GetUser(d, userID)
	if err != nil {
		return nil, nil, "", err
	}
	if u == nil {
		return nil, nil, "", sql.ErrNoRows
	}
	if u.IsAdmin {
		return nil, nil, "", fmt.Errorf("refusing to delete an admin account")
	}
	// v0.19：用户可能有多个仓库，全部级联（磁盘引用逐仓库收集）
	vaults, err := ListUserVaults(d, userID)
	if err != nil {
		return nil, nil, "", err
	}
	for i := range vaults {
		b, s, cerr := collectVaultArtifacts(d, vaults[i].VaultID)
		if cerr != nil {
			return nil, nil, "", cerr
		}
		blobIDs = append(blobIDs, b...)
		shareIDs = append(shareIDs, s...)
	}
	if len(vaults) > 0 {
		vaultID = vaults[0].VaultID
	}

	tx, err := d.Begin()
	if err != nil {
		return nil, nil, "", err
	}
	defer tx.Rollback() //nolint:errcheck
	for i := range vaults {
		if err := deleteVaultRowsTx(tx, vaults[i].VaultID); err != nil {
			return nil, nil, "", err
		}
	}
	if _, err := tx.Exec(`DELETE FROM devices WHERE user_id = ?`, userID); err != nil {
		return nil, nil, "", err
	}
	if _, err := tx.Exec(`DELETE FROM memberships WHERE user_id = ?`, userID); err != nil {
		return nil, nil, "", err
	}
	if _, err := tx.Exec(`DELETE FROM users WHERE user_id = ?`, userID); err != nil {
		return nil, nil, "", err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, "", err
	}
	return blobIDs, shareIDs, vaultID, nil
}

