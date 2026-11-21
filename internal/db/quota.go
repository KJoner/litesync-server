package db

import (
	"database/sql"
	"errors"
)

// 用户级配额（v0.20 公开化 / 需求 §12「配额和保留期」）。
//
// 口径：
//   - 存储：用户作为 owner 的全部仓库里，live 内容 + 非 HEAD 历史的字节数。
//     字节是服务器上的**密文**大小（含填充），与磁盘占用同口径。历史计入总量（需求 §12）——
//     删除对象保留下来的历史也算，它们仍占着磁盘；
//   - 仓库数：用户作为 owner 的仓库数；
//   - 覆盖值：users.quota_bytes / quota_vaults —— 0 = 跟随服务器默认，-1 = 不限，>0 = 指定值。
//
// 配额只拦**新增**：读取、导出、删除、清理历史永远可用（需求 §12：达到额度时
// 不能因无法写入而阻止读取现有资料）。

// QuotaUnlimited 覆盖值「不限」。
const QuotaUnlimited int64 = -1

// ErrUserNotFound：按 ID 找不到用户。
var ErrUserNotFound = errors.New("user not found")

// UserQuota 一个用户的配额覆盖值与是否实例管理员。
type UserQuota struct {
	Bytes  int64 // 0 = 跟随默认，-1 = 不限
	Vaults int64 // 0 = 跟随默认，-1 = 不限
	Admin  bool
}

// GetUserQuota 读取用户的配额覆盖值；用户不存在时返回零值（跟随默认）。
func GetUserQuota(q dbtx, userID string) (UserQuota, error) {
	var u UserQuota
	var admin int
	err := q.QueryRow(`SELECT quota_bytes, quota_vaults, is_admin FROM users WHERE user_id = ?`, userID).
		Scan(&u.Bytes, &u.Vaults, &admin)
	if errors.Is(err, sql.ErrNoRows) {
		return UserQuota{}, nil
	}
	u.Admin = admin != 0
	return u, err
}

// SetUserQuota 设置用户的配额覆盖值（管理员操作）。
func SetUserQuota(q dbtx, userID string, bytes, vaults int64) error {
	res, err := q.Exec(`UPDATE users SET quota_bytes = ?, quota_vaults = ? WHERE user_id = ?`, bytes, vaults, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// VaultOwner 返回仓库的 owner；没有 vaults 行（旧单仓实例的 default）时返回空串。
func VaultOwner(q dbtx, s VaultScope) (string, error) {
	var owner string
	err := q.QueryRow(`SELECT owner_id FROM vaults WHERE vault_id = ?`, s.ID()).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return owner, err
}

// OwnedVaultCount 用户作为 owner 的仓库数。
func OwnedVaultCount(q dbtx, userID string) (int64, error) {
	var n int64
	err := q.QueryRow(`SELECT COUNT(*) FROM memberships WHERE user_id = ? AND role = 'owner'`, userID).Scan(&n)
	return n, err
}

// UserStorageUsage 用户名下（owner）全部仓库的存储占用：live 内容 + 非 HEAD 历史。
//
// 不用相关子查询找「非 HEAD 版本」（大库上每次上传都要扫一遍）：
// 总量 = HEAD 字节 + 全部版本字节 − 与 HEAD 同 revision 的那条版本的字节。
// 未开启历史时版本表为空，结果退化为 HEAD 字节。
func UserStorageUsage(q dbtx, userID string) (int64, error) {
	var heads, versions, headVersions int64
	if err := q.QueryRow(`SELECT COALESCE(SUM(h.size), 0) FROM file_heads h
		JOIN vaults v ON v.vault_id = h.vault_id WHERE v.owner_id = ?`, userID).Scan(&heads); err != nil {
		return 0, err
	}
	if err := q.QueryRow(`SELECT COALESCE(SUM(o.size), 0) FROM object_versions o
		JOIN vaults v ON v.vault_id = o.vault_id WHERE v.owner_id = ?`, userID).Scan(&versions); err != nil {
		return 0, err
	}
	if err := q.QueryRow(`SELECT COALESCE(SUM(o.size), 0) FROM object_versions o
		JOIN file_heads h ON h.vault_id = o.vault_id AND h.file_id = o.file_id AND h.revision = o.revision
		JOIN vaults v ON v.vault_id = o.vault_id WHERE v.owner_id = ?`, userID).Scan(&headVersions); err != nil {
		return 0, err
	}
	return heads + versions - headVersions, nil
}
