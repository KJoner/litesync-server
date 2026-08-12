package db

import (
	"database/sql"
	"errors"
	"fmt"
)

// 成员管理与密钥轮换（v0.16.0 / 计划书 §10.4、ADR-010 §6）。
//
// # 移除成员到底能保证什么
//
// 这件事很容易被说过头。移除一个成员之后，**能**保证的是：
//
//   - 该成员的所有设备凭据立刻作废，拿不到任何新内容；
//   - Vault Key 进入新的 keyEpoch，新内容用新密钥加密，旧密钥解不开。
//
// **不能**保证的是：他已经下载到本地的明文。那些字节在他的磁盘上，
// 服务器没有任何办法收回。产品文案必须直说这一点——
// 让用户以为「移除 = 对方再也看不到任何东西」是危险的误导。
//
// # 为什么轮换要分两步
//
// 服务器拿不到 Vault Key（E2EE），因此**没法自己重新封装**。它能做的是：
// 立刻推进 keyEpoch 并把仓库标成「待重新封装」，然后等一台管理员设备
// 用剩余成员的公钥重新封装并上传。在此之前，用旧 epoch 的写入会被拒绝——
// 否则新内容会继续用被移除成员仍持有的那把密钥加密。

var (
	// ErrNotAMember：目标用户根本不在这个 Vault 里。
	ErrNotAMember = errors.New("user is not a member of this vault")
	// ErrLastOwner：移除之后 Vault 就没有 owner 了。
	// 允许这么做等于制造一个谁也管不了的 Vault。
	ErrLastOwner = errors.New("cannot remove the last owner of a vault")
)

// MembershipRemoval 描述一次成员移除的后果。
type MembershipRemoval struct {
	UserID          string
	Role            Role
	RevokedDevices  int
	NewKeyEpoch     int64
	PendingRewrap   bool
	RemovedAt       int64
	LocalPlaintext  string // 给 UI 直接显示的、关于本地明文的说明
	RemainingOwners int
}

// CountRole 返回该 Vault 里某个角色的成员数。
func CountRole(q dbtx, s VaultScope, role Role) (int, error) {
	if !s.Valid() {
		return 0, ErrVaultScopeMissing
	}
	var n int
	err := q.QueryRow(`SELECT COUNT(*) FROM memberships WHERE vault_id = ? AND role = ?`,
		s.ID(), string(role)).Scan(&n)
	return n, err
}

// RevokeDevicesOfUser 撤销某用户在该 Vault 的全部设备，返回撤销数量。
func RevokeDevicesOfUser(q dbtx, s VaultScope, userID string) (int, error) {
	if !s.Valid() {
		return 0, ErrVaultScopeMissing
	}
	res, err := q.Exec(
		`UPDATE devices SET revoked = 1 WHERE vault_id = ? AND user_id = ? AND revoked = 0`,
		s.ID(), userID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return int(n), nil
}

// CurrentKeyEpoch 返回该 Vault 当前的 keyEpoch。
//
// §10.2 之后 key_epoch 是**按 Vault** 的：不带范围会读到别人的世代，
// 而 keyEpoch 决定了哪些内容还能写入——读错等于把别人的密钥轮换算到自己头上。
func CurrentKeyEpoch(q dbtx, s VaultScope) (int64, error) {
	if !s.Valid() {
		return 0, ErrVaultScopeMissing
	}
	var e int64
	err := q.QueryRow(`SELECT key_epoch FROM repo_state WHERE vault_id = ?`, s.ID()).Scan(&e)
	return e, err
}

// RotateKeyEpoch 推进 keyEpoch 并留下审计记录，返回新的 epoch。
//
// reason 会写进 key_epochs：事后要能回答「这次轮换是因为谁被移除了」。
func RotateKeyEpoch(q dbtx, s VaultScope, reason string) (int64, error) {
	if !s.Valid() {
		return 0, ErrVaultScopeMissing
	}
	var epoch int64
	if err := q.QueryRow(
		`UPDATE repo_state SET key_epoch = key_epoch + 1 WHERE vault_id = ? RETURNING key_epoch`,
		s.ID()).Scan(&epoch); err != nil {
		return 0, err
	}
	if err := RecordKeyEpoch(q, s, epoch, reason); err != nil {
		return 0, err
	}
	return epoch, nil
}

// SetPendingRewrap 把 Vault 标记为「Vault Key 需要在 epoch 处重新封装」。
// epoch = 0 表示清除标记。
func SetPendingRewrap(q dbtx, s VaultScope, epoch int64) error {
	if !s.Valid() {
		return ErrVaultScopeMissing
	}
	res, err := q.Exec(`UPDATE vaults SET pending_rewrap_epoch = ? WHERE vault_id = ?`, epoch, s.ID())
	if err != nil {
		return err
	}
	// 没有这一行意味着 Vault 记录不存在。静默成功会让「待重新封装」这个标记
	// 凭空消失——管理员会以为轮换已经收尾，而实际上没人被要求重新封装。
	if n, _ := res.RowsAffected(); n == 0 { //nolint:errcheck
		return fmt.Errorf("vault %s 不存在，无法记录待重新封装状态", s.ID())
	}
	return nil
}

// PendingRewrap 返回等待重新封装的 epoch；0 表示没有待办。
func PendingRewrap(q dbtx, s VaultScope) (int64, error) {
	if !s.Valid() {
		return 0, ErrVaultScopeMissing
	}
	var epoch int64
	err := q.QueryRow(`SELECT pending_rewrap_epoch FROM vaults WHERE vault_id = ?`, s.ID()).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return epoch, err
}

// DeleteMembership 移除成员行；返回是否确实删掉了一行。
func DeleteMembership(q dbtx, s VaultScope, userID string) (bool, error) {
	if !s.Valid() {
		return false, ErrVaultScopeMissing
	}
	res, err := q.Exec(`DELETE FROM memberships WHERE vault_id = ? AND user_id = ?`, s.ID(), userID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return n > 0, nil
}

// BindDeviceToTenant 把设备挂到 (vault, user) 上。
//
// 没有这条绑定，「移除成员时撤销他的设备」就无从谈起——
// 服务器分不清哪台设备属于谁。
func BindDeviceToTenant(q dbtx, s VaultScope, deviceID, userID string) error {
	if !s.Valid() {
		return ErrVaultScopeMissing
	}
	_, err := q.Exec(`UPDATE devices SET vault_id = ?, user_id = ? WHERE id = ?`,
		s.ID(), userID, deviceID)
	return err
}

// DeviceTenant 返回设备所属的 (vaultID, userID)。
func DeviceTenant(q dbtx, deviceID string) (vaultID, userID string, err error) {
	err = q.QueryRow(`SELECT vault_id, user_id FROM devices WHERE id = ?`, deviceID).
		Scan(&vaultID, &userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	return vaultID, userID, err
}
