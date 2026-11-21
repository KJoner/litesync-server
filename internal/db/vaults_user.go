package db

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// 单用户多仓库（v0.19 / v11 设计《v0.19.0 单用户多仓库设计》）。
//
// 一个用户名下可以有多个互相隔离的 Vault：目标仓库由请求头 X-Vault-ID 显式
// 声明、authGate 按 membership 硬校验（不属于你 → 404）。这里是仓库的
// 生命周期与列表查询；隔离本身沿用 0.16/0.18 的 VaultScope 体系，零新机制。

// MaxVaultsPerUser 每用户仓库上限（D8：小范围自用的护栏）。
const MaxVaultsPerUser = 20

// ErrVaultLimit：仓库数量达到上限。
var ErrVaultLimit = errors.New("vault limit reached")

// ErrVaultNameTaken：同一用户下仓库重名。
var ErrVaultNameTaken = errors.New("vault name already taken")

// ErrLastVault：不能删除最后一个仓库（默认仓库/登录上下文会悬空）。
var ErrLastVault = errors.New("cannot delete the last vault")

// UserVault 是仓库列表的一行（选择仓库的界面用）。
type UserVault struct {
	VaultID         string
	Name            string
	CreatedAt       int64
	FileCount       int64
	BytesUsed       int64
	UpdatedAt       int64 // live 对象的最近更新（Unix 秒；0 = 空仓库）
	EncryptionState string
	KeyEpoch        int64
	// InitState / Identity（v0.20）：初始化状态（ADR-012）与加密绑定身份（= v1 info.vaultId）
	InitState string
	Identity  string
}

// ListUserVaults 列出该用户为 owner 的全部仓库及概要（created_at 升序，
// 第一个即「默认仓库」——与 OwnerVaultOf 的取法一致）。
func ListUserVaults(d *sql.DB, userID string) ([]UserVault, error) {
	rows, err := d.Query(`
		SELECT v.vault_id, v.name, v.created_at, v.init_state, v.identity
		  FROM memberships m JOIN vaults v ON v.vault_id = m.vault_id
		 WHERE m.user_id = ? AND m.role = 'owner'
		 ORDER BY m.created_at ASC, v.vault_id ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserVault
	for rows.Next() {
		var v UserVault
		if err := rows.Scan(&v.VaultID, &v.Name, &v.CreatedAt, &v.InitState, &v.Identity); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		v := &out[i]
		if err := d.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size), 0), COALESCE(MAX(updated_at), 0)
			FROM file_heads WHERE vault_id = ?`, v.VaultID).
			Scan(&v.FileCount, &v.BytesUsed, &v.UpdatedAt); err != nil {
			return nil, err
		}
		if err := d.QueryRow(`SELECT encryption_state, key_epoch FROM repo_state WHERE vault_id = ?`,
			v.VaultID).Scan(&v.EncryptionState, &v.KeyEpoch); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	return out, nil
}

// createVaultTx 在事务里建立一个仓库的全套行（vault + identity + secret +
// owner membership）。repo_state 行由调用方在事务提交后 EnsureRepoStateFor
//（initRepoState 自管读写，不能嵌在外部事务里）。
// 注册流程（invites.go）与新建仓库共用这一个实现。
func createVaultTx(tx *sql.Tx, userID, name string, now int64) (vaultID string, err error) {
	rawVault := make([]byte, 8)
	rawIdentity := make([]byte, 16)
	secret := make([]byte, VaultSecretLen)
	for _, b := range [][]byte{rawVault, rawIdentity, secret} {
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
	}
	vaultID = "v-" + hex.EncodeToString(rawVault)
	if _, err := tx.Exec(`INSERT INTO vaults (vault_id, owner_id, name, secret, created_at, identity)
		VALUES (?, ?, ?, ?, ?, ?)`,
		vaultID, userID, name, secret, now, hex.EncodeToString(rawIdentity)); err != nil {
		return "", err
	}
	if _, err := tx.Exec(`INSERT INTO memberships (user_id, vault_id, role, created_at)
		VALUES (?, ?, 'owner', ?)`, userID, vaultID, now); err != nil {
		return "", err
	}
	return vaultID, nil
}

// CreateUserVault 为用户新建一个仓库（v0.19）。
// 上限与同名检查在同一事务里完成；返回时 repo_state 已就绪（可立即接入）。
func CreateUserVault(d *sql.DB, userID, name string) (string, error) {
	return CreateUserVaultWithLimit(d, userID, name, MaxVaultsPerUser)
}

// CreateUserVaultWithLimit 同 CreateUserVault，仓库数上限由调用方给出（v0.20 配额；≤0 用默认）。
func CreateUserVaultWithLimit(d *sql.DB, userID, name string, maxVaults int) (string, error) {
	if maxVaults <= 0 {
		maxVaults = MaxVaultsPerUser
	}
	now := time.Now().Unix()
	tx, err := d.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck

	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM memberships WHERE user_id = ? AND role = 'owner'`,
		userID).Scan(&count); err != nil {
		return "", err
	}
	if count >= maxVaults {
		return "", ErrVaultLimit
	}
	var dup int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM memberships m JOIN vaults v ON v.vault_id = m.vault_id
		WHERE m.user_id = ? AND m.role = 'owner' AND v.name = ?`, userID, name).Scan(&dup); err != nil {
		return "", err
	}
	if dup > 0 {
		return "", ErrVaultNameTaken
	}
	vaultID, err := createVaultTx(tx, userID, name, now)
	if err != nil {
		return "", err
	}
	if err := AppendAudit(tx, VaultScope{vaultID: vaultID}, userID, "vault-created",
		fmt.Sprintf("name=%s", name)); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	if err := initRepoState(d, VaultScope{vaultID: vaultID}); err != nil {
		return "", fmt.Errorf("init repo state for new vault: %w", err)
	}
	return vaultID, nil
}

// RenameUserVault 重命名用户自己的一个仓库（v0.19.x）。
// 归属校验（非 owner 与不存在同响应 404）+ 同用户内同名拒绝；改名只动展示名，
// vault_id / 密钥 / 账本 / 绑定指纹一概不受影响（INV-05 的仓库级对应）。
func RenameUserVault(d *sql.DB, userID, vaultID, newName string) error {
	role, ok, err := RoleOf(d, VaultScope{vaultID: vaultID}, userID)
	if err != nil {
		return err
	}
	if !ok || role != RoleOwner {
		return sql.ErrNoRows // 与不存在同响应（404 语义）
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	var dup int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM memberships m JOIN vaults v ON v.vault_id = m.vault_id
		WHERE m.user_id = ? AND m.role = 'owner' AND v.name = ? AND v.vault_id != ?`,
		userID, newName, vaultID).Scan(&dup); err != nil {
		return err
	}
	if dup > 0 {
		return ErrVaultNameTaken
	}
	if _, err := tx.Exec(`UPDATE vaults SET name = ? WHERE vault_id = ?`, newName, vaultID); err != nil {
		return err
	}
	if err := AppendAudit(tx, VaultScope{vaultID: vaultID}, userID, "vault-renamed",
		fmt.Sprintf("name=%s", newName)); err != nil {
		return err
	}
	return tx.Commit()
}

// deleteVaultRowsTx 删除一个仓库的全部数据行（DeleteUserCascade 与
// DeleteUserVault 共用的表清单——两处清单漂移就是残留数据的来源）。
func deleteVaultRowsTx(tx *sql.Tx, vaultID string) error {
	for _, stmt := range []string{
		`DELETE FROM file_heads WHERE vault_id = ?`,
		`DELETE FROM file_objects WHERE vault_id = ?`,
		`DELETE FROM object_versions WHERE vault_id = ?`,
		`DELETE FROM object_changes WHERE vault_id = ?`,
		`DELETE FROM tombstones WHERE vault_id = ?`,
		`DELETE FROM migration_journal WHERE vault_id = ?`,
		`DELETE FROM checkpoints WHERE vault_id = ?`,
		`DELETE FROM key_epochs WHERE vault_id = ?`,
		`DELETE FROM audit_events WHERE vault_id = ?`,
		`DELETE FROM vault_retention WHERE vault_id = ?`,
		`DELETE FROM shares WHERE vault_id = ?`,
		`DELETE FROM enrollments WHERE vault_id = ?`,
		`DELETE FROM pairings WHERE vault_id = ?`,
		`DELETE FROM devices WHERE vault_id = ?`,
		`DELETE FROM repo_state WHERE vault_id = ?`,
		`DELETE FROM memberships WHERE vault_id = ?`,
		`DELETE FROM vaults WHERE vault_id = ?`,
		`DELETE FROM vault_meta WHERE key = 'vault-key:' || ?`,
	} {
		if _, err := tx.Exec(stmt, vaultID); err != nil {
			return err
		}
	}
	return nil
}

// collectVaultArtifacts 在删除前收集磁盘侧要清理的引用（blob 与分享密文）。
func collectVaultArtifacts(d *sql.DB, vaultID string) (blobIDs, shareIDs []string, err error) {
	seen := map[string]bool{}
	rows, err := d.Query(`SELECT blob_id FROM file_heads WHERE vault_id = ? AND COALESCE(blob_id,'') != ''
		UNION SELECT blob_id FROM object_versions WHERE vault_id = ? AND COALESCE(blob_id,'') != ''`,
		vaultID, vaultID)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var b string
		if err := rows.Scan(&b); err != nil {
			rows.Close()
			return nil, nil, err
		}
		if !seen[b] {
			seen[b] = true
			blobIDs = append(blobIDs, b)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	shares, err := ListShares(d, VaultScope{vaultID: vaultID})
	if err != nil {
		return nil, nil, err
	}
	for i := range shares {
		shareIDs = append(shareIDs, shares[i].ID)
	}
	return blobIDs, shareIDs, nil
}

// DeleteUserVault 删除用户自己的一个仓库（v0.19，D8）。
// 归属校验 + confirmName 必须等于仓库名 + 不能删最后一个；
// 返回磁盘侧待清理引用（调用方清分享密文并把 blob 交给 GC）。
func DeleteUserVault(d *sql.DB, userID, vaultID, confirmName string) (blobIDs, shareIDs []string, err error) {
	role, ok, err := RoleOf(d, VaultScope{vaultID: vaultID}, userID)
	if err != nil {
		return nil, nil, err
	}
	if !ok || role != RoleOwner {
		return nil, nil, sql.ErrNoRows // 与不存在同响应（404 语义）
	}
	v, err := GetVault(d, VaultScope{vaultID: vaultID})
	if err != nil || v == nil {
		return nil, nil, sql.ErrNoRows
	}
	if v.Name != confirmName {
		return nil, nil, fmt.Errorf("confirmName mismatch")
	}
	var count int
	if err := d.QueryRow(`SELECT COUNT(*) FROM memberships WHERE user_id = ? AND role = 'owner'`,
		userID).Scan(&count); err != nil {
		return nil, nil, err
	}
	if count <= 1 {
		return nil, nil, ErrLastVault
	}

	blobIDs, shareIDs, err = collectVaultArtifacts(d, vaultID)
	if err != nil {
		return nil, nil, err
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := deleteVaultRowsTx(tx, vaultID); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return blobIDs, shareIDs, nil
}

// RevokeAllDevicesOfUser 撤销该用户名下**所有仓库**的全部设备（v0.19：
// 重置 Token 的作废范围——Token 属于人，撤销也按人）。
func RevokeAllDevicesOfUser(q dbtx, userID string) (int, error) {
	res, err := q.Exec(`UPDATE devices SET revoked = 1 WHERE user_id = ? AND revoked = 0`, userID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return int(n), nil
}

// VerifyResetAuthAnyVault 重置门禁的多仓库形态（D7）：名下任一仓库登记过
// 重置凭证即视为强制（enforced）；提交值匹配**任一**已登记凭证即放行——
// 任何一个仓库的 E2EE 密码知识都证明请求者是主人。
func VerifyResetAuthAnyVault(d *sql.DB, userID, submitted string) (enforced, ok bool, err error) {
	rows, err := d.Query(`SELECT COALESCE(v.reset_auth_hash, '')
		  FROM memberships m JOIN vaults v ON v.vault_id = m.vault_id
		 WHERE m.user_id = ? AND m.role = 'owner'`, userID)
	if err != nil {
		return false, false, err
	}
	defer rows.Close()
	submittedHash := HashToken(submitted)
	matched := false
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return false, false, err
		}
		if h == "" {
			continue
		}
		enforced = true
		if constantTimeEq(h, submittedHash) {
			matched = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, false, err
	}
	if !enforced {
		return false, true, nil
	}
	return true, matched, nil
}

func constantTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// UserHasVault 报告用户是否是该仓库的成员（authGate 的 X-Vault-ID 校验用）。
// 构造 scope 的动作发生在 db 包内——授权判断只看 memberships，头里的声明
// 永远只是「选择」，不是「权限」。
func UserHasVault(q dbtx, userID, vaultID string) (bool, error) {
	if vaultID == "" || userID == "" {
		return false, nil
	}
	_, ok, err := RoleOf(q, VaultScope{vaultID: vaultID}, userID)
	return ok, err
}
