package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
)

// 内容加密状态机（v9）：plaintext → migrating → encrypted。
// migrating/encrypted 状态下服务器拒绝明文上传（明文写冻结）。
const (
	EncryptionPlaintext = "plaintext"
	EncryptionMigrating = "migrating"
	EncryptionEncrypted = "encrypted"
)

// 元数据加密状态机（v6 / ADR-003）：plain → migrating → verifying → encrypted。
//
// verifying 是 v6 新增的一态：**验证与不可逆擦除彻底分离**。
// 进入 verifying 后不再接受迁移写入，只接受验证读取与 complete；
// 验证失败时数据一个字节都没被动过，可以直接 abort 回 plain。
const (
	MetaPlain     = "plain"
	MetaMigrating = "migrating"
	MetaVerifying = "verifying"
	MetaEncrypted = "encrypted"
)

// 信封版本下限（ADR-006）。单调不减，落库前校验，覆盖全部写入路径。
const (
	EnvelopeAny  = 0 // 明文仓库
	EnvelopeLSE1 = 1 // E2EE 已启用，接受 LSE1/LSE2/LSE3
	EnvelopeLSE3 = 3 // 已完成信封升级，只接受 LSE3
)

// RepoState 是**一个 Vault** 的权威状态（v0.16 / 计划书 §10.2）。
//
// v0.16 之前 repo_state 是一张单行表（id=1），也就是实例级的。多租户下这不成立：
// repoEpoch、headSequence、迁移状态、formatEpoch、keyEpoch 每一项都必须按 Vault
// 独立，否则一个租户的灾备恢复会让所有租户的游标作废，一个租户的写入会推高别人
// 看到的 head——后者还顺带泄露「别人今天写了多少」。
type RepoState struct {
	RepoEpoch           string
	HeadSequence        int64
	MinRetainedSequence int64
	EncryptionState     string
	KeyEpoch            int64
	MetaState           string
	SchemaVersion       int64
	// FormatEpoch 寻址格式世代（ADR-006）：元数据加密完成时 +1。
	// 与 RepoEpoch（灾备恢复）、KeyEpoch（密钥轮换）语义完全不同，三者不得互相替代。
	FormatEpoch int64
	// MinimumEnvelopeVersion 仓库级信封下限：只增不减
	MinimumEnvelopeVersion int64
	MetaSchemaVersion      int64

	MigrationID                string
	MigrationOwnerDeviceID     string
	MigrationLeaseExpiresAt    int64
	MigrationCutoffSequence    int64
	MigrationTargetFormatEpoch int64
	MigrationKeyEpoch          int64
}

func randomEpoch() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// initRepoState 初始化 repo_state（幂等，db.Open 时调用）。
// 旧库迁移：head 取 MAX(sequence)、sqlite_sequence、旧水位线三者最大值，
// 保证升级后 head 绝不小于任何客户端已见过的 sequence。
func initRepoState(d *sql.DB, s VaultScope) error {
	if !s.Valid() {
		return ErrVaultScopeMissing
	}
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM repo_state WHERE vault_id = ?`, s.ID()).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}

	var maxChanges, sqliteSeq, watermark int64
	// v5 库升级时 changes 表可能还在；新库则只有 object_changes
	for _, q := range []string{
		`SELECT COALESCE(MAX(sequence), 0) FROM changes`,
		`SELECT COALESCE(MAX(sequence), 0) FROM object_changes`,
	} {
		var v int64
		if err := d.QueryRow(q).Scan(&v); err == nil && v > maxChanges {
			maxChanges = v
		}
	}
	// AUTOINCREMENT 的历史最大值（changes 被整表裁剪后仍然保留）
	err := d.QueryRow(`SELECT seq FROM sqlite_sequence WHERE name = 'changes'`).Scan(&sqliteSeq)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if v, ok, err := GetMeta(d, "changes-watermark"); err != nil {
		return err
	} else if ok {
		fmt.Sscanf(v, "%d", &watermark) //nolint:errcheck
	}

	head := max(maxChanges, sqliteSeq, watermark)
	epoch, err := randomEpoch()
	if err != nil {
		return err
	}
	_, err = d.Exec(
		`INSERT INTO repo_state (vault_id, repo_epoch, head_sequence, min_retained_sequence,
			encryption_state, key_epoch, schema_version, format_epoch, minimum_envelope_version)
		 VALUES (?, ?, ?, ?, ?, 0, ?, 1, 0)`,
		s.ID(), epoch, head, watermark, EncryptionPlaintext, SchemaVersion,
	)
	return err
}

// InitVaultState 为一个新 Vault 建立独立的状态行（§10.2）。
//
// 新 Vault 从零开始：自己的 repoEpoch、head=0、plaintext、formatEpoch=1。
// 刻意**不**继承任何现有 Vault 的值——继承 repoEpoch 会让两个租户的
// 灾备恢复互相干扰，继承 head 会白白泄露别人写了多少。
func InitVaultState(d *sql.DB, s VaultScope) error {
	if !s.Valid() {
		return ErrVaultScopeMissing
	}
	epoch, err := randomEpoch()
	if err != nil {
		return err
	}
	_, err = d.Exec(
		`INSERT INTO repo_state (vault_id, repo_epoch, head_sequence, min_retained_sequence,
			encryption_state, key_epoch, schema_version, format_epoch, minimum_envelope_version)
		 VALUES (?, ?, 0, 0, ?, 0, ?, 1, 0)
		 ON CONFLICT(vault_id) DO NOTHING`,
		s.ID(), epoch, EncryptionPlaintext, SchemaVersion)
	return err
}

const repoStateColumns = `repo_epoch, head_sequence, min_retained_sequence, encryption_state, key_epoch,
	COALESCE(meta_state, 'plain'), schema_version, format_epoch, minimum_envelope_version, meta_schema_version,
	migration_id, migration_owner_device_id, migration_lease_expires_at, migration_cutoff_sequence,
	migration_target_format_epoch, migration_key_epoch`

// GetRepoState 读取仓库权威状态。
func GetRepoState(q dbtx, s VaultScope) (*RepoState, error) {
	if !s.Valid() {
		return nil, ErrVaultScopeMissing
	}
	rs := &RepoState{}
	err := q.QueryRow(`SELECT `+repoStateColumns+` FROM repo_state WHERE vault_id = ?`, s.ID()).Scan(
		&rs.RepoEpoch, &rs.HeadSequence, &rs.MinRetainedSequence, &rs.EncryptionState, &rs.KeyEpoch,
		&rs.MetaState, &rs.SchemaVersion, &rs.FormatEpoch, &rs.MinimumEnvelopeVersion, &rs.MetaSchemaVersion,
		&rs.MigrationID, &rs.MigrationOwnerDeviceID, &rs.MigrationLeaseExpiresAt, &rs.MigrationCutoffSequence,
		&rs.MigrationTargetFormatEpoch, &rs.MigrationKeyEpoch)
	if err != nil {
		return nil, err
	}
	return rs, nil
}

// SetMetaState 更新元数据加密状态机。
func SetMetaState(q dbtx, s VaultScope, state string) error {
	_, err := q.Exec(`UPDATE repo_state SET meta_state = ? WHERE vault_id = ?`, state, s.ID())
	return err
}

// BeginMigrationRecord 记录一次迁移的身份、归属、租约与 cutoff（ADR-003 §3.2）。
func BeginMigrationRecord(q dbtx, s VaultScope, migrationID, ownerDeviceID string, leaseExpiresAt, cutoffSequence, targetFormatEpoch, keyEpoch int64) error {
	_, err := q.Exec(
		`UPDATE repo_state SET migration_id = ?, migration_owner_device_id = ?,
			migration_lease_expires_at = ?, migration_cutoff_sequence = ?,
			migration_target_format_epoch = ?, migration_key_epoch = ? WHERE vault_id = ?`,
		migrationID, ownerDeviceID, leaseExpiresAt, cutoffSequence, targetFormatEpoch, keyEpoch, s.ID())
	return err
}

// RenewMigrationLease 续租（只有 owner 能续）。
func RenewMigrationLease(q dbtx, s VaultScope, migrationID string, leaseExpiresAt int64) error {
	_, err := q.Exec(
		`UPDATE repo_state SET migration_lease_expires_at = ? WHERE vault_id = ? AND migration_id = ?`,
		leaseExpiresAt, s.ID(), migrationID)
	return err
}

// ClearMigrationRecord 清除迁移记录（complete / abort 后调用）。
func ClearMigrationRecord(q dbtx, s VaultScope) error {
	_, err := q.Exec(
		`UPDATE repo_state SET migration_id = '', migration_owner_device_id = '',
			migration_lease_expires_at = 0, migration_cutoff_sequence = 0,
			migration_target_format_epoch = 0, migration_key_epoch = 0 WHERE vault_id = ?`, s.ID())
	return err
}

// SetFormatEpoch 设置寻址格式世代（只增不减）。
func SetFormatEpoch(q dbtx, s VaultScope, epoch int64) error {
	_, err := q.Exec(
		`UPDATE repo_state SET format_epoch = ? WHERE vault_id = ? AND format_epoch < ?`, epoch, s.ID(), epoch)
	return err
}

// RaiseMinimumEnvelopeVersion 提升仓库级信封下限。
// WHERE 保护使降级调用变成 no-op——信封只许升级不许降级（INV-07），
// 且没有任何 API 能把它降回去，从备份恢复也不会（repo_state 是备份的一部分）。
func RaiseMinimumEnvelopeVersion(q dbtx, s VaultScope, version int64) error {
	_, err := q.Exec(
		`UPDATE repo_state SET minimum_envelope_version = ?
		  WHERE vault_id = ? AND minimum_envelope_version < ?`, version, s.ID(), version)
	return err
}

// NextSequence 在变更事务内分配下一个 sequence（head_sequence += 1）。
// 必须与 HEAD 更新、version、change 写入在同一事务中提交，保证：
// 任何已返回给客户端的 sequence 都精确对应一次已持久化的状态变更（INV-02）。
func NextSequence(q dbtx, s VaultScope) (int64, error) {
	rs, err := GetRepoState(q, s)
	if err != nil {
		return 0, err
	}
	seq := rs.HeadSequence + 1
	if _, err := q.Exec(`UPDATE repo_state SET head_sequence = ? WHERE vault_id = ?`, seq, s.ID()); err != nil {
		return 0, err
	}
	return seq, nil
}

// SetMinRetainedSequence 推进裁剪水位线（只增不减，事务内调用）。
func SetMinRetainedSequence(q dbtx, s VaultScope, seq int64) error {
	_, err := q.Exec(
		`UPDATE repo_state SET min_retained_sequence = ? WHERE vault_id = ? AND min_retained_sequence < ?`,
		seq, s.ID(), seq,
	)
	return err
}

// SetEncryptionState 更新加密状态机；keyEpoch 只在进入 migrating 时递增。
func SetEncryptionState(q dbtx, s VaultScope, state string, bumpKeyEpoch bool) error {
	if bumpKeyEpoch {
		_, err := q.Exec(
			`UPDATE repo_state SET encryption_state = ?, key_epoch = key_epoch + 1 WHERE vault_id = ?`, state, s.ID())
		return err
	}
	_, err := q.Exec(`UPDATE repo_state SET encryption_state = ? WHERE vault_id = ?`, state, s.ID())
	return err
}

// SetSchemaVersion 记录数据模型版本（v5 → v6 迁移完成时调用）。
func SetSchemaVersion(q dbtx, s VaultScope, version int64) error {
	_, err := q.Exec(`UPDATE repo_state SET schema_version = ? WHERE vault_id = ?`, version, s.ID())
	return err
}

// RotateEpoch 旋转 repo_epoch（灾备恢复后由 obsync rotate-epoch 命令执行）。
// 客户端发现 epoch 变化后停止普通增量同步，进入恢复合并流程。
func RotateEpoch(q dbtx, s VaultScope) (string, error) {
	epoch, err := randomEpoch()
	if err != nil {
		return "", err
	}
	if _, err := q.Exec(`UPDATE repo_state SET repo_epoch = ? WHERE vault_id = ?`, epoch, s.ID()); err != nil {
		return "", err
	}
	return epoch, nil
}
