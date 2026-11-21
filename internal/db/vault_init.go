package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// 仓库加密初始化状态机（v0.20 公开化 / ADR-012）。
//
//	pending_encryption ──claim(opId)──▶ initializing(租约 10 分钟)
//	initializing ──commit(opId, expectedInitVersion, keyDoc)──▶ ready
//
// 只有 ready 的仓库接受内容写入——**服务端强制**（api 层的写入闸门 + 业务层
// 写路径各一道），不是前端藏按钮。既有仓库迁移为 ready（含旧明文仓库：
// 它们的 encryption_state 不变，界面如实显示「未加密」）。
//
// 提交是原子的：keyDoc、加密状态、keyEpoch、信封下限、重置凭证哈希、
// init_state 在同一事务里落库。响应丢失后同 opId 同摘要重放返回同一结果；
// 已 ready 的仓库永远不会被这条路径换掉密钥文档（I-2）。

const (
	InitPendingEncryption = "pending_encryption"
	InitInitializing      = "initializing"
	InitReady             = "ready"

	// InitLeaseSeconds：初始化认领的租约（另一个标签页在此期间不能抢）。
	InitLeaseSeconds = 600
)

var (
	ErrInitInProgress      = errors.New("vault initialization claimed by another client")
	ErrInitVersionMismatch = errors.New("vault initialization version mismatch")
	ErrInitAlreadyReady    = errors.New("vault is already initialized")
	ErrInitLeaseMissing    = errors.New("vault initialization must be claimed first")
	ErrIdempotencyReused   = errors.New("operation id reused with a different request")
	ErrVaultNotEmpty       = errors.New("vault is not empty")
)

const vaultInitSchema = `
CREATE TABLE IF NOT EXISTS vault_init_ops (
	vault_id     TEXT NOT NULL,
	op_id        TEXT NOT NULL,
	request_hash TEXT NOT NULL,
	result_json  TEXT NOT NULL,
	created_at   INTEGER NOT NULL,
	PRIMARY KEY (vault_id, op_id)
);
`

// VaultInit 是一个仓库的初始化状态。
type VaultInit struct {
	VaultID         string
	State           string
	Version         int64
	LeaseOp         string
	LeaseExpires    int64
	ClientRequestID string
}

// GetVaultInit 读取初始化状态；仓库不存在返回 (nil, nil)。
func GetVaultInit(q dbtx, s VaultScope) (*VaultInit, error) {
	if !s.Valid() {
		return nil, ErrVaultScopeMissing
	}
	vi := &VaultInit{VaultID: s.ID()}
	err := q.QueryRow(`SELECT init_state, init_version, init_lease_op, init_lease_expires, client_request_id
		FROM vaults WHERE vault_id = ?`, s.ID()).
		Scan(&vi.State, &vi.Version, &vi.LeaseOp, &vi.LeaseExpires, &vi.ClientRequestID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return vi, nil
}

// VaultIsReady 报告仓库是否已完成初始化（内容写入闸门用）。
//
// 没有 vaults 行的只可能是 v0.16 之前的单用户 default 实例（vaults 行是后来
// 惰性补建的）——初始化状态机只作用于新建仓库，而新建仓库一定有行，所以缺行
// 视为就绪。HTTP 路径上 enforceVault 已经保证了仓库存在。
func VaultIsReady(q dbtx, s VaultScope) (bool, error) {
	vi, err := GetVaultInit(q, s)
	if err != nil {
		return false, err
	}
	if vi == nil {
		return true, nil
	}
	return vi.State == InitReady, nil
}

// SetVaultInitState 直接设置状态（v1 兼容路径：插件 0.19 经 e2ee complete 完成初始化时）。
func SetVaultInitState(q dbtx, s VaultScope, state string) error {
	if !s.Valid() {
		return ErrVaultScopeMissing
	}
	_, err := q.Exec(`UPDATE vaults SET init_state = ?, init_version = init_version + 1,
		init_lease_op = '', init_lease_expires = 0 WHERE vault_id = ? AND init_state != ?`, state, s.ID(), state)
	return err
}

// CreateUserVaultV2 新建仓库（v2，接口约定 §2.3）。
//
// 同一用户同一 clientRequestID 重放返回同一仓库（重复点击、刷新重试不会建出两个）。
// pending=true 时仓库从 pending_encryption 开始（公开模式默认）；false 时与 v0.19
// 行为一致直接 ready（自托管明确关闭强制 E2EE 时）。
func CreateUserVaultV2(d *sql.DB, userID, name, clientRequestID string, pending bool, maxVaults int) (vaultID string, created bool, err error) {
	if clientRequestID == "" || len(clientRequestID) > 128 {
		return "", false, fmt.Errorf("invalid client request id")
	}
	if maxVaults <= 0 {
		maxVaults = MaxVaultsPerUser
	}
	now := time.Now().Unix()
	tx, err := d.Begin()
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback() //nolint:errcheck

	var existing string
	err = tx.QueryRow(`SELECT v.vault_id FROM vaults v JOIN memberships m ON m.vault_id = v.vault_id
		WHERE m.user_id = ? AND m.role = 'owner' AND v.client_request_id = ?`, userID, clientRequestID).Scan(&existing)
	if err == nil {
		return existing, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", false, err
	}

	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM memberships WHERE user_id = ? AND role = 'owner'`,
		userID).Scan(&count); err != nil {
		return "", false, err
	}
	if count >= maxVaults {
		return "", false, ErrVaultLimit
	}
	var dup int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM memberships m JOIN vaults v ON v.vault_id = m.vault_id
		WHERE m.user_id = ? AND m.role = 'owner' AND v.name = ?`, userID, name).Scan(&dup); err != nil {
		return "", false, err
	}
	if dup > 0 {
		return "", false, ErrVaultNameTaken
	}
	vaultID, err = createVaultTx(tx, userID, name, now)
	if err != nil {
		return "", false, err
	}
	state := InitReady
	if pending {
		state = InitPendingEncryption
	}
	if _, err := tx.Exec(`UPDATE vaults SET client_request_id = ?, init_state = ?, init_version = 1 WHERE vault_id = ?`,
		clientRequestID, state, vaultID); err != nil {
		return "", false, err
	}
	if err := AppendAudit(tx, VaultScope{vaultID: vaultID}, userID, "vault-created",
		fmt.Sprintf("name=%s init=%s", name, state)); err != nil {
		return "", false, err
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	if err := initRepoState(d, VaultScope{vaultID: vaultID}); err != nil {
		return "", false, fmt.Errorf("init repo state for new vault: %w", err)
	}
	return vaultID, true, nil
}

// ClaimVaultInit 认领初始化（pending_encryption 或租约已过期的 initializing → initializing）。
// 同一 opID 重复认领幂等（续租）；他人租约未过期 → ErrInitInProgress。
func ClaimVaultInit(d *sql.DB, s VaultScope, opID string, now int64) (*VaultInit, error) {
	if !s.Valid() {
		return nil, ErrVaultScopeMissing
	}
	if opID == "" || len(opID) > 128 {
		return nil, fmt.Errorf("invalid op id")
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	vi, err := GetVaultInit(tx, s)
	if err != nil {
		return nil, err
	}
	if vi == nil {
		return nil, sql.ErrNoRows
	}
	switch vi.State {
	case InitReady:
		return vi, ErrInitAlreadyReady
	case InitInitializing:
		if vi.LeaseOp != opID && vi.LeaseExpires > now {
			return vi, ErrInitInProgress
		}
	case InitPendingEncryption:
	default:
		return vi, fmt.Errorf("unknown init state %q", vi.State)
	}
	if _, err := tx.Exec(`UPDATE vaults SET init_state = ?, init_lease_op = ?, init_lease_expires = ?
		WHERE vault_id = ?`, InitInitializing, opID, now+InitLeaseSeconds, s.ID()); err != nil {
		return nil, err
	}
	out, err := GetVaultInit(tx, s)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

// InitCommit 是一次初始化提交的全部输入（keyDoc 等只是服务端不理解的密文文档）。
type InitCommit struct {
	OpID            string
	ExpectedVersion int64
	KeyDocMetaKey   string // vault_meta 里存放 keyDoc 的键（由业务层按仓库计算）
	KeyDoc          string
	ResetAuthHash   string // SHA-256(resetAuth)，可空
	RequestHash     string // 请求摘要：同 opId 不同摘要即拒绝
	ResultJSON      string // 成功时要返回（并为重放保存）的结果
}

// CommitVaultInit 原子提交初始化（ADR-012 I-3）。
// 返回保存的结果 JSON；replay=true 表示这是同一 opId 的重放。
func CommitVaultInit(d *sql.DB, s VaultScope, c InitCommit, now int64) (result string, replay bool, err error) {
	if !s.Valid() {
		return "", false, ErrVaultScopeMissing
	}
	tx, err := d.Begin()
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback() //nolint:errcheck

	var prevHash, prevResult string
	err = tx.QueryRow(`SELECT request_hash, result_json FROM vault_init_ops WHERE vault_id = ? AND op_id = ?`,
		s.ID(), c.OpID).Scan(&prevHash, &prevResult)
	if err == nil {
		if prevHash != c.RequestHash {
			return "", false, ErrIdempotencyReused
		}
		return prevResult, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", false, err
	}

	vi, err := GetVaultInit(tx, s)
	if err != nil {
		return "", false, err
	}
	if vi == nil {
		return "", false, sql.ErrNoRows
	}
	switch {
	case vi.State == InitReady:
		return "", false, ErrInitAlreadyReady
	case vi.State != InitInitializing || vi.LeaseOp != c.OpID || vi.LeaseExpires <= now:
		return "", false, ErrInitLeaseMissing
	case vi.Version != c.ExpectedVersion:
		return "", false, ErrInitVersionMismatch
	}
	var heads int64
	if err := tx.QueryRow(`SELECT COUNT(*) FROM file_heads WHERE vault_id = ?`, s.ID()).Scan(&heads); err != nil {
		return "", false, err
	}
	if heads > 0 {
		return "", false, ErrVaultNotEmpty
	}
	if _, exists, gerr := GetMeta(tx, c.KeyDocMetaKey); gerr != nil {
		return "", false, gerr
	} else if exists {
		// 只可能来自 v1 兼容路径的半途状态：绝不覆盖已有的密钥文档
		return "", false, ErrInitAlreadyReady
	}
	if err := SetMeta(tx, c.KeyDocMetaKey, c.KeyDoc, now); err != nil {
		return "", false, err
	}
	if _, err := tx.Exec(`UPDATE repo_state SET encryption_state = ?, key_epoch = CASE WHEN key_epoch < 1 THEN 1 ELSE key_epoch END
		WHERE vault_id = ?`, EncryptionEncrypted, s.ID()); err != nil {
		return "", false, err
	}
	if err := RaiseMinimumEnvelopeVersion(tx, s, EnvelopeLSE3); err != nil {
		return "", false, err
	}
	if c.ResetAuthHash != "" {
		if _, err := tx.Exec(`UPDATE vaults SET reset_auth_hash = ? WHERE vault_id = ? AND reset_auth_hash IS NULL`,
			c.ResetAuthHash, s.ID()); err != nil {
			return "", false, err
		}
	}
	if _, err := tx.Exec(`UPDATE vaults SET init_state = ?, init_version = init_version + 1,
		init_lease_op = '', init_lease_expires = 0 WHERE vault_id = ?`, InitReady, s.ID()); err != nil {
		return "", false, err
	}
	if _, err := tx.Exec(`INSERT INTO vault_init_ops (vault_id, op_id, request_hash, result_json, created_at)
		VALUES (?, ?, ?, ?, ?)`, s.ID(), c.OpID, c.RequestHash, c.ResultJSON, now); err != nil {
		return "", false, err
	}
	if err := AppendAudit(tx, s, "", "vault-initialized", "e2ee=web"); err != nil {
		return "", false, err
	}
	return c.ResultJSON, false, tx.Commit()
}

// ListPendingVaults 列出尚未完成初始化的仓库（运维：回滚前检查、清理放弃的空库）。
func ListPendingVaults(q dbtx) ([]VaultInit, error) {
	rows, err := q.Query(`SELECT vault_id, init_state, init_version, init_lease_op, init_lease_expires, client_request_id
		FROM vaults WHERE init_state != ? ORDER BY created_at ASC`, InitReady)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VaultInit
	for rows.Next() {
		var vi VaultInit
		if err := rows.Scan(&vi.VaultID, &vi.State, &vi.Version, &vi.LeaseOp, &vi.LeaseExpires, &vi.ClientRequestID); err != nil {
			return nil, err
		}
		out = append(out, vi)
	}
	return out, rows.Err()
}

// NewOpID 生成服务端侧的操作 ID（测试与 CLI 用）。
func NewOpID() string {
	b := make([]byte, 12)
	rand.Read(b) //nolint:errcheck
	return "op_" + hex.EncodeToString(b)
}
