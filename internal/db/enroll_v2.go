package db

import (
	"database/sql"
	"errors"
)

// 配对 v2 / 可恢复兑换（v0.20 公开化 / ADR-014）的数据访问。
//
// grant 就是 enrollments 的一行：创建时定死 (vault, user, scopes)，兑换请求不能
// 改变它们。v2 兑换额外记录客户端生成的 exchange_id，并把签发结果用 secret 派生
// 的密钥加密后暂存一个短窗口——响应丢失时同 secret + 同 exchangeId 可以原样取回，
// 只知道 exchangeId（或只拿到数据库）的人得不到凭据。

// EnrollmentRow 是一条注册凭据（grant）的完整状态。
type EnrollmentRow struct {
	ID               string
	Scopes           string
	VaultID          string
	UserID           string
	ExpiresAt        int64
	ConsumedAt       int64
	Revoked          bool
	ExchangeID       string
	ReplayCiphertext string
	ReplayExpiresAt  int64
}

const enrollmentRowColumns = `id, scopes, vault_id, user_id, expires_at, consumed_at, revoked,
	exchange_id, replay_ciphertext, replay_expires_at`

func scanEnrollment(sc interface{ Scan(...any) error }) (*EnrollmentRow, error) {
	e := &EnrollmentRow{}
	var revoked int
	err := sc.Scan(&e.ID, &e.Scopes, &e.VaultID, &e.UserID, &e.ExpiresAt, &e.ConsumedAt, &revoked,
		&e.ExchangeID, &e.ReplayCiphertext, &e.ReplayExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.Revoked = revoked != 0
	if e.VaultID == "" {
		e.VaultID = DefaultVaultID
	}
	if e.UserID == "" {
		e.UserID = AdminUserID
	}
	return e, nil
}

// GetEnrollmentBySecretHash 按 secret 哈希查 grant（任何状态）；不存在返回 (nil, nil)。
func GetEnrollmentBySecretHash(q dbtx, secretHash string) (*EnrollmentRow, error) {
	return scanEnrollment(q.QueryRow(`SELECT `+enrollmentRowColumns+` FROM enrollments WHERE secret_hash = ?`, secretHash))
}

// GetEnrollmentByID 按 grant id 查（配对包绑定 grant 时校验归属）。
func GetEnrollmentByID(q dbtx, id string) (*EnrollmentRow, error) {
	return scanEnrollment(q.QueryRow(`SELECT `+enrollmentRowColumns+` FROM enrollments WHERE id = ?`, id))
}

// ConsumeEnrollmentV2 原子消费 grant 并记录 exchangeID；已被消费/撤销/过期返回 (nil, nil)。
func ConsumeEnrollmentV2(q dbtx, secretHash, exchangeID string, now int64) (*EnrollmentGrant, error) {
	g := &EnrollmentGrant{}
	err := q.QueryRow(
		`UPDATE enrollments SET consumed_at = ?, exchange_id = ?
		 WHERE secret_hash = ? AND consumed_at = 0 AND revoked = 0 AND expires_at > ?
		 RETURNING scopes, vault_id, user_id`,
		now, exchangeID, secretHash, now,
	).Scan(&g.Scopes, &g.VaultID, &g.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if g.VaultID == "" {
		g.VaultID = DefaultVaultID
	}
	if g.UserID == "" {
		g.UserID = AdminUserID
	}
	return g, nil
}

// StoreEnrollmentReplay 保存加密后的兑换结果（重放窗口）。
func StoreEnrollmentReplay(q dbtx, secretHash, ciphertext string, expiresAt int64) error {
	_, err := q.Exec(`UPDATE enrollments SET replay_ciphertext = ?, replay_expires_at = ? WHERE secret_hash = ?`,
		ciphertext, expiresAt, secretHash)
	return err
}

// ClearExpiredReplays 抹掉过了重放窗口的暂存结果（维护任务）。
func ClearExpiredReplays(q dbtx, now int64) error {
	_, err := q.Exec(`UPDATE enrollments SET replay_ciphertext = '' WHERE replay_ciphertext != '' AND replay_expires_at <= ?`, now)
	return err
}

// InsertDeviceTx 是 InsertDevice 的同名别名，强调它可以在事务里调用（dbtx）。
func InsertDeviceTx(q dbtx, d *Device) error { return InsertDevice(q, d) }
