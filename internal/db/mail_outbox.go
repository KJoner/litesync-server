package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
)

// 产品通知邮件 outbox（v0.20 公开化 / ADR-018）。
//
// 身份邮件（注册验证、找回密码、换邮箱）由身份服务（Keycloak）发送，不经过这里；
// 这里只放产品自己的安全通知（新设备接入、Token 重置、仓库删除、退出所有设备）。
//
// 隐私：收件地址与正文只在待发期间存在；发送成功或最终失败后立即清空，只留地址
// 哈希、模板名与状态用于排障与抑制判断。日志一律不记地址、正文与链接。

const mailSchema = `
CREATE TABLE IF NOT EXISTS mail_outbox (
	id                  INTEGER PRIMARY KEY AUTOINCREMENT,
	idempotency_key     TEXT NOT NULL UNIQUE,
	template            TEXT NOT NULL,
	to_addr             TEXT NOT NULL DEFAULT '',
	to_hash             TEXT NOT NULL,
	subject             TEXT NOT NULL DEFAULT '',
	body_text           TEXT NOT NULL DEFAULT '',
	status              TEXT NOT NULL CHECK (status IN ('queued','sending','sent','failed','suppressed')),
	attempts            INTEGER NOT NULL DEFAULT 0,
	next_attempt_at     INTEGER NOT NULL DEFAULT 0,
	last_error_code     TEXT NOT NULL DEFAULT '',
	provider_message_id TEXT NOT NULL DEFAULT '',
	created_at          INTEGER NOT NULL,
	updated_at          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mail_outbox_due ON mail_outbox(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_mail_outbox_to ON mail_outbox(to_hash, created_at);

CREATE TABLE IF NOT EXISTS mail_suppressions (
	addr_hash  TEXT PRIMARY KEY,
	reason     TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
`

// MailAddrHash 是收件地址的规范化哈希（小写、去空白）：抑制表与统计只用它。
func MailAddrHash(addr string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(addr))))
	return hex.EncodeToString(sum[:])
}

// OutboxMail 是一封待发邮件。
type OutboxMail struct {
	ID         int64
	Template   string
	To         string
	ToHash     string
	Subject    string
	BodyText   string
	Attempts   int
	IdemKey    string
	Status     string
	LastError  string
	ProviderID string
}

var ErrMailSuppressed = errors.New("recipient is suppressed")

// EnqueueMail 入队（幂等：同一 idempotencyKey 只会有一封）。
// 收件人在抑制表里（硬退信/投诉）时记为 suppressed，不再尝试投递。
// 返回 (是否新入队, error)。
func EnqueueMail(q dbtx, idemKey, template, to, subject, body string, now int64) (bool, error) {
	h := MailAddrHash(to)
	status := "queued"
	var reason string
	err := q.QueryRow(`SELECT reason FROM mail_suppressions WHERE addr_hash = ?`, h).Scan(&reason)
	switch {
	case err == nil:
		status, to, subject, body = "suppressed", "", "", ""
	case !errors.Is(err, sql.ErrNoRows):
		return false, err
	}
	res, err := q.Exec(`INSERT INTO mail_outbox (idempotency_key, template, to_addr, to_hash, subject, body_text,
		status, next_attempt_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(idempotency_key) DO NOTHING`,
		idemKey, template, to, h, subject, body, status, now, now, now)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return n > 0, nil
}

// CountRecentMailTo 统计某地址在 since 之后入队的邮件数（按收件人限额，防滥用放大）。
func CountRecentMailTo(q dbtx, to string, since int64) (int, error) {
	var n int
	err := q.QueryRow(`SELECT COUNT(*) FROM mail_outbox WHERE to_hash = ? AND created_at >= ?`, MailAddrHash(to), since).Scan(&n)
	return n, err
}

// CountMailSentSince 全局已发出（status=sent）且发送时间不早于 since 的邮件数（日预算用）。
// sent 行的 updated_at 就是发送时刻（MarkMailSent 写入）。
func CountMailSentSince(q dbtx, since int64) (int, error) {
	var n int
	err := q.QueryRow(`SELECT COUNT(*) FROM mail_outbox WHERE status = 'sent' AND updated_at >= ?`, since).Scan(&n)
	return n, err
}

// ClaimDueMail 取出到期的待发邮件并标记 sending（最多 limit 封）。
// 进程崩溃留下的 sending 在 staleBefore 之后重新视为到期（至少一次投递，靠幂等键去重）。
func ClaimDueMail(d *sql.DB, now, staleBefore int64, limit int) ([]OutboxMail, error) {
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	rows, err := tx.Query(`SELECT id, template, to_addr, to_hash, subject, body_text, attempts, idempotency_key
		FROM mail_outbox
		WHERE (status = 'queued' AND next_attempt_at <= ?) OR (status = 'sending' AND updated_at < ?)
		ORDER BY next_attempt_at ASC LIMIT ?`, now, staleBefore, limit)
	if err != nil {
		return nil, err
	}
	var out []OutboxMail
	for rows.Next() {
		var m OutboxMail
		if err := rows.Scan(&m.ID, &m.Template, &m.To, &m.ToHash, &m.Subject, &m.BodyText, &m.Attempts, &m.IdemKey); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, m)
	}
	rows.Close()
	for _, m := range out {
		if _, err := tx.Exec(`UPDATE mail_outbox SET status = 'sending', updated_at = ? WHERE id = ?`, now, m.ID); err != nil {
			return nil, err
		}
	}
	return out, tx.Commit()
}

// MarkMailSent 发送成功：清空地址与正文，只留哈希与服务商消息 ID。
func MarkMailSent(q dbtx, id int64, providerID string, now int64) error {
	_, err := q.Exec(`UPDATE mail_outbox SET status = 'sent', provider_message_id = ?, to_addr = '', subject = '', body_text = '',
		attempts = attempts + 1, last_error_code = '', updated_at = ? WHERE id = ?`, providerID, now, id)
	return err
}

// MarkMailRetry 临时失败：退避后重试。
func MarkMailRetry(q dbtx, id int64, errCode string, nextAt, now int64) error {
	_, err := q.Exec(`UPDATE mail_outbox SET status = 'queued', attempts = attempts + 1, last_error_code = ?,
		next_attempt_at = ?, updated_at = ? WHERE id = ?`, errCode, nextAt, now, id)
	return err
}

// MarkMailFailed 永久失败（或超过最大次数）：清空地址与正文；permanent=true 时把地址加入抑制表。
func MarkMailFailed(q dbtx, id int64, toHash, errCode string, permanent bool, now int64) error {
	if _, err := q.Exec(`UPDATE mail_outbox SET status = 'failed', attempts = attempts + 1, last_error_code = ?,
		to_addr = '', subject = '', body_text = '', updated_at = ? WHERE id = ?`, errCode, now, id); err != nil {
		return err
	}
	if permanent {
		return SuppressMailHash(q, toHash, "hard-bounce:"+errCode, now)
	}
	return nil
}

// SuppressMail / SuppressMailHash 把地址加入抑制表（硬退信、投诉）；已在表中则保持原因。
func SuppressMail(q dbtx, addr, reason string, now int64) error {
	return SuppressMailHash(q, MailAddrHash(addr), reason, now)
}

func SuppressMailHash(q dbtx, h, reason string, now int64) error {
	_, err := q.Exec(`INSERT INTO mail_suppressions (addr_hash, reason, created_at) VALUES (?, ?, ?)
		ON CONFLICT(addr_hash) DO NOTHING`, h, reason, now)
	return err
}

// MailStats 是管理员告警用的计数（不含任何地址）。
type MailStats struct {
	Queued, Sending, Sent, Failed, Suppressed int
}

func GetMailStats(q dbtx) (MailStats, error) {
	var s MailStats
	rows, err := q.Query(`SELECT status, COUNT(*) FROM mail_outbox GROUP BY status`)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return s, err
		}
		switch st {
		case "queued":
			s.Queued = n
		case "sending":
			s.Sending = n
		case "sent":
			s.Sent = n
		case "failed":
			s.Failed = n
		case "suppressed":
			s.Suppressed = n
		}
	}
	return s, rows.Err()
}

// UserNotifyAddress 返回用户可用于安全通知的邮箱（只取**已验证**的统一身份邮箱）。
func UserNotifyAddress(q dbtx, userID string) (string, error) {
	var addr string
	err := q.QueryRow(`SELECT email FROM external_identities WHERE user_id = ? AND email != '' AND email_verified = 1
		ORDER BY last_login_at DESC LIMIT 1`, userID).Scan(&addr)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return addr, err
}

// VaultDisplayName 返回仓库的展示名（只用于通知文案；不存在返回空串）。
func VaultDisplayName(q dbtx, vaultID string) string {
	var name string
	_ = q.QueryRow(`SELECT name FROM vaults WHERE vault_id = ?`, vaultID).Scan(&name) //nolint:errcheck
	return name
}
