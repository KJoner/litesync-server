package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
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
//
// 耐久性（v0.20.1 / 复审 SV-05）：业务操作在**自己的事务里**写一条最小的安全事件
//（security_events：账号、事件类型、几项展示字段），与业务变更同生共死；后台 worker 负责
// 查收件地址、渲染、入队（mail_outbox）与网络发送，每条事件的去向都记成结果（outcome）。
// 以前是先进容量 256 的内存队列、满了丢弃、由另一个协程再落盘——业务成功到落盘之间进程退出就丢通知。

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

CREATE TABLE IF NOT EXISTS security_events (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	event_key    TEXT NOT NULL UNIQUE,
	user_id      TEXT NOT NULL,
	event        TEXT NOT NULL,
	data         TEXT NOT NULL DEFAULT '',
	event_state  TEXT NOT NULL DEFAULT 'pending' CHECK (event_state IN ('pending','done')),
	outcome      TEXT NOT NULL DEFAULT '',
	mail_id      INTEGER NOT NULL DEFAULT 0,
	created_at   INTEGER NOT NULL,
	processed_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_security_events_pending ON security_events(event_state, id);
`

// ---------------------------------------------------------------- 安全事件（SV-05）

// 安全事件的处理结果（每条事件都有一个；管理员统计按它分组）。
const (
	EventOutcomeMailQueued      = "mail-queued"           // 已渲染并进入投递队列
	EventOutcomeDuplicate       = "duplicate"             // 同一事件的邮件早已入队（重放 / 崩溃后重处理）
	EventOutcomeSuppressed      = "suppressed"            // 收件人在抑制表（硬退信 / 投诉）
	EventOutcomeNoAddress       = "no-verified-address"   // 账号没有已验证的统一账号邮箱（如只用 API Token 的旧管理员）
	EventOutcomeRecipientLimit  = "recipient-daily-limit" // 同一收件人 24 小时内超过上限（防邮件炸弹），本条不发
	EventOutcomeUnknownTemplate = "unknown-template"      // 程序缺陷：事件类型没有模板
)

// SecurityEvent 是一条待处理（或已处理）的安全事件。
type SecurityEvent struct {
	ID        int64
	Key       string
	UserID    string
	Event     string
	Data      map[string]string
	CreatedAt int64
}

// RecordSecurityEvent 在调用方的事务里记下一条安全事件（幂等：同一 event:user:eventId 只记一次）。
// data 只放模板需要的最少字段（设备名、平台、仓库名、数量、eventId）；不得含任何秘密。
func RecordSecurityEvent(q dbtx, userID, event string, data map[string]string, now int64) error {
	if userID == "" || event == "" {
		return nil
	}
	key := event + ":" + userID + ":" + data["eventId"]
	if data["eventId"] == "" {
		raw := make([]byte, 8)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		key += "nonce-" + hex.EncodeToString(raw)
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = q.Exec(`INSERT INTO security_events (event_key, user_id, event, data, event_state, created_at)
		VALUES (?, ?, ?, ?, 'pending', ?) ON CONFLICT(event_key) DO NOTHING`, key, userID, event, string(payload), now)
	return err
}

// PendingSecurityEvents 取出最早的一批未处理事件。
func PendingSecurityEvents(q dbtx, limit int) ([]SecurityEvent, error) {
	rows, err := q.Query(`SELECT id, event_key, user_id, event, data, created_at FROM security_events
		WHERE event_state = 'pending' ORDER BY id ASC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecurityEvent
	for rows.Next() {
		var ev SecurityEvent
		var data string
		if err := rows.Scan(&ev.ID, &ev.Key, &ev.UserID, &ev.Event, &data, &ev.CreatedAt); err != nil {
			return nil, err
		}
		ev.Data = map[string]string{}
		_ = json.Unmarshal([]byte(data), &ev.Data) //nolint:errcheck // 坏数据按空字段渲染，不卡住队列
		out = append(out, ev)
	}
	return out, rows.Err()
}

// CompleteSecurityEvent 记下事件的去向并清空展示字段（隐私：处理完只留类型、账号与结果）。
func CompleteSecurityEvent(q dbtx, id int64, outcome string, mailID, now int64) error {
	_, err := q.Exec(`UPDATE security_events SET event_state = 'done', outcome = ?, mail_id = ?, data = '',
		processed_at = ? WHERE id = ? AND event_state = 'pending'`, outcome, mailID, now, id)
	return err
}

// MailByKey 按幂等键取邮件的 id 与状态；不存在返回 (0, "", nil)。
func MailByKey(q dbtx, idemKey string) (int64, string, error) {
	var id int64
	var status string
	err := q.QueryRow(`SELECT id, status FROM mail_outbox WHERE idempotency_key = ?`, idemKey).Scan(&id, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", nil
	}
	return id, status, err
}

// SecurityEventStats 是管理员页的事件计数（不含任何身份信息）。
type SecurityEventStats struct {
	Pending   int            `json:"pending"`
	Processed int            `json:"processed"`
	ByOutcome map[string]int `json:"byOutcome"`
}

// GetSecurityEventStats 统计安全事件的积压与去向。
func GetSecurityEventStats(q dbtx) (SecurityEventStats, error) {
	st := SecurityEventStats{ByOutcome: map[string]int{}}
	rows, err := q.Query(`SELECT event_state, outcome, COUNT(*) FROM security_events GROUP BY event_state, outcome`)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var state, outcome string
		var n int
		if err := rows.Scan(&state, &outcome, &n); err != nil {
			return st, err
		}
		if state == "pending" {
			st.Pending += n
			continue
		}
		st.Processed += n
		st.ByOutcome[outcome] += n
	}
	return st, rows.Err()
}

// PruneSecurityEvents 清理 30 天前已处理的事件（未处理的永远保留，直到 worker 处理掉）。
func PruneSecurityEvents(q dbtx, now int64) error {
	_, err := q.Exec(`DELETE FROM security_events WHERE event_state = 'done' AND processed_at < ?`, now-30*86400)
	return err
}

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

// MarkMailUncertain 请求已经发出、没有拿到结果（可能已投递）：记一次不确定的尝试，退避后用
// **同一个幂等键**重试（服务商侧去重）。uncertain_attempts > 0 的已发邮件在统计里单独计数。
func MarkMailUncertain(q dbtx, id int64, nextAt, now int64) error {
	_, err := q.Exec(`UPDATE mail_outbox SET status = 'queued', attempts = attempts + 1,
		uncertain_attempts = uncertain_attempts + 1, last_error_code = 'outcome-unknown',
		next_attempt_at = ?, updated_at = ? WHERE id = ?`, nextAt, now, id)
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
	// Uncertain：至少有一次「请求已发出、没有拿到结果」的邮件数（可能重复投递，SMTP 没有服务商侧去重）
	Uncertain int
	// Events：安全事件的积压与去向（SV-05）
	Events SecurityEventStats
}

func GetMailStats(q dbtx) (MailStats, error) {
	var s MailStats
	if err := q.QueryRow(`SELECT COUNT(*) FROM mail_outbox WHERE uncertain_attempts > 0`).Scan(&s.Uncertain); err != nil {
		return s, err
	}
	ev, err := GetSecurityEventStats(q)
	if err != nil {
		return s, err
	}
	s.Events = ev
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
