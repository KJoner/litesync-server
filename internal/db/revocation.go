package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
)

// NewEventID 生成撤销事件 id（128 位随机，小写 hex；ADR-019 §2.4 的 eventId 格式）。
func NewEventID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// 账号撤销的三种范围与跨产品传播（v0.20.1 / ADR-019）的数据访问。
//
//   - users.auth_epoch 是账号授权代次，只增不减（R-2）。网页会话、设备凭据、待领取授权
//     （enrollments）与 API Token 在签发时记下代次，每次校验都要求相等（R-1）。
//   - RevokeAccountTx 是动作 B 的唯一实现：代次 +1、设备与待领取授权标记撤销（列表展示用；
//     判定以代次为准）、删除待领取的配对包、记下一条撤销事件——全部在调用方的事务里。
//     动作 C 的本产品部分、D（中心停用 / 删除）、管理员停用、Token 重置、收到的跨产品事件
//     都走它，差别只在 scope / reason / origin。
//   - revocation_deliveries 是发往另一个产品的事件 outbox：与本产品的撤销**同一事务**写入，
//     请求返回前同步投递一次，失败由后台按 5 s、15 s、30 s、30 s… 重试，7 天后记为失败。
//   - revocation_inbox 是收到的事件（按 eventId 去重，重复投递返回同样的结果）。
//
// 这几张表都不存任何令牌：投递载荷里只有 eventId、(issuer, subject) 与范围/原因/时间。

const revocationSchema = `
CREATE TABLE IF NOT EXISTS account_revocations (
	event_id             TEXT PRIMARY KEY,
	user_id              TEXT NOT NULL,
	scope                TEXT NOT NULL,
	reason               TEXT NOT NULL,
	origin               TEXT NOT NULL,
	auth_epoch           INTEGER NOT NULL,
	revoked_devices      INTEGER NOT NULL DEFAULT 0,
	revoked_grants       INTEGER NOT NULL DEFAULT 0,
	identity_state       TEXT NOT NULL DEFAULT 'not-applicable',
	identity_error       TEXT NOT NULL DEFAULT '',
	status_token_hash    TEXT NOT NULL DEFAULT '',
	status_token_expires INTEGER NOT NULL DEFAULT 0,
	created_at           INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_account_revocations_user ON account_revocations(user_id, created_at);

CREATE TABLE IF NOT EXISTS revocation_deliveries (
	event_id        TEXT NOT NULL,
	peer            TEXT NOT NULL,
	payload         TEXT NOT NULL,
	delivery_state  TEXT NOT NULL CHECK (delivery_state IN ('pending','delivered','failed')),
	attempts        INTEGER NOT NULL DEFAULT 0,
	next_attempt_at INTEGER NOT NULL DEFAULT 0,
	last_error      TEXT NOT NULL DEFAULT '',
	peer_result     TEXT NOT NULL DEFAULT '',
	delivered_at    INTEGER NOT NULL DEFAULT 0,
	expires_at      INTEGER NOT NULL,
	created_at      INTEGER NOT NULL,
	updated_at      INTEGER NOT NULL,
	PRIMARY KEY (event_id, peer)
);
CREATE INDEX IF NOT EXISTS idx_revocation_deliveries_due ON revocation_deliveries(delivery_state, next_attempt_at);

CREATE TABLE IF NOT EXISTS revocation_inbox (
	event_id    TEXT PRIMARY KEY,
	origin      TEXT NOT NULL,
	result      TEXT NOT NULL,
	user_id     TEXT NOT NULL DEFAULT '',
	received_at INTEGER NOT NULL
);
`

// 撤销范围（ADR-019 §2.1）。
const (
	// RevocationScopeProduct：动作 B——本产品的全部网页会话 + 设备凭据 + 待领取授权。
	RevocationScopeProduct = "product-devices"
	// RevocationScopeAllProducts：动作 C（以及收到的跨产品事件）。
	RevocationScopeAllProducts = "all-products-all-devices"
)

// 投递状态（ADR-019 §5）。
const (
	DeliveryPending   = "pending"
	DeliveryDelivered = "delivered"
	DeliveryFailed    = "failed"
)

// ErrNoSuchUser：撤销的目标账号不存在。
var ErrNoSuchUser = errors.New("user not found")

// RevokeParams 描述一次账号级撤销。
type RevokeParams struct {
	UserID  string
	EventID string
	Scope   string
	// Reason：user-request | admin-disable | central-disabled | account-deleted | token-reset | peer:<origin>:<reason>
	Reason string
	// Origin：发起方产品（本产品发起为 litesync；收到的事件为对方的 origin）
	Origin string
	// IdentityState：C 为 pending（随后写入真实结果），其余为 not-applicable
	IdentityState string
	// StatusTokenHash / StatusTokenExpires：C 之后浏览器查看进度、重新发送用的一次性凭证（只存哈希）
	StatusTokenHash    string
	StatusTokenExpires int64
	Now                int64
}

// RevokeOutcome 是本产品部分的结果。
type RevokeOutcome struct {
	EventID        string
	AuthEpoch      int64
	RevokedDevices int
	RevokedGrants  int
}

// RevokeAccountTx 在调用方的事务里执行动作 B（ADR-019 §2.2）。
//
// 设备与授权的 revoked 标记只是给列表看的（以及回退到旧版本时仍然有效，ADR §8）；
// **判定以代次为准**：即使某个兑换与这里并发、抢先插入了一台设备，它记的是旧代次，
// 下一次校验时就会失败（R-4）。
func RevokeAccountTx(q dbtx, p RevokeParams) (*RevokeOutcome, error) {
	if p.UserID == "" || p.EventID == "" {
		return nil, errors.New("revoke account: empty user or event id")
	}
	var epoch int64
	err := q.QueryRow(`UPDATE users SET auth_epoch = auth_epoch + 1 WHERE user_id = ? RETURNING auth_epoch`,
		p.UserID).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoSuchUser
	}
	if err != nil {
		return nil, err
	}
	out := &RevokeOutcome{EventID: p.EventID, AuthEpoch: epoch}
	res, err := q.Exec(`UPDATE devices SET revoked = 1 WHERE user_id = ? AND revoked = 0`, p.UserID)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	out.RevokedDevices = int(n)

	// 待领取授权：管理员账号的存量行可能是 user_id = ''（v0.18 加列时的默认值，读取时归到管理员）
	grantOwner := `user_id = ?`
	if p.UserID == AdminUserID {
		grantOwner = `(user_id = ? OR user_id = '')`
	}
	res, err = q.Exec(`UPDATE enrollments SET revoked = 1, replay_ciphertext = ''
		WHERE `+grantOwner+` AND consumed_at = 0 AND revoked = 0 AND expires_at > ?`, p.UserID, p.Now)
	if err != nil {
		return nil, err
	}
	n, _ = res.RowsAffected() //nolint:errcheck
	out.RevokedGrants = int(n)
	// 已消费授权的「响应丢失重放」暂存一并抹掉（重放本来也会因代次不符被拒，这里是第二道）
	if _, err := q.Exec(`UPDATE enrollments SET replay_ciphertext = '' WHERE `+grantOwner+` AND replay_ciphertext != ''`,
		p.UserID); err != nil {
		return nil, err
	}
	// 待领取的配对包：里面只有一次性 secret，授权已死，包留着只会让链接看起来「还能用」
	if _, err := q.Exec(`DELETE FROM pairings WHERE user_id = ?`, p.UserID); err != nil {
		return nil, err
	}
	identity := p.IdentityState
	if identity == "" {
		identity = "not-applicable"
	}
	if _, err := q.Exec(`INSERT INTO account_revocations (event_id, user_id, scope, reason, origin, auth_epoch,
		revoked_devices, revoked_grants, identity_state, identity_error, status_token_hash, status_token_expires, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?)`,
		p.EventID, p.UserID, p.Scope, truncate(p.Reason, 64), truncate(p.Origin, 32), epoch,
		out.RevokedDevices, out.RevokedGrants, identity, p.StatusTokenHash, p.StatusTokenExpires, p.Now); err != nil {
		return nil, err
	}
	return out, nil
}

// SetRevocationIdentityResult 写入动作 C 第 2 步（身份中心）的真实结果。
func SetRevocationIdentityResult(q dbtx, eventID, state, errClass string) error {
	_, err := q.Exec(`UPDATE account_revocations SET identity_state = ?, identity_error = ? WHERE event_id = ?`,
		state, truncate(errClass, 64), eventID)
	return err
}

// RevocationDelivery 是一条发往另一个产品的事件投递。
type RevocationDelivery struct {
	EventID       string
	Peer          string
	Payload       string
	State         string
	Attempts      int
	NextAttemptAt int64
	LastError     string
	PeerResult    string
	DeliveredAt   int64
	ExpiresAt     int64
	CreatedAt     int64
	UpdatedAt     int64
}

const deliveryColumns = `event_id, peer, payload, delivery_state, attempts, next_attempt_at, last_error,
	peer_result, delivered_at, expires_at, created_at, updated_at`

func scanDelivery(sc interface{ Scan(...any) error }) (*RevocationDelivery, error) {
	d := &RevocationDelivery{}
	err := sc.Scan(&d.EventID, &d.Peer, &d.Payload, &d.State, &d.Attempts, &d.NextAttemptAt, &d.LastError,
		&d.PeerResult, &d.DeliveredAt, &d.ExpiresAt, &d.CreatedAt, &d.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return d, err
}

func scanDeliveries(rows *sql.Rows) ([]RevocationDelivery, error) {
	defer rows.Close()
	var out []RevocationDelivery
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// InsertRevocationDelivery 写入一条待投递事件（与本产品的撤销同一事务）。
func InsertRevocationDelivery(q dbtx, eventID, peer, payload string, now, expiresAt int64) error {
	_, err := q.Exec(`INSERT INTO revocation_deliveries (event_id, peer, payload, delivery_state, attempts,
		next_attempt_at, last_error, peer_result, delivered_at, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, 'pending', 0, ?, '', '', 0, ?, ?, ?)`, eventID, peer, payload, now, expiresAt, now, now)
	return err
}

// ClaimRevocationDelivery 领取一条到期的待投递事件（租约，ADR-019 §2.4）：attempts + 1、下次到期推后到
// leaseUntil。领到返回 true；别的 worker 正在发（租约未到期）或还没到重试时间返回 false。
// 发送途中进程中断时，租约到期后由下一个 worker 接续。
func ClaimRevocationDelivery(q dbtx, eventID, peer string, now, leaseUntil int64) (bool, error) {
	res, err := q.Exec(`UPDATE revocation_deliveries SET attempts = attempts + 1, next_attempt_at = ?, updated_at = ?
		WHERE event_id = ? AND peer = ? AND delivery_state = 'pending' AND next_attempt_at <= ?`,
		leaseUntil, now, eventID, peer, now)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return n == 1, nil
}

// GetRevocationDelivery 取一条投递；不存在返回 (nil, nil)。
func GetRevocationDelivery(q dbtx, eventID, peer string) (*RevocationDelivery, error) {
	return scanDelivery(q.QueryRow(`SELECT `+deliveryColumns+` FROM revocation_deliveries WHERE event_id = ? AND peer = ?`,
		eventID, peer))
}

// DeliveriesOfEvent 列出一个事件的全部投递。
func DeliveriesOfEvent(q dbtx, eventID string) ([]RevocationDelivery, error) {
	rows, err := q.Query(`SELECT `+deliveryColumns+` FROM revocation_deliveries WHERE event_id = ? ORDER BY peer`, eventID)
	if err != nil {
		return nil, err
	}
	return scanDeliveries(rows)
}

// DueRevocationDeliveries 返回到期的待投递事件（最早到期的先）。
func DueRevocationDeliveries(q dbtx, now int64, limit int) ([]RevocationDelivery, error) {
	rows, err := q.Query(`SELECT `+deliveryColumns+` FROM revocation_deliveries
		WHERE delivery_state = 'pending' AND next_attempt_at <= ? ORDER BY next_attempt_at ASC LIMIT ?`, now, limit)
	if err != nil {
		return nil, err
	}
	return scanDeliveries(rows)
}

// UpdateRevocationDelivery 写回一次投递尝试的结果。
func UpdateRevocationDelivery(q dbtx, d *RevocationDelivery) error {
	_, err := q.Exec(`UPDATE revocation_deliveries SET delivery_state = ?, attempts = ?, next_attempt_at = ?,
		last_error = ?, peer_result = ?, delivered_at = ?, expires_at = ?, updated_at = ?
		WHERE event_id = ? AND peer = ?`,
		d.State, d.Attempts, d.NextAttemptAt, truncate(d.LastError, 64), truncate(d.PeerResult, 32), d.DeliveredAt,
		d.ExpiresAt, d.UpdatedAt, d.EventID, d.Peer)
	return err
}

// ResetRevocationDeliveries 「重新发送」：把该事件尚未送达的投递重新置为立即到期（失败的也重新开始，
// 再给 7 天）。返回被重置的条数；已送达的不动。
func ResetRevocationDeliveries(q dbtx, eventID string, now, expiresAt int64) (int, error) {
	res, err := q.Exec(`UPDATE revocation_deliveries SET delivery_state = 'pending', next_attempt_at = ?,
		expires_at = ?, updated_at = ? WHERE event_id = ? AND delivery_state != 'delivered'`, now, expiresAt, now, eventID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return int(n), nil
}

// RevocationRecord 是一次撤销事件（账户中心「最近的撤销」）。
type RevocationRecord struct {
	EventID            string
	UserID             string
	Scope              string
	Reason             string
	Origin             string
	AuthEpoch          int64
	RevokedDevices     int
	RevokedGrants      int
	IdentityState      string
	IdentityError      string
	StatusTokenHash    string
	StatusTokenExpires int64
	CreatedAt          int64
	Deliveries         []RevocationDelivery
}

const revocationColumns = `event_id, user_id, scope, reason, origin, auth_epoch, revoked_devices, revoked_grants,
	identity_state, identity_error, status_token_hash, status_token_expires, created_at`

func scanRevocation(sc interface{ Scan(...any) error }) (*RevocationRecord, error) {
	r := &RevocationRecord{}
	err := sc.Scan(&r.EventID, &r.UserID, &r.Scope, &r.Reason, &r.Origin, &r.AuthEpoch, &r.RevokedDevices,
		&r.RevokedGrants, &r.IdentityState, &r.IdentityError, &r.StatusTokenHash, &r.StatusTokenExpires, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// GetRevocation 取一个撤销事件及其投递；不存在返回 (nil, nil)。
func GetRevocation(q dbtx, eventID string) (*RevocationRecord, error) {
	r, err := scanRevocation(q.QueryRow(`SELECT `+revocationColumns+` FROM account_revocations WHERE event_id = ?`, eventID))
	if err != nil || r == nil {
		return r, err
	}
	r.Deliveries, err = DeliveriesOfEvent(q, eventID)
	return r, err
}

// ListRevocationsOfUser 返回某账号最近的撤销事件（新的在前）及其投递。
func ListRevocationsOfUser(q dbtx, userID string, limit int) ([]RevocationRecord, error) {
	rows, err := q.Query(`SELECT `+revocationColumns+` FROM account_revocations WHERE user_id = ?
		ORDER BY created_at DESC, event_id DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	var out []RevocationRecord
	for rows.Next() {
		r, err := scanRevocation(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, *r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Deliveries, err = DeliveriesOfEvent(q, out[i].EventID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// GetRevocationInbox 查一个收到过的事件；没收到过 found=false。
func GetRevocationInbox(q dbtx, eventID string) (result, userID string, found bool, err error) {
	err = q.QueryRow(`SELECT result, user_id FROM revocation_inbox WHERE event_id = ?`, eventID).Scan(&result, &userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	return result, userID, err == nil, err
}

// InsertRevocationInbox 记下一个收到的事件（与执行 B 同一事务）。
func InsertRevocationInbox(q dbtx, eventID, origin, result, userID string, now int64) error {
	_, err := q.Exec(`INSERT INTO revocation_inbox (event_id, origin, result, user_id, received_at) VALUES (?, ?, ?, ?, ?)`,
		eventID, truncate(origin, 32), result, userID, now)
	return err
}

// RevocationStats 是管理员页的投递计数（不含任何身份信息）。
type RevocationStats struct {
	Pending, Delivered, Failed int
}

// GetRevocationStats 统计发往另一个产品的投递状态。
func GetRevocationStats(q dbtx) (RevocationStats, error) {
	var s RevocationStats
	rows, err := q.Query(`SELECT delivery_state, COUNT(*) FROM revocation_deliveries GROUP BY delivery_state`)
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
		case DeliveryPending:
			s.Pending = n
		case DeliveryDelivered:
			s.Delivered = n
		case DeliveryFailed:
			s.Failed = n
		}
	}
	return s, rows.Err()
}

// PruneRevocationRecords 清理过期记录：收件箱保留 30 天（对方最多重试 7 天，去重窗口必须盖住它）；
// 撤销事件与投递保留 90 天（账户中心只展示最近的）。
func PruneRevocationRecords(q dbtx, now int64) error {
	if _, err := q.Exec(`DELETE FROM revocation_inbox WHERE received_at < ?`, now-30*86400); err != nil {
		return err
	}
	cut := now - 90*86400
	if _, err := q.Exec(`DELETE FROM revocation_deliveries WHERE created_at < ? AND delivery_state != 'pending'`, cut); err != nil {
		return err
	}
	_, err := q.Exec(`DELETE FROM account_revocations WHERE created_at < ?
		AND event_id NOT IN (SELECT event_id FROM revocation_deliveries)`, cut)
	return err
}
