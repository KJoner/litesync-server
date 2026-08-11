package db

import (
	"database/sql"
	"errors"
)

// Device 对应 devices 表的一行（token 只存 hash，明文只在注册响应里出现一次）。
type Device struct {
	DeviceID   string
	Name       string
	TokenHash  string
	Scopes     string // 逗号分隔：sync,share,key-admin,pairing
	CreatedAt  int64
	LastSeenAt int64
	Revoked    bool
}

func InsertDevice(q dbtx, d *Device) error {
	revoked := 0
	if d.Revoked {
		revoked = 1
	}
	_, err := q.Exec(
		`INSERT INTO devices (id, name, token_hash, scopes, created_at, last_seen_at, revoked)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		d.DeviceID, d.Name, d.TokenHash, d.Scopes, d.CreatedAt, d.LastSeenAt, revoked,
	)
	return err
}

// GetDeviceByTokenHash 按 token hash 查找未撤销的设备；不存在返回 (nil, nil)。
func GetDeviceByTokenHash(q dbtx, tokenHash string) (*Device, error) {
	d := &Device{}
	var revoked int64
	err := q.QueryRow(
		`SELECT id, name, token_hash, scopes, created_at, last_seen_at, revoked
		 FROM devices WHERE token_hash = ?`, tokenHash,
	).Scan(&d.DeviceID, &d.Name, &d.TokenHash, &d.Scopes, &d.CreatedAt, &d.LastSeenAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	d.Revoked = revoked != 0
	return d, nil
}

func ListDevices(q dbtx) ([]Device, error) {
	rows, err := q.Query(
		`SELECT id, name, token_hash, scopes, created_at, last_seen_at, revoked
		 FROM devices ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var revoked int64
		if err := rows.Scan(&d.DeviceID, &d.Name, &d.TokenHash, &d.Scopes,
			&d.CreatedAt, &d.LastSeenAt, &revoked); err != nil {
			return nil, err
		}
		d.Revoked = revoked != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

// RevokeDevice 撤销设备；返回是否存在该设备。
func RevokeDevice(q dbtx, deviceID string) (bool, error) {
	res, err := q.Exec(`UPDATE devices SET revoked = 1 WHERE id = ?`, deviceID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return n > 0, nil
}

func TouchDevice(q dbtx, deviceID string, now int64) error {
	_, err := q.Exec(`UPDATE devices SET last_seen_at = ? WHERE id = ?`, now, deviceID)
	return err
}

// InsertEnrollment 保存一次性注册凭据（只存 hash）。
func InsertEnrollment(q dbtx, id, secretHash, scopes string, now, expiresAt int64) error {
	_, err := q.Exec(
		`INSERT INTO enrollments (id, secret_hash, scopes, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		id, secretHash, scopes, now, expiresAt,
	)
	return err
}

// ConsumeEnrollment 原子消费注册凭据（一次性）：有效则标记 consumed 并返回 scopes。
// 不存在 / 已消费 / 已过期返回 ("", false, nil)。
func ConsumeEnrollment(q dbtx, secretHash string, now int64) (string, bool, error) {
	var scopes string
	err := q.QueryRow(
		`UPDATE enrollments SET consumed_at = ?
		 WHERE secret_hash = ? AND consumed_at = 0 AND expires_at > ?
		 RETURNING scopes`,
		now, secretHash, now,
	).Scan(&scopes)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return scopes, true, nil
}

// PruneEnrollments 清理已过期或已消费超过一天的注册凭据。
func PruneEnrollments(q dbtx, now int64) (int64, error) {
	res, err := q.Exec(
		`DELETE FROM enrollments WHERE expires_at <= ? OR (consumed_at > 0 AND consumed_at < ?)`,
		now, now-86400,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return n, nil
}
