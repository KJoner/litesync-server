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
	// SigningPublicKey（v0.15 / §9.2）：该设备的 checkpoint 签名公钥
	//（base64 SPKI，ECDSA P-256）。服务器只存不用——它没有私钥，
	// 也不验证签名；验证在客户端做，「服务器说签名是对的」毫无价值。
	SigningPublicKey string
	// VaultID / UserID（v0.16 / §10.4）：设备属于哪个租户的哪个人。
	// 没有这条绑定，「移除成员时撤销他的设备」无从谈起。
	VaultID string
	UserID  string
	// ClientVersion / ClientProtocol（v0.17 / §15 第 3 步）：
	// 该设备最后一次请求上报的插件版本与协议版本。
	// 迁移前要回答「所有设备都升级了吗」，这是唯一的事实来源。
	ClientVersion  string
	ClientProtocol int64
}

const deviceColumns = `id, name, token_hash, scopes, created_at, last_seen_at, revoked,
	signing_public_key, vault_id, user_id, client_version, client_protocol`

func scanDevice(sc interface{ Scan(...any) error }) (*Device, error) {
	d := &Device{}
	var revoked int64
	if err := sc.Scan(&d.DeviceID, &d.Name, &d.TokenHash, &d.Scopes, &d.CreatedAt,
		&d.LastSeenAt, &revoked, &d.SigningPublicKey, &d.VaultID, &d.UserID,
		&d.ClientVersion, &d.ClientProtocol); err != nil {
		return nil, err
	}
	d.Revoked = revoked != 0
	return d, nil
}

// GetDeviceByID 按设备 id 查找；不存在返回 (nil, nil)。
//
// access token 校验每次都会走这里：票是自包含的，但撤销必须即时生效，
// 因此每次用票都要回查设备是否还在、是否已被撤销。
func GetDeviceByID(q dbtx, deviceID string) (*Device, error) {
	d, err := scanDevice(q.QueryRow(`SELECT `+deviceColumns+` FROM devices WHERE id = ?`, deviceID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return d, nil
}

func InsertDevice(q dbtx, d *Device) error {
	revoked := 0
	if d.Revoked {
		revoked = 1
	}
	_, err := q.Exec(
		`INSERT INTO devices (id, name, token_hash, scopes, created_at, last_seen_at, revoked, vault_id, user_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.DeviceID, d.Name, d.TokenHash, d.Scopes, d.CreatedAt, d.LastSeenAt, revoked,
		defaultIfEmpty(d.VaultID, DefaultVaultID), d.UserID,
	)
	return err
}

// GetDeviceByTokenHash 按 token hash 查找未撤销的设备；不存在返回 (nil, nil)。
func GetDeviceByTokenHash(q dbtx, tokenHash string) (*Device, error) {
	d, err := scanDevice(q.QueryRow(
		`SELECT `+deviceColumns+` FROM devices WHERE token_hash = ?`, tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return d, nil
}

func ListDevices(q dbtx) ([]Device, error) {
	rows, err := q.Query(`SELECT ` + deviceColumns + ` FROM devices ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
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

// SetDeviceSigningKey 登记设备的 checkpoint 签名公钥（§9.2）。
//
// 只允许**首次**设置：公钥一旦发布，其他设备就可能已经据此验证过 checkpoint。
// 允许改写等于允许「换一把钥匙，然后重新解释历史」——那正是这套机制要防的事。
// 需要换密钥时的正确做法是撤销该设备再重新接入。
func SetDeviceSigningKey(q dbtx, deviceID, spkiB64 string) error {
	_, err := q.Exec(
		`UPDATE devices SET signing_public_key = ? WHERE id = ? AND signing_public_key = ''`,
		spkiB64, deviceID)
	return err
}

func defaultIfEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// RecordClientVersion 记录设备最后一次上报的客户端版本（§15 第 3 步）。
//
// 只写不比较：判断「够不够新」是运维决策，属于 preflight，不属于这里。
// 服务器在这里做版本门禁会变成一个新的拒绝服务面——一次误配就把所有设备挡在外面。
func RecordClientVersion(q dbtx, deviceID, version string, protocol int64) error {
	if version == "" && protocol == 0 {
		return nil
	}
	_, err := q.Exec(
		`UPDATE devices SET client_version = ?, client_protocol = ? WHERE id = ?`,
		version, protocol, deviceID)
	return err
}
