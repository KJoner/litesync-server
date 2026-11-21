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
	// Platform / LastIP（v0.17 运维页增强）：该设备最后一次上报的平台
	// 与最近来源 IP。丢设备的那天，「哪台是那部手机、它最后从哪连上来」
	// 靠只有设备名的列表答不了。
	Platform string
	LastIP   string
	// AuthEpoch（v0.20.1 / ADR-019 §2.2）：签发这台设备凭据时账号的授权代次。
	// 账号代次前进（退出全部设备、停用、中心停用……）之后它就再也对不上，校验即失败——
	// 判定发生在校验时，撤销与兑换并发也不会留下有效凭据。
	AuthEpoch int64
}

const deviceColumns = `id, name, token_hash, scopes, created_at, last_seen_at, revoked,
	signing_public_key, vault_id, user_id, client_version, client_protocol, platform, last_ip, auth_epoch`

// deviceColumnsD 同 deviceColumns，带表别名 d（与 users 联查时避免同名列歧义）。
const deviceColumnsD = `d.id, d.name, d.token_hash, d.scopes, d.created_at, d.last_seen_at, d.revoked,
	d.signing_public_key, d.vault_id, d.user_id, d.client_version, d.client_protocol, d.platform, d.last_ip, d.auth_epoch`

func scanDevice(sc interface{ Scan(...any) error }) (*Device, error) {
	d := &Device{}
	var revoked int64
	if err := sc.Scan(&d.DeviceID, &d.Name, &d.TokenHash, &d.Scopes, &d.CreatedAt,
		&d.LastSeenAt, &revoked, &d.SigningPublicKey, &d.VaultID, &d.UserID,
		&d.ClientVersion, &d.ClientProtocol, &d.Platform, &d.LastIP, &d.AuthEpoch); err != nil {
		return nil, err
	}
	d.Revoked = revoked != 0
	return d, nil
}

// DeviceAuth 是认证用的设备视图：设备行 + 其账号此刻的授权代次与停用状态。
type DeviceAuth struct {
	Device
	UserExists   bool
	UserDisabled bool
	UserEpoch    int64
}

// Valid 是 ADR-019 R-1 的设备形态：未单独撤销 **且** 凭据代次 == 账号当前代次 **且** 账号未停用。
//
// 设备行指向的账号行不存在时按「代次 0、未停用」处理（v0.16 之前的单用户库里设备先于
// 账号行存在；删除账号时 DeleteUserCascade 会连设备一起删掉，正常数据里不会出现孤儿设备）。
// 这样任何被撤销过的账号（代次 ≥ 1）都不可能因为「查不到账号」而让旧设备复活。
func (d *DeviceAuth) Valid() bool {
	return !d.Revoked && !d.UserDisabled && d.AuthEpoch == d.UserEpoch
}

func scanDeviceAuth(row *sql.Row) (*DeviceAuth, error) {
	var a DeviceAuth
	var revoked, disabled, exists int64
	err := row.Scan(&a.DeviceID, &a.Name, &a.TokenHash, &a.Scopes, &a.CreatedAt,
		&a.LastSeenAt, &revoked, &a.SigningPublicKey, &a.VaultID, &a.UserID,
		&a.ClientVersion, &a.ClientProtocol, &a.Platform, &a.LastIP, &a.Device.AuthEpoch,
		&a.UserEpoch, &disabled, &exists)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.Revoked, a.UserDisabled, a.UserExists = revoked != 0, disabled != 0, exists != 0
	return &a, nil
}

const deviceAuthSelect = `SELECT ` + deviceColumnsD + `,
	COALESCE(u.auth_epoch, 0), COALESCE(u.disabled, 0), CASE WHEN u.user_id IS NULL THEN 0 ELSE 1 END
	FROM devices d LEFT JOIN users u ON u.user_id = d.user_id`

// GetDeviceAuthByTokenHash 按凭据哈希取设备与其账号状态（任何状态都返回；不存在返回 (nil, nil)）。
func GetDeviceAuthByTokenHash(q dbtx, tokenHash string) (*DeviceAuth, error) {
	return scanDeviceAuth(q.QueryRow(deviceAuthSelect+` WHERE d.token_hash = ?`, tokenHash))
}

// GetDeviceAuthByID 按设备 id 取设备与其账号状态（短期票每次回查用）。
func GetDeviceAuthByID(q dbtx, deviceID string) (*DeviceAuth, error) {
	return scanDeviceAuth(q.QueryRow(deviceAuthSelect+` WHERE d.id = ?`, deviceID))
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
	// 归属兜底：单用户语境下「未指明归属的设备属于 default vault 的管理员」
	// 是正确语义；多用户路径（v0.18 起）都会显式带上 (vault, user)。
	// 没有这条绑定，「重置 Token / 移除成员时撤销他的设备」无从谈起。
	_, err := q.Exec(
		`INSERT INTO devices (id, name, token_hash, scopes, created_at, last_seen_at, revoked, vault_id, user_id, platform, auth_epoch)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.DeviceID, d.Name, d.TokenHash, d.Scopes, d.CreatedAt, d.LastSeenAt, revoked,
		defaultIfEmpty(d.VaultID, DefaultVaultID), defaultIfEmpty(d.UserID, AdminUserID), d.Platform, d.AuthEpoch,
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

// MinAckedSequence 返回某 Vault 全部未撤销设备中最小的已确认 sequence，
// 以及设备数量（tombstone 双条件清理用；0 台设备时无法证明安全，调用方跳过）。
func MinAckedSequence(q dbtx, s VaultScope) (int64, int, error) {
	if !s.Valid() {
		return 0, 0, ErrVaultScopeMissing
	}
	rows, err := q.Query(`SELECT last_acked_sequence FROM devices WHERE revoked = 0 AND vault_id = ?`, s.ID())
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	minAcked := int64(-1)
	count := 0
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return 0, 0, err
		}
		count++
		if minAcked < 0 || v < minAcked {
			minAcked = v
		}
	}
	if minAcked < 0 {
		minAcked = 0
	}
	return minAcked, count, rows.Err()
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

// ListDevicesOfUser 列出某用户在某 Vault 下的设备（v0.20 / 公开化基线 PRE-01）。
//
// ListDevices 是全实例视图，只给管理员运维页用；普通的 /api/v1/devices 曾经
// 直接返回它——多用户之后，任何一个用户都能看到全实例所有人的设备名、scope
// 与设备 ID。按内容断言的回归测试在 api/tenancy_devices_test.go。
func ListDevicesOfUser(q dbtx, s VaultScope, userID string) ([]Device, error) {
	if !s.Valid() {
		return nil, ErrVaultScopeMissing
	}
	if userID == "" {
		return nil, nil
	}
	rows, err := q.Query(`SELECT `+deviceColumns+` FROM devices
		WHERE vault_id = ? AND user_id = ? ORDER BY created_at ASC`, s.ID(), userID)
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

// ListAllDevicesOfUser 列出某用户名下全部仓库的设备（账户中心「设备列表」）。
func ListAllDevicesOfUser(q dbtx, userID string) ([]Device, error) {
	if userID == "" {
		return nil, nil
	}
	rows, err := q.Query(`SELECT `+deviceColumns+` FROM devices
		WHERE user_id = ? ORDER BY created_at ASC`, userID)
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

// RevokeDeviceOfUser 只撤销属于 userID 的设备（PRE-02）；不属于他的与不存在的
// 同样返回 false——调用方据此回 404，不泄露「这个 ID 存在但不是你的」。
func RevokeDeviceOfUser(q dbtx, deviceID, userID string) (bool, error) {
	if userID == "" || deviceID == "" {
		return false, nil
	}
	res, err := q.Exec(`UPDATE devices SET revoked = 1 WHERE id = ? AND user_id = ?`, deviceID, userID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return n > 0, nil
}

// RevokeDevice 撤销设备；返回是否存在该设备。
// 只用于管理员运维与内部流程（成员移除、Token 重置）；请求路径上的普通撤销
// 必须走 RevokeDeviceOfUser。
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
//
// authEpoch 是**签发者凭据**的授权代次（ADR-019 §2.2）：用的是发起请求的那张会话 / 设备 /
// Token 上记的代次，而不是此刻账号的代次——否则一个在「退出全部设备」之前通过校验的旧会话，
// 可以在撤销提交之后插进来一张属于新代次的授权。
func InsertEnrollment(q dbtx, id, secretHash, scopes string, now, expiresAt int64, vaultID, userID string, authEpoch int64) error {
	_, err := q.Exec(
		`INSERT INTO enrollments (id, secret_hash, scopes, created_at, expires_at, vault_id, user_id, auth_epoch)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, secretHash, scopes, now, expiresAt,
		defaultIfEmpty(vaultID, DefaultVaultID), defaultIfEmpty(userID, AdminUserID), authEpoch,
	)
	return err
}

// EnrollmentGrant 是一次性注册凭据兑现的内容：新设备将获得的 scopes 与归属。
// 归属在**创建邀请/配对包时**就定死（v0.18）——消费方无法声称自己属于别的租户。
type EnrollmentGrant struct {
	Scopes  string
	VaultID string
	UserID  string
	// AuthEpoch：签发时的账号授权代次；新设备继承它（ADR-019 §2.2）
	AuthEpoch int64
}

// ConsumeEnrollment 原子消费注册凭据（一次性）：有效则标记 consumed 并返回授予内容。
// 不存在 / 已消费 / 已过期 / 已撤销 / 代次与 wantEpoch 不符返回 (nil, nil)。
func ConsumeEnrollment(q dbtx, secretHash string, now, wantEpoch int64) (*EnrollmentGrant, error) {
	g := &EnrollmentGrant{}
	err := q.QueryRow(
		`UPDATE enrollments SET consumed_at = ?
		 WHERE secret_hash = ? AND consumed_at = 0 AND revoked = 0 AND expires_at > ? AND auth_epoch = ?
		 RETURNING scopes, vault_id, user_id, auth_epoch`,
		now, secretHash, now, wantEpoch,
	).Scan(&g.Scopes, &g.VaultID, &g.UserID, &g.AuthEpoch)
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

// RevokeEnrollmentGrant 作废一个尚未兑换的注册凭据（v2 配对包被发行者撤销时连带执行）。
// 已兑换的不受影响——那台设备要单独撤销。
func RevokeEnrollmentGrant(q dbtx, grantID string, now int64) error {
	if grantID == "" {
		return nil
	}
	_, err := q.Exec(`UPDATE enrollments SET revoked = 1 WHERE id = ? AND consumed_at = 0`, grantID)
	return err
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

// RecordClientSeen 记录设备最后一次上报的客户端版本、平台与来源 IP
//（§15 第 3 步 + v0.17 运维页增强，原 RecordClientVersion）。
//
// 只写不比较：判断「够不够新」是运维决策，属于 preflight，不属于这里。
// 服务器在这里做版本门禁会变成一个新的拒绝服务面——一次误配就把所有设备挡在外面。
//
// 每个字段都是「空值 = 未上报，保留旧值」：旧客户端不带 X-Client-Platform 头，
// 不能让它每次请求把已记录的平台抹掉；version/protocol 同理。
func RecordClientSeen(q dbtx, deviceID, version string, protocol int64, platform, ip string) error {
	if version == "" && protocol == 0 && platform == "" && ip == "" {
		return nil
	}
	_, err := q.Exec(
		`UPDATE devices SET
		 client_version = CASE WHEN ? != '' THEN ? ELSE client_version END,
		 client_protocol = CASE WHEN ? != 0 THEN ? ELSE client_protocol END,
		 platform = CASE WHEN ? != '' THEN ? ELSE platform END,
		 last_ip = CASE WHEN ? != '' THEN ? ELSE last_ip END
		 WHERE id = ?`,
		version, version, protocol, protocol, platform, platform, ip, ip, deviceID)
	return err
}
