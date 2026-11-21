package sync

// v9.2 设备级凭据（二阶段，审查 14）：
//   - 每台设备独立随机 token（服务器只存 SHA-256），最小权限 scopes，可单独撤销；
//   - 配对包 v2 只携带一次性 enrollment secret，根 Token 不再离开服务器与首台设备；
//   - 根 Token 保留全权限：首台设备注册、设备管理、备份 admin、灾难恢复。

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// 设备 scopes（最小权限）。backup-admin 与设备管理不授予任何设备，仅根 Token。
const (
	ScopeSync     = "sync"      // 文件/变更/快照/历史读 + vault-key 读
	ScopeShare    = "share"     // 分享创建/列表/撤销
	ScopeKeyAdmin = "key-admin" // vault-key 写、E2EE 状态机、历史清理
	ScopePairing  = "pairing"   // 创建配对包与注册凭据（添加新设备）
	// ScopeBackupAdmin（v0.16 / §10.5）：备份与灾难恢复。
	//
	// 它被**显式命名**出来，是为了让「不授予」变成一条可测试的规则而不是
	// 一句注释。备份能读到整个仓库的密文与全部元数据——一台普通同步设备
	// 被攻破，不应该顺带把它交出去。因此：不在 DefaultDeviceScopes 里，
	// 签发 access token 时会被剥掉，只属于根 Token 与 admin 会话。
	ScopeBackupAdmin = "backup-admin"
	// ScopeMigration（v0.16 / §10.5）：元数据迁移状态机。
	// 迁移会改写整个仓库的寻址格式，是仓库级不可逆动作，与日常同步分开。
	ScopeMigration = "migration"
)

// DefaultDeviceScopes：同步客户端设备的默认权限集合。
var DefaultDeviceScopes = []string{ScopeSync, ScopeShare, ScopeKeyAdmin, ScopePairing}

var ErrEnrollmentInvalid = errors.New("enrollment secret invalid, expired, or already used")

// ErrDeviceRevoked：凭据曾经有效、已被撤销（单独撤销或 Token 重置的连带撤销）。
// 与「查无此凭据」分开返回，客户端才能给出「请填入新 Token 重新接入」而不是
// 含糊的「认证失败」（v11 设计 §4.2）。
var ErrDeviceRevoked = errors.New("device credential has been revoked")

const enrollmentDefaultTTL = 900 * time.Second

func randomHex(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// DeviceCredential：注册响应（token 明文仅在此出现一次）。
type DeviceCredential struct {
	DeviceID string
	Name     string
	Token    string
	Scopes   []string
}

// HasScope 判断 scopes 串是否包含指定 scope。
func HasScope(scopes, want string) bool {
	for _, s := range strings.Split(scopes, ",") {
		if strings.TrimSpace(s) == want {
			return true
		}
	}
	return false
}

// CreateDevice 直接创建设备凭据（用户 Token 专用：首台设备自注册）。
// vaultID / userID 是新设备的归属，来自认证上下文；空值落到 default 管理员
//（单用户旧路径的正确语义，db.InsertDevice 兜底）。
//
// 新设备属于账号**此刻**的授权代次——只给运维 CLI 与测试用；请求路径上必须用
// CreateDeviceAt 传入签发者凭据自己的代次（ADR-019 §2.2）。
func (s *Service) CreateDevice(name, vaultID, userID string) (*DeviceCredential, error) {
	s.mu.Lock()
	epoch, err := db.UserAuthEpoch(s.db, defaultIfEmptyStr(userID, db.AdminUserID))
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.CreateDeviceAt(name, vaultID, userID, epoch)
}

// CreateDeviceAt 以签发者凭据的授权代次创建设备凭据（ADR-019 §2.2）。
// 签发者在撤销之前通过了校验、撤销又抢先提交时，新设备带的是旧代次，下一次校验即失败。
func (s *Service) CreateDeviceAt(name, vaultID, userID string, authEpoch int64) (*DeviceCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var cred *DeviceCredential
	err := s.inTx(func(tx *sql.Tx) error {
		var err error
		if cred, err = s.createDeviceLocked(tx, name, strings.Join(DefaultDeviceScopes, ","), vaultID, userID, authEpoch, ""); err != nil {
			return err
		}
		return s.recordDeviceEvent(tx, userID, vaultID, cred.DeviceID, name, "")
	})
	if err != nil {
		return nil, err
	}
	s.wake()
	return cred, nil
}

func defaultIfEmptyStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// recordDeviceEvent 在建设备的同一事务里记下「新设备已连接」安全事件（复审 SV-05）。
func (s *Service) recordDeviceEvent(q db.Queryer, userID, vaultID, deviceID, name, platform string) error {
	if userID == "" {
		userID = db.AdminUserID
	}
	if vaultID == "" {
		vaultID = db.DefaultVaultID
	}
	return s.recordEvent(q, userID, "device-enrolled", map[string]string{
		"device": name, "platform": platform, "vault": db.VaultDisplayName(q, vaultID), "eventId": deviceID,
	})
}

// createDeviceLocked 写入一台新设备（q 可以是事务；调用方持有 s.mu）。
func (s *Service) createDeviceLocked(q db.Queryer, name, scopes, vaultID, userID string, authEpoch int64, platform string) (*DeviceCredential, error) {
	id, err := randomHex(8)
	if err != nil {
		return nil, err
	}
	token, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if err := db.InsertDevice(q, &db.Device{
		DeviceID:   id,
		Name:       name,
		TokenHash:  sha256Hex([]byte(token)),
		Scopes:     scopes,
		CreatedAt:  now,
		LastSeenAt: now,
		VaultID:    vaultID,
		UserID:     userID,
		Platform:   platform,
		AuthEpoch:  authEpoch,
	}); err != nil {
		return nil, err
	}
	s.log.Info("device created", "deviceId", id, "name", name, "scopes", scopes)
	return &DeviceCredential{DeviceID: id, Name: name, Token: token, Scopes: strings.Split(scopes, ",")}, nil
}

// CreateEnrollment 生成一次性注册凭据（配对流程；secret 明文只返回一次）。
//
// 归属在创建时定死：新设备将落到 (vaultID, userID)。userID 为空而
// actorDeviceID 非空时，继承该设备的归属——配对包由某台设备生成，
// 新设备自然属于同一个人。
//
// 授权代次取账号此刻的值——只给测试与 CLI 用；请求路径用 CreateEnrollmentAt。
func (s *Service) CreateEnrollment(ttl time.Duration, vaultID, userID, actorDeviceID string) (id, secret string, expiresAt int64, err error) {
	return s.createEnrollment(ttl, vaultID, userID, actorDeviceID, nil)
}

// CreateEnrollmentAt 以签发者凭据的授权代次生成一次性注册凭据（ADR-019 §2.2）。
func (s *Service) CreateEnrollmentAt(ttl time.Duration, vaultID, userID, actorDeviceID string, authEpoch int64) (id, secret string, expiresAt int64, err error) {
	return s.createEnrollment(ttl, vaultID, userID, actorDeviceID, &authEpoch)
}

func (s *Service) createEnrollment(ttl time.Duration, vaultID, userID, actorDeviceID string, authEpoch *int64) (id, secret string, expiresAt int64, err error) {
	if ttl <= 0 || ttl > 2*enrollmentDefaultTTL {
		ttl = enrollmentDefaultTTL
	}
	id, err = randomHex(8)
	if err != nil {
		return "", "", 0, err
	}
	secret, err = randomHex(32)
	if err != nil {
		return "", "", 0, err
	}
	now := time.Now()
	expiresAt = now.Add(ttl).Unix()

	s.mu.Lock()
	defer s.mu.Unlock()
	if userID == "" && actorDeviceID != "" {
		if _, ownerID, terr := db.DeviceTenant(s.db, actorDeviceID); terr == nil && ownerID != "" {
			userID = ownerID
		}
	}
	var epoch int64
	if authEpoch != nil {
		epoch = *authEpoch
	} else if epoch, err = db.UserAuthEpoch(s.db, defaultIfEmptyStr(userID, db.AdminUserID)); err != nil {
		return "", "", 0, err
	}
	err = db.InsertEnrollment(s.db, id, sha256Hex([]byte(secret)),
		strings.Join(DefaultDeviceScopes, ","), now.Unix(), expiresAt, vaultID, userID, epoch)
	if err != nil {
		return "", "", 0, err
	}
	return id, secret, expiresAt, nil
}

// EnrollDevice 用一次性注册凭据换取设备凭据（公开接口，secret 即认证）。
// 新设备的归属来自 enrollment 自身（创建时定死），不来自请求。
//
// ADR-019：授权签发时的代次必须仍等于账号当前代次、账号未停用；消费授权与建设备在
// 同一事务里，新设备继承授权的代次（撤销与兑换并发时，晚到的这台下一次校验即失败）。
// 失败一律 ErrEnrollmentInvalid（v1 端点「不暴露凭据是否曾经有效」的既有约定）。
func (s *Service) EnrollDevice(secret, name string) (*DeviceCredential, error) {
	hash := sha256Hex([]byte(secret))
	s.mu.Lock()
	defer s.mu.Unlock()
	row, err := db.GetEnrollmentBySecretHash(s.db, hash)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, ErrEnrollmentInvalid
	}
	st, err := db.UserSessionState(s.db, row.UserID)
	if err != nil {
		return nil, err
	}
	if st.Disabled || row.AuthEpoch != st.AuthEpoch {
		return nil, ErrEnrollmentInvalid
	}
	var cred *DeviceCredential
	err = s.inTx(func(tx *sql.Tx) error {
		g, err := db.ConsumeEnrollment(tx, hash, time.Now().Unix(), row.AuthEpoch)
		if err != nil {
			return err
		}
		if g == nil {
			return ErrEnrollmentInvalid
		}
		// 事务内复核（多连接的 PG 部署里撤销可能刚好提交）
		if cur, err := db.UserAuthEpoch(tx, g.UserID); err != nil {
			return err
		} else if cur != g.AuthEpoch {
			return ErrEnrollmentInvalid
		}
		if cred, err = s.createDeviceLocked(tx, name, g.Scopes, g.VaultID, g.UserID, g.AuthEpoch, ""); err != nil {
			return err
		}
		return s.recordDeviceEvent(tx, g.UserID, g.VaultID, cred.DeviceID, name, "")
	})
	if err != nil {
		return nil, err
	}
	s.wake()
	return cred, nil
}

// AuthDevice 校验设备 token；有效则返回设备并更新 last_seen（节流到 5 分钟一次）。
func (s *Service) AuthDevice(token string) (*db.Device, error) {
	return s.AuthDeviceWithClient(token, "", 0, "", "")
}

// AuthDeviceWithClient 在校验的同时记录客户端上报的版本、平台与来源 IP
//（§15 第 3 步 + v0.17 运维页增强）。
//
// 与 last_seen 用同一套节流：每个请求都写一次数据库，只为了记几个几乎不变的
// 值，不值得。对「迁移前确认全部升级」这个用途来说，5 分钟的延迟无关紧要。
func (s *Service) AuthDeviceWithClient(token, clientVersion string, protocol int64, platform, ip string) (*db.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := db.GetDeviceAuthByTokenHash(s.db, sha256Hex([]byte(token)))
	if err != nil || a == nil {
		return nil, err
	}
	// ADR-019 R-1：单独撤销、账号授权代次已前进（退出全部设备 / 停用 / 中心停用……）、
	// 账号已停用——都是「曾有效、已被撤销」
	if !a.Valid() {
		return nil, ErrDeviceRevoked
	}
	d := &a.Device
	now := time.Now().Unix()
	// 版本/平台/IP 任一变化就立刻记，否则沿用 5 分钟节流：升级完（或换了网络）
	// 立刻去看设备列表是个很自然的动作，让人等五分钟才看到新值会被当成「没生效」
	changed := (clientVersion != "" && clientVersion != d.ClientVersion) ||
		(platform != "" && platform != d.Platform) ||
		(ip != "" && ip != d.LastIP)
	if now-d.LastSeenAt > 300 || changed {
		if err := db.TouchDevice(s.db, d.DeviceID, now); err != nil {
			s.log.Warn("device last_seen update failed", "deviceId", d.DeviceID, "error", err)
		}
		d.LastSeenAt = now
		if err := db.RecordClientSeen(s.db, d.DeviceID, clientVersion, protocol, platform, ip); err != nil {
			s.log.Warn("device client info update failed", "deviceId", d.DeviceID, "error", err)
		} else {
			// 内存副本与 RecordClientSeen 的落库语义保持一致：空值 = 未上报
			if clientVersion != "" {
				d.ClientVersion = clientVersion
			}
			if protocol != 0 {
				d.ClientProtocol = protocol
			}
			if platform != "" {
				d.Platform = platform
			}
			if ip != "" {
				d.LastIP = ip
			}
		}
	}
	return d, nil
}

func (s *Service) ListDevices() ([]db.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.ListDevices(s.db)
}

// ListDevicesFor 列出 userID 在该 Vault 下的设备（普通 /api/v1/devices，PRE-01）。
// ListDevices（全实例）只给管理员运维页。
func (s *Service) ListDevicesFor(scope db.VaultScope, userID string) ([]db.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.ListDevicesOfUser(s.db, scope, userID)
}

// ListAllUserDevices 列出 userID 名下全部仓库的设备（账户中心）。
func (s *Service) ListAllUserDevices(userID string) ([]db.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.ListAllDevicesOfUser(s.db, userID)
}

// RevokeUserDevice 撤销属于 userID 的设备（PRE-02）；不是他的返回 false（调用方回 404）。
func (s *Service) RevokeUserDevice(userID, deviceID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok, err := db.RevokeDeviceOfUser(s.db, deviceID, userID)
	if err == nil && ok {
		s.log.Info("device revoked", "deviceId", deviceID)
	}
	return ok, err
}

// RevokeDevice 撤销设备（管理员运维与内部流程专用）；被撤销设备的下一个请求即 401。
func (s *Service) RevokeDevice(deviceID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok, err := db.RevokeDevice(s.db, deviceID)
	if err == nil && ok {
		s.log.Info("device revoked", "deviceId", deviceID)
	}
	return ok, err
}

// maintainEnrollments 清理过期/已消费的注册凭据。
func (s *Service) maintainEnrollments(now int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.PruneEnrollments(s.db, now)
}
