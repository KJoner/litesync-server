package sync

// v9.2 设备级凭据（二阶段，审查 14）：
//   - 每台设备独立随机 token（服务器只存 SHA-256），最小权限 scopes，可单独撤销；
//   - 配对包 v2 只携带一次性 enrollment secret，根 Token 不再离开服务器与首台设备；
//   - 根 Token 保留全权限：首台设备注册、设备管理、备份 admin、灾难恢复。

import (
	"crypto/rand"
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

// CreateDevice 直接创建设备凭据（根 Token 专用：首台设备自注册）。
func (s *Service) CreateDevice(name string) (*DeviceCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createDeviceLocked(name, strings.Join(DefaultDeviceScopes, ","))
}

func (s *Service) createDeviceLocked(name, scopes string) (*DeviceCredential, error) {
	id, err := randomHex(8)
	if err != nil {
		return nil, err
	}
	token, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if err := db.InsertDevice(s.db, &db.Device{
		DeviceID:   id,
		Name:       name,
		TokenHash:  sha256Hex([]byte(token)),
		Scopes:     scopes,
		CreatedAt:  now,
		LastSeenAt: now,
	}); err != nil {
		return nil, err
	}
	s.log.Info("device created", "deviceId", id, "name", name, "scopes", scopes)
	return &DeviceCredential{DeviceID: id, Name: name, Token: token, Scopes: strings.Split(scopes, ",")}, nil
}

// CreateEnrollment 生成一次性注册凭据（配对流程；secret 明文只返回一次）。
func (s *Service) CreateEnrollment(ttl time.Duration) (id, secret string, expiresAt int64, err error) {
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
	err = db.InsertEnrollment(s.db, id, sha256Hex([]byte(secret)),
		strings.Join(DefaultDeviceScopes, ","), now.Unix(), expiresAt)
	if err != nil {
		return "", "", 0, err
	}
	return id, secret, expiresAt, nil
}

// EnrollDevice 用一次性注册凭据换取设备凭据（公开接口，secret 即认证）。
func (s *Service) EnrollDevice(secret, name string) (*DeviceCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	scopes, ok, err := db.ConsumeEnrollment(s.db, sha256Hex([]byte(secret)), time.Now().Unix())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrEnrollmentInvalid
	}
	return s.createDeviceLocked(name, scopes)
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
	d, err := db.GetDeviceByTokenHash(s.db, sha256Hex([]byte(token)))
	if err != nil || d == nil || d.Revoked {
		return nil, err
	}
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

// RevokeDevice 撤销设备（根 Token 专用）；被撤销设备的下一个请求即 401。
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
