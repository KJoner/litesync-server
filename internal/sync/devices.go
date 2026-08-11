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
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := db.GetDeviceByTokenHash(s.db, sha256Hex([]byte(token)))
	if err != nil || d == nil || d.Revoked {
		return nil, err
	}
	now := time.Now().Unix()
	if now-d.LastSeenAt > 300 {
		if err := db.TouchDevice(s.db, d.DeviceID, now); err != nil {
			s.log.Warn("device last_seen update failed", "deviceId", d.DeviceID, "error", err)
		}
		d.LastSeenAt = now
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
