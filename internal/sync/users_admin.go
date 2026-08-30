package sync

import (
	"errors"
	"strings"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// 邀请与用户管理（v0.18 / v11 设计 §5.5–§5.7）。全部只由管理员端点调用；
// 注册消费端点公开（secret 即凭证）。

const (
	inviteDefaultTTL = 24 * time.Hour
	inviteMaxTTL     = 7 * 24 * time.Hour
)

// CreateInvite 生成邀请。serverURL 是注册页展示给新用户的接入地址
//（默认请求 origin，管理员可覆盖——反代/内网场景两者不同）。
func (s *Service) CreateInvite(serverURL string, ttl time.Duration) (id, secret string, expiresAt int64, err error) {
	if ttl <= 0 || ttl > inviteMaxTTL {
		ttl = inviteDefaultTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.CreateInvite(s.db, serverURL, ttl)
}

// ListInvites 返回邀请列表（管理页）。
func (s *Service) ListInvites() ([]db.Invite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.ListInvites(s.db)
}

// RevokeInvite 撤销未使用的邀请。
func (s *Service) RevokeInvite(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.RevokeInvite(s.db, id)
}

// InviteInfo 查询邀请是否可用（注册页加载时）。不可用返回 (nil, nil)。
func (s *Service) InviteInfo(secret string) (*db.Invite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.GetInviteBySecret(s.db, secret, time.Now().Unix())
}

// ErrInvalidUserName：用户名不符合规则。
var ErrInvalidUserName = errors.New("invalid user name")

// validUserName：1–32 个可打印字符，无空白/控制字符/路径分隔符。
func validUserName(name string) bool {
	if name == "" || len(name) > 32 {
		return false
	}
	if strings.TrimSpace(name) != name {
		return false
	}
	for _, r := range name {
		if r < 0x21 || r == 0x7f || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}

// RegisterInvitedUser 消费邀请建立新用户与专属 Vault（v11 设计 §5.5 的注册事务），
// 并保证新 Vault 的 repo_state 就绪——注册返回时这个 Vault 已经可以接受首次同步。
func (s *Service) RegisterInvitedUser(secret, name string) (*db.NewUserRegistration, error) {
	if !validUserName(name) {
		return nil, ErrInvalidUserName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, err := db.RegisterInvitedUser(s.db, secret, name, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	s.log.Info("user registered", "user", reg.UserID, "vault", reg.VaultID)
	return reg, nil
}

// ListUserAccounts 管理列表。
func (s *Service) ListUserAccounts() ([]db.UserAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.ListUserAccounts(s.db)
}

// SetUserDisabled 禁用/解禁用户。禁用 = 撤销全部设备凭据 + 会话世代 +1 +
// enforceVault 拒绝（VaultActive 检查 owner）；数据保留，解禁后重新接入即可。
func (s *Service) SetUserDisabled(userID string, disabled bool, actor string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	revoked, err := db.SetUserDisabledCascade(s.db, userID, disabled, actor)
	if err != nil {
		return 0, err
	}
	s.log.Warn("user disabled state changed", "user", userID, "disabled", disabled, "revokedDevices", revoked)
	return revoked, nil
}

// DeleteUser 删除用户及其专属 Vault 的全部数据（不可逆；两步确认在 API 层）。
// 分享密文文件与 blob 由数据行删除后统一清理。
func (s *Service) DeleteUser(userID, actor string) error {
	s.mu.Lock()
	blobIDs, shareIDs, vaultID, err := db.DeleteUserCascade(s.db, userID)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	for _, id := range shareIDs {
		if rerr := s.shares.Remove(id); rerr != nil {
			s.log.Warn("delete user: share content remove failed", "share", truncateID(id), "error", rerr)
		}
	}
	// blob 的最终裁决交给全局引用检查（域化后别的租户不可能引用同一 id，
	// 但同 Vault 数据已删干净，这里必然判为无引用）
	s.gcBlobs(blobIDs)
	s.log.Warn("user deleted", "user", userID, "vault", vaultID,
		"shares", len(shareIDs), "blobs", len(blobIDs), "actor", actor)
	return nil
}

// ---------- 单用户多仓库（v0.19） ----------

// ListUserVaults 列出用户名下全部仓库及概要（选择仓库的界面用）。
func (s *Service) ListUserVaults(userID string) ([]db.UserVault, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.ListUserVaults(s.db, userID)
}

// CreateUserVault 新建仓库（上限与同名检查在 db 层事务内）。
func (s *Service) CreateUserVault(userID, name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, err := db.CreateUserVault(s.db, userID, name)
	if err == nil {
		s.log.Info("vault created", "user", userID, "vault", id)
	}
	return id, err
}

// DeleteUserVault 删除用户自己的一个仓库（confirmName 校验、最后一个保护在 db 层）。
func (s *Service) DeleteUserVault(userID, vaultID, confirmName string) error {
	s.mu.Lock()
	blobIDs, shareIDs, err := db.DeleteUserVault(s.db, userID, vaultID, confirmName)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	for _, id := range shareIDs {
		if rerr := s.shares.Remove(id); rerr != nil {
			s.log.Warn("delete vault: share content remove failed", "share", truncateID(id), "error", rerr)
		}
	}
	s.gcBlobs(blobIDs)
	s.log.Warn("vault deleted", "user", userID, "vault", vaultID,
		"shares", len(shareIDs), "blobs", len(blobIDs))
	return nil
}

// UserHasVault 校验用户对某仓库的成员资格（authGate 的 X-Vault-ID 解析用）。
func (s *Service) RenameUserVault(userID, vaultID, newName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := db.RenameUserVault(s.db, userID, vaultID, newName)
	if err == nil {
		s.log.Info("vault renamed", "user", userID, "vault", vaultID)
	}
	return err
}

func (s *Service) UserHasVault(userID, vaultID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.UserHasVault(s.db, userID, vaultID)
}

// DeviceOwner 返回设备归属的用户（设备凭据调 ListVaults 时解析主人用）。
func (s *Service) DeviceOwner(deviceID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, userID, err := db.DeviceTenant(s.db, deviceID)
	return userID, err
}
