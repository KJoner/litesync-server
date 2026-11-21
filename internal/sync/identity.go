package sync

import (
	"errors"
	"fmt"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// 统一身份（v0.20 公开化 / ADR-011）的服务层。
//
// 这里只做「外部主体 → 本地用户」的映射与账号状态；OIDC 协议本身（state、
// PKCE、nonce、ID Token 验签）在 api 层完成，验证通过后才会调用这里。

// RegistrationMode 是产品侧的注册兜底开关（接口约定 §1.6）。
// 身份服务那边的自助注册开关是第一道门；这里是第二道——即使身份服务误开了
// 注册，closed 模式下陌生主体也拿不到 LiteSync 账号。
type RegistrationMode string

const (
	RegistrationClosed RegistrationMode = "closed"
	RegistrationInvite RegistrationMode = "invite"
	RegistrationOpen   RegistrationMode = "open"
)

// ParseRegistrationMode 解析配置值；未知值按最保守的 closed 处理。
func ParseRegistrationMode(v string) RegistrationMode {
	switch RegistrationMode(v) {
	case RegistrationOpen, RegistrationInvite, RegistrationClosed:
		return RegistrationMode(v)
	default:
		return RegistrationClosed
	}
}

var (
	// ErrRegistrationClosed：注册关闭或邀请无效，陌生主体不建本地用户。
	ErrRegistrationClosed = db.ErrRegistrationClosed
	// ErrIdentityTaken / ErrUserAlreadyLinked：认领冲突（绝不合并、绝不覆盖）。
	ErrIdentityTaken     = db.ErrIdentityTaken
	ErrUserAlreadyLinked = db.ErrUserAlreadyLinked
	// ErrAccountDisabled：本地账号已被禁用。
	ErrAccountDisabled = errors.New("account disabled")
)

// ResolveOIDCLogin 把验证通过的外部主体解析为本地用户。
//
// 已映射 → 刷新资料快照后返回该用户；未映射 → 按注册开关决定是否新建
// （零仓库、无 API Token、非管理员）。invite 模式下 inviteSecret 必须是
// 一条有效邀请，邀请与建号在同一事务里消费。
func (s *Service) ResolveOIDCLogin(issuer, subject string, p db.IdentityProfile,
	mode RegistrationMode, inviteSecret string) (*db.User, bool, error) {
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := db.GetIdentity(s.db, issuer, subject)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		if err := db.TouchIdentity(s.db, issuer, subject, p, now); err != nil {
			return nil, false, err
		}
		if err := db.SetUserProfileSnapshot(s.db, existing.UserID, p); err != nil {
			return nil, false, err
		}
		u, err := db.GetUser(s.db, existing.UserID)
		if err != nil {
			return nil, false, err
		}
		if u == nil {
			// 映射指向一个不存在的用户：数据不一致，不建会话
			return nil, false, errors.New("identity maps to a missing user")
		}
		if u.Disabled {
			return nil, false, ErrAccountDisabled
		}
		return u, false, nil
	}

	inviteID := ""
	switch mode {
	case RegistrationOpen:
	case RegistrationInvite:
		if inviteSecret == "" {
			return nil, false, ErrRegistrationClosed
		}
		inv, err := db.GetInviteBySecret(s.db, inviteSecret, now)
		if err != nil {
			return nil, false, err
		}
		if inv == nil {
			return nil, false, ErrRegistrationClosed
		}
		inviteID = inv.ID
	default:
		return nil, false, ErrRegistrationClosed
	}

	userID, created, err := db.CreateOIDCUserWithInvite(s.db, issuer, subject, p, inviteID, now)
	if err != nil {
		return nil, false, err
	}
	u, err := db.GetUser(s.db, userID)
	if err != nil {
		return nil, false, err
	}
	if u == nil {
		return nil, false, errors.New("created user vanished")
	}
	if created {
		s.log.Info("account created via external identity", "user", userID, "issuer", issuer, "invite", inviteID != "")
	}
	return u, created, nil
}

// LinkOIDCIdentity 把外部主体绑定到一个**已认证**的既有本地用户（旧账号认领）。
// 调用方（api 层）负责证明「发起者确实已以该用户身份登录」。
func (s *Service) LinkOIDCIdentity(userID, issuer, subject string, p db.IdentityProfile) (*db.User, error) {
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := db.GetUser(s.db, userID)
	if err != nil {
		return nil, err
	}
	if u == nil || u.Disabled {
		return nil, ErrAccountDisabled
	}
	if err := db.LinkIdentity(s.db, issuer, subject, userID, p, now); err != nil {
		return nil, err
	}
	if err := db.SetUserProfileSnapshot(s.db, userID, p); err != nil {
		return nil, err
	}
	// 审计落在该用户的默认仓库上（零仓库用户没有可挂的仓库，只记日志）
	if err := db.AuditUserEvent(s.db, userID, "identity-linked", "issuer="+issuer); err != nil {
		s.log.Warn("identity link audit failed", "error", err)
	}
	s.log.Info("external identity linked", "user", userID, "issuer", issuer)
	return u, nil
}

// IdentitiesOf 返回用户已绑定的外部身份（账户页）。
func (s *Service) IdentitiesOf(userID string) ([]db.ExternalIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.IdentitiesOfUser(s.db, userID)
}

// UserByID 返回用户（不存在返回 nil）。
func (s *Service) UserByID(userID string) (*db.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.GetUser(s.db, userID)
}

// UserIDForIdentity 按外部主体查本地用户（back-channel logout 用）；未映射返回 ""。
func (s *Service) UserIDForIdentity(issuer, subject string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := db.GetIdentity(s.db, issuer, subject)
	if err != nil || e == nil {
		return "", err
	}
	return e.UserID, nil
}

// EndAllSessions 让用户的全部网页会话失效（会话世代 +1）。API Token 与设备不受影响。
func (s *Service) EndAllSessions(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := db.BumpSessionGeneration(s.db, userID)
	return err
}

// LogoutEverywhere 「退出所有产品与设备」（需求 §3.2）：全部网页会话失效 +
// 撤销该用户名下全部设备凭据（各仓库）。返回撤销的设备数。
//
// 这是有代价的：每台 Obsidian 都需要重新连接。界面在执行前必须讲清楚。
func (s *Service) LogoutEverywhere(userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := db.BumpSessionGeneration(s.db, userID); err != nil {
		return 0, err
	}
	n, err := db.RevokeAllDevicesOfUser(s.db, userID)
	if err == nil {
		s.log.Info("logout everywhere", "user", userID, "revokedDevices", n)
		s.notify(userID, "logout-everywhere", map[string]string{"revokedDevices": fmt.Sprint(n)})
	}
	return n, err
}
