package sync

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// 用户账号与 API Token 重置（v0.18.0 / v11 设计 §4）。
//
// 与设备凭据（devices.go）的关系：
//
//	用户 Token（长期，users.token_hash）──网页登录──→ 网页会话
//	      │ 注册设备（POST /api/v1/devices）
//	      ▼
//	设备凭据（devices.token_hash）──换票──→ 短期 access token
//
// 重置用户 Token 时四件事在同一事务里完成：换哈希、会话世代 +1、
// 撤销该用户全部设备、审计。在途 access token 由「撤销设备即杀票」的
// 既有回查机制（§10.5）自动失效，无需额外处理。

// TokenResetResult 是一次 Token 重置的结果。Token 明文只在这里出现一次。
type TokenResetResult struct {
	Token             string
	RevokedDevices    int
	RevokedGrants     int
	Generation        int64
	AuthEpoch         int64
	ResetAuthEnforced bool
}

// EnsureAdminAccount 启动对账（幂等）：内置管理员账号存在、持有可用 Token 哈希、
// 是 default vault 的 owner。返回对账结果供调用方决定日志级别；
// AdminTokenSuperseded 必须醒目告知（环境变量已失效是最容易困惑的状态）。
func (s *Service) EnsureAdminAccount(envToken string) (db.AdminTokenReconcile, error) {
	// vaults 行是 membership 与重置凭证的落点；一台从未上传过内容的
	// 新服务器可能还没有这一行（vaultSecret 是规范创建入口，且不能在锁内调）。
	if _, err := s.vaultSecret(); err != nil {
		return db.AdminTokenUnchanged, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	envHash := ""
	if envToken != "" {
		envHash = db.HashToken(envToken)
	}
	rec, err := db.EnsureAdminUser(s.db, envHash)
	if err != nil {
		return rec, err
	}
	if err := db.UpsertMembership(s.db, &db.Membership{
		UserID: db.AdminUserID, VaultID: db.DefaultVaultID, Role: db.RoleOwner,
	}); err != nil {
		return rec, err
	}
	switch rec {
	case db.AdminTokenCreated:
		s.log.Info("admin account created from OBSYNC_TOKEN")
	case db.AdminTokenAdopted:
		s.log.Info("admin token adopted from OBSYNC_TOKEN")
	case db.AdminTokenSuperseded:
		s.log.Warn("OBSYNC_TOKEN has been superseded by a rotated admin token; " +
			"the environment variable is currently ignored " +
			"(run `obsync token reset --from-env` to force it back)")
	case db.AdminTokenRevoked:
		s.log.Warn("管理员 API Token（OBSYNC_TOKEN）已随「退出本产品的全部设备」等操作作废，重启不会让它恢复；" +
			"需要继续使用时运行 `obsync token reset --from-env`（或 `obsync token reset` 换一个新的）")
	}
	return rec, nil
}

// ErrTokenRevoked：API Token 曾有效、已随账号授权代次前进而作废（退出本产品的全部设备、
// 管理员停用、中心停用……，ADR-019 R-1）。与「查无此 Token」分开告知，客户端才能给出
// 「重新登录后重置 API Token，或在服务器上运行 obsync token reset」的指引。
var ErrTokenRevoked = errors.New("api token has been revoked")

// AuthUserByToken 校验用户 Token；有效则返回用户并节流更新最近活动时间。
// 无效、已禁用一律返回 (nil, nil)——同响应，不泄露账号状态；授权代次已前进的
// 返回 ErrTokenRevoked。
func (s *Service) AuthUserByToken(token string) (*db.User, error) {
	if token == "" {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := db.GetUserByTokenHash(s.db, db.HashToken(token))
	if err != nil || u == nil {
		return nil, err
	}
	if u.Disabled {
		return nil, nil
	}
	if !u.TokenValid() {
		return nil, ErrTokenRevoked
	}
	now := time.Now().Unix()
	if now-u.LastSeenAt > 300 {
		if terr := db.TouchUser(s.db, u.UserID, now); terr != nil {
			s.log.Warn("user last_seen update failed", "userId", u.UserID, "error", terr)
		}
		u.LastSeenAt = now
	}
	return u, nil
}

// OwnerVaultOf 返回用户的专属 Vault（一人一 Vault 约定）。
func (s *Service) OwnerVaultOf(userID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.OwnerVaultOf(s.db, userID)
}

// UserTokenGeneration 返回用户当前会话世代（网页会话校验用）。
// 顺带承担禁用检查：已禁用用户返回 0，任何按世代校验的会话随之失效。
func (s *Service) UserTokenGeneration(userID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := db.GetUser(s.db, userID)
	if err != nil || u == nil {
		return 0, err
	}
	if u.Disabled {
		return 0, nil
	}
	return u.TokenGeneration, nil
}

// UserSessionState 返回网页会话每次校验要比较的账号状态（会话世代 + 授权代次 + 停用位）。
func (s *Service) UserSessionState(userID string) (db.SessionState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.UserSessionState(s.db, userID)
}

// ResetUserToken 轮换用户的 API Token（v11 设计 §3.4 的作废矩阵）。
//
// scope 必须是目标用户的专属 Vault——重置凭证按 Vault 登记，设备撤销也按
// (vault, user) 进行。E2EE 门禁：该 Vault 已登记重置凭证时，提交值不符即拒
// （ErrResetAuthMismatch）；未登记时放行，结果里 ResetAuthEnforced=false，
// 调用方必须如实告知「本次重置未经 E2EE 密码确认」。
//
// keyEpoch 刻意不动：这个功能的前提就是 E2EE 密钥未泄露；
// 需要轮换密钥的场景（成员移除）另有 RemoveMember。
func (s *Service) ResetUserToken(scope db.VaultScope, targetUserID, submittedResetAuth, actor string) (*TokenResetResult, error) {
	if targetUserID == "" {
		return nil, fmt.Errorf("target user is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// v0.19：门禁按「名下任一仓库」判定——任何一个仓库的 E2EE 密码知识都
	// 证明请求者是主人（同一密码在不同仓库派生值不同，逐一比对）
	enforced, ok, err := db.VerifyResetAuthAnyVault(s.db, targetUserID, submittedResetAuth)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, db.ErrResetAuthMismatch
	}

	token, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	token = db.TokenPrefix + token

	eventID, err := db.NewEventID()
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	// v0.20.1（ADR-019）：重置 = 动作 B + 新 Token。授权代次 +1 让全部设备、待领取授权、
	// 旧 API Token 与其他网页会话一起失效（以前只撤销已有设备，未领取的连接链接仍能换出设备）
	out, err := db.RevokeAccountTx(tx, db.RevokeParams{
		UserID: targetUserID, EventID: eventID, Scope: db.RevocationScopeProduct,
		Reason: "token-reset", Origin: "litesync", Now: time.Now().Unix(),
	})
	if err != nil {
		return nil, err
	}
	// 新 Token 属于新代次（SetUserToken 同时把会话世代 +1）
	gen, err := db.SetUserToken(tx, targetUserID, db.HashToken(token))
	if err != nil {
		return nil, err
	}
	// 审计只记身份与动作；绝不记 Token 本身或它的哈希
	if err := db.AppendAudit(tx, scope, actor, "token-reset",
		fmt.Sprintf("user=%s devices=%d grants=%d generation=%d authEpoch=%d resetAuthEnforced=%v",
			targetUserID, out.RevokedDevices, out.RevokedGrants, gen, out.AuthEpoch, enforced)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.log.Warn("api token reset", "user", targetUserID, "revokedDevices", out.RevokedDevices,
		"revokedGrants", out.RevokedGrants, "resetAuthEnforced", enforced)
	s.notify(targetUserID, "token-reset", map[string]string{
		"revokedDevices": fmt.Sprint(out.RevokedDevices), "eventId": fmt.Sprintf("gen-%d", gen),
	})
	return &TokenResetResult{
		Token: token, RevokedDevices: out.RevokedDevices, RevokedGrants: out.RevokedGrants,
		Generation: gen, AuthEpoch: out.AuthEpoch, ResetAuthEnforced: enforced,
	}, nil
}

// RegisterResetAuth 登记（或持旧值更新）重置凭证。规则见 db.RegisterVaultResetAuth。
func (s *Service) RegisterResetAuth(scope db.VaultScope, resetAuth, previous string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := db.RegisterVaultResetAuth(s.db, scope, resetAuth, previous); err != nil {
		return err
	}
	s.log.Info("token-reset credential registered", "vault", scope.ID())
	return nil
}

// CheckE2eeConsistency 启动自检（v0.18 实测事故）：逐 Vault 检查
// 「vault-key 文档 enabled=true 而仓库 keyEpoch=0（plaintext）」的矛盾状态。
//
// 这种残留（历史版本启用 E2EE 后 abort 只回退了状态、没删文档）会让新接入的
// 设备把自己配置成「已加密但没有合法密钥世代」的死局。客户端 0.18 起会显式
// 停机并提示看服务器日志——这里就是那条日志。服务器**不能**自行删文档
//（服务器改写/隐藏密钥文档 = 降级攻击的形状，客户端不该也不会接受），
// 只能告诉管理员矛盾在哪、怎么修。
func (s *Service) CheckE2eeConsistency() {
	scopes, err := db.AllVaultScopes(s.db)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, scope := range scopes {
		rs, rerr := db.GetRepoState(s.db, scope)
		if rerr != nil || rs == nil || rs.KeyEpoch > 0 {
			continue
		}
		docStr, ok, gerr := db.GetMeta(s.db, vaultKeyMetaKeyFor(scope))
		if gerr != nil || !ok || docStr == "" {
			continue
		}
		var doc struct {
			Enabled bool `json:"enabled"`
		}
		if json.Unmarshal([]byte(docStr), &doc) == nil && doc.Enabled {
			s.log.Warn("E2EE 状态自相矛盾：密钥文档已启用但仓库 keyEpoch=0（plaintext）——"+
				"新设备接入会被此矛盾挡停。这通常是旧版本启用又中止 E2EE 后残留的文档；"+
				"修复方式：在任一设备上重新完整启用 E2EE，或（确认无任何密文内容后）"+
				"删除 vault_meta 中的 vault-key 条目",
				"vault", scope.ID())
		}
	}
}

// VaultActive 报告该 Vault 是否可服务：存在、且 owner 未被禁用。
// 认证层的 enforceVault 每请求调用（禁用用户的一切凭据在这里被拦，
// 不依赖「禁用时记得撤销所有设备」）。
func (s *Service) VaultActive(scope db.VaultScope) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := db.GetVault(s.db, scope)
	if err != nil || v == nil {
		return false, err
	}
	owner, err := db.GetUser(s.db, v.OwnerID)
	if err != nil {
		return false, err
	}
	if owner != nil && owner.Disabled {
		return false, nil
	}
	return true, nil
}

// ResetAuthConfigured 报告本 Vault 是否已登记重置凭证（/api/v1/info 暴露，
// 客户端据此决定要不要在解锁后自动补登记）。
func (s *Service) ResetAuthConfigured(scope db.VaultScope) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := db.GetVaultResetAuth(s.db, scope)
	return h != "", err
}
