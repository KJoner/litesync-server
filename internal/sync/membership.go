package sync

import (
	"errors"
	"fmt"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// 成员移除与密钥轮换（v0.16.0 / 计划书 §10.4、ADR-010 §6）。

// ErrNotAuthorized：调用方在这个 Vault 里没有管理权限。
var ErrNotAuthorized = errors.New("not authorized: this action requires owner or admin")

// Actor 是发起治理动作的主体。
//
// 刻意不是一个裸字符串：把「根 Token」和「某台设备」揉进同一个 string 里，
// 迟早会有人用一个恰好等于哨兵值的 deviceID 冒充根身份。
type Actor struct {
	// Root：根 Token。服务器管理员，在所有角色之上，且不需要是成员。
	Root bool
	// DeviceID：设备凭据。服务器自己去查这台设备属于哪个用户——
	// 请求里声称的用户身份一律不作数。
	DeviceID string
}

// resolve 把 Actor 解析成 (用户 id, 是否有管理权限)。
func (s *Service) resolve(a Actor) (string, bool, error) {
	if a.Root {
		return db.RootActorID, true, nil
	}
	if a.DeviceID == "" {
		return "", false, nil
	}
	_, userID, err := db.DeviceTenant(s.db, a.DeviceID)
	if err != nil || userID == "" {
		return "", false, err
	}
	role, ok, err := db.RoleOf(s.db, s.scope(), userID)
	if err != nil {
		return "", false, err
	}
	return userID, ok && role.CanAdmin(), nil
}

// LocalPlaintextNotice 是移除成员时必须原样展示给用户的说明。
//
// 它不是免责声明，是事实陈述：被移除的人已经下载到本地的明文，
// 服务器没有任何办法收回。把这句话藏起来，用户就会基于一个错误的
// 安全模型做决定（比如「先分享再移除」）。
const LocalPlaintextNotice = "对方已经同步到本地的内容仍然留在他的设备上，服务器无法远程删除或收回。" +
	"本次操作能保证的是：他的所有设备凭据立即失效，且此后的新内容用新密钥加密，他拿不到也解不开。"

// RemoveMember 把某个用户移出 Vault，并完成随之而来的密钥轮换。
//
// 四件事必须在**同一个事务**里发生，顺序也不能变：
//
//  1. 删除成员关系；
//  2. 撤销该用户的全部设备（先撤销：epoch 先推进而设备还有效的话，
//     被移除的设备仍能在窗口期内拉走一批新内容）；
//  3. 推进 keyEpoch；
//  4. 标记 Vault Key 待重新封装。
//
// 服务器拿不到 Vault Key，因此第 4 步只能是「记下待办」——真正的重新封装
// 由管理员设备用剩余成员的公钥完成，然后 PUT 新的 vault-key 文档。
func (s *Service) RemoveMember(actor Actor, targetUserID string) (*db.MembershipRemoval, error) {
	if targetUserID == "" {
		return nil, fmt.Errorf("target user is required")
	}
	scope := s.scope()
	// 确保 Vault 记录存在：轮换要往 vaults 上写「待重新封装」，
	// 而一台从未上传过内容的新服务器可能还没有这一行。
	// vaultSecret 是这条记录的规范创建入口（它会读写数据库，所以必须在事务外调用）。
	if _, err := s.vaultSecret(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 授权判断只看数据库里的成员关系，不看请求里的任何声明
	actorUserID, canAdmin, err := s.resolve(actor)
	if err != nil {
		return nil, err
	}
	if !canAdmin {
		return nil, ErrNotAuthorized
	}

	targetRole, ok, err := db.RoleOf(s.db, scope, targetUserID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, db.ErrNotAMember
	}
	if targetRole == db.RoleOwner {
		owners, cerr := db.CountRole(s.db, scope, db.RoleOwner)
		if cerr != nil {
			return nil, cerr
		}
		if owners <= 1 {
			return nil, db.ErrLastOwner
		}
	}

	now := time.Now().Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := db.DeleteMembership(tx, scope, targetUserID); err != nil {
		return nil, err
	}
	revoked, err := db.RevokeDevicesOfUser(tx, scope, targetUserID)
	if err != nil {
		return nil, err
	}
	epoch, err := db.RotateKeyEpoch(tx, scope, "member-removed")
	if err != nil {
		return nil, err
	}
	if err := db.SetPendingRewrap(tx, scope, epoch); err != nil {
		return nil, err
	}
	// 审计只记身份与动作，不记路径与内容（ADR-008 §3.5）
	if err := db.AppendAudit(tx, scope, actorUserID, "member-removed",
		fmt.Sprintf("user=%s role=%s devices=%d keyEpoch=%d", targetUserID, targetRole, revoked, epoch)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	owners, err := db.CountRole(s.db, scope, db.RoleOwner)
	if err != nil {
		return nil, err
	}
	s.log.Warn("member removed; vault key must be rewrapped",
		"actor", actorUserID, "target", targetUserID,
		"revokedDevices", revoked, "keyEpoch", epoch)

	return &db.MembershipRemoval{
		UserID:          targetUserID,
		Role:            targetRole,
		RevokedDevices:  revoked,
		NewKeyEpoch:     epoch,
		PendingRewrap:   true,
		RemovedAt:       now,
		LocalPlaintext:  LocalPlaintextNotice,
		RemainingOwners: owners,
	}, nil
}

// PendingRewrapEpoch 返回等待重新封装的 keyEpoch；0 表示没有待办。
func (s *Service) PendingRewrapEpoch() (int64, error) {
	return db.PendingRewrap(s.db, s.scope())
}

// ErrRewrapRequired：Vault Key 还没有为新 epoch 重新封装。
//
// 这时候允许写入等于让新内容继续用被移除成员仍持有的那把密钥加密——
// 整套轮换就白做了。
var ErrRewrapRequired = errors.New("vault key must be rewrapped for the new key epoch before writing")

// ClearPendingRewrap 在管理员设备上传了新 epoch 的 Vault Key 之后清除待办。
//
// epoch 必须与待办的 epoch 一致：上传一份仍属于旧 epoch 的文档不算完成轮换。
func (s *Service) ClearPendingRewrap(epoch int64) error {
	scope := s.scope()
	pending, err := db.PendingRewrap(s.db, scope)
	if err != nil {
		return err
	}
	if pending == 0 {
		return nil
	}
	if epoch != pending {
		return fmt.Errorf("%w: 待重新封装的是 epoch %d，收到的是 %d", ErrRewrapRequired, pending, epoch)
	}
	if err := db.SetPendingRewrap(s.db, scope, 0); err != nil {
		return err
	}
	if err := db.AppendAudit(s.db, scope, "system", "vault-key-rewrapped",
		fmt.Sprintf("keyEpoch=%d", epoch)); err != nil {
		return err
	}
	s.log.Info("vault key rewrapped for new key epoch", "keyEpoch", epoch)
	return nil
}

// AuditTrail 返回该 Vault 最近的治理审计记录。
func (s *Service) AuditTrail(limit int) ([]db.AuditEvent, error) {
	return db.ListAudit(s.db, s.scope(), limit)
}
