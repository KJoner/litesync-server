package sync

import (
	"fmt"
	"math"

	"github.com/KJoner/litesync-server/internal/db"
)

// 用户级配额（v0.20 / 需求 §12）。
//
// 「所有配额在后端原子执行」：存储检查放在 Upload 的全局写锁内、提交之前——
// 并发上传不会各自看到「还有余量」然后一起越过上限；收流与落临时文件仍在锁外，
// 失败的上传丢弃临时文件，不会占用额度（相当于「预留失败即释放」）。

// QuotaExceededError 永久性配额超限（不是临时限流；客户端不应自动重试）。
type QuotaExceededError struct {
	Kind  string // "storage" | "vaults"
	Limit int64
	Used  int64
}

func (e *QuotaExceededError) Error() string {
	return fmt.Sprintf("%s quota exceeded (%d of %d used)", e.Kind, e.Used, e.Limit)
}

// effectiveLimit 覆盖值优先（-1 = 不限 → 0），否则用默认值；默认值只约束非管理员时 adminExempt=true。
func effectiveLimit(override, def int64, admin, adminExempt bool) int64 {
	switch {
	case override == db.QuotaUnlimited:
		return 0
	case override > 0:
		return override
	case admin && adminExempt:
		return 0
	default:
		return def
	}
}

// vaultLimitFor 用户可拥有的仓库数（调用方持锁）。
func (s *Service) vaultLimitFor(userID string) (int, error) {
	q, err := db.GetUserQuota(s.db, userID)
	if err != nil {
		return 0, err
	}
	def := int64(s.opts.QuotaVaultsPerUser)
	if def <= 0 {
		def = db.MaxVaultsPerUser
	}
	limit := effectiveLimit(q.Vaults, def, q.Admin, false)
	if limit <= 0 {
		return math.MaxInt32, nil
	}
	return int(limit), nil
}

// storageLimitFor 用户的存储上限（0 = 不限；调用方持锁）。
func (s *Service) storageLimitFor(userID string) (int64, error) {
	q, err := db.GetUserQuota(s.db, userID)
	if err != nil {
		return 0, err
	}
	return effectiveLimit(q.Bytes, s.opts.QuotaBytesPerUser, q.Admin, true), nil
}

// checkStorageQuota 在 Upload 的写锁内调用：仓库 owner 的占用 + 本次写入 > 上限 → 拒绝。
// 没有 owner 的旧 default 仓库（单用户时代）不受约束。
func (s *Service) checkStorageQuota(scope db.VaultScope, incoming int64) error {
	owner, err := db.VaultOwner(s.db, scope)
	if err != nil || owner == "" {
		return err
	}
	limit, err := s.storageLimitFor(owner)
	if err != nil || limit <= 0 {
		return err
	}
	used, err := db.UserStorageUsage(s.db, owner)
	if err != nil {
		return err
	}
	if used+incoming > limit {
		return &QuotaExceededError{Kind: "storage", Limit: limit, Used: used}
	}
	return nil
}

// Usage 一个账号的用量与上限（0 = 不限）。
type Usage struct {
	BytesUsed   int64
	BytesLimit  int64
	Vaults      int64
	VaultsLimit int64
	// 覆盖值原样（管理员界面用；0 = 跟随默认，-1 = 不限）
	OverrideBytes  int64
	OverrideVaults int64
}

// UserUsage 账号页与管理员列表展示用。
func (s *Service) UserUsage(userID string) (Usage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, err := db.GetUserQuota(s.db, userID)
	if err != nil {
		return Usage{}, err
	}
	u := Usage{OverrideBytes: q.Bytes, OverrideVaults: q.Vaults}
	if u.BytesUsed, err = db.UserStorageUsage(s.db, userID); err != nil {
		return Usage{}, err
	}
	if u.Vaults, err = db.OwnedVaultCount(s.db, userID); err != nil {
		return Usage{}, err
	}
	u.BytesLimit = effectiveLimit(q.Bytes, s.opts.QuotaBytesPerUser, q.Admin, true)
	vl, err := s.vaultLimitFor(userID)
	if err != nil {
		return Usage{}, err
	}
	if vl != math.MaxInt32 {
		u.VaultsLimit = int64(vl)
	}
	return u, nil
}

// SetUserQuota 管理员设置配额覆盖值（0 = 跟随默认，-1 = 不限，>0 = 指定值）。
func (s *Service) SetUserQuota(userID string, bytes, vaults int64) error {
	if bytes < -1 || vaults < -1 {
		return fmt.Errorf("invalid quota override")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := db.SetUserQuota(s.db, userID, bytes, vaults); err != nil {
		return err
	}
	s.log.Info("user quota updated", "user", userID, "bytes", bytes, "vaults", vaults)
	return nil
}
