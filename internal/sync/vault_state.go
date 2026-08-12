package sync

import (
	gosync "sync"

	"github.com/KJoner/litesync-server/internal/db"
)

// 每 Vault 独立状态里剩下的两项：锁与保留策略（v0.16.0 / 计划书 §10.2）。
//
// repoEpoch / headSequence / minRetainedSequence / migration state / formatEpoch /
// keyEpoch 已经随 repo_state 按 vault_id 划分；audit_events 本来就带 vault_id。
// 这里补上 §10.2 列的另外两项。

// vaultMu 返回某个 Vault 的写锁。
//
// # 为什么不能共用一把锁
//
// 元数据写用互斥锁串行化。一个实例服务多个 Vault 时共用一把，
// 一个租户的慢速大附件上传会把**所有**租户的写入一起挡住——
// 这不是性能问题而已：外部看来就是「别人一忙，我这边就卡住」，
// 一个租户的负载因此变成另一个租户可观测的信号。
//
// 用 sync.Map 而不是「map + 一把保护它的锁」：后者在高并发下
// 会把刚才那把共用锁原样请回来，只是换了个位置。
func (s *Service) vaultMu(scope db.VaultScope) *gosync.Mutex {
	if !scope.Valid() {
		// 零值范围是编程错误。回退到默认租户会把一个漏洞变成静默的跨租户写入，
		// 所以这里给一把全新的、谁也拿不到第二次的锁：调用方随后一定会在
		// 查询上硬失败（ErrVaultScopeMissing），而不是先悄悄拿到别人的锁。
		//
		// 刻意**不**在这里造一个哨兵 VaultScope——VaultScope 的唯一构造入口
		// 在认证层，业务代码自造一个正是 tenancy_guard_test 要拦的事。
		return &gosync.Mutex{}
	}
	m, _ := s.vaultLocks.LoadOrStore(scope.ID(), &gosync.Mutex{})
	return m.(*gosync.Mutex)
}

// Retention 是一个 Vault 的历史保留策略。
type Retention struct {
	HistoryDays       int
	HistoryMaxPerFile int
	AttachmentDays    int
	AttachmentMax     int
}

// retentionOf 返回该 Vault 生效的保留策略。
//
// 顺序是「Vault 覆盖值 → 实例默认值」。共用实例默认值在单租户下没问题，
// 但多租户下保留策略是**每个租户自己的数据治理决定**：一个团队要保留一年，
// 另一个要求 30 天后必须消失，这不是服务器能替他们统一的。
// q 必须是调用方手上正在用的那个 queryer：事务开着时走 s.db 会死锁
// （连接池上限为 1）。
func (s *Service) retentionOf(q db.Queryer, scope db.VaultScope) Retention {
	base := Retention{
		HistoryDays:       s.opts.HistoryDays,
		HistoryMaxPerFile: s.opts.HistoryMaxPerFile,
		AttachmentDays:    s.opts.HistoryAttachmentDays,
		AttachmentMax:     s.opts.HistoryAttachmentMax,
	}
	if !scope.Valid() {
		return base
	}
	ov, err := db.GetVaultRetention(q, scope)
	if err != nil {
		s.log.Warn("retention: read override failed", "vault", scope.ID(), "error", err)
		return base
	}
	if ov == nil {
		return base
	}
	// 只有显式设过的项才覆盖。用 -1 表示「未设置」而不是 0——
	// 0 在这套语义里是「不限」，一个有意义的值，不能拿来当哨兵
	if ov.HistoryDays >= 0 {
		base.HistoryDays = ov.HistoryDays
	}
	if ov.HistoryMaxPerFile >= 0 {
		base.HistoryMaxPerFile = ov.HistoryMaxPerFile
	}
	if ov.AttachmentDays >= 0 {
		base.AttachmentDays = ov.AttachmentDays
	}
	if ov.AttachmentMax >= 0 {
		base.AttachmentMax = ov.AttachmentMax
	}
	return base
}

// SetVaultRetention 为某个 Vault 设置保留策略覆盖（-1 = 沿用实例默认）。
func (s *Service) SetVaultRetention(scope db.VaultScope, r Retention) error {
	return db.SetVaultRetention(s.db, scope, db.VaultRetention{
		HistoryDays:       r.HistoryDays,
		HistoryMaxPerFile: r.HistoryMaxPerFile,
		AttachmentDays:    r.AttachmentDays,
		AttachmentMax:     r.AttachmentMax,
	})
}
