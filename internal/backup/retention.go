package backup

import (
	"context"
	"time"
)

// 备份计划（个人使用推荐值，见 v6 计划 Part 14）：
//   - 每 6 小时备份一次（LiteSync 实时同步 + History 已覆盖细粒度恢复，
//     R2 备份只承担灾难恢复层）
//   - 每日 forget（应用保留策略）、每周 prune（真正清理对象）、每月 check
const (
	backupInterval = 6 * time.Hour
	forgetInterval = 24 * time.Hour
	pruneInterval  = 7 * 24 * time.Hour
	checkInterval  = 30 * 24 * time.Hour
)

// retentionArgs restic forget 的保留策略参数。
func retentionArgs() []string {
	return []string{
		"--keep-last", "8",
		"--keep-daily", "14",
		"--keep-weekly", "8",
		"--keep-monthly", "6",
	}
}

// StartScheduler 启动自动备份调度循环（ctx 取消即退出）。
// 每分钟检查一次；到达整 6 小时边界执行备份，随后按需 forget/prune/check。
// 任何失败只记录状态与日志，等待下一轮自动重试，绝不影响同步服务。
func (m *Manager) StartScheduler(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.tick(ctx)
			}
		}
	}()
}

// nextBoundary 返回 now 之后最近的整 backupInterval 边界（00:00/06:00/12:00/18:00 UTC）。
func nextBoundary(now time.Time) time.Time {
	return now.Truncate(backupInterval).Add(backupInterval)
}

func (m *Manager) tick(ctx context.Context) {
	m.mu.Lock()
	enabled := m.key != nil && m.cfg.Enabled && m.cfg.configured()
	if !enabled {
		m.mu.Unlock()
		return
	}
	now := time.Now()
	if m.status.NextRunAt == 0 {
		// 刚启用或刚启动：对齐到下一个整点边界
		m.status.NextRunAt = nextBoundary(now).Unix()
		m.saveStatusLocked()
		m.mu.Unlock()
		return
	}
	due := now.Unix() >= m.status.NextRunAt
	if due {
		// 先推进下次时间：本轮失败也不会在一分钟后疯狂重试，等下一个边界
		m.status.NextRunAt = nextBoundary(now).Unix()
		m.saveStatusLocked()
	}
	lastForget, lastPrune, lastCheck := m.status.LastForgetAt, m.status.LastPruneAt, m.status.LastCheckAt
	m.mu.Unlock()

	if !due {
		return
	}
	if _, err := m.Backup(ctx, "scheduled"); err != nil {
		return // Backup 内部已记录 LastError；同步完全不受影响
	}

	// 备份成功后的例行维护（都受同一个任务互斥保护，串行执行）
	if now.Unix()-lastForget >= int64(forgetInterval/time.Second) {
		if err := m.Forget(ctx); err != nil {
			m.log.Warn("backup forget failed", "error", err)
		}
	}
	if now.Unix()-lastPrune >= int64(pruneInterval/time.Second) {
		if err := m.Prune(ctx); err != nil {
			m.log.Warn("backup prune failed", "error", err)
		}
	}
	if now.Unix()-lastCheck >= int64(checkInterval/time.Second) {
		if err := m.Check(ctx); err != nil {
			m.log.Warn("backup check failed", "error", err)
		}
	}
}
