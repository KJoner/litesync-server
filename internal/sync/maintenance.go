package sync

import (
	"os"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/failpoint"
)

// MaintenanceStats 单次维护任务的结果统计。
type MaintenanceStats struct {
	VersionsPruned int
	BudgetPruned   int
	OrphanBlobs    int
	SharesCleaned  int
	ChangesPruned  int64
	Vacuumed       bool
	HistoryBytes   int64
	ChangesCount   int64
	// IntegrityIssues：本轮完整性 scrub 发现的问题数（应始终为 0）
	IntegrityIssues int
	// TombstonesPurged：本轮清理的删除记录数（默认配置下恒为 0）
	TombstonesPurged int
}

// RunMaintenance 执行一轮资源治理（启动时 + 每 N 小时）。
// 每个步骤独立持锁，避免长时间阻塞同步请求；步骤失败不影响后续步骤。
func (s *Service) RunMaintenance() MaintenanceStats {
	stats := MaintenanceStats{}
	now := time.Now().Unix()

	if n, err := s.maintainHistoryRetention(now); err != nil {
		s.log.Warn("maintenance: history retention", "error", err)
	} else {
		stats.VersionsPruned = n
	}
	if n, err := s.maintainHistoryBudget(); err != nil {
		s.log.Warn("maintenance: history budget", "error", err)
	} else {
		stats.BudgetPruned = n
	}
	if n, err := s.maintainOrphanBlobs(); err != nil {
		s.log.Warn("maintenance: orphan blobs", "error", err)
	} else {
		stats.OrphanBlobs = n
	}
	if n, err := s.maintainShares(now); err != nil {
		s.log.Warn("maintenance: shares", "error", err)
	} else {
		stats.SharesCleaned = n
	}
	if n, err := s.maintainChanges(now); err != nil {
		s.log.Warn("maintenance: changes", "error", err)
	} else {
		stats.ChangesPruned = n
	}
	if _, err := s.maintainPairings(now); err != nil {
		s.log.Warn("maintenance: pairings", "error", err)
	}
	if _, err := s.maintainEnrollments(now); err != nil {
		s.log.Warn("maintenance: enrollments", "error", err)
	}
	if _, err := db.PruneInvites(s.db, now); err != nil {
		s.log.Warn("maintenance: invites", "error", err)
	}
	// 已处理 30 天以上的安全事件（SV-05；未处理的永远保留）与过期的撤销记录（ADR-019）
	s.mu.Lock()
	if err := db.PruneSecurityEvents(s.db, now); err != nil {
		s.log.Warn("maintenance: security events", "error", err)
	}
	if err := db.PruneRevocationRecords(s.db, now); err != nil {
		s.log.Warn("maintenance: revocation records", "error", err)
	}
	s.mu.Unlock()
	// tombstone 清理走双条件（时间 + 全部未撤销设备已确认越过删除点）；
	// 默认配置下 TombstoneRetentionDays = 0，这里永远是 no-op（ADR-002 §3.4）
	if n, err := s.PurgeTombstones(now); err != nil {
		s.log.Warn("maintenance: tombstones", "error", err)
	} else {
		stats.TombstonesPurged = n
	}
	if n, err := s.maintainIntegrity(); err != nil {
		s.log.Warn("maintenance: integrity", "error", err)
	} else {
		stats.IntegrityIssues = n
	}
	if v, err := s.maintainSQLite(); err != nil {
		s.log.Warn("maintenance: sqlite", "error", err)
	} else {
		stats.Vacuumed = v
	}

	stats.HistoryBytes, _ = db.NonHeadHistoryBytes(s.db)                           //nolint:errcheck
	s.db.QueryRow(`SELECT COUNT(*) FROM object_changes`).Scan(&stats.ChangesCount) //nolint:errcheck

	s.log.Info("maintenance done",
		"versionsPruned", stats.VersionsPruned,
		"budgetPruned", stats.BudgetPruned,
		"orphanBlobs", stats.OrphanBlobs,
		"sharesCleaned", stats.SharesCleaned,
		"changesPruned", stats.ChangesPruned,
		"vacuumed", stats.Vacuumed,
		"historyBytes", stats.HistoryBytes,
		"changesCount", stats.ChangesCount,
		"integrityIssues", stats.IntegrityIssues,
		"tombstonesPurged", stats.TombstonesPurged,
	)
	return stats
}

// maintainIntegrity：完整性 scrub（v9.2，审查 12 收尾）。
// - SQLite quick_check；
// - 每个未删除 HEAD 的 blob 必须存在且尺寸一致（「已确认的 HEAD 必有正确 blob」不变量）；
// - 随机抽查最多 8 个 HEAD blob 做全量 hash 校验（位腐坏检测）。
// 发现问题只告警隔离，绝不静默跳过，也不自动删除任何数据。
func (s *Service) maintainIntegrity() (int, error) {
	issues := 0

	// 批次 G：quick_check 是 SQLite 的页级自检；PG 上由数据库服务器负责（见 Scrub 的说明），跳过
	if !db.IsPostgres(s.db) {
		var check string
		if err := s.db.QueryRow(`PRAGMA quick_check(1)`).Scan(&check); err != nil {
			return issues, err
		}
		if check != "ok" {
			issues++
			s.log.Error("integrity: sqlite quick_check failed", "result", check)
		}
	}

	// v0.18：scrub 覆盖全部 Vault 的 HEAD
	scopes, err := db.AllVaultScopes(s.db)
	if err != nil {
		return issues, err
	}
	var heads []db.ObjectHead
	s.mu.Lock()
	for _, sc := range scopes {
		hs, herr := db.ListHeads(s.db, sc)
		if herr != nil {
			s.mu.Unlock()
			return issues, herr
		}
		heads = append(heads, hs...)
	}
	s.mu.Unlock()

	// 日志隐私（ADR-008 §3.5）：只输出截断的 fileId，绝不输出路径
	for i := range heads {
		h := &heads[i]
		if h.BlobID == "" {
			continue
		}
		size, ok := s.blobs.StatSize(h.BlobID)
		if !ok {
			issues++
			s.log.Error("integrity: HEAD blob missing", "fileId", truncateID(h.FileID), "blob", h.BlobID)
			continue
		}
		if size != h.Size {
			issues++
			s.log.Error("integrity: HEAD blob size mismatch", "fileId", truncateID(h.FileID), "want", h.Size, "got", size)
		}
	}

	// 随机抽查全量 hash（每轮最多 8 个；伪随机取样即可）
	sampled := 0
	for i := range heads {
		if sampled >= 8 {
			break
		}
		if len(heads) > 8 && i%(len(heads)/8+1) != 0 {
			continue
		}
		h := &heads[i]
		ok, err := s.blobs.VerifyContent(h.BlobID, h.ContentHash)
		if err != nil {
			continue // 存在性问题已在上面报告
		}
		sampled++
		if !ok {
			issues++
			s.log.Error("integrity: blob content corrupted (hash mismatch)",
				"fileId", truncateID(h.FileID), "blob", h.BlobID)
		}
	}
	return issues, nil
}

// maintainHistoryRetention：对所有路径应用时间/数量保留规则
// （解决“文件不再修改就永远不裁剪”的问题）。
func (s *Service) maintainHistoryRetention(now int64) (int, error) {
	if !s.opts.HistoryEnabled {
		return 0, nil
	}
	// v0.18：按 Vault 遍历——保留策略与 meta 状态都是每个租户自己的
	scopes, err := db.AllVaultScopes(s.db)
	if err != nil {
		return 0, err
	}
	pruned := 0
	for _, scope := range scopes {
		n, err := s.maintainHistoryRetentionVault(scope, now)
		pruned += n
		if err != nil {
			return pruned, err
		}
	}
	return pruned, nil
}

func (s *Service) maintainHistoryRetentionVault(scope db.VaultScope, now int64) (int, error) {
	fileIDs, err := db.DistinctVersionFileIDs(s.db, scope)
	if err != nil {
		return 0, err
	}
	rs, err := db.GetRepoState(s.db, scope)
	if err != nil {
		return 0, err
	}
	pruned := 0
	for _, fileID := range fileIDs {
		s.mu.Lock()
		tx, err := s.db.Begin()
		if err != nil {
			s.mu.Unlock()
			return pruned, err
		}
		// meta 模式下服务器看不到后缀，retentionFor 自动退化为「最长保留」。
		// 注意：这里必须用 tx 而不是 s.db——连接池上限是 1，事务开着时
		// 任何走 s.db 的查询都会永远等待那条被占用的连接（死锁）
		pseudonym := fileID
		if h, herr := db.GetHead(tx, scope, fileID); herr == nil && h != nil {
			pseudonym = h.Pseudonym
		}
		days, maxPerFile := s.retentionFor(tx, scope, rs.MetaState, pseudonym)
		blobs, err := s.pruneVersionsTx(tx, scope, fileID, now, days, maxPerFile)
		if err != nil {
			tx.Rollback() //nolint:errcheck
			s.mu.Unlock()
			return pruned, err
		}
		if err := tx.Commit(); err != nil {
			s.mu.Unlock()
			return pruned, err
		}
		pruned += len(blobs)
		s.gcBlobs(blobs)
		s.mu.Unlock()
	}
	return pruned, nil
}

// maintainHistoryBudget：非 HEAD 历史总字节超过预算时，从最旧版本开始裁剪（硬上限）。
func (s *Service) maintainHistoryBudget() (int, error) {
	if !s.opts.HistoryEnabled || s.opts.HistoryMaxBytes <= 0 {
		return 0, nil
	}
	pruned := 0
	for {
		total, err := db.NonHeadHistoryBytes(s.db)
		if err != nil {
			return pruned, err
		}
		if total <= s.opts.HistoryMaxBytes {
			return pruned, nil
		}
		victims, err := db.OldestNonHeadVersions(s.db, 32)
		if err != nil {
			return pruned, err
		}
		if len(victims) == 0 {
			return pruned, nil
		}
		s.mu.Lock()
		tx, err := s.db.Begin()
		if err != nil {
			s.mu.Unlock()
			return pruned, err
		}
		var blobs []string
		freed := int64(0)
		for _, v := range victims {
			if _, err := tx.Exec(`DELETE FROM object_versions WHERE id = ?`, v.ID); err != nil {
				tx.Rollback() //nolint:errcheck
				s.mu.Unlock()
				return pruned, err
			}
			if v.BlobID != "" {
				blobs = append(blobs, v.BlobID)
			}
			freed += v.Size
			pruned++
			if total-freed <= s.opts.HistoryMaxBytes {
				break
			}
		}
		if err := tx.Commit(); err != nil {
			s.mu.Unlock()
			return pruned, err
		}
		s.gcBlobs(blobs)
		s.mu.Unlock()
	}
}

// maintainOrphanBlobs：清理数据库中无任何引用的 blob 文件（v0.13.3 / §7.3）。
//
// 这里同时满足计划书 §7.3 的五条要求：
//
//  1. **与写入一致的锁**：删除动作在 s.mu 内进行，与 Upload 的元数据提交互斥；
//  2. **删除前锁内最终确认无引用**：无锁扫描只收集候选，删除前重查一次；
//  3. **不与 migration / scrub / backup 竞态**：这三者进行中时整轮 GC 直接跳过；
//  4. **保留两轮确认**：候选要连续两轮被判定为无引用才真正删除，状态落盘，
//     因此重启不会让计数清零，也不会因为一次瞬时误判就删文件；
//  5. **隔离区独立清理**：Walk 跳过隔离区，那里由 PurgeQuarantine 按独立保留期处理。
//
// 1 小时门槛只用来避开「blob 已写入、事务未提交」的上传窗口，不构成正确性保证。
func (s *Service) maintainOrphanBlobs() (int, error) {
	// §7.3 第 3 条：迁移进行中绝不 GC。迁移会重写寻址与引用关系，
	// 此时的「无引用」判断根本不可信
	if busy, why := s.gcBlockedReason(); busy {
		s.log.Info("gc: skipped", "reason", why)
		return 0, nil
	}

	cutoff := time.Now().Add(-1 * time.Hour)
	var candidates []string
	err := s.blobs.Walk(func(hash string, info os.FileInfo) error {
		if info.ModTime().After(cutoff) {
			return nil
		}
		ref, err := db.BlobReferenced(s.db, hash)
		if err != nil {
			return nil //nolint:nilerr
		}
		if ref {
			// 重新被引用（去重命中、restore）→ 撤销候选状态，
			// 否则它会带着旧轮次计数在将来某轮被误删
			db.ClearGCCandidate(s.db, hash) //nolint:errcheck
			return nil
		}
		candidates = append(candidates, hash)
		return nil
	})

	removed := 0
	for _, hash := range candidates {
		s.mu.Lock()
		// 锁内最终确认：扫描到现在这段时间里可能刚有一次去重命中
		ref, rerr := db.BlobReferenced(s.db, hash)
		if rerr != nil || ref {
			if rerr == nil {
				db.ClearGCCandidate(s.db, hash) //nolint:errcheck
			}
			s.mu.Unlock()
			continue
		}
		rounds, merr := db.MarkGCCandidate(s.db, hash, time.Now().Unix())
		if merr != nil || rounds < 2 {
			s.mu.Unlock()
			continue // 第一轮只入册，不删
		}
		// §8.1 注入点：已判定可删、尚未删除。此刻崩溃只是少删一个 blob，
		// 下一轮会重新走完整的两轮确认——绝不会变成「删了但记录还在」
		if err := failpoint.Eval(failpoint.GCBeforeDelete); err != nil {
			s.mu.Unlock()
			continue
		}
		if s.blobs.Remove(hash) == nil {
			db.ClearGCCandidate(s.db, hash) //nolint:errcheck
			removed++
		}
		s.mu.Unlock()
	}
	return removed, err
}

// gcBlockedReason 报告本轮是否必须跳过 GC（§7.3 第 3 条）。
//
// 这三种情况下「无引用」的判断都不可信或不安全：
//   - 元数据迁移：寻址与引用关系正在被重写；
//   - scrub：正在逐个校验内容，此时删文件会让 scrub 报出一堆假的 missing；
//   - backup：备份读取的是某一时刻的快照，中途删文件会让备份自身不一致。
func (s *Service) gcBlockedReason() (bool, string) {
	if n := s.busyOps.Load(); n > 0 {
		return true, "scrub-or-backup-running"
	}
	// v0.18：任何一个 Vault 在迁移中，全实例的「无引用」判断都不可信
	migrating, err := db.AnyVaultMigrating(s.db)
	if err != nil {
		return true, "repo-state-unavailable" // 读不到状态就别动数据
	}
	if migrating {
		return true, "migration-in-progress"
	}
	return false, ""
}

// maintainShares：删除已过期分享的密文；清理 30 天前失效（撤销/过期）的元数据。
func (s *Service) maintainShares(now int64) (int, error) {
	shares, err := db.AdminListShares(s.db)
	if err != nil {
		return 0, err
	}
	const metaRetention = 30 * 86400
	cleaned := 0
	for _, sh := range shares {
		expired := sh.ExpiresAt > 0 && now > sh.ExpiresAt
		if expired && !sh.Revoked {
			if err := s.shares.Remove(sh.ID); err == nil {
				cleaned++
			}
		}
		dead := sh.Revoked || expired
		deadSince := sh.CreatedAt
		if sh.ExpiresAt > 0 && sh.ExpiresAt > deadSince {
			deadSince = sh.ExpiresAt
		}
		if dead && now-deadSince > metaRetention {
			s.mu.Lock()
			_, err := s.db.Exec(`DELETE FROM shares WHERE id = ?`, sh.ID)
			s.mu.Unlock()
			if err == nil {
				s.shares.Remove(sh.ID) //nolint:errcheck
				cleaned++
			}
		}
	}
	return cleaned, nil
}

// maintainChanges：按天数/行数裁剪 changes，并推进 resync 水位线。
// 旧游标的客户端会收到 resyncRequired，走 snapshot 全量对账，绝不漏删事件。
func (s *Service) maintainChanges(now int64) (int64, error) {
	if s.opts.ChangesDays <= 0 && s.opts.ChangesMax <= 0 {
		return 0, nil
	}
	// v0.18：sequence 空间是每 Vault 独立的（repo_state 按 Vault 分行），
	// 裁剪与水位线推进必须按 Vault 进行——按全表 sequence 裁剪会拿着一个
	// 租户的水位线删掉别人的低序号变更
	scopes, err := db.AllVaultScopes(s.db)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	total := int64(0)
	cutoff := int64(0)
	if s.opts.ChangesDays > 0 {
		cutoff = now - int64(s.opts.ChangesDays)*86400
	}
	for _, scope := range scopes {
		deleteUpTo, err := db.ChangesPruneCandidate(s.db, scope, cutoff, int64(s.opts.ChangesMax))
		if err != nil {
			return total, err
		}
		if deleteUpTo == 0 {
			continue
		}
		tx, err := s.db.Begin()
		if err != nil {
			return total, err
		}
		n, err := db.DeleteChangesUpTo(tx, scope, deleteUpTo)
		if err != nil {
			tx.Rollback() //nolint:errcheck
			return total, err
		}
		// 水位线记录在 repo_state（v9），与删除同一事务提交，且只增不减
		if err := db.SetMinRetainedSequence(tx, scope, deleteUpTo); err != nil {
			tx.Rollback() //nolint:errcheck
			return total, err
		}
		if err := tx.Commit(); err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// maintainSQLite：WAL checkpoint；freelist 明显偏大时低频 VACUUM。
func (s *Service) maintainSQLite() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return false, err
	}
	var freelist, pages int64
	if err := s.db.QueryRow(`PRAGMA freelist_count`).Scan(&freelist); err != nil {
		return false, err
	}
	if err := s.db.QueryRow(`PRAGMA page_count`).Scan(&pages); err != nil {
		return false, err
	}
	if pages > 1000 && freelist*4 > pages {
		if _, err := s.db.Exec(`VACUUM`); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}
