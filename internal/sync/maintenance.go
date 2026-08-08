package sync

import (
	"fmt"
	"os"
	"time"

	"obsync/internal/db"
)

// MaintenanceStats 单次维护任务的结果统计。
type MaintenanceStats struct {
	VersionsPruned  int
	BudgetPruned    int
	OrphanBlobs     int
	SharesCleaned   int
	ChangesPruned   int64
	Vacuumed        bool
	HistoryBytes    int64
	ChangesCount    int64
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
	if v, err := s.maintainSQLite(); err != nil {
		s.log.Warn("maintenance: sqlite", "error", err)
	} else {
		stats.Vacuumed = v
	}

	stats.HistoryBytes, _ = db.NonHeadHistoryBytes(s.db)          //nolint:errcheck
	s.db.QueryRow(`SELECT COUNT(*) FROM changes`).Scan(&stats.ChangesCount) //nolint:errcheck

	s.log.Info("maintenance done",
		"versionsPruned", stats.VersionsPruned,
		"budgetPruned", stats.BudgetPruned,
		"orphanBlobs", stats.OrphanBlobs,
		"sharesCleaned", stats.SharesCleaned,
		"changesPruned", stats.ChangesPruned,
		"vacuumed", stats.Vacuumed,
		"historyBytes", stats.HistoryBytes,
		"changesCount", stats.ChangesCount,
	)
	return stats
}

// maintainHistoryRetention：对所有路径应用时间/数量保留规则
// （解决“文件不再修改就永远不裁剪”的问题）。
func (s *Service) maintainHistoryRetention(now int64) (int, error) {
	if !s.opts.HistoryEnabled {
		return 0, nil
	}
	paths, err := db.DistinctVersionPaths(s.db)
	if err != nil {
		return 0, err
	}
	pruned := 0
	for _, path := range paths {
		s.mu.Lock()
		tx, err := s.db.Begin()
		if err != nil {
			s.mu.Unlock()
			return pruned, err
		}
		days, maxPerFile := s.retentionFor(path)
		blobs, err := s.pruneVersionsTx(tx, path, now, days, maxPerFile)
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
			if _, err := tx.Exec(`DELETE FROM file_versions WHERE id = ?`, v.ID); err != nil {
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

// maintainOrphanBlobs：清理数据库中无任何引用的 blob 文件。
// 只处理 1 小时前的文件，避开“blob 已写入、事务未提交”的上传窗口。
func (s *Service) maintainOrphanBlobs() (int, error) {
	cutoff := time.Now().Add(-1 * time.Hour)
	removed := 0
	err := s.blobs.Walk(func(hash string, info os.FileInfo) error {
		if info.ModTime().After(cutoff) {
			return nil
		}
		ref, err := db.BlobReferenced(s.db, hash)
		if err != nil || ref {
			return nil //nolint:nilerr
		}
		if err := s.blobs.Remove(hash); err == nil {
			removed++
		}
		return nil
	})
	return removed, err
}

// maintainShares：删除已过期分享的密文；清理 30 天前失效（撤销/过期）的元数据。
func (s *Service) maintainShares(now int64) (int, error) {
	shares, err := db.ListShares(s.db)
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
	s.mu.Lock()
	defer s.mu.Unlock()

	deleteUpTo := int64(0)
	if s.opts.ChangesDays > 0 {
		cutoff := now - int64(s.opts.ChangesDays)*86400
		var seq int64
		if err := s.db.QueryRow(
			`SELECT COALESCE(MAX(sequence), 0) FROM changes WHERE created_at < ?`, cutoff,
		).Scan(&seq); err != nil {
			return 0, err
		}
		deleteUpTo = seq
	}
	if s.opts.ChangesMax > 0 {
		var count int64
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM changes`).Scan(&count); err != nil {
			return 0, err
		}
		if count > int64(s.opts.ChangesMax) {
			var seq int64
			if err := s.db.QueryRow(
				`SELECT sequence FROM changes ORDER BY sequence DESC LIMIT 1 OFFSET ?`, s.opts.ChangesMax,
			).Scan(&seq); err != nil {
				return 0, err
			}
			if seq > deleteUpTo {
				deleteUpTo = seq
			}
		}
	}
	if deleteUpTo == 0 {
		return 0, nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := tx.Exec(`DELETE FROM changes WHERE sequence <= ?`, deleteUpTo)
	if err != nil {
		return 0, err
	}
	// 水位线单调递增
	cur, _, err := db.GetMeta(tx, watermarkMetaKey)
	if err != nil {
		return 0, err
	}
	var curN int64
	fmt.Sscanf(cur, "%d", &curN) //nolint:errcheck
	if deleteUpTo > curN {
		if err := db.SetMeta(tx, watermarkMetaKey, fmt.Sprintf("%d", deleteUpTo), now); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return n, nil
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
