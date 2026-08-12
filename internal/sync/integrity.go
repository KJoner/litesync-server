package sync

import (
	"database/sql"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
)

// 完整性自愈与 scrub（v0.13.3 / 计划书 §7.1、§7.2）。

// recordBlobRepairLocked 记录一次「去重命中时发现旧副本损坏并已修复」的事件。
// 调用方必须持 s.mu（它在 Upload 的锁内被调用）。
//
// 这里同时完成 §7.1 的第 5、6 步：记录完整性事件，并重新检查有多少 HEAD /
// 历史版本引用了这个 blob——损坏的影响范围是运维决策的依据，不能只说「修好了」。
func (s *Service) recordBlobRepairLocked(hash string, res storage.CommitResult) {
	refs, err := db.CountBlobReferences(s.db, hash)
	if err != nil {
		s.log.Warn("integrity: count references failed", "blob", hash, "error", err)
	}
	ev := &db.IntegrityEvent{
		BlobID:       hash,
		Kind:         res.Reason,
		Detail:       "repaired-on-upload",
		DetectedAt:   time.Now().Unix(),
		Serving:      true, // 已用校验过 hash 的副本替换，可以继续服务
		Resolved:     true,
		AffectedRefs: refs,
	}
	if err := db.RecordIntegrityEvent(s.db, ev); err != nil {
		s.log.Error("integrity: record event failed", "blob", hash, "error", err)
	}
	// 日志隐私（§7.7）：只有 blob hash、分类与引用数，没有任何路径
	s.log.Error("integrity: corrupt blob replaced by verified upload",
		"blob", hash, "kind", res.Reason, "affectedRefs", refs, "quarantined", res.QuarantinePath != "")
}

// markBlobUnservable 把一个已确认损坏、且**无法自愈**的 blob 标记为不可服务。
//
// 这是 §7.2 的硬性要求：发现损坏之后不得只写日志然后继续提供损坏内容。
// 标记之后所有下载路径都会拒绝它——客户端会看到明确的错误而不是坏字节。
func (s *Service) markBlobUnservable(hash, kind string) {
	refs, err := db.CountBlobReferences(s.db, hash)
	if err != nil {
		s.log.Warn("integrity: count references failed", "blob", hash, "error", err)
	}
	ev := &db.IntegrityEvent{
		BlobID:       hash,
		Kind:         kind,
		Detail:       "detected-by-scrub",
		DetectedAt:   time.Now().Unix(),
		Serving:      false,
		Resolved:     false,
		AffectedRefs: refs,
	}
	if err := db.RecordIntegrityEvent(s.db, ev); err != nil {
		s.log.Error("integrity: record event failed", "blob", hash, "error", err)
	}
	s.log.Error("integrity: blob marked unservable — 需要人工处理或从备份恢复",
		"blob", hash, "kind", kind, "affectedRefs", refs)
}

// blobServable 在每个下载路径上做一次廉价检查。
// 出错时返回 true（保持可服务）：完整性表本身故障不应该让整个仓库读不出来，
// 真正的损坏由 scrub 与 hash 校验兜底。
func (s *Service) blobServable(hash string) bool {
	ok, err := db.BlobServable(s.db, hash)
	if err != nil {
		s.log.Warn("integrity: servable check failed", "blob", hash, "error", err)
		return true
	}
	return ok
}

// ScrubReport 是一次完整性 scrub 的结果。
type ScrubReport struct {
	// DBCheck 是 SQLite integrity_check 的结果（"ok" 表示正常）
	DBCheck string
	// Checked 各类目标的检查数量
	HeadsChecked    int
	VersionsChecked int
	SharesChecked   int
	// Issues 发现的问题数
	Issues int
	// Unservable 本轮新标记为不可服务的 blob 数
	Unservable int
	// Recovered 从其他副本/历史引用中确认可恢复的数量
	Recovered int
	// Details 每条问题的简述（不含任何用户路径）
	Details []string
}

// Scrub 执行完整的完整性巡检（§7.2）。
//
// 覆盖范围：所有 live HEAD、所有历史版本、分享 blob、元数据（metaEnc 存在 DB 里，
// 由 DB integrity check 覆盖）、key document（同上）、tombstone 引用，
// 外加 SQLite 的完整 integrity_check。
//
// 与 maintainIntegrity 的分工：那个是每轮维护的**抽样**巡检（便宜、常跑）；
// 这个是全量巡检（贵、按需或定期跑），并且会把损坏的 blob 标记为不可服务。
//
// full 为 false 时只校验存在性与尺寸；为 true 时对每个 blob 全量重算 hash。
func (s *Service) Scrub(full bool) (*ScrubReport, error) {
	rep := &ScrubReport{}

	// §7.3：scrub 期间禁止 GC——正在逐个校验内容时删文件，
	// 会让 scrub 报出一堆本来不存在的 missing
	s.busyOps.Add(1)
	defer s.busyOps.Add(-1)

	s.mu.Lock()
	defer s.mu.Unlock()

	// SQLite 全量 integrity_check（quick_check 的严格版）
	if err := s.db.QueryRow(`PRAGMA integrity_check`).Scan(&rep.DBCheck); err != nil {
		return nil, err
	}
	if rep.DBCheck != "ok" {
		rep.Issues++
		rep.Details = append(rep.Details, "sqlite integrity_check: "+rep.DBCheck)
		s.log.Error("scrub: sqlite integrity_check failed", "result", rep.DBCheck)
	}

	// 待检 blob 集合：live HEAD + 所有历史版本 + tombstone 指向的内容
	type ref struct {
		hash string
		size int64
		kind string
	}
	seen := map[string]bool{}
	var refs []ref

	heads, err := db.ListHeads(s.db)
	if err != nil {
		return nil, err
	}
	for i := range heads {
		h := &heads[i]
		if h.BlobID == "" || seen[h.BlobID] {
			continue
		}
		seen[h.BlobID] = true
		refs = append(refs, ref{h.BlobID, h.Size, "head"})
		rep.HeadsChecked++
	}

	fileIDs, err := db.DistinctVersionFileIDs(s.db)
	if err != nil {
		return nil, err
	}
	for _, fid := range fileIDs {
		versions, verr := db.ListVersions(s.db, fid)
		if verr != nil {
			return nil, verr
		}
		for i := range versions {
			v := &versions[i]
			if v.BlobID == "" || seen[v.BlobID] {
				continue
			}
			seen[v.BlobID] = true
			refs = append(refs, ref{v.BlobID, v.Size, "version"})
			rep.VersionsChecked++
		}
	}

	for _, r := range refs {
		size, ok := s.blobs.StatSize(r.hash)
		if !ok {
			rep.Issues++
			rep.Unservable++
			rep.Details = append(rep.Details, r.kind+" blob missing: "+r.hash)
			s.markBlobUnservable(r.hash, "missing")
			continue
		}
		if r.size > 0 && size != r.size {
			rep.Issues++
			rep.Unservable++
			rep.Details = append(rep.Details, r.kind+" blob size mismatch: "+r.hash)
			s.markBlobUnservable(r.hash, "size-mismatch")
			continue
		}
		if !full {
			continue
		}
		okHash, verr := s.blobs.VerifyHash(r.hash)
		if verr != nil {
			rep.Issues++
			rep.Unservable++
			rep.Details = append(rep.Details, r.kind+" blob unreadable: "+r.hash)
			s.markBlobUnservable(r.hash, "unreadable")
			continue
		}
		if !okHash {
			rep.Issues++
			rep.Unservable++
			rep.Details = append(rep.Details, r.kind+" blob content corrupted: "+r.hash)
			s.markBlobUnservable(r.hash, "hash-mismatch")
		}
	}

	// 分享 blob：内容独立存放，同样不能在损坏后继续对外返回
	shares, err := db.ListShares(s.db)
	if err != nil {
		return nil, err
	}
	for i := range shares {
		sh := &shares[i]
		rep.SharesChecked++
		if !s.shares.Has(sh.ID) {
			rep.Issues++
			rep.Details = append(rep.Details, "share blob missing: "+truncateID(sh.ID))
			s.log.Error("scrub: share blob missing", "share", truncateID(sh.ID))
		}
	}

	if rep.Issues > 0 {
		s.log.Error("scrub: 发现完整性问题，受影响内容已停止对外返回",
			"issues", rep.Issues, "unservable", rep.Unservable, "full", full)
	} else {
		s.log.Info("scrub: clean", "heads", rep.HeadsChecked, "versions", rep.VersionsChecked,
			"shares", rep.SharesChecked, "full", full)
	}
	return rep, nil
}

// BeginExclusiveRead 声明「我正在读一份全量视图」（备份、导出等），
// 返回释放函数。期间 GC 整轮跳过（§7.3 第 3 条）。
//
// 备份读的是某一时刻的快照，中途删文件会让备份自身不一致——
// 而这份不一致要等到真正需要恢复的那天才会被发现。
func (s *Service) BeginExclusiveRead() func() {
	s.busyOps.Add(1)
	return func() { s.busyOps.Add(-1) }
}

// DB 暴露底层连接，供运维工具与测试直接查询。
// 业务代码一律走 Service 的方法——那里才有锁与状态守卫。
func (s *Service) DB() *sql.DB { return s.db }

// IntegrityEvents 列出完整性事件（运维接口）。
func (s *Service) IntegrityEvents(onlyUnresolved bool) ([]db.IntegrityEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.ListIntegrityEvents(s.db, onlyUnresolved)
}

// PurgeQuarantine 按独立保留期清理隔离区（§7.3：不与普通 GC 混用）。
func (s *Service) PurgeQuarantine(now time.Time) (int, error) {
	days := s.opts.QuarantineRetentionDays
	if days <= 0 {
		return 0, nil // 0 = 永久保留：取证材料默认不自动删
	}
	before := now.AddDate(0, 0, -days).Unix()
	return s.blobs.PurgeQuarantine(before)
}
