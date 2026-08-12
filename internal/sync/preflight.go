package sync

import (
	"fmt"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// 迁移前置检查（v0.17 / 计划书 §15 第 3、6、7 步）。
//
// §15 的前七步全是「动手之前先确认」。它们看上去很啰嗦，直到你意识到第 9 步
// 之后的某些动作是**不可逆**的——而不可逆动作前的每一次「我以为没问题」
// 都会在事后变成一句「早知道就先查一下」。
//
// 这个检查把那些「我以为」变成可以打印出来的事实。它**只读**，任何时候跑都安全。

// PreflightIssue 是一条阻止迁移的问题。
type PreflightIssue struct {
	// Blocking 为 true 时不应继续迁移。false 表示值得注意但可以继续。
	Blocking bool
	Code     string
	Detail   string
}

// PreflightReport 是一次迁移前置检查的完整结果。
type PreflightReport struct {
	Issues []PreflightIssue

	ActiveDevices  int
	StaleDevices   int // 超过 30 天没出现过：它可能永远不会回来，也可能明天就回来
	UnknownVersion int // 从未上报过版本：老服务器时代接入的设备
	OutdatedClient int

	LatestSequence int64
	MetaState      string
	FormatEpoch    int64
	EnvelopeFloor  int64

	PlaintextTombstones int64
	OrphanVersions      int64
	MissingBlobs        int64
}

// Blocked 报告是否存在阻塞性问题。
func (r *PreflightReport) Blocked() bool {
	for i := range r.Issues {
		if r.Issues[i].Blocking {
			return true
		}
	}
	return false
}

// staleDeviceDays：超过这么久没出现的设备算「陈旧」。
//
// 30 天是一个判断而不是一个事实：它长到足以覆盖一次假期，短到不会把一台
// 半年前就不用了的旧手机一直算作「在用」。陈旧设备不阻塞迁移，但会被列出来
// ——因为它回来的那一天，如果还是旧客户端，就会造成 ADR-006 的 T-2。
const staleDeviceDays = 30

// MigrationPreflight 执行迁移前置检查（只读）。
//
// requiredClient 为空时跳过版本比对（只报告未知版本的设备数）。
func (s *Service) MigrationPreflight(requiredClient string) (*PreflightReport, error) {
	scope := s.scope()
	rep := &PreflightReport{}

	rs, err := db.GetRepoState(s.db, scope)
	if err != nil {
		return nil, err
	}
	rep.MetaState = rs.MetaState
	rep.FormatEpoch = rs.FormatEpoch
	rep.EnvelopeFloor = rs.MinimumEnvelopeVersion
	rep.LatestSequence = rs.HeadSequence

	// --- §15 第 3 步：设备列表里不能有旧客户端 ---
	devices, err := db.ListDevices(s.db)
	if err != nil {
		return nil, err
	}
	staleBefore := time.Now().AddDate(0, 0, -staleDeviceDays).Unix()
	for i := range devices {
		d := &devices[i]
		if d.Revoked {
			continue
		}
		rep.ActiveDevices++
		if d.LastSeenAt < staleBefore {
			rep.StaleDevices++
		}
		switch {
		case d.ClientVersion == "":
			rep.UnknownVersion++
		case requiredClient != "" && d.ClientVersion != requiredClient:
			rep.OutdatedClient++
			rep.Issues = append(rep.Issues, PreflightIssue{
				Blocking: true,
				Code:     "OUTDATED_CLIENT",
				Detail: fmt.Sprintf("设备 %s（%s）上报版本 %s，要求 %s",
					truncateID(d.DeviceID), d.Name, d.ClientVersion, requiredClient),
			})
		}
	}
	if rep.UnknownVersion > 0 {
		rep.Issues = append(rep.Issues, PreflightIssue{
			// 阻塞：从未上报过版本的设备**可能**是旧客户端，而这一步的全部意义
			// 就是排除这种可能。让它通过等于把检查变成安慰剂
			Blocking: true,
			Code:     "UNKNOWN_CLIENT_VERSION",
			Detail: fmt.Sprintf("%d 台在用设备从未上报客户端版本；"+
				"请让它们各连一次服务器（打开 Obsidian 同步一次即可），或撤销不再使用的设备",
				rep.UnknownVersion),
		})
	}
	if rep.StaleDevices > 0 {
		rep.Issues = append(rep.Issues, PreflightIssue{
			Blocking: false,
			Code:     "STALE_DEVICE",
			Detail: fmt.Sprintf("%d 台设备超过 %d 天没有出现。"+
				"它们回来的那天如果仍是旧客户端，会覆盖已升级的内容——"+
				"确认不再使用的话建议先撤销",
				rep.StaleDevices, staleDeviceDays),
		})
	}

	// --- §15 第 7 步：历史、tombstone、Blob 的遗留问题 ---
	rep.PlaintextTombstones, err = db.PlaintextTombstoneCount(s.db)
	if err != nil {
		return nil, err
	}
	if rep.PlaintextTombstones > 0 && rs.MetaState == db.MetaEncrypted {
		rep.Issues = append(rep.Issues, PreflightIssue{
			Blocking: true,
			Code:     "PLAINTEXT_TOMBSTONE",
			Detail: fmt.Sprintf("仓库已是 encrypted，但仍有 %d 条明文 tombstone 未迁移；"+
				"擦除会把它们连同真实路径一起固化下来", rep.PlaintextTombstones),
		})
	}

	orphans, err := db.CountOrphanHistory(s.db, scope)
	if err != nil {
		return nil, err
	}
	rep.OrphanVersions = int64(orphans)
	if orphans > 0 {
		rep.Issues = append(rep.Issues, PreflightIssue{
			Blocking: true,
			Code:     "ORPHAN_HISTORY",
			Detail: fmt.Sprintf("%d 条历史版本无法归属到任何对象。"+
				"迁移会把它们留在原地成为永久孤儿——先用 `obsync migration status` 查明来源", orphans),
		})
	}

	// Blob 完整性：迁移会重写引用，此刻缺失的 blob 迁完只会更难查
	scrub, err := s.Scrub(false)
	if err != nil {
		return nil, err
	}
	rep.MissingBlobs = int64(scrub.Unservable)
	if scrub.Issues > 0 {
		rep.Issues = append(rep.Issues, PreflightIssue{
			Blocking: true,
			Code:     "INTEGRITY",
			Detail: fmt.Sprintf("完整性扫描发现 %d 个问题（%d 份内容已停止对外提供）。"+
				"先从备份修复——迁移不会修复损坏，只会让它更难定位", scrub.Issues, scrub.Unservable),
		})
	}

	// --- 迁移进行中 ---
	if rs.MigrationID != "" {
		rep.Issues = append(rep.Issues, PreflightIssue{
			Blocking: true,
			Code:     "MIGRATION_IN_PROGRESS",
			Detail: fmt.Sprintf("已有一次迁移在进行中（id=%s，持有者=%s）。"+
				"要么让它做完，要么 `obsync migration abort`",
				rs.MigrationID, truncateID(rs.MigrationOwnerDeviceID)),
		})
	}
	return rep, nil
}
