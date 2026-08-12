package db

// v5 → v6 数据库迁移（ADR-001 §5 / ADR-003 §5）。
//
// 迁移由 migration_journal 驱动（migration_id = "schema-v6"）：逐对象记录 stage，
// 每个对象的数据变更与它的 journal 标记在**同一事务**内提交。因此：
//   - 中途崩溃后重启可续跑，不会重复迁移，也不会漏迁移（INV-11）
//   - 重复执行是幂等的
//
// 迁移**不删除** v5 表：完成后重命名为 v5_files / v5_changes / v5_file_versions
// 只读保留，作为回滚窗口。用户显式确认后由 FinalizeV6Migration 删除。

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"
)

// V6MigrationReport 是 dry-run 与正式迁移的结果报告。
type V6MigrationReport struct {
	SchemaVersionBefore int64 `json:"schemaVersionBefore"`
	LiveObjects         int   `json:"liveObjects"`
	Tombstones          int   `json:"tombstones"`
	// PseudoTombstones：v5 元数据迁移遗留的假删除（不是真实删除，见 ADR-002 §5）
	PseudoTombstones int `json:"pseudoTombstones"`
	// NeedsReview：无法判定归属、按保守策略保留下来的 tombstone
	NeedsReview int `json:"needsReview"`
	Versions    int `json:"versions"`
	// OrphanVersions：无法归属到任何 file_id 的历史行（保留并报告，绝不静默丢弃）
	OrphanVersions int `json:"orphanVersions"`
	// DuplicateFileIDs：v5 里出现重复 file_id 的对象（迁移会重新分配并报告）
	DuplicateFileIDs int `json:"duplicateFileIds"`
	// RevisionConflicts：同一 (file_id, revision) 出现多行历史
	RevisionConflicts int `json:"revisionConflicts"`
	// MissingBlobs：HEAD 或历史引用了不存在的 blob（只报告，不阻断）
	MissingBlobs int `json:"missingBlobs"`
	// InvalidKeyEpochs：信封头里出现非法 keyEpoch 的对象
	InvalidKeyEpochs int      `json:"invalidKeyEpochs"`
	InferredEnvelope int64    `json:"inferredMinimumEnvelopeVersion"`
	InferredFormat   int64    `json:"inferredFormatEpoch"`
	Warnings         []string `json:"warnings"`
}

// BlobProbe 让迁移在不引入 storage 依赖的前提下检查 blob 是否存在与其信封版本。
type BlobProbe interface {
	Has(hash string) bool
	EnvelopeVersion(hash string) int64
	ContentGeneration(hash string) (int64, bool)
	KeyEpoch(hash string) (int64, bool)
}

// noProbe 在没有 blob 存储时使用（dry-run 的最小模式）。
type noProbe struct{}

func (noProbe) Has(string) bool                        { return true }
func (noProbe) EnvelopeVersion(string) int64           { return 0 }
func (noProbe) ContentGeneration(string) (int64, bool) { return 0, false }
func (noProbe) KeyEpoch(string) (int64, bool)          { return 0, false }

// NeedsV6Migration 判断是否需要执行 v5 → v6 迁移。
func NeedsV6Migration(d *sql.DB) (bool, error) {
	hasLegacy, err := TableExists(d, "files")
	if err != nil {
		return false, err
	}
	if !hasLegacy {
		return false, nil
	}
	rs, err := GetRepoState(d)
	if err != nil {
		return false, err
	}
	return rs.SchemaVersion < SchemaVersion, nil
}

// DryRunV6Migration 只读检查（v10 计划 §4.9）：不修改任何数据。
func DryRunV6Migration(d *sql.DB, probe BlobProbe) (*V6MigrationReport, error) {
	if probe == nil {
		probe = noProbe{}
	}
	rs, err := GetRepoState(d)
	if err != nil {
		return nil, err
	}
	report := &V6MigrationReport{SchemaVersionBefore: rs.SchemaVersion}

	hasLegacy, err := TableExists(d, "files")
	if err != nil {
		return nil, err
	}
	if !hasLegacy {
		report.Warnings = append(report.Warnings, "no v5 tables present; nothing to migrate")
		return report, nil
	}

	files, err := ListLegacyFiles(d)
	if err != nil {
		return nil, err
	}
	versions, err := ListLegacyVersions(d)
	if err != nil {
		return nil, err
	}

	plan := planV6(files, versions, probe)
	report.LiveObjects = len(plan.heads)
	report.Tombstones = len(plan.tombstones)
	report.PseudoTombstones = plan.pseudoTombstones
	report.NeedsReview = plan.needsReview
	report.Versions = len(plan.versions)
	report.OrphanVersions = plan.orphanVersions
	report.DuplicateFileIDs = plan.duplicateFileIDs
	report.RevisionConflicts = plan.revisionConflicts
	report.InvalidKeyEpochs = plan.invalidKeyEpochs
	report.Warnings = append(report.Warnings, plan.warnings...)

	for _, h := range plan.heads {
		if h.BlobID != "" && !probe.Has(h.BlobID) {
			report.MissingBlobs++
		}
	}
	report.InferredEnvelope = plan.inferredEnvelope
	report.InferredFormat = inferFormatEpoch(rs)
	return report, nil
}

type v6Plan struct {
	heads      []ObjectHead
	tombstones []Tombstone
	versions   []ObjectVersion
	// legacy path → file_id，用于把历史行归属到对象
	pathToFileID      map[string]string
	pseudoTombstones  int
	needsReview       int
	orphanVersions    int
	duplicateFileIDs  int
	revisionConflicts int
	invalidKeyEpochs  int
	inferredEnvelope  int64
	warnings          []string
}

// planV6 把 v5 的行规划成 v6 的对象/tombstone/历史（纯函数，dry-run 与正式迁移共用）。
func planV6(files []LegacyFile, versions []LegacyVersion, probe BlobProbe) *v6Plan {
	p := &v6Plan{pathToFileID: map[string]string{}}

	seenFileID := map[string]bool{}
	livePseudonymOfFileID := map[string]string{}

	// 第一遍：live 行 → HEAD
	for i := range files {
		f := &files[i]
		if f.Deleted {
			continue
		}
		fileID := f.FileID
		if !isHex32(fileID) || seenFileID[fileID] {
			if seenFileID[fileID] {
				p.duplicateFileIDs++
			}
			newID, err := NewFileID()
			if err == nil {
				p.warnings = append(p.warnings,
					fmt.Sprintf("reassigned file_id for one live object (was %q)", truncateID(fileID)))
				fileID = newID
			}
		}
		seenFileID[fileID] = true
		p.pathToFileID[f.Path] = fileID
		livePseudonymOfFileID[fileID] = f.Path

		env := probe.EnvelopeVersion(f.ContentHash)
		gen, _ := probe.ContentGeneration(f.ContentHash)
		keyEpoch, keyOK := probe.KeyEpoch(f.ContentHash)
		if env == 3 && !keyOK {
			p.invalidKeyEpochs++
		}
		p.heads = append(p.heads, ObjectHead{
			VaultID:           DefaultVaultID,
			FileID:            fileID,
			Revision:          f.Revision, // 关键：revision 原样保留，绝不重置（INV-05）
			ContentGeneration: gen,
			BlobID:            f.ContentHash,
			ContentHash:       f.ContentHash,
			Size:              f.Size,
			Mtime:             f.Mtime,
			MetaGeneration:    f.MetaGeneration,
			Pseudonym:         f.Path,
			EncryptedMetadata: f.MetaEnc,
			CanonicalPathHmac: f.CanonicalKey,
			KeyEpoch:          keyEpoch,
			EnvelopeVersion:   env,
			CreatedAt:         f.CreatedAt,
			UpdatedAt:         f.UpdatedAt,
		})
	}

	// 推断仓库信封下限（ADR-006 §4）
	p.inferredEnvelope = inferEnvelopeFloor(p.heads)

	// 第二遍：tombstone。
	//
	// v5 的元数据迁移与 MOVE 都会在旧路径上留下一条**假** tombstone（当时新造了
	// 一个 tombID，真身随内容去了新路径）。它与真实删除在 files 表里长得一模一样，
	// 无法可靠区分——因此这里**一条都不丢**，只对可疑的打标记：
	// 假 tombstone 的 file_id 是凭空造的，名下不会有任何历史版本；
	// 真实删除则至少有删除前的内容版本。
	versionsByPath := map[string]int{}
	for i := range versions {
		versionsByPath[versions[i].Path]++
	}
	for i := range files {
		f := &files[i]
		if !f.Deleted {
			continue
		}
		fileID := f.FileID
		needsReview := false
		if versionsByPath[f.Path] == 0 {
			// 名下没有任何历史 → 很可能是 v5 迁移/MOVE 留下的假删除。
			// 保留（防复活优先），但标记出来供人工核对
			needsReview = true
			p.pseudoTombstones++
		}
		if !isHex32(fileID) || seenFileID[fileID] {
			newID, err := NewFileID()
			if err == nil {
				fileID = newID
			}
			needsReview = true // 身份存疑：保留但标记，绝不静默丢弃
		}
		if needsReview {
			p.needsReview++
		}
		seenFileID[fileID] = true
		if _, exists := p.pathToFileID[f.Path]; !exists {
			p.pathToFileID[f.Path] = fileID
		}
		p.tombstones = append(p.tombstones, Tombstone{
			VaultID:           DefaultVaultID,
			FileID:            fileID,
			LastPseudonym:     f.Path,
			CanonicalPathHmac: f.CanonicalKey,
			DeletionRevision:  f.Revision,
			MetaGeneration:    f.MetaGeneration,
			DeletedAt:         f.UpdatedAt,
			NeedsReview:       needsReview,
		})
	}

	// 第三遍：历史 → 按 path 归属到 file_id
	revSeen := map[string]bool{}
	priorHash := map[string]string{}
	for i := range versions {
		v := &versions[i]
		fileID := v.FileID
		if !isHex32(fileID) {
			fileID = p.pathToFileID[v.Path]
		}
		if fileID == "" {
			p.orphanVersions++
			continue
		}
		key := fileID + "/" + fmt.Sprint(v.Revision)
		if revSeen[key] {
			p.revisionConflicts++
			continue // (file_id, revision) 唯一：重复行丢弃并计数
		}
		revSeen[key] = true
		gen, _ := probe.ContentGeneration(v.BlobID)
		keyEpoch, _ := probe.KeyEpoch(v.BlobID)
		if v.Action != "delete" && v.ContentHash != "" {
			priorHash[fileID] = v.ContentHash
		}
		p.versions = append(p.versions, ObjectVersion{
			VaultID:           DefaultVaultID,
			FileID:            fileID,
			Revision:          v.Revision,
			ContentGeneration: gen,
			BlobID:            v.BlobID,
			ContentHash:       v.ContentHash,
			Size:              v.Size,
			Mtime:             v.Mtime,
			Action:            v.Action,
			DeviceID:          v.DeviceID,
			KeyEpoch:          keyEpoch,
			CreatedAt:         v.CreatedAt,
		})
	}

	// 回填 tombstone 的 prior_content_hash（陈旧副本判定用）
	for i := range p.tombstones {
		p.tombstones[i].PriorContentHash = priorHash[p.tombstones[i].FileID]
	}
	return p
}

// inferEnvelopeFloor 按 ADR-006 §4 推断仓库信封下限。
func inferEnvelopeFloor(heads []ObjectHead) int64 {
	if len(heads) == 0 {
		return EnvelopeAny
	}
	allV3, anyEncrypted := true, false
	for i := range heads {
		switch heads[i].EnvelopeVersion {
		case 3:
			anyEncrypted = true
		case 1, 2:
			anyEncrypted = true
			allV3 = false
		default:
			allV3 = false
		}
	}
	switch {
	case anyEncrypted && allV3:
		return EnvelopeLSE3
	case anyEncrypted:
		return EnvelopeLSE1
	default:
		return EnvelopeAny
	}
}

func inferFormatEpoch(rs *RepoState) int64 {
	if rs.MetaState == MetaEncrypted {
		return 2
	}
	return 1
}

// MigrateToV6 执行正式迁移（幂等、可续跑）。
func MigrateToV6(d *sql.DB, probe BlobProbe, log *slog.Logger) (*V6MigrationReport, error) {
	if probe == nil {
		probe = noProbe{}
	}
	need, err := NeedsV6Migration(d)
	if err != nil {
		return nil, err
	}
	if !need {
		return nil, nil
	}

	report, err := DryRunV6Migration(d, probe)
	if err != nil {
		return nil, err
	}

	files, err := ListLegacyFiles(d)
	if err != nil {
		return nil, err
	}
	versions, err := ListLegacyVersions(d)
	if err != nil {
		return nil, err
	}
	plan := planV6(files, versions, probe)
	now := time.Now().Unix()

	// 1) 登记 journal（幂等；崩溃重启后已 done 的条目不会重做）
	for i := range plan.heads {
		if err := EnqueueJournal(d, SchemaMigrationID, plan.heads[i].FileID, KindObject, "v5", "v6"); err != nil {
			return nil, err
		}
	}
	for i := range plan.tombstones {
		if err := EnqueueJournal(d, SchemaMigrationID, plan.tombstones[i].FileID, KindTombstone, "v5", "v6"); err != nil {
			return nil, err
		}
	}

	// 2) 逐对象迁移：数据变更与 journal 标记同一事务提交
	for i := range plan.heads {
		h := plan.heads[i]
		if err := migrateOneObject(d, &h, plan.versions, now); err != nil {
			_ = MarkJournalFailed(d, SchemaMigrationID, h.FileID, KindObject, err.Error())
			return nil, fmt.Errorf("migrate object %s: %w", truncateID(h.FileID), err)
		}
	}
	for i := range plan.tombstones {
		t := plan.tombstones[i]
		if err := migrateOneTombstone(d, &t, plan.versions, now); err != nil {
			_ = MarkJournalFailed(d, SchemaMigrationID, t.FileID, KindTombstone, err.Error())
			return nil, fmt.Errorf("migrate tombstone %s: %w", truncateID(t.FileID), err)
		}
	}

	// 3) 收尾：changes 作废（协议版本变化本来就要求全量对账）、推断 epoch/下限、
	//    旧表重命名只读保留
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	rs, err := GetRepoState(tx)
	if err != nil {
		return nil, err
	}
	if err := SetMinRetainedSequence(tx, rs.HeadSequence); err != nil {
		return nil, err
	}
	if err := RaiseMinimumEnvelopeVersion(tx, plan.inferredEnvelope); err != nil {
		return nil, err
	}
	if err := SetFormatEpoch(tx, inferFormatEpoch(rs)); err != nil {
		return nil, err
	}
	if err := SetSchemaVersion(tx, SchemaVersion); err != nil {
		return nil, err
	}
	for _, rename := range []struct{ from, to string }{
		{"files", "v5_files"},
		{"changes", "v5_changes"},
		{"file_versions", "v5_file_versions"},
	} {
		exists, err := TableExists(tx, rename.from)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		if _, err := tx.Exec(`DROP TABLE IF EXISTS ` + rename.to); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`ALTER TABLE ` + rename.from + ` RENAME TO ` + rename.to); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	if log != nil {
		log.Info("schema migrated to v6",
			"objects", report.LiveObjects, "tombstones", report.Tombstones,
			"pseudoTombstones", report.PseudoTombstones, "versions", report.Versions,
			"orphanVersions", report.OrphanVersions, "needsReview", report.NeedsReview,
			"minimumEnvelopeVersion", plan.inferredEnvelope, "formatEpoch", inferFormatEpoch(rs))
		for _, w := range report.Warnings {
			log.Warn("v6 migration", "warning", w)
		}
	}
	return report, nil
}

func migrateOneObject(d *sql.DB, h *ObjectHead, all []ObjectVersion, now int64) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if err := UpsertObject(tx, h.FileID, ObjectLive, h.CreatedAt, 0); err != nil {
		return err
	}
	if err := UpsertHead(tx, h); err != nil {
		return err
	}
	for i := range all {
		if all[i].FileID != h.FileID {
			continue
		}
		if err := InsertVersion(tx, &all[i]); err != nil {
			return err
		}
	}
	if err := MarkJournalDone(tx, SchemaMigrationID, h.FileID, KindObject); err != nil {
		return err
	}
	_ = now
	return tx.Commit()
}

func migrateOneTombstone(d *sql.DB, t *Tombstone, all []ObjectVersion, now int64) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if err := UpsertObject(tx, t.FileID, ObjectDeleted, t.DeletedAt, t.DeletedAt); err != nil {
		return err
	}
	if err := UpsertTombstone(tx, t); err != nil {
		return err
	}
	for i := range all {
		if all[i].FileID != t.FileID {
			continue
		}
		if err := InsertVersion(tx, &all[i]); err != nil {
			return err
		}
	}
	if err := MarkJournalDone(tx, SchemaMigrationID, t.FileID, KindTombstone); err != nil {
		return err
	}
	_ = now
	return tx.Commit()
}

// FinalizeV6Migration 删除只读保留的 v5 旧表（用户显式确认后调用）。
// 执行后不再能通过换回 0.12.x 二进制回滚——必须依赖迁移后备份。
func FinalizeV6Migration(d *sql.DB) error {
	for _, t := range []string{"v5_files", "v5_changes", "v5_file_versions"} {
		if _, err := d.Exec(`DROP TABLE IF EXISTS ` + t); err != nil {
			return err
		}
	}
	return ClearJournal(d, SchemaMigrationID)
}

func isHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// truncateID 只输出身份的前 8 位（日志隐私，ADR-008 §3.5）。
func truncateID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
