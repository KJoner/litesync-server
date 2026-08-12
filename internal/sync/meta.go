package sync

// 元数据加密状态机与迁移（协议 v6 / ADR-003）。
//
//	PLAIN ──begin──► META_MIGRATING ──verify──► META_VERIFYING ──complete──► META_ENCRYPTED
//	  ▲                    │                          │
//	  └────────────────────┴──────────────────────────┘
//	                     abort（无破坏性操作）
//
// 与 v5 的关键差异：
//   - **验证与不可逆擦除彻底分离**：VERIFYING 是独立一态，验证失败时数据没被动过
//   - 迁移进度落在 migration_journal，服务端重启可续跑（INV-11）
//   - 迁移只改 pseudonym / encrypted_metadata / canonical HMAC，
//     revision、contentGeneration、blob 全部原样不动，**不产生任何 tombstone**
//   - tombstone 做**格式转换**而不是删除（ADR-002），删除屏障完整保留（INV-06）

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/failpoint"
)

// 迁移租约默认时长。owner 需在此之前续租；过期后可被显式接管（v0.13.1）。
const migrationLeaseDuration = 30 * time.Minute

// MigrationStatus 汇报迁移进度（GET /api/v1/meta/status）。
type MigrationStatus struct {
	MetaState              string           `json:"metaState"`
	MigrationID            string           `json:"migrationId"`
	OwnerDeviceID          string           `json:"ownerDeviceId"`
	LeaseExpiresAt         int64            `json:"leaseExpiresAt"`
	CutoffSequence         int64            `json:"cutoffSequence"`
	TargetFormatEpoch      int64            `json:"targetFormatEpoch"`
	FormatEpoch            int64            `json:"formatEpoch"`
	MinimumEnvelopeVersion int64            `json:"minimumEnvelopeVersion"`
	Journal                map[string]int64 `json:"journal"`
	PlaintextTombstones    int64            `json:"plaintextTombstones"`
}

// ValidationFailure 是 complete 验证器的一条失败项。
type ValidationFailure struct {
	Check   string `json:"check"`
	Code    string `json:"code"`
	Count   int64  `json:"count"`
	Example string `json:"example,omitempty"` // 只放截断后的 fileId，绝不放路径
}

// ValidationError 携带**完整**失败清单——用户需要一次看到全部问题，
// 而不是修一个跑一次（ADR-003 §3.5）。
type ValidationError struct {
	Failures []ValidationFailure
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("migration validation failed (%d checks)", len(e.Failures))
}

func newMigrationID() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// ExpireStaleMigrationLease 释放已过期的迁移租约（v0.13.3 / §7.8 `migration resume`）。
//
// 服务器**不能**替客户端把迁移做完——迁移需要 vault key，服务器根本没有。
// 这里能做的只有一件事：把一个已经过期、但记录仍挂着 owner 的租约清掉，
// 让任一在线设备可以正常接管续做。返回释放的数量（0 表示没有过期租约）。
//
// 只清**已过期**的：强行踢掉一个还活着的 owner，会让两台设备同时写迁移。
func (s *Service) ExpireStaleMigrationLease(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return 0, err
	}
	if rs.MigrationOwnerDeviceID == "" || rs.MigrationLeaseExpiresAt > now.Unix() {
		return 0, nil
	}
	if _, err := s.db.Exec(
		`UPDATE repo_state SET migration_owner_device_id = '', migration_lease_expires_at = 0`); err != nil {
		return 0, err
	}
	s.log.Info("migration lease released by operator", "previousOwner", truncateID(rs.MigrationOwnerDeviceID))
	return 1, nil
}

// MigrationStatusOf 返回当前迁移状态与 journal 汇总。
func (s *Service) MigrationStatusOf() (*MigrationStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	counts := map[string]int64{}
	if rs.MigrationID != "" {
		if counts, err = db.JournalCounts(s.db, rs.MigrationID); err != nil {
			return nil, err
		}
	}
	plain, err := db.PlaintextTombstoneCount(s.db)
	if err != nil {
		return nil, err
	}
	return &MigrationStatus{
		MetaState: rs.MetaState, MigrationID: rs.MigrationID,
		OwnerDeviceID: rs.MigrationOwnerDeviceID, LeaseExpiresAt: rs.MigrationLeaseExpiresAt,
		CutoffSequence: rs.MigrationCutoffSequence, TargetFormatEpoch: rs.MigrationTargetFormatEpoch,
		FormatEpoch: rs.FormatEpoch, MinimumEnvelopeVersion: rs.MinimumEnvelopeVersion,
		Journal: counts, PlaintextTombstones: plain,
	}, nil
}

// BeginMetaMigration：plain → migrating。
// 同一 owner 重复调用 = 续租（幂等）；其他 owner 且租约未过期 → MIGRATION_LOCKED。
func (s *Service) BeginMetaMigration(deviceID string) (*MigrationStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	// 前置：内容加密必须已完成，且信封下限已经是 LSE3——
	// 否则迁移后会留下无法按 fileId 解密的旧信封内容
	if rs.EncryptionState != db.EncryptionEncrypted {
		return nil, ErrEncryptionState
	}
	if rs.MinimumEnvelopeVersion < db.EnvelopeLSE3 {
		return nil, ErrEnvelopeTooOld
	}

	switch rs.MetaState {
	case db.MetaEncrypted:
		return nil, ErrEncryptionState
	case db.MetaMigrating, db.MetaVerifying:
		if rs.MigrationOwnerDeviceID != "" && rs.MigrationOwnerDeviceID != deviceID {
			// 别的设备持有迁移：租约未过期 → 锁定；已过期 → 仍然拒绝，
			// 必须走**显式接管**（POST /meta/takeover）。绝不因为「begin 又被调了一次」
			// 就悄悄换 owner——那会让两台设备同时以为自己在推进迁移
			return nil, ErrMigrationLocked
		}
		// 同一 owner → 续租并继续
		if err := db.RenewMigrationLease(s.db, rs.MigrationID,
			time.Now().Add(migrationLeaseDuration).Unix()); err != nil {
			return nil, err
		}
		if rs.MetaState == db.MetaVerifying {
			// 回到 migrating 以便补迁移遗漏项
			if err := db.SetMetaState(s.db, db.MetaMigrating); err != nil {
				return nil, err
			}
		}
		if err := s.enqueueMigrationJournalLocked(rs.MigrationID); err != nil {
			return nil, err
		}
		return s.statusLocked()
	}

	migrationID, err := newMigrationID()
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := db.SetMetaState(tx, db.MetaMigrating); err != nil {
		return nil, err
	}
	if err := db.BeginMigrationRecord(tx, migrationID, deviceID,
		time.Now().Add(migrationLeaseDuration).Unix(), rs.HeadSequence,
		rs.FormatEpoch+1, rs.KeyEpoch); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if err := s.enqueueMigrationJournalLocked(migrationID); err != nil {
		return nil, err
	}
	s.log.Info("meta migration begin", "migrationId", migrationID, "device", deviceID,
		"cutoff", rs.HeadSequence, "targetFormatEpoch", rs.FormatEpoch+1)
	return s.statusLocked()
}

// enqueueMigrationJournalLocked 把全部待迁移对象与明文 tombstone 登记进 journal（幂等）。
func (s *Service) enqueueMigrationJournalLocked(migrationID string) error {
	heads, err := db.ListHeads(s.db)
	if err != nil {
		return err
	}
	for i := range heads {
		if heads[i].Pseudonym == heads[i].FileID && heads[i].EncryptedMetadata != "" {
			continue // 已经是伪名化状态
		}
		if err := db.EnqueueJournal(s.db, migrationID, heads[i].FileID, db.KindObject, "plain", "pseudonymous"); err != nil {
			return err
		}
	}
	tombs, err := db.ListTombstones(s.db)
	if err != nil {
		return err
	}
	for i := range tombs {
		if tombs[i].LastPseudonym == tombs[i].FileID {
			continue // 已经是隐私格式
		}
		if err := db.EnqueueJournal(s.db, migrationID, tombs[i].FileID, db.KindTombstone, "plain", "private"); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) statusLocked() (*MigrationStatus, error) {
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	counts := map[string]int64{}
	if rs.MigrationID != "" {
		if counts, err = db.JournalCounts(s.db, rs.MigrationID); err != nil {
			return nil, err
		}
	}
	plain, err := db.PlaintextTombstoneCount(s.db)
	if err != nil {
		return nil, err
	}
	return &MigrationStatus{
		MetaState: rs.MetaState, MigrationID: rs.MigrationID,
		OwnerDeviceID: rs.MigrationOwnerDeviceID, LeaseExpiresAt: rs.MigrationLeaseExpiresAt,
		CutoffSequence: rs.MigrationCutoffSequence, TargetFormatEpoch: rs.MigrationTargetFormatEpoch,
		FormatEpoch: rs.FormatEpoch, MinimumEnvelopeVersion: rs.MinimumEnvelopeVersion,
		Journal: counts, PlaintextTombstones: plain,
	}, nil
}

// RenewMigrationLease 续租（计划书 §5.4）。
//
// owner 在长时间迁移中必须周期性续租；租约到期后其他设备可以**显式接管**，
// 但服务器绝不自动接管、也绝不自动 complete——迁移停在原地是安全的。
func (s *Service) RenewMigrationLease(deviceID string) (*MigrationStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if rs.MigrationID == "" {
		return nil, ErrEncryptionState
	}
	if rs.MigrationOwnerDeviceID != "" && deviceID != rs.MigrationOwnerDeviceID {
		return nil, ErrMigrationNotOwner
	}
	if err := db.RenewMigrationLease(s.db, rs.MigrationID,
		time.Now().Add(migrationLeaseDuration).Unix()); err != nil {
		return nil, err
	}
	return s.statusLocked()
}

// TakeoverMigration 显式接管一个租约已过期的迁移（计划书 §5.4）。
//
// 「租约到期就自动接管」会让两台设备同时认为自己是 owner；接管必须是单方、
// 显式、且携带正确的 migrationId 的动作。owner 失联后迁移不会自动完成，
// 也不会自动回滚——需要人来决定。
func (s *Service) TakeoverMigration(migrationID, deviceID string) (*MigrationStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if rs.MigrationID == "" {
		return nil, ErrEncryptionState
	}
	if migrationID != rs.MigrationID {
		return nil, ErrMigrationMismatch
	}
	if rs.MigrationOwnerDeviceID == deviceID {
		return s.statusLocked() // 幂等：本来就是自己
	}
	if rs.MigrationLeaseExpiresAt > time.Now().Unix() {
		return nil, ErrLeaseActive
	}
	if err := db.BeginMigrationRecord(s.db, rs.MigrationID, deviceID,
		time.Now().Add(migrationLeaseDuration).Unix(), rs.MigrationCutoffSequence,
		rs.MigrationTargetFormatEpoch, rs.MigrationKeyEpoch); err != nil {
		return nil, err
	}
	s.log.Warn("migration taken over", "migrationId", rs.MigrationID,
		"previousOwner", rs.MigrationOwnerDeviceID, "newOwner", deviceID)
	return s.statusLocked()
}

// MigrateObjectMeta 把一个对象伪名化（真实路径 → fileId + LSM1 元数据）。
//
// 与 v5 的 MigrateFileMeta 不同：这里**只是一次元数据更新**。
// revision、contentGeneration、blob 全部不动，也不产生任何 tombstone——
// 这正是 v0.12.1 死结（迁移必然留下明文 tombstone）消失的原因。
func (s *Service) MigrateObjectMeta(pseudonym, metaEnc, canonicalHash, deviceID string) (*RenameResult, error) {
	// §8.1 注入点：迁移逐对象推进。此刻崩溃 → journal 里这条仍是 pending，
	// 续跑时会重做；重做必须幂等，绝不能产生第二个对象或第二条 change
	if err := failpoint.Eval(failpoint.MigrationEachObj); err != nil {
		return nil, err
	}
	if metaEnc == "" || !isHex64(canonicalHash) {
		return nil, ErrMetaRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if rs.MetaState != db.MetaMigrating {
		return nil, ErrEncryptionState
	}
	if rs.MigrationOwnerDeviceID != "" && deviceID != rs.MigrationOwnerDeviceID {
		return nil, ErrMigrationNotOwner
	}

	cur, err := db.GetHeadByPseudonym(s.db, pseudonym)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nil, ErrNotFound
	}
	// 内容必须已是 LSE3（fileId-AAD）——否则伪名化后无法解密
	if cur.EnvelopeVersion < 3 {
		return nil, ErrPlaintextRejected
	}

	// 幂等：已经伪名化且元数据一致 → 直接成功（断点续传安全）
	if cur.Pseudonym == cur.FileID && cur.EncryptedMetadata == metaEnc {
		if err := db.MarkJournalDone(s.db, rs.MigrationID, cur.FileID, db.KindObject); err != nil {
			return nil, err
		}
		return &RenameResult{FileID: cur.FileID, FromPseudonym: pseudonym, ToPseudonym: cur.Pseudonym,
			Revision: cur.Revision, MetaGeneration: cur.MetaGeneration}, nil
	}

	now := time.Now().Unix()
	metaGen := cur.MetaGeneration
	if metaGen < 1 {
		metaGen = 1
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	head := *cur
	head.Pseudonym = cur.FileID
	head.EncryptedMetadata = metaEnc
	head.CanonicalPathHmac = "h:" + canonicalHash
	head.MetaGeneration = metaGen
	head.UpdatedAt = now
	if err := db.UpsertHead(tx, &head); err != nil {
		return nil, err
	}
	seq, err := db.InsertChange(tx, &db.ObjectChange{
		FileID: head.FileID, Action: "upsert", Revision: head.Revision,
		ContentGeneration: head.ContentGeneration, MetaGeneration: metaGen,
		Pseudonym: head.Pseudonym, ContentHash: head.ContentHash, CreatedAt: now,
	})
	if err != nil {
		return nil, err
	}
	// journal 标记与数据变更同一事务提交（INV-11）
	if err := db.MarkJournalDone(tx, rs.MigrationID, head.FileID, db.KindObject); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	s.log.Info("meta migrate object", "fileId", truncateID(head.FileID), "device", deviceID)
	return &RenameResult{FileID: head.FileID, FromPseudonym: pseudonym, ToPseudonym: head.Pseudonym,
		Revision: head.Revision, MetaGeneration: metaGen, Sequence: seq}, nil
}

// PlaintextTombstone 是待转换的删除记录（迁移客户端据此计算 canonical HMAC）。
type PlaintextTombstone struct {
	FileID           string `json:"fileId"`
	LastPseudonym    string `json:"lastPseudonym"`
	DeletionRevision int64  `json:"deletionRevision"`
}

// ListPlaintextTombstones 列出仍带明文寻址名的删除记录（仅 migrating 态、仅 owner）。
// 客户端本来就知道这些真实路径，返回给它不构成新的泄露面。
func (s *Service) ListPlaintextTombstones(deviceID string) ([]PlaintextTombstone, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if rs.MetaState != db.MetaMigrating {
		return nil, ErrEncryptionState
	}
	if rs.MigrationOwnerDeviceID != "" && deviceID != rs.MigrationOwnerDeviceID {
		return nil, ErrMigrationNotOwner
	}
	tombs, err := db.ListTombstones(s.db)
	if err != nil {
		return nil, err
	}
	out := make([]PlaintextTombstone, 0, len(tombs))
	for i := range tombs {
		if tombs[i].LastPseudonym == tombs[i].FileID {
			continue
		}
		out = append(out, PlaintextTombstone{
			FileID: tombs[i].FileID, LastPseudonym: tombs[i].LastPseudonym,
			DeletionRevision: tombs[i].DeletionRevision,
		})
	}
	return out, nil
}

// MigrateTombstone 把一条 tombstone 转成隐私格式（ADR-002 §3.2）。
// 明文寻址名换成 fileId、归一化路径换成客户端 HMAC；删除屏障完整保留。
func (s *Service) MigrateTombstone(fileID, canonicalHash, deviceID string) error {
	if !isHex32(fileID) || !isHex64(canonicalHash) {
		return ErrMetaRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return err
	}
	if rs.MetaState != db.MetaMigrating {
		return ErrEncryptionState
	}
	if rs.MigrationOwnerDeviceID != "" && deviceID != rs.MigrationOwnerDeviceID {
		return ErrMigrationNotOwner
	}
	t, err := db.GetTombstone(s.db, fileID)
	if err != nil {
		return err
	}
	if t == nil {
		return ErrNotFound
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := db.ConvertTombstoneToPrivate(tx, fileID, "h:"+canonicalHash); err != nil {
		return err
	}
	if err := db.MarkJournalDone(tx, rs.MigrationID, fileID, db.KindTombstone); err != nil {
		return err
	}
	return tx.Commit()
}

// VerifyMetaMigration：migrating → verifying。
// 前置：journal 中不存在 pending/failed 条目。进入 verifying 后不再接受迁移写入，
// 只接受验证读取与 complete——**验证失败时数据一个字节都没被动过**。
func (s *Service) VerifyMetaMigration(deviceID string) (*MigrationStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if rs.MetaState == db.MetaVerifying {
		return s.statusLocked() // 幂等
	}
	if rs.MetaState != db.MetaMigrating {
		return nil, ErrEncryptionState
	}
	if rs.MigrationOwnerDeviceID != "" && deviceID != rs.MigrationOwnerDeviceID {
		return nil, ErrMigrationNotOwner
	}
	unfinished, err := db.UnfinishedJournalCount(s.db, rs.MigrationID)
	if err != nil {
		return nil, err
	}
	if unfinished > 0 {
		return nil, ErrMigrationIncomplete
	}
	if err := db.SetMetaState(s.db, db.MetaVerifying); err != nil {
		return nil, err
	}
	s.log.Info("meta migration verifying", "migrationId", rs.MigrationID)
	return s.statusLocked()
}

// AbortMetaMigration：migrating / verifying → plain。
// 已伪名化的对象保持原样（混合态可正常同步），不做任何删除或改写。
func (s *Service) AbortMetaMigration() (*MigrationStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if rs.MetaState != db.MetaMigrating && rs.MetaState != db.MetaVerifying {
		return nil, ErrEncryptionState
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := db.SetMetaState(tx, db.MetaPlain); err != nil {
		return nil, err
	}
	if err := db.ClearMigrationRecord(tx); err != nil {
		return nil, err
	}
	if err := db.ClearJournal(tx, rs.MigrationID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.log.Info("meta migration aborted", "migrationId", rs.MigrationID)
	return s.statusLocked()
}

// ValidateMetaMigration 执行 ADR-003 §3.5 的全部 11 项检查。
// 返回的清单是**完整**的——用户需要一次看到所有问题。
// scope 返回本 Service 当前操作的租户范围。
//
// 单用户阶段固定是 default 租户；多租户上线后这里改为从调用方传入的
// 认证上下文取值——届时 Service 的方法签名会带上 VaultScope 参数，
// 这个临时方法随之删除。保留它是为了让 db 层**现在就**只接受
// VaultScope，而不是等多租户那天再一次性改几十处调用。
func (s *Service) scope() db.VaultScope { return db.LegacyDefaultScope() }

func (s *Service) ValidateMetaMigration() ([]ValidationFailure, error) {
	scope := s.scope()
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	var out []ValidationFailure
	add := func(check, code string, count int64, example string) {
		if count > 0 {
			out = append(out, ValidationFailure{Check: check, Code: code, Count: count, Example: example})
		}
	}

	heads, err := db.ListHeads(s.db)
	if err != nil {
		return nil, err
	}

	// 1) 所有 live HEAD 均为当前 keyEpoch 的 LSE3
	var badEnvelope, badKeyEpoch int64
	var envExample, keyExample string
	// 2) 所有 live HEAD 有加密元数据且已伪名化
	var missingMeta int64
	var metaExample string
	// 3) 所有对象有合法 fileId
	var badFileID int64
	var idExample string
	// 5) generation 单调（HEAD 不得低于其历史最大值）
	var badGeneration int64
	var genExample string
	for i := range heads {
		h := &heads[i]
		if h.EnvelopeVersion < 3 {
			badEnvelope++
			envExample = truncateID(h.FileID)
		}
		if rs.KeyEpoch > 0 && h.KeyEpoch != rs.KeyEpoch {
			badKeyEpoch++
			keyExample = truncateID(h.FileID)
		}
		if h.EncryptedMetadata == "" || h.Pseudonym != h.FileID {
			missingMeta++
			metaExample = truncateID(h.FileID)
		}
		if !isHex32(h.FileID) {
			badFileID++
			idExample = truncateID(h.FileID)
		}
		maxGen, err := db.MaxContentGeneration(s.db, scope, h.FileID)
		if err != nil {
			return nil, err
		}
		if h.ContentGeneration < maxGen {
			badGeneration++
			genExample = truncateID(h.FileID)
		}
	}
	add("all live heads are LSE3", "ENVELOPE_TOO_OLD", badEnvelope, envExample)
	add("all live heads use the current key epoch", "KEY_EPOCH_MISMATCH", badKeyEpoch, keyExample)
	add("all live heads carry encrypted metadata and a pseudonymous name", "META_REQUIRED", missingMeta, metaExample)
	add("all objects have a valid file id", "INVALID_FILE_ID", badFileID, idExample)
	add("content generation is monotonic", "GENERATION_NOT_MONOTONIC", badGeneration, genExample)

	// 4) 历史 (file_id, revision) 无重复（UNIQUE 保证，这里再核一次）
	dupRevisions, err := db.CountDuplicateRevisions(s.db, scope)
	if err != nil {
		return nil, err
	}
	add("history revisions are unique per object", "REVISION_CONFLICT", dupRevisions, "")

	// 6) 历史全部能归属到已知对象
	orphanHistory, err := db.CountOrphanHistory(s.db, scope)
	if err != nil {
		return nil, err
	}
	add("history rows all resolve to a known object", "ORPHAN_HISTORY", orphanHistory, "")

	// 7) 所有 tombstone 已转为隐私格式
	plainTombs, err := db.PlaintextTombstoneCount(s.db)
	if err != nil {
		return nil, err
	}
	add("tombstones carry no plaintext names", "TOMBSTONE_PLAINTEXT", plainTombs, "")

	// 8) cutoff 之后不得再有以明文寻址名发布的变更。
	//
	// 只看 cutoff 之后：cutoff 之前的变更本来就是迁移前产生的，它们携带明文路径
	// 是正常的，并且会被 complete 的全量裁剪一并清除。真正要抓的是**迁移期间**
	// 有设备绕过冻结、又把真实路径写了回来。
	staleChanges, err := db.CountPlaintextAddressedChangesAfter(s.db, scope, rs.MigrationCutoffSequence)
	if err != nil {
		return nil, err
	}
	add("no plaintext-addressed change was published after the cutoff", "STALE_CHANGES", staleChanges, "")

	// 9) 分享名不含真实路径（meta 模式下必须为空）
	var namedShares int64
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM shares WHERE revoked = 0 AND name != ''`).Scan(&namedShares); err != nil {
		return nil, err
	}
	add("share names carry no plaintext paths", "SHARE_NAME_PLAINTEXT", namedShares, "")

	// 10) 当前逻辑库中没有明文路径哨兵
	residual, err := s.scanLogicalSentinels()
	if err != nil {
		return nil, err
	}
	add("no plaintext sentinel remains in logical tables", "PLAINTEXT_SENTINEL", residual, "")

	// 11) formatEpoch 与信封下限已就绪
	var notReady int64
	if rs.MigrationTargetFormatEpoch <= rs.FormatEpoch || rs.MinimumEnvelopeVersion < db.EnvelopeLSE3 {
		notReady = 1
	}
	add("format epoch and envelope floor are ready", "FORMAT_EPOCH_NOT_READY", notReady, "")

	return out, nil
}

// CompleteMetaMigration：verifying → encrypted。
//
// 先跑完整验证器；任一项失败即返回**完整清单**并保持 verifying——
// 不删除旧数据、不清空 changes、不执行任何擦除（INV-11）。
// 全部通过后执行擦除流程（ADR-008）并递增 formatEpoch。
func (s *Service) CompleteMetaMigration(migrationID, deviceID string) (*MigrationStatus, error) {
	// §8.1 注入点：complete 之前。complete 会不可逆地抹掉明文寻址名，
	// 因此这里崩溃必须让仓库停在 verifying，而不是半个 encrypted
	if err := failpoint.Eval(failpoint.MigrationBeforeDone); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if rs.MetaState == db.MetaEncrypted {
		return s.statusLocked() // 幂等
	}
	if rs.MetaState != db.MetaVerifying {
		return nil, ErrEncryptionState
	}
	if migrationID != "" && migrationID != rs.MigrationID {
		return nil, ErrMigrationMismatch
	}
	if rs.MigrationOwnerDeviceID != "" && deviceID != rs.MigrationOwnerDeviceID {
		return nil, ErrMigrationNotOwner
	}

	failures, err := s.ValidateMetaMigration()
	if err != nil {
		return nil, err
	}
	if len(failures) > 0 {
		s.log.Warn("meta complete refused", "migrationId", rs.MigrationID, "failures", len(failures))
		return nil, &ValidationError{Failures: failures}
	}

	// 擦除（ADR-008）：任一步失败保持 verifying，可修复后重试
	report, err := s.erasePlaintextPathsLocked(rs)
	if err != nil {
		return nil, err
	}
	if report.Residual > 0 {
		s.log.Error("erasure left residual sentinels", "residual", report.Residual)
		return nil, &ValidationError{Failures: []ValidationFailure{{
			Check: "post-erasure sentinel scan", Code: "PLAINTEXT_SENTINEL", Count: report.Residual,
		}}}
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := db.SetMetaState(tx, db.MetaEncrypted); err != nil {
		return nil, err
	}
	if err := db.SetFormatEpoch(tx, rs.MigrationTargetFormatEpoch); err != nil {
		return nil, err
	}
	// 全量裁剪 changes：旧记录里还带着迁移前的明文寻址名，
	// 且 formatEpoch 变化本来就要求所有客户端重新对账
	if err := db.DeleteAllChanges(tx, s.scope()); err != nil {
		return nil, err
	}
	if err := db.SetMinRetainedSequence(tx, rs.HeadSequence); err != nil {
		return nil, err
	}
	if err := db.ClearMigrationRecord(tx); err != nil {
		return nil, err
	}
	if err := db.ClearJournal(tx, rs.MigrationID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	s.log.Info("meta migration complete", "migrationId", rs.MigrationID,
		"formatEpoch", rs.MigrationTargetFormatEpoch)
	return s.statusLocked()
}

// isHex64 校验 32 字节 hex（canonical path HMAC）。
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
