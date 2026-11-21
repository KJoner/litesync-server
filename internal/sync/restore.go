package sync

// 显式恢复（协议 v6 / ADR-002 §3.6）。
//
// v5 里「删除后重建」是靠客户端拿 tombstone revision 做普通 upsert 穿透墓碑，
// 语义含混：服务器分不清「用户真的想恢复这个对象」与「一台陈旧设备把三个月前
// 的副本传了回来」。v6 把它变成一个显式操作：
//
//	POST /api/v1/files/{fileId}/restore
//
// 恢复后 revision = N+1（连续）、file_id 不变（全部历史仍然可达）、
// contentGeneration 必须严格大于删除时的值（抗回退）。
// operationId 让「响应丢失后重试」保持幂等。

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/failpoint"
	"github.com/KJoner/litesync-server/internal/storage"
)

// ErrOperationRequired：带新内容的恢复必须携带 operationId（响应丢失后的重试靠它幂等收敛）。
var ErrOperationRequired = errors.New("X-Operation-Id is required for restore with content")

// RestoreParams 恢复参数。
type RestoreParams struct {
	FileID string
	// ExpectedTombstoneRevision：防复活锚点，必须与台账一致
	ExpectedTombstoneRevision int64
	// ContentGeneration：恢复后写入内容的世代，必须 > tombstone 的值
	ContentGeneration int64
	// Pseudonym：恢复后的寻址名（meta 模式下必须等于 fileId）
	Pseudonym     string
	MetaEnc       string
	CanonicalHash string
	DeviceID      string
	// Client：逐请求协议/世代上下文（含幂等键）
	Client ClientContext
}

// RestoreResult 恢复结果。随后的内容上传以 Revision 作为 baseRevision。
type RestoreResult struct {
	FileID    string
	Pseudonym string
	// Revision：恢复后的 revision（= tombstone revision + 1，连续不重置）
	Revision int64
	// MetaGeneration：恢复后的元数据世代（= tombstone 的值 + 1）。
	// 客户端必须记账，否则恢复后的第一次改名会拿旧世代做 CAS 而 412
	MetaGeneration int64
	Sequence       int64
}

// TrashItem 回收站条目：删除记录 + 删除前最后一份内容所在的历史版本。
//
// 带新内容的恢复（W4）要求客户端**先**取回删除前的内容、以更新的世代重新加密，再一次提交；
// PriorRevision 告诉它去取哪个版本（GET /api/v1/version?fileId=&revision=）。
type TrashItem struct {
	db.Tombstone
	// PriorRevision / PriorGeneration：删除前内容所在的历史版本与它的内容世代；
	// PriorRevision = 0 表示那份内容已被历史清理（或 blob 已不在），无法恢复内容
	PriorRevision   int64
	PriorGeneration int64
}

// ListTrash 回收站：本仓库仍保留的全部删除记录（显式恢复的入口；只读）。
func (s *Service) ListTrash(scope db.VaultScope) ([]TrashItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tombs, err := db.ListTombstones(s.db, scope)
	if err != nil {
		return nil, err
	}
	out := make([]TrashItem, 0, len(tombs))
	for _, t := range tombs {
		it := TrashItem{Tombstone: t}
		v, err := db.PriorContentVersion(s.db, scope, t.FileID, t.PriorContentHash)
		if err != nil {
			return nil, err
		}
		if v != nil && s.blobServable(v.BlobID) {
			if _, ok := s.blobs.StatSize(v.BlobID); ok {
				it.PriorRevision, it.PriorGeneration = v.Revision, v.ContentGeneration
			}
		}
		out = append(out, it)
	}
	return out, nil
}

// Restore 把一个已删除对象恢复为 live（内容随后由普通上传写入）。
func (s *Service) Restore(scope db.VaultScope, p RestoreParams) (*RestoreResult, error) {
	if !isHex32(p.FileID) {
		return nil, storage.ErrInvalidPath
	}
	if err := storage.ValidatePath(p.Pseudonym); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := db.GetRepoState(s.db, scope)
	if err != nil {
		return nil, err
	}
	if err := s.guardWriteReady(scope, rs, p.Client, p.DeviceID, p.Pseudonym); err != nil {
		return nil, err
	}

	metaMode := rs.MetaState == db.MetaEncrypted || rs.MetaState == db.MetaVerifying
	if metaMode {
		if p.Pseudonym != p.FileID {
			return nil, ErrMetaRequired
		}
		if p.MetaEnc == "" || p.CanonicalHash == "" {
			return nil, ErrMetaRequired
		}
	}

	// 幂等：同一 operationId 已提交过 → 返回那次结果
	if p.Client.OperationID != "" {
		if prev, err := db.FindChangeByOperation(s.db, scope, p.FileID, p.Client.OperationID); err != nil {
			return nil, err
		} else if prev != nil {
			return &RestoreResult{FileID: p.FileID, Pseudonym: prev.Pseudonym,
				Revision: prev.Revision, MetaGeneration: prev.MetaGeneration, Sequence: prev.Sequence}, nil
		}
	}

	tomb, err := db.GetTombstone(s.db, scope, p.FileID)
	if err != nil {
		return nil, err
	}
	if tomb == nil {
		// 对象仍是 live → 不需要恢复；对象从未存在或 tombstone 已被清理 → 显式报错，
		// 绝不静默当作新建（那正是「静默复活」的形状）
		if h, err := db.GetHead(s.db, scope, p.FileID); err != nil {
			return nil, err
		} else if h != nil {
			return &RestoreResult{FileID: h.FileID, Pseudonym: h.Pseudonym,
				Revision: h.Revision, MetaGeneration: h.MetaGeneration}, nil
		}
		state, err := db.ObjectState(s.db, scope, p.FileID)
		if err != nil {
			return nil, err
		}
		if state == db.ObjectDeleted {
			return nil, ErrTombstonePurged
		}
		return nil, ErrNotFound
	}
	if p.ExpectedTombstoneRevision != tomb.DeletionRevision {
		return nil, ErrStaleRevision
	}
	// 抗回退：恢复写入的内容世代必须严格新于删除时的世代
	if tomb.ContentGeneration > 0 && p.ContentGeneration <= tomb.ContentGeneration {
		return nil, &ConflictError{
			Path: p.Pseudonym, Revision: tomb.DeletionRevision, Deleted: true,
			PriorHash: tomb.PriorContentHash, FileID: tomb.FileID,
		}
	}

	canonicalKey := storage.CanonicalKey(p.Pseudonym)
	if p.CanonicalHash != "" {
		canonicalKey = "h:" + p.CanonicalHash
	}
	// 恢复目标名不能与现有 live 对象冲突
	if other, err := db.FindCanonicalCollision(s.db, scope, canonicalKey, p.FileID); err != nil {
		return nil, err
	} else if other != "" {
		return nil, &PathCollisionError{Path: p.Pseudonym, Existing: other}
	}
	if occupied, err := db.GetHeadByPseudonym(s.db, scope, p.Pseudonym); err != nil {
		return nil, err
	} else if occupied != nil && occupied.FileID != p.FileID {
		return nil, &ConflictError{Path: p.Pseudonym, Revision: occupied.Revision,
			Hash: occupied.ContentHash, FileID: occupied.FileID}
	}

	now := time.Now().Unix()
	newRevision := tomb.DeletionRevision + 1

	// 域化 blobID 必须在事务外算：vaultSecret 的惰性加载会读数据库，
	// 单连接下在事务里读会死锁
	priorBlobID, err := s.blobIDOf(scope, tomb.PriorContentHash)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	// HEAD 先以「删除前的内容」重建：随后的普通上传会把内容更新为新版本。
	// prior_content_hash 为空（历史已被裁剪）时留空 blob，客户端必须紧接着上传内容。
	head := &db.ObjectHead{
		FileID:            p.FileID,
		Revision:          newRevision,
		ContentGeneration: p.ContentGeneration,
		BlobID:            priorBlobID,
		ContentHash:       tomb.PriorContentHash,
		Size:              0,
		Mtime:             now * 1000,
		MetaGeneration:    tomb.MetaGeneration + 1,
		Pseudonym:         p.Pseudonym,
		EncryptedMetadata: p.MetaEnc,
		CanonicalPathHmac: canonicalKey,
		KeyEpoch:          tomb.KeyEpoch,
		EnvelopeVersion:   s.envelopeVersionOfBlob(priorBlobID),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if head.BlobID != "" {
		if size, ok := s.blobs.StatSize(head.BlobID); ok {
			head.Size = size
		}
	}
	if err := db.UpsertHead(tx, scope, head); err != nil {
		return nil, err
	}
	if err := db.UpsertObject(tx, scope, p.FileID, db.ObjectLive, now, 0); err != nil {
		return nil, err
	}
	if err := db.RemoveTombstone(tx, scope, p.FileID); err != nil {
		return nil, err
	}
	seq, err := db.InsertChange(tx, scope, &db.ObjectChange{
		FileID: p.FileID, Action: "restore", Revision: newRevision,
		ContentGeneration: p.ContentGeneration, MetaGeneration: head.MetaGeneration,
		Pseudonym: p.Pseudonym, ContentHash: head.ContentHash,
		OperationID: p.Client.OperationID, CreatedAt: now,
	})
	if err != nil {
		return nil, err
	}
	if s.opts.HistoryEnabled {
		if err := db.InsertVersion(tx, scope, &db.ObjectVersion{
			FileID: p.FileID, Revision: newRevision, ContentGeneration: p.ContentGeneration,
			BlobID: head.BlobID, ContentHash: head.ContentHash, Size: head.Size, Mtime: head.Mtime,
			Action: "restore", DeviceID: p.DeviceID, KeyEpoch: head.KeyEpoch,
			OperationID: p.Client.OperationID, CreatedAt: now,
		}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	s.log.Info("restore", "fileId", truncateID(p.FileID), "revision", newRevision, "device", p.DeviceID)
	return &RestoreResult{FileID: p.FileID, Pseudonym: p.Pseudonym,
		Revision: newRevision, MetaGeneration: head.MetaGeneration, Sequence: seq}, nil
}

// ---------------------------------------------------------------- 带新内容的恢复（W4）
//
//	PUT /api/v1/files/{fileId}/restore   body = 新世代的密文
//
// 旧的两阶段恢复（POST restore 先复活一个指向删除前旧密文、却已声明新世代的 HEAD，
// 再由客户端补传新内容）在第二步失败时会把「旧密文 + 新世代」的 HEAD 留在服务器上：
// 恢复方自己的防回退检查挡住打开，其他端拿到的 HEAD 与信封世代对不上。
// 这里把两步合成**一个事务**：客户端先取回删除前的内容、以严格更新的世代重新加密，
// 连同期望的墓碑 revision / 世代与 operationId 一次提交——要么什么都没发生（墓碑原样还在），
// 要么恢复与新内容同时生效。同一 operationId 重试返回首次结果（响应丢失后可安全重试）。
// POST restore 的语义一个字节都没变（插件仍在用）。

// RestoreContentParams 带新内容的恢复参数。
type RestoreContentParams struct {
	FileID string
	// ExpectedTombstoneRevision / ExpectedTombstoneGeneration：防复活锚点，必须与台账一致
	ExpectedTombstoneRevision   int64
	ExpectedTombstoneGeneration int64
	// Pseudonym：恢复后的寻址名（meta 模式必须等于 fileId；明文模式可以是新路径——原位置被占时另选）
	Pseudonym     string
	ClaimedHash   string
	Mtime         int64
	MetaEnc       string
	CanonicalHash string
	DeviceID      string
	Client        ClientContext
}

// RestoreContentResult 带新内容的恢复结果。
type RestoreContentResult struct {
	FileID            string
	Pseudonym         string
	Revision          int64
	ContentGeneration int64
	MetaGeneration    int64
	Sequence          int64
	Hash              string
	Size              int64
	// Replayed：同一 operationId 的重试，返回的是首次提交的结果
	Replayed bool
}

// lsm1Header 读取 LSM1 元数据信封头（明文部分：magic | keyEpoch u32 | metaGeneration u64）。
// 服务器解不开内容，只核对头部世代与自己的记账一致——认证在客户端（AAD 绑定这两个值）。
func lsm1Header(metaEnc string) (keyEpoch, metaGeneration int64, ok bool) {
	raw, err := base64.StdEncoding.DecodeString(metaEnc)
	if err != nil || len(raw) < 16 || string(raw[:4]) != "LSM1" {
		return 0, 0, false
	}
	return int64(binary.BigEndian.Uint32(raw[4:8])), int64(binary.BigEndian.Uint64(raw[8:16])), true
}

// RestoreWithContent 一次事务完成「复活对象 + 写入新内容」。
func (s *Service) RestoreWithContent(scope db.VaultScope, p RestoreContentParams, body io.Reader) (*RestoreContentResult, error) {
	if !isHex32(p.FileID) {
		return nil, storage.ErrInvalidPath
	}
	if err := storage.ValidatePath(p.Pseudonym); err != nil {
		return nil, err
	}
	if p.Client.OperationID == "" {
		return nil, ErrOperationRequired
	}

	// 锁外：收流、落临时文件、算 hash（与 Upload 相同）
	tmp, actualHash, size, err := s.blobs.IngestVerify(body)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			s.blobs.Discard(tmp)
		}
	}()
	if actualHash != p.ClaimedHash {
		return nil, storage.ErrHashMismatch
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := db.GetRepoState(s.db, scope)
	if err != nil {
		return nil, err
	}
	if err := s.guardWriteReady(scope, rs, p.Client, p.DeviceID, p.Pseudonym); err != nil {
		return nil, err
	}
	env := envelopeVersionOfFile(tmp)
	if rs.EncryptionState != db.EncryptionPlaintext && env == 0 {
		return nil, ErrPlaintextRejected
	}
	if env < rs.MinimumEnvelopeVersion {
		return nil, ErrEnvelopeTooOld
	}
	metaMode := rs.MetaState == db.MetaEncrypted || rs.MetaState == db.MetaVerifying
	if metaMode && (p.Pseudonym != p.FileID || p.MetaEnc == "" || p.CanonicalHash == "") {
		return nil, ErrMetaRequired
	}

	// 幂等：同一 operationId 已提交过 → 返回首次结果（墓碑此时已不在，必须先于墓碑检查）
	if prev, err := db.FindChangeByOperation(s.db, scope, p.FileID, p.Client.OperationID); err != nil {
		return nil, err
	} else if prev != nil {
		res := &RestoreContentResult{FileID: p.FileID, Pseudonym: prev.Pseudonym, Revision: prev.Revision,
			ContentGeneration: prev.ContentGeneration, MetaGeneration: prev.MetaGeneration,
			Sequence: prev.Sequence, Hash: prev.ContentHash, Replayed: true}
		if h, err := db.GetHead(s.db, scope, p.FileID); err == nil && h != nil && h.ContentHash == prev.ContentHash {
			res.Size = h.Size
		}
		return res, nil
	}

	tomb, err := db.GetTombstone(s.db, scope, p.FileID)
	if err != nil {
		return nil, err
	}
	if tomb == nil {
		// 对象已经是 live（别的设备 / 别的请求先恢复了）：不能当作成功——这次的内容并没有写进去
		if h, err := db.GetHead(s.db, scope, p.FileID); err != nil {
			return nil, err
		} else if h != nil {
			return nil, &ConflictError{Path: h.Pseudonym, Revision: h.Revision, Hash: h.ContentHash, FileID: h.FileID}
		}
		state, err := db.ObjectState(s.db, scope, p.FileID)
		if err != nil {
			return nil, err
		}
		if state == db.ObjectDeleted {
			return nil, ErrTombstonePurged
		}
		return nil, ErrNotFound
	}
	if p.ExpectedTombstoneRevision != tomb.DeletionRevision || p.ExpectedTombstoneGeneration != tomb.ContentGeneration {
		return nil, ErrStaleRevision
	}
	// 抗回退：新内容的世代必须严格新于删除时的世代（信封头是明文，服务器无需密钥即可读）
	newGen, hasGen := lse3GenerationFromFile(tmp)
	if tomb.ContentGeneration > 0 && (!hasGen || newGen <= tomb.ContentGeneration) {
		return nil, &ConflictError{
			Path: p.Pseudonym, Revision: tomb.DeletionRevision, Deleted: true,
			PriorHash: tomb.PriorContentHash, FileID: tomb.FileID, ContentGeneration: tomb.ContentGeneration,
		}
	}
	// 单对象不降级：删除前已经是 LSE3+ 的对象，恢复时不能换成更旧的信封
	priorBlobID, err := s.blobIDOf(scope, tomb.PriorContentHash)
	if err != nil {
		return nil, err
	}
	if priorBlobID != "" && s.envelopeVersionOfBlob(priorBlobID) >= 3 && env < 3 {
		return nil, ErrEnvelopeTooOld
	}
	newMetaGen := tomb.MetaGeneration + 1
	if metaMode {
		// LSM1 头部的世代必须就是恢复后服务器记账的世代：两者对不上的 HEAD 会让其他端的
		// 元数据回退检查（插件 assertMetaGeneration）误判
		ke, mg, ok := lsm1Header(p.MetaEnc)
		if !ok || mg != newMetaGen || (rs.KeyEpoch != 0 && ke != rs.KeyEpoch) {
			return nil, ErrMetaRequired
		}
	}

	// 配额：恢复写入的是一份新密文（历史计入），与普通上传同一条规则
	if err := s.checkStorageQuota(scope, size); err != nil {
		return nil, err
	}

	canonicalKey := storage.CanonicalKey(p.Pseudonym)
	if p.CanonicalHash != "" {
		canonicalKey = "h:" + p.CanonicalHash
	}
	if other, err := db.FindCanonicalCollision(s.db, scope, canonicalKey, p.FileID); err != nil {
		return nil, err
	} else if other != "" {
		return nil, &PathCollisionError{Path: p.Pseudonym, Existing: other}
	}
	if occupied, err := db.GetHeadByPseudonym(s.db, scope, p.Pseudonym); err != nil {
		return nil, err
	} else if occupied != nil && occupied.FileID != p.FileID {
		return nil, &ConflictError{Path: p.Pseudonym, Revision: occupied.Revision, Hash: occupied.ContentHash, FileID: occupied.FileID}
	}

	blobID, err := s.blobIDOf(scope, actualHash)
	if err != nil {
		return nil, err
	}
	commitRes, err := s.blobs.CommitAs(tmp, blobID, actualHash, s.opts.StrictBlobVerify)
	if err != nil {
		return nil, err
	}
	committed = true
	if commitRes.Repaired {
		s.recordBlobRepairLocked(blobID, commitRes)
	}

	now := time.Now().Unix()
	mtime := p.Mtime
	if mtime <= 0 {
		mtime = time.Now().UnixMilli()
	}
	metaEnc := ""
	if metaMode {
		metaEnc = p.MetaEnc
	}
	head := &db.ObjectHead{
		FileID:            p.FileID,
		Revision:          tomb.DeletionRevision + 1,
		BlobID:            blobID,
		ContentHash:       actualHash,
		Size:              size,
		Mtime:             mtime,
		MetaGeneration:    newMetaGen,
		Pseudonym:         p.Pseudonym,
		EncryptedMetadata: metaEnc,
		CanonicalPathHmac: canonicalKey,
		KeyEpoch:          lse3KeyEpochOfFile(tmp),
		EnvelopeVersion:   env,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if hasGen {
		head.ContentGeneration = newGen
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := db.UpsertHead(tx, scope, head); err != nil {
		return nil, err
	}
	if err := db.UpsertObject(tx, scope, p.FileID, db.ObjectLive, now, 0); err != nil {
		return nil, err
	}
	if err := db.RemoveTombstone(tx, scope, p.FileID); err != nil {
		return nil, err
	}
	seq, err := db.InsertChange(tx, scope, &db.ObjectChange{
		FileID: p.FileID, Action: "restore", Revision: head.Revision,
		ContentGeneration: head.ContentGeneration, MetaGeneration: head.MetaGeneration,
		Pseudonym: head.Pseudonym, ContentHash: actualHash, OperationID: p.Client.OperationID, CreatedAt: now,
	})
	if err != nil {
		return nil, err
	}
	var prunedBlobs []string
	if s.opts.HistoryEnabled {
		if err := db.InsertVersion(tx, scope, &db.ObjectVersion{
			FileID: p.FileID, Revision: head.Revision, ContentGeneration: head.ContentGeneration,
			BlobID: blobID, ContentHash: actualHash, Size: size, Mtime: mtime,
			Action: "restore", DeviceID: p.DeviceID, KeyEpoch: head.KeyEpoch,
			OperationID: p.Client.OperationID, CreatedAt: now,
		}); err != nil {
			return nil, err
		}
		days, maxPerFile := s.retentionFor(tx, scope, rs.MetaState, head.Pseudonym)
		prunedBlobs, err = s.pruneVersionsTx(tx, scope, p.FileID, now, days, maxPerFile)
		if err != nil {
			return nil, err
		}
	}
	// 与 Upload 同样的两个崩溃注入点：提交前崩溃 → 什么都没发生、墓碑原样；
	// 提交后、响应前崩溃 → 已生效，客户端同一 operationId 重试拿回首次结果
	if err := failpoint.Eval(failpoint.DBBeforeCommit); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if err := failpoint.Eval(failpoint.DBAfterCommit); err != nil {
		return nil, err
	}
	s.gcBlobs(prunedBlobs)

	s.log.Info("restore with content", "fileId", truncateID(p.FileID), "revision", head.Revision, "device", p.DeviceID)
	return &RestoreContentResult{FileID: p.FileID, Pseudonym: head.Pseudonym, Revision: head.Revision,
		ContentGeneration: head.ContentGeneration, MetaGeneration: head.MetaGeneration, Sequence: seq,
		Hash: actualHash, Size: size}, nil
}

// PurgeTombstones 清理过期删除记录（ADR-002 §3.4 的双条件）。
//
// 只按时间清理等于赌「没有设备离线超过 N 天」——那正是删除屏障要防的场景。
// 因此还要求：所有**未撤销**设备的 last_acked_sequence 都已越过该删除点。
// 默认配置（TombstoneRetentionDays = 0）下本函数永远不删任何东西。
func (s *Service) PurgeTombstones(now int64) (int, error) {
	if s.opts.TombstoneRetentionDays <= 0 {
		return 0, nil
	}
	// v0.18：deletion_sequence 与设备 ack 都是每 Vault 独立的，逐 Vault 判定
	scopes, err := db.AllVaultScopes(s.db)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for _, scope := range scopes {
		n, perr := s.purgeTombstonesVaultLocked(scope, now)
		total += n
		if perr != nil {
			return total, perr
		}
	}
	return total, nil
}

func (s *Service) purgeTombstonesVaultLocked(scope db.VaultScope, now int64) (int, error) {
	minAcked, deviceCount, err := s.minAckedSequenceLocked(scope)
	if err != nil {
		return 0, err
	}
	if deviceCount == 0 {
		return 0, nil // 没有已注册设备时不做任何清理（无法证明安全）
	}

	tombs, err := db.ListTombstones(s.db, scope)
	if err != nil {
		return 0, err
	}
	purged := 0
	for i := range tombs {
		t := &tombs[i]
		if t.RetainUntil == 0 || now < t.RetainUntil {
			continue
		}
		if t.DeletionSequence == 0 || t.DeletionSequence > minAcked {
			continue // 还有设备没确认越过这个删除点
		}
		if err := db.RemoveTombstone(s.db, scope, t.FileID); err != nil {
			return purged, err
		}
		s.log.Info("tombstone purged", "fileId", truncateID(t.FileID),
			"deletionSequence", t.DeletionSequence, "minAcked", minAcked)
		purged++
	}
	return purged, nil
}

func (s *Service) minAckedSequenceLocked(scope db.VaultScope) (int64, int, error) {
	return db.MinAckedSequence(s.db, scope)
}

// AckSequence 记录设备已确认到的 sequence（tombstone 清理的第二个条件）。
func (s *Service) AckSequence(deviceID string, sequence int64) error {
	if deviceID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`UPDATE devices SET last_acked_sequence = ? WHERE id = ? AND last_acked_sequence < ?`,
		sequence, deviceID, sequence)
	return err
}
