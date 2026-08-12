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
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
)

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
	Sequence int64
}

// Restore 把一个已删除对象恢复为 live（内容随后由普通上传写入）。
func (s *Service) Restore(p RestoreParams) (*RestoreResult, error) {
	if !isHex32(p.FileID) {
		return nil, storage.ErrInvalidPath
	}
	if err := storage.ValidatePath(p.Pseudonym); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if err := s.guardWrite(rs, p.Client, p.DeviceID, p.Pseudonym); err != nil {
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
		if prev, err := db.FindChangeByOperation(s.db, p.FileID, p.Client.OperationID); err != nil {
			return nil, err
		} else if prev != nil {
			return &RestoreResult{FileID: p.FileID, Pseudonym: prev.Pseudonym,
				Revision: prev.Revision, Sequence: prev.Sequence}, nil
		}
	}

	tomb, err := db.GetTombstone(s.db, p.FileID)
	if err != nil {
		return nil, err
	}
	if tomb == nil {
		// 对象仍是 live → 不需要恢复；对象从未存在或 tombstone 已被清理 → 显式报错，
		// 绝不静默当作新建（那正是「静默复活」的形状）
		if h, err := db.GetHead(s.db, p.FileID); err != nil {
			return nil, err
		} else if h != nil {
			return &RestoreResult{FileID: h.FileID, Pseudonym: h.Pseudonym, Revision: h.Revision}, nil
		}
		state, err := db.ObjectState(s.db, p.FileID)
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
	if other, err := db.FindCanonicalCollision(s.db, canonicalKey, p.FileID); err != nil {
		return nil, err
	} else if other != "" {
		return nil, &PathCollisionError{Path: p.Pseudonym, Existing: other}
	}
	if occupied, err := db.GetHeadByPseudonym(s.db, p.Pseudonym); err != nil {
		return nil, err
	} else if occupied != nil && occupied.FileID != p.FileID {
		return nil, &ConflictError{Path: p.Pseudonym, Revision: occupied.Revision,
			Hash: occupied.ContentHash, FileID: occupied.FileID}
	}

	now := time.Now().Unix()
	newRevision := tomb.DeletionRevision + 1

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
		BlobID:            tomb.PriorContentHash,
		ContentHash:       tomb.PriorContentHash,
		Size:              0,
		Mtime:             now * 1000,
		MetaGeneration:    tomb.MetaGeneration + 1,
		Pseudonym:         p.Pseudonym,
		EncryptedMetadata: p.MetaEnc,
		CanonicalPathHmac: canonicalKey,
		KeyEpoch:          tomb.KeyEpoch,
		EnvelopeVersion:   s.envelopeVersionOfBlob(tomb.PriorContentHash),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if head.BlobID != "" {
		if size, ok := s.blobs.StatSize(head.BlobID); ok {
			head.Size = size
		}
	}
	if err := db.UpsertHead(tx, head); err != nil {
		return nil, err
	}
	if err := db.UpsertObject(tx, p.FileID, db.ObjectLive, now, 0); err != nil {
		return nil, err
	}
	if err := db.RemoveTombstone(tx, p.FileID); err != nil {
		return nil, err
	}
	seq, err := db.InsertChange(tx, &db.ObjectChange{
		FileID: p.FileID, Action: "restore", Revision: newRevision,
		ContentGeneration: p.ContentGeneration, MetaGeneration: head.MetaGeneration,
		Pseudonym: p.Pseudonym, ContentHash: head.ContentHash,
		OperationID: p.Client.OperationID, CreatedAt: now,
	})
	if err != nil {
		return nil, err
	}
	if s.opts.HistoryEnabled {
		if err := db.InsertVersion(tx, &db.ObjectVersion{
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
	return &RestoreResult{FileID: p.FileID, Pseudonym: p.Pseudonym, Revision: newRevision, Sequence: seq}, nil
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
	s.mu.Lock()
	defer s.mu.Unlock()

	minAcked, deviceCount, err := s.minAckedSequenceLocked()
	if err != nil {
		return 0, err
	}
	if deviceCount == 0 {
		return 0, nil // 没有已注册设备时不做任何清理（无法证明安全）
	}

	tombs, err := db.ListTombstones(s.db)
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
		if err := db.RemoveTombstone(s.db, t.FileID); err != nil {
			return purged, err
		}
		s.log.Info("tombstone purged", "fileId", truncateID(t.FileID),
			"deletionSequence", t.DeletionSequence, "minAcked", minAcked)
		purged++
	}
	return purged, nil
}

func (s *Service) minAckedSequenceLocked() (int64, int, error) {
	rows, err := s.db.Query(`SELECT last_acked_sequence FROM devices WHERE revoked = 0`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	minAcked := int64(-1)
	count := 0
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return 0, 0, err
		}
		count++
		if minAcked < 0 || v < minAcked {
			minAcked = v
		}
	}
	if minAcked < 0 {
		minAcked = 0
	}
	return minAcked, count, rows.Err()
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
