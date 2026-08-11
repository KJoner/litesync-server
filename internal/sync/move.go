package sync

// 原子 MOVE（v9.3 三阶段一期，审查 18 遗留的 rename 原子化）。
//
// 单事务内完成「旧路径 tombstone + 新路径新行」：崩溃或并发观察者绝不会
// 看到「删除已发生、新增还没来」的中间态。file_id 跟随内容走到新路径
//（稳定身份，二期 LSE3 的 AAD 将绑定它），旧路径的 tombstone 行换新 id。
//
// changes feed 仍表示为 delete(from) + upsert(to) 两条连续 sequence——
// 旧客户端（协议 v3）的处理与普通改名完全一致，无需协议升级。
//
// 仅明文模式：LSE1/LSE2 的 AAD 绑定 path，服务器侧移动无法复用密文；
// E2EE 下客户端维持「重新加密上传 + 删除旧路径」，待 LSE3（fileId-AAD）统一。

import (
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
)

type MoveResult struct {
	FromPath          string
	ToPath            string
	Revision          int64 // 新路径的 revision
	TombstoneRevision int64 // 旧路径的墓碑 revision
	Sequence          int64 // upsert(to) 的 sequence（本次操作的最新 sequence）
}

func (s *Service) Move(fromPath, toPath string, baseRevision int64, deviceID string) (*MoveResult, error) {
	if err := storage.ValidatePath(fromPath); err != nil {
		return nil, err
	}
	if err := storage.ValidatePath(toPath); err != nil {
		return nil, err
	}
	if fromPath == toPath {
		return nil, storage.ErrInvalidPath
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}

	from, err := db.GetFile(s.db, fromPath)
	if err != nil {
		return nil, err
	}
	if from == nil || from.Deleted {
		return nil, ErrNotFound
	}
	// E2EE（v9.3）：LSE3 的 AAD 绑定 fileId 而非路径 → 移动无需重新加密，放行；
	// LSE1/LSE2 密文 AAD 绑路径，服务器侧移动会产出无法解密的内容 → 拒绝
	if rs.EncryptionState != db.EncryptionPlaintext {
		if _, isV3 := s.lse3GenerationFromBlob(from.ContentHash); !isV3 {
			return nil, ErrEncryptionState
		}
	}
	if baseRevision != from.Revision {
		return nil, &ConflictError{Path: fromPath, Revision: from.Revision, Hash: from.ContentHash}
	}

	to, err := db.GetFile(s.db, toPath)
	if err != nil {
		return nil, err
	}
	if to != nil && !to.Deleted {
		// 目标已有未删除文件：交给客户端回退 delete+upsert（走正常冲突语义）
		return nil, &ConflictError{Path: toPath, Revision: to.Revision, Hash: to.ContentHash}
	}
	// 跨平台碰撞检查：排除 fromPath 自身——大小写改名（Note.md → note.md）必须允许
	if other, err := db.FindCanonicalCollision(s.db, storage.CanonicalKey(toPath), toPath); err != nil {
		return nil, err
	} else if other != "" && other != fromPath {
		return nil, &PathCollisionError{Path: toPath, Existing: other}
	}

	now := time.Now().Unix()
	tombRev := from.Revision + 1
	newRev := int64(1)
	createdAt := now
	if to != nil {
		newRev = to.Revision + 1
		createdAt = to.CreatedAt
	}
	// 旧路径的 tombstone 行换新 file_id（file_id 唯一，真身随内容去了新路径）
	tombID, err := db.NewFileID()
	if err != nil {
		return nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	// 1) from → tombstone
	if err := db.UpsertFile(tx, &db.File{
		Path:         fromPath,
		ContentHash:  from.ContentHash,
		Size:         from.Size,
		Mtime:        from.Mtime,
		Revision:     tombRev,
		Deleted:      true,
		CreatedAt:    from.CreatedAt,
		UpdatedAt:    now,
		CanonicalKey: from.CanonicalKey,
		FileID:       tombID,
	}); err != nil {
		return nil, err
	}
	if _, err := db.InsertChange(tx, fromPath, tombRev, "delete", "", now); err != nil {
		return nil, err
	}
	if s.opts.HistoryEnabled {
		if err := db.InsertVersion(tx, &db.FileVersion{
			Path: fromPath, Revision: tombRev, BlobID: "", ContentHash: "",
			Size: 0, Mtime: from.Mtime, Action: "delete", DeviceID: deviceID, CreatedAt: now,
		}); err != nil {
			return nil, err
		}
	}

	// 2) to ← 内容与 file_id 原样继承（blob 内容寻址，无需复制）
	if err := db.UpsertFile(tx, &db.File{
		Path:         toPath,
		ContentHash:  from.ContentHash,
		Size:         from.Size,
		Mtime:        from.Mtime,
		Revision:     newRev,
		Deleted:      false,
		CreatedAt:    createdAt,
		UpdatedAt:    now,
		CanonicalKey: storage.CanonicalKey(toPath),
		FileID:       from.FileID,
	}); err != nil {
		return nil, err
	}
	seq, err := db.InsertChange(tx, toPath, newRev, "upsert", from.ContentHash, now)
	if err != nil {
		return nil, err
	}
	var prunedBlobs []string
	if s.opts.HistoryEnabled {
		if err := db.InsertVersion(tx, &db.FileVersion{
			Path: toPath, Revision: newRev, BlobID: from.ContentHash, ContentHash: from.ContentHash,
			Size: from.Size, Mtime: from.Mtime, Action: "upsert", DeviceID: deviceID, CreatedAt: now,
			FileID: from.FileID,
		}); err != nil {
			return nil, err
		}
		days, maxPerFile := s.retentionFor(toPath)
		if prunedBlobs, err = s.pruneVersionsTx(tx, toPath, now, days, maxPerFile); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.gcBlobs(prunedBlobs)

	s.log.Info("move", "from", fromPath, "to", toPath, "fileId", from.FileID, "rev", newRev)
	return &MoveResult{
		FromPath:          fromPath,
		ToPath:            toPath,
		Revision:          newRev,
		TombstoneRevision: tombRev,
		Sequence:          seq,
	}, nil
}
