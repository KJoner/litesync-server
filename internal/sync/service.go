// Package sync 实现同步核心逻辑：revision 校验、原子写入与元数据事务。
package sync

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	gosync "sync"
	"time"

	"obsync/internal/db"
	"obsync/internal/storage"
)

var ErrNotFound = errors.New("file not found")

// ConflictError 表示 baseRevision 与服务器当前 revision 不一致。
// 携带服务器当前状态，客户端据此决定如何解决冲突。
type ConflictError struct {
	Path     string
	Revision int64
	Hash     string
	Deleted  bool
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("revision conflict on %q (server revision %d)", e.Path, e.Revision)
}

type UploadResult struct {
	Path     string
	Revision int64
	Hash     string
	Size     int64
	Sequence int64
}

type DeleteResult struct {
	Path     string
	Revision int64
	Sequence int64
}

type ChangesResult struct {
	LatestSequence int64
	HasMore        bool
	Changes        []db.Change
}

type Service struct {
	// 单用户场景：一个互斥锁串行化所有写操作，彻底避免 revision 检查的竞态。
	mu    gosync.Mutex
	db    *sql.DB
	store *storage.Storage
	log   *slog.Logger
}

func New(database *sql.DB, store *storage.Storage, logger *slog.Logger) *Service {
	return &Service{db: database, store: store, log: logger}
}

// Upload 处理文件上传。
// 规则：
//   - 服务器已有相同内容（hash 相同且未删除）→ 幂等成功，不产生新 revision；
//   - 文件不存在 → baseRevision 必须为 0；
//   - 文件已删除 → baseRevision 为 0 或等于当前（tombstone）revision 均可重新创建；
//   - 其他情况 → baseRevision 必须等于当前 revision，否则 409。
//
// 写入顺序遵循计划书第 28 节：临时文件 → 验证 hash → 原子改名 → SQLite 事务。
func (s *Service) Upload(path string, baseRevision int64, claimedHash string, body io.Reader, mtime int64) (*UploadResult, error) {
	if err := storage.ValidatePath(path); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cur, err := db.GetFile(s.db, path)
	if err != nil {
		return nil, err
	}

	// 幂等：内容与服务器现状一致时直接成功（覆盖“重复提交同一个 change”场景）。
	if cur != nil && !cur.Deleted && cur.ContentHash == claimedHash {
		io.Copy(io.Discard, body) //nolint:errcheck // 服务器状态已正确，body 内容无关紧要
		seq, err := db.LastSequenceForPath(s.db, path)
		if err != nil {
			return nil, err
		}
		return &UploadResult{Path: path, Revision: cur.Revision, Hash: cur.ContentHash, Size: cur.Size, Sequence: seq}, nil
	}

	// revision 校验（数据安全红线：上传必须有 revision 校验）
	switch {
	case cur == nil:
		if baseRevision != 0 {
			return nil, &ConflictError{Path: path, Revision: 0}
		}
	case cur.Deleted:
		if baseRevision != 0 && baseRevision != cur.Revision {
			return nil, &ConflictError{Path: path, Revision: cur.Revision, Hash: cur.ContentHash, Deleted: true}
		}
	default:
		if baseRevision != cur.Revision {
			return nil, &ConflictError{Path: path, Revision: cur.Revision, Hash: cur.ContentHash}
		}
	}

	tmp, actualHash, size, err := s.store.WriteTemp(path, body)
	if err != nil {
		return nil, err
	}
	if actualHash != claimedHash {
		s.store.Discard(tmp)
		return nil, storage.ErrHashMismatch
	}

	if err := s.store.Promote(tmp, path); err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	newRevision := int64(1)
	createdAt := now
	if cur != nil {
		newRevision = cur.Revision + 1
		createdAt = cur.CreatedAt
	}
	if mtime <= 0 {
		mtime = time.Now().UnixMilli()
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	if err := db.UpsertFile(tx, &db.File{
		Path:        path,
		ContentHash: actualHash,
		Size:        size,
		Mtime:       mtime,
		Revision:    newRevision,
		Deleted:     false,
		CreatedAt:   createdAt,
		UpdatedAt:   now,
	}); err != nil {
		return nil, err
	}
	seq, err := db.InsertChange(tx, path, newRevision, "upsert", actualHash, now)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &UploadResult{Path: path, Revision: newRevision, Hash: actualHash, Size: size, Sequence: seq}, nil
}

// Delete 逻辑删除文件（tombstone），磁盘文件在事务提交后移除。
func (s *Service) Delete(path string, baseRevision int64) (*DeleteResult, error) {
	if err := storage.ValidatePath(path); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cur, err := db.GetFile(s.db, path)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nil, ErrNotFound
	}
	// 重复删除：幂等成功
	if cur.Deleted {
		seq, err := db.LastSequenceForPath(s.db, path)
		if err != nil {
			return nil, err
		}
		return &DeleteResult{Path: path, Revision: cur.Revision, Sequence: seq}, nil
	}
	// 数据安全红线：删除必须有 revision 校验
	if baseRevision != cur.Revision {
		return nil, &ConflictError{Path: path, Revision: cur.Revision, Hash: cur.ContentHash}
	}

	now := time.Now().Unix()
	newRevision := cur.Revision + 1

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	cur.Revision = newRevision
	cur.Deleted = true
	cur.UpdatedAt = now
	if err := db.UpsertFile(tx, cur); err != nil {
		return nil, err
	}
	seq, err := db.InsertChange(tx, path, newRevision, "delete", "", now)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// 先提交元数据再删磁盘文件：即使删除失败也只会留下孤立文件，不会丢数据。
	if err := s.store.Remove(path); err != nil {
		s.log.Warn("failed to remove file from disk after delete", "path", path, "error", err)
	}

	return &DeleteResult{Path: path, Revision: newRevision, Sequence: seq}, nil
}

// OpenFile 返回文件元数据和内容读取器。
// 记录存在但已删除时，返回 (元数据, nil, ErrNotFound)，供 API 层提示客户端。
func (s *Service) OpenFile(path string) (*db.File, io.ReadCloser, error) {
	if err := storage.ValidatePath(path); err != nil {
		return nil, nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cur, err := db.GetFile(s.db, path)
	if err != nil {
		return nil, nil, err
	}
	if cur == nil {
		return nil, nil, ErrNotFound
	}
	if cur.Deleted {
		return cur, nil, ErrNotFound
	}
	f, err := s.store.Open(path)
	if err != nil {
		s.log.Error("metadata exists but file missing on disk", "path", path, "error", err)
		return nil, nil, ErrNotFound
	}
	return cur, f, nil
}

// Changes 返回 since 之后的变更列表。
func (s *Service) Changes(since, limit int64) (*ChangesResult, error) {
	changes, err := db.ListChanges(s.db, since, limit)
	if err != nil {
		return nil, err
	}
	latest, err := db.LatestSequence(s.db)
	if err != nil {
		return nil, err
	}
	hasMore := len(changes) > 0 && changes[len(changes)-1].Sequence < latest
	return &ChangesResult{LatestSequence: latest, HasMore: hasMore, Changes: changes}, nil
}

func (s *Service) LatestSequence() (int64, error) {
	return db.LatestSequence(s.db)
}
