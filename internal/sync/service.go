// Package sync 实现同步核心逻辑：revision 校验、原子写入、元数据事务与版本历史。
package sync

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
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

// Options 控制版本历史行为（Phase 11）。
type Options struct {
	HistoryEnabled    bool
	HistoryDays       int // 0 = 不按天数裁剪
	HistoryMaxPerFile int // 0 = 不限数量
}

type Service struct {
	// 单用户场景：一个互斥锁串行化所有写操作，彻底避免 revision 检查的竞态。
	mu    gosync.Mutex
	db    *sql.DB
	store *storage.Storage
	blobs *storage.BlobStore
	opts  Options
	log   *slog.Logger
}

func New(database *sql.DB, store *storage.Storage, blobs *storage.BlobStore, opts Options, logger *slog.Logger) *Service {
	return &Service{db: database, store: store, blobs: blobs, opts: opts, log: logger}
}

// validAction 校验客户端声明的上传动作类型。
func validAction(action string) bool {
	switch action {
	case "upsert", "merge", "restore":
		return true
	}
	return false
}

// Upload 处理文件上传。
// 规则：
//   - 服务器已有相同内容（hash 相同且未删除）→ 幂等成功，不产生新 revision；
//   - 文件不存在 → baseRevision 必须为 0；
//   - 文件已删除 → baseRevision 为 0 或等于当前（tombstone）revision 均可重新创建；
//   - 其他情况 → baseRevision 必须等于当前 revision，否则 409。
//
// 写入顺序：临时文件 → 验证 hash → 存入 blob（历史）→ 原子改名（HEAD）→ SQLite 事务。
func (s *Service) Upload(path string, baseRevision int64, claimedHash string, body io.Reader, mtime int64, deviceID, action string) (*UploadResult, error) {
	if err := storage.ValidatePath(path); err != nil {
		return nil, err
	}
	if action == "" {
		action = "upsert"
	}
	if !validAction(action) {
		return nil, storage.ErrInvalidPath // 语义上是 bad request；复用 400 映射
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

	// 历史 blob 必须在 Promote 之前写入（Promote 会把临时文件改名走）
	if s.opts.HistoryEnabled {
		if err := s.putBlobFromFile(actualHash, tmp); err != nil {
			s.store.Discard(tmp)
			return nil, fmt.Errorf("store history blob: %w", err)
		}
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

	var prunedBlobs []string
	if s.opts.HistoryEnabled {
		if err := db.InsertVersion(tx, &db.FileVersion{
			Path: path, Revision: newRevision, BlobID: actualHash, ContentHash: actualHash,
			Size: size, Mtime: mtime, Action: action, DeviceID: deviceID, CreatedAt: now,
		}); err != nil {
			return nil, err
		}
		prunedBlobs, err = s.pruneVersions(tx, path, now)
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.gcBlobs(prunedBlobs)

	return &UploadResult{Path: path, Revision: newRevision, Hash: actualHash, Size: size, Sequence: seq}, nil
}

// Delete 逻辑删除文件（tombstone），磁盘文件在事务提交后移除。
// 删除同样产生一条历史版本记录（action=delete，不可抹掉历史）。
func (s *Service) Delete(path string, baseRevision int64, deviceID string) (*DeleteResult, error) {
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
	if s.opts.HistoryEnabled {
		if err := db.InsertVersion(tx, &db.FileVersion{
			Path: path, Revision: newRevision, BlobID: "", ContentHash: "",
			Size: 0, Mtime: cur.Mtime, Action: "delete", DeviceID: deviceID, CreatedAt: now,
		}); err != nil {
			return nil, err
		}
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

// History 返回某路径的历史版本列表（revision 降序）。
func (s *Service) History(path string) ([]db.FileVersion, error) {
	if err := storage.ValidatePath(path); err != nil {
		return nil, err
	}
	return db.ListVersions(s.db, path)
}

// OpenVersion 返回历史版本的元数据和内容读取器。
// 版本不存在、是 delete 版本或 blob 已被 GC 时返回 ErrNotFound。
func (s *Service) OpenVersion(path string, revision int64) (*db.FileVersion, io.ReadCloser, error) {
	if err := storage.ValidatePath(path); err != nil {
		return nil, nil, err
	}
	v, err := db.GetVersion(s.db, path, revision)
	if err != nil {
		return nil, nil, err
	}
	if v == nil || v.BlobID == "" {
		return nil, nil, ErrNotFound
	}
	f, err := s.blobs.Open(v.BlobID)
	if err != nil {
		return nil, nil, ErrNotFound
	}
	return v, f, nil
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

// BackfillVersions 为升级前已存在、但还没有任何历史记录的文件补一条当前版本。
// 幂等；启动时调用。
func (s *Service) BackfillVersions() error {
	if !s.opts.HistoryEnabled {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(
		`SELECT f.path, f.content_hash, f.size, f.mtime, f.revision, f.updated_at
		 FROM files f
		 WHERE f.deleted = 0
		   AND NOT EXISTS (SELECT 1 FROM file_versions v WHERE v.path = f.path)`)
	if err != nil {
		return err
	}
	type pending struct{ path, hash string; size, mtime, revision, updatedAt int64 }
	var todo []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.path, &p.hash, &p.size, &p.mtime, &p.revision, &p.updatedAt); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, p := range todo {
		f, err := s.store.Open(p.path)
		if err != nil {
			s.log.Warn("backfill: cannot open vault file, skipping", "path", p.path, "error", err)
			continue
		}
		err = s.blobs.PutReader(p.hash, f)
		f.Close()
		if err != nil {
			s.log.Warn("backfill: blob write failed, skipping", "path", p.path, "error", err)
			continue
		}
		if err := db.InsertVersion(s.db, &db.FileVersion{
			Path: p.path, Revision: p.revision, BlobID: p.hash, ContentHash: p.hash,
			Size: p.size, Mtime: p.mtime, Action: "upsert", DeviceID: "", CreatedAt: p.updatedAt,
		}); err != nil {
			return err
		}
		s.log.Info("backfill: version recorded", "path", p.path, "revision", p.revision)
	}
	return nil
}

// pruneVersions 按 retention 规则裁剪某路径的历史（在上传事务内执行）。
// 规则：保留最近 HistoryMaxPerFile 个版本，且不早于 HistoryDays 天；
// 最新的一条（HEAD 对应的版本）永远保留。
// 返回被删元数据引用的 blob 列表，由调用方在事务提交后做引用计数 GC。
func (s *Service) pruneVersions(tx *sql.Tx, path string, now int64) ([]string, error) {
	if s.opts.HistoryMaxPerFile <= 0 && s.opts.HistoryDays <= 0 {
		return nil, nil
	}
	versions, err := db.ListVersions(tx, path) // revision 降序
	if err != nil {
		return nil, err
	}
	cutoff := int64(0)
	if s.opts.HistoryDays > 0 {
		cutoff = now - int64(s.opts.HistoryDays)*86400
	}
	var pruneIDs []int64
	var pruneBlobs []string
	for i, v := range versions {
		if i == 0 {
			continue // 最新版本永远保留
		}
		tooMany := s.opts.HistoryMaxPerFile > 0 && i >= s.opts.HistoryMaxPerFile
		tooOld := cutoff > 0 && v.CreatedAt < cutoff
		if tooMany || tooOld {
			pruneIDs = append(pruneIDs, v.ID)
			if v.BlobID != "" {
				pruneBlobs = append(pruneBlobs, v.BlobID)
			}
		}
	}
	for _, id := range pruneIDs {
		if _, err := tx.Exec(`DELETE FROM file_versions WHERE id = ?`, id); err != nil {
			return nil, err
		}
	}
	return pruneBlobs, nil
}

// gcBlobs 删除不再被任何版本引用的 blob（GC 顺序：先删元数据，确认无引用，再删 blob）。
func (s *Service) gcBlobs(blobIDs []string) {
	seen := map[string]bool{}
	for _, id := range blobIDs {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		n, err := db.CountBlobRefs(s.db, id)
		if err != nil {
			s.log.Warn("blob gc: refcount query failed", "blob", id, "error", err)
			continue
		}
		if n == 0 {
			if err := s.blobs.Remove(id); err != nil {
				s.log.Warn("blob gc: remove failed", "blob", id, "error", err)
			}
		}
	}
}

func (s *Service) putBlobFromFile(hash, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	return s.blobs.PutReader(hash, f)
}
