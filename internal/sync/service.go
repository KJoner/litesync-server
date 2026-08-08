// Package sync 实现同步核心逻辑：revision 校验、内容寻址存储、元数据事务与版本历史。
//
// v4 存储模型：Blob Store 是唯一内容存储（内容寻址、不可变、去重）。
// files 表的 content_hash 指向当前 HEAD blob，file_versions 指向历史 blob，
// HEAD 不再单独保存一份物理文件（旧部署由启动迁移自动收编，读取带回退兼容）。
package sync

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	gosync "sync"
	"time"

	"obsync/internal/db"
	"obsync/internal/storage"
)

var (
	ErrNotFound       = errors.New("file not found")
	ErrVaultKeyExists = errors.New("vault key already exists")
)

const (
	vaultKeyMetaKey  = "vault-key"
	watermarkMetaKey = "changes-watermark" // 已裁剪到的 sequence（含）
)

// ConflictError 表示 baseRevision 与服务器当前 revision 不一致。
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
	// ResyncRequired：客户端游标早于已裁剪的水位线，必须走 snapshot 全量对账
	ResyncRequired bool
	MinSequence    int64
}

// Options 控制历史保留与资源治理（v4）。
type Options struct {
	HistoryEnabled    bool
	HistoryDays       int // Markdown 历史保留天数（0 = 不限）
	HistoryMaxPerFile int // Markdown 每文件版本数（0 = 不限）

	HistoryAttachmentDays int   // 附件历史保留天数
	HistoryAttachmentMax  int   // 附件每文件版本数
	HistoryMaxBytes       int64 // 非 HEAD 历史总字节硬上限（0 = 不限）

	ChangesDays int // changes 保留天数（0 = 不裁剪）
	ChangesMax  int // changes 最大行数（0 = 不限）
}

type Service struct {
	// 单用户场景：互斥锁串行化元数据写；v4 起收流与哈希在锁外完成，
	// 大文件慢速上传不再阻塞其他请求。
	mu     gosync.Mutex
	db     *sql.DB
	store  *storage.Storage // 旧版 vault 文件目录（仅迁移与读取回退用）
	blobs  *storage.BlobStore
	shares *storage.ShareStore
	opts   Options
	log    *slog.Logger
}

func New(database *sql.DB, store *storage.Storage, blobs *storage.BlobStore, shares *storage.ShareStore, opts Options, logger *slog.Logger) *Service {
	return &Service{db: database, store: store, blobs: blobs, shares: shares, opts: opts, log: logger}
}

func validAction(action string) bool {
	switch action {
	case "upsert", "merge", "restore":
		return true
	}
	return false
}

// isMarkdownPath 决定历史保留策略分类（Markdown 历史同时是三方合并的 merge-base）。
func isMarkdownPath(path string) bool {
	p := strings.ToLower(path)
	return strings.HasSuffix(p, ".md") || strings.HasSuffix(p, ".txt")
}

// retentionFor 返回该路径适用的（保留天数, 版本数上限）。
func (s *Service) retentionFor(path string) (days, maxPerFile int) {
	if isMarkdownPath(path) {
		return s.opts.HistoryDays, s.opts.HistoryMaxPerFile
	}
	return s.opts.HistoryAttachmentDays, s.opts.HistoryAttachmentMax
}

// Upload 处理文件上传。
// v4 流程：收流 + SHA-256（锁外）→ 加锁 → revision 校验 → blob 原子提交 → SQLite 事务。
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

	// 锁外：接收 body、落临时文件、计算 hash（慢速网络不影响其他请求）
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
	if actualHash != claimedHash {
		return nil, storage.ErrHashMismatch
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cur, err := db.GetFile(s.db, path)
	if err != nil {
		return nil, err
	}

	// 幂等：内容与服务器现状一致时直接成功（覆盖“重复提交同一个 change”场景）
	if cur != nil && !cur.Deleted && cur.ContentHash == claimedHash {
		seq, err := db.LastSequenceForPath(s.db, path)
		if err != nil {
			return nil, err
		}
		return &UploadResult{Path: path, Revision: cur.Revision, Hash: cur.ContentHash, Size: cur.Size, Sequence: seq}, nil
	}

	// revision 校验（数据安全红线）
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

	// blob 原子入库（同时充当 HEAD 与历史内容，单份存储）
	if err := s.blobs.Commit(tmp, actualHash); err != nil {
		return nil, err
	}
	committed = true

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
		days, maxPerFile := s.retentionFor(path)
		prunedBlobs, err = s.pruneVersionsTx(tx, path, now, days, maxPerFile)
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

// Delete 逻辑删除文件（tombstone）。内容 blob 由历史保留与孤儿 GC 治理，这里不动磁盘。
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
	if cur.Deleted {
		seq, err := db.LastSequenceForPath(s.db, path)
		if err != nil {
			return nil, err
		}
		return &DeleteResult{Path: path, Revision: cur.Revision, Sequence: seq}, nil
	}
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

	// 迁移前的旧 vault 物理文件（如仍存在）顺手清理
	if err := s.store.Remove(path); err != nil {
		s.log.Debug("legacy vault file cleanup", "path", path, "error", err)
	}

	return &DeleteResult{Path: path, Revision: newRevision, Sequence: seq}, nil
}

// OpenFile 返回文件元数据和内容读取器（blob 优先，旧部署回退 vault 文件）。
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
	if f, err := s.blobs.Open(cur.ContentHash); err == nil {
		return cur, f, nil
	}
	// 迁移前的旧部署：内容还在 vault 目录
	f, err := s.store.Open(path)
	if err != nil {
		s.log.Error("content missing in both blob store and vault dir", "path", path)
		return nil, nil, ErrNotFound
	}
	return cur, f, nil
}

// MigrateHeadToBlobs 把旧版 vault 目录中的 HEAD 文件收编进 blob store（幂等，启动时调用）。
// 验证通过后删除 vault 物理文件，消除双份存储。
func (s *Service) MigrateHeadToBlobs() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	files, err := db.ListFiles(s.db)
	if err != nil {
		return err
	}
	migrated := 0
	for i := range files {
		f := &files[i]
		if s.blobs.Has(f.ContentHash) {
			// blob 已有（如历史 backfill 已复制）→ 直接清理旧物理文件
			if err := s.store.Remove(f.Path); err == nil {
				migrated++
			}
			continue
		}
		src, err := s.store.Open(f.Path)
		if err != nil {
			continue // 旧文件不存在（全新部署）
		}
		err = s.blobs.PutReader(f.ContentHash, src)
		src.Close()
		if err != nil {
			s.log.Warn("head migration: blob write failed, keeping vault file", "path", f.Path, "error", err)
			continue
		}
		if err := s.store.Remove(f.Path); err != nil {
			s.log.Warn("head migration: vault file cleanup failed", "path", f.Path, "error", err)
		}
		migrated++
	}
	if migrated > 0 {
		s.log.Info("head migration: vault files absorbed into blob store", "count", migrated)
	}
	return nil
}

// History / OpenVersion --------------------------------------------------

func (s *Service) History(path string) ([]db.FileVersion, error) {
	if err := storage.ValidatePath(path); err != nil {
		return nil, err
	}
	return db.ListVersions(s.db, path)
}

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

// Changes -----------------------------------------------------------------

// Changes 返回 since 之后的变更；since 早于裁剪水位线时要求客户端走 snapshot 对账。
func (s *Service) Changes(since, limit int64) (*ChangesResult, error) {
	watermark, err := s.changesWatermark()
	if err != nil {
		return nil, err
	}
	latest, err := db.LatestSequence(s.db)
	if err != nil {
		return nil, err
	}
	if since < watermark {
		return &ChangesResult{LatestSequence: latest, ResyncRequired: true, MinSequence: watermark}, nil
	}
	changes, err := db.ListChanges(s.db, since, limit)
	if err != nil {
		return nil, err
	}
	// latest 需要重取一次以覆盖 List 期间的新写入导致的 hasMore 误判？
	// 这里保持先取 latest：若期间有新写入，客户端下轮拉取自然补齐。
	hasMore := len(changes) > 0 && changes[len(changes)-1].Sequence < latest
	return &ChangesResult{LatestSequence: latest, HasMore: hasMore, Changes: changes}, nil
}

func (s *Service) changesWatermark() (int64, error) {
	v, ok, err := db.GetMeta(s.db, watermarkMetaKey)
	if err != nil || !ok {
		return 0, err
	}
	var n int64
	fmt.Sscanf(v, "%d", &n) //nolint:errcheck
	return n, nil
}

func (s *Service) LatestSequence() (int64, error) {
	return db.LatestSequence(s.db)
}

// Snapshot 返回当前所有未删除文件的元数据与最新 sequence。
func (s *Service) Snapshot() (int64, []db.File, error) {
	files, err := db.ListFiles(s.db)
	if err != nil {
		return 0, nil, err
	}
	latest, err := db.LatestSequence(s.db)
	if err != nil {
		return 0, nil, err
	}
	return latest, files, nil
}

// Shares ------------------------------------------------------------------

func (s *Service) CreateShare(name string, expiresAt int64, body io.Reader) (*db.Share, error) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idBytes)

	size, err := s.shares.Put(id, body)
	if err != nil {
		return nil, err
	}
	share := &db.Share{
		ID:        id,
		Name:      name,
		Size:      size,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now().Unix(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := db.InsertShare(s.db, share); err != nil {
		s.shares.Remove(id) //nolint:errcheck
		return nil, err
	}
	return share, nil
}

func (s *Service) ListShares() ([]db.Share, error) {
	return db.ListShares(s.db)
}

func (s *Service) RevokeShare(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	share, err := db.GetShare(s.db, id)
	if err != nil {
		return err
	}
	if share == nil {
		return ErrNotFound
	}
	if err := db.MarkShareRevoked(s.db, id); err != nil {
		return err
	}
	if err := s.shares.Remove(id); err != nil {
		s.log.Warn("failed to remove share content", "id", id, "error", err)
	}
	return nil
}

func (s *Service) OpenShare(id string) (*db.Share, io.ReadCloser, error) {
	share, err := db.GetShare(s.db, id)
	if err != nil {
		return nil, nil, err
	}
	if share == nil || share.Revoked {
		return nil, nil, ErrNotFound
	}
	if share.ExpiresAt > 0 && time.Now().Unix() > share.ExpiresAt {
		s.shares.Remove(id) //nolint:errcheck
		return nil, nil, ErrNotFound
	}
	f, err := s.shares.Open(id)
	if err != nil {
		return nil, nil, ErrNotFound
	}
	return share, f, nil
}

// Vault key ---------------------------------------------------------------

func (s *Service) GetVaultKey() (string, error) {
	doc, ok, err := db.GetMeta(s.db, vaultKeyMetaKey)
	if err != nil || !ok {
		return "", err
	}
	return doc, nil
}

func (s *Service) SetVaultKey(doc string, replace bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists, err := db.GetMeta(s.db, vaultKeyMetaKey)
	if err != nil {
		return err
	}
	if exists && !replace {
		return ErrVaultKeyExists
	}
	return db.SetMeta(s.db, vaultKeyMetaKey, doc, time.Now().Unix())
}

// PruneHistoryBefore（E2EE 迁移用）：删除某路径 revision < before 的历史版本。
func (s *Service) PruneHistoryBefore(path string, before int64) (int, error) {
	if err := storage.ValidatePath(path); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	versions, err := db.ListVersions(s.db, path)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	var pruneBlobs []string
	removed := 0
	for i, v := range versions {
		if i == 0 || v.Revision >= before {
			continue
		}
		if _, err := tx.Exec(`DELETE FROM file_versions WHERE id = ?`, v.ID); err != nil {
			return 0, err
		}
		removed++
		if v.BlobID != "" {
			pruneBlobs = append(pruneBlobs, v.BlobID)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	s.gcBlobs(pruneBlobs)
	return removed, nil
}

// BackfillVersions 为升级前已存在、但还没有任何历史记录的文件补一条当前版本。
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
	type pending struct {
		path, hash                      string
		size, mtime, revision, updated int64
	}
	var todo []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.path, &p.hash, &p.size, &p.mtime, &p.revision, &p.updated); err != nil {
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
		if !s.blobs.Has(p.hash) {
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
		}
		if err := db.InsertVersion(s.db, &db.FileVersion{
			Path: p.path, Revision: p.revision, BlobID: p.hash, ContentHash: p.hash,
			Size: p.size, Mtime: p.mtime, Action: "upsert", DeviceID: "", CreatedAt: p.updated,
		}); err != nil {
			return err
		}
	}
	return nil
}

// 内部工具 -----------------------------------------------------------------

// pruneVersionsTx 按 retention 规则裁剪某路径历史（事务内），返回待 GC 的 blob。
// 最新版本永远保留。
func (s *Service) pruneVersionsTx(tx *sql.Tx, path string, now int64, days, maxPerFile int) ([]string, error) {
	if days <= 0 && maxPerFile <= 0 {
		return nil, nil
	}
	versions, err := db.ListVersions(tx, path) // revision 降序
	if err != nil {
		return nil, err
	}
	cutoff := int64(0)
	if days > 0 {
		cutoff = now - int64(days)*86400
	}
	var pruneBlobs []string
	for i, v := range versions {
		if i == 0 {
			continue
		}
		tooMany := maxPerFile > 0 && i >= maxPerFile
		tooOld := cutoff > 0 && v.CreatedAt < cutoff
		if tooMany || tooOld {
			if _, err := tx.Exec(`DELETE FROM file_versions WHERE id = ?`, v.ID); err != nil {
				return nil, err
			}
			if v.BlobID != "" {
				pruneBlobs = append(pruneBlobs, v.BlobID)
			}
		}
	}
	return pruneBlobs, nil
}

// gcBlobs 删除不再被引用的 blob（引用 = 任何历史版本 或 未删除文件的 HEAD）。
func (s *Service) gcBlobs(blobIDs []string) {
	seen := map[string]bool{}
	for _, id := range blobIDs {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ref, err := db.BlobReferenced(s.db, id)
		if err != nil {
			s.log.Warn("blob gc: reference query failed", "blob", id, "error", err)
			continue
		}
		if !ref {
			if err := s.blobs.Remove(id); err != nil {
				s.log.Warn("blob gc: remove failed", "blob", id, "error", err)
			}
		}
	}
}
