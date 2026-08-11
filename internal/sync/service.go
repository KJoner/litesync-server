// Package sync 实现同步核心逻辑：revision 校验、内容寻址存储、元数据事务与版本历史。
//
// v4 存储模型：Blob Store 是唯一内容存储（内容寻址、不可变、去重）。
// files 表的 content_hash 指向当前 HEAD blob，file_versions 指向历史 blob，
// HEAD 不再单独保存一份物理文件（旧部署由启动迁移自动收编，读取带回退兼容）。
package sync

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	gosync "sync"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
)

var (
	ErrNotFound       = errors.New("file not found")
	ErrVaultKeyExists = errors.New("vault key already exists")
	// ErrPlaintextRejected：E2EE migrating/encrypted 状态下拒绝非 LSE1 密文上传
	//（明文写冻结：旧设备不能在迁移中/迁移后把明文写回仓库）
	ErrPlaintextRejected = errors.New("plaintext upload rejected: vault encryption is enabled")
	// ErrVaultKeyCAS：vault key 替换时的 CAS 校验失败（fingerprint 不匹配或缺失）
	ErrVaultKeyCAS = errors.New("vault key fingerprint mismatch")
	// ErrEncryptionState：E2EE 状态机转换非法（如已 encrypted 再 begin）
	ErrEncryptionState = errors.New("invalid encryption state transition")
)

const vaultKeyMetaKey = "vault-key"

// lse1Magic：LiteSync 加密文件格式头（客户端 crypto.ts 同源常量）。
var lse1Magic = []byte{0x4c, 0x53, 0x45, 0x31} // "LSE1"

// PathCollisionError：新路径与现有未删除路径在大小写/Unicode 归一化后冲突。
type PathCollisionError struct {
	Path     string
	Existing string
}

func (e *PathCollisionError) Error() string {
	return fmt.Sprintf("path %q collides with existing file %q on case-insensitive filesystems", e.Path, e.Existing)
}

// ConflictError 表示 baseRevision 与服务器当前 revision 不一致。
type ConflictError struct {
	Path     string
	Revision int64
	Hash     string
	Deleted  bool
	// PriorHash：tombstone 冲突时删除前最后一个版本的内容 hash，
	// 客户端用它识别「陈旧副本复活」与「同名新内容重建」
	PriorHash string
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
	RepoEpoch      string
	LatestSequence int64 // = repo_state.head_sequence（与响应内容同一事务读出）
	HasMore        bool
	Changes        []db.Change
	// ResyncRequired：客户端游标早于已裁剪的水位线，必须走 snapshot 全量对账
	ResyncRequired bool
	MinSequence    int64
}

// SnapshotResult：与 sequence 严格对应同一时刻状态的全量快照。
type SnapshotResult struct {
	RepoEpoch string
	Sequence  int64
	Files     []db.File
}

// RepoInfo：/api/v1/info 的仓库权威信息（单锁内一致读出）。
type RepoInfo struct {
	VaultID         string
	RepoEpoch       string
	HeadSequence    int64
	EncryptionState string
	KeyEpoch        int64
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

	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	// E2EE 明文写冻结（v9）：migrating/encrypted 状态下所有内容必须是 LSE1 密文，
	// 旧设备无法在迁移中或迁移后把明文静默写回仓库
	if rs.EncryptionState != db.EncryptionPlaintext && !fileHasMagic(tmp, lse1Magic) {
		return nil, ErrPlaintextRejected
	}

	cur, err := db.GetFile(s.db, path)
	if err != nil {
		return nil, err
	}

	// 幂等：内容与服务器现状一致时直接成功（覆盖“重复提交同一个 change”场景）
	if cur != nil && !cur.Deleted && cur.ContentHash == claimedHash {
		return &UploadResult{Path: path, Revision: cur.Revision, Hash: cur.ContentHash, Size: cur.Size, Sequence: rs.HeadSequence}, nil
	}

	// revision 校验（数据安全红线）
	switch {
	case cur == nil:
		if baseRevision != 0 {
			return nil, &ConflictError{Path: path, Revision: 0}
		}
		// 跨平台路径碰撞（v9）：与现有未删除路径大小写/NFC 归一化后相同 → 拒绝并存
		if other, err := db.FindCanonicalCollision(s.db, storage.CanonicalKey(path), path); err != nil {
			return nil, err
		} else if other != "" {
			return nil, &PathCollisionError{Path: path, Existing: other}
		}
	case cur.Deleted:
		// tombstone 防复活（v9）：baseRevision=0 不再允许穿透墓碑——
		// 客户端必须显式基于 tombstone revision 重建（并自行核对 priorHash，
		// 陈旧副本回传与「同名新内容」由客户端据此区分）
		if baseRevision != cur.Revision {
			prior, perr := db.PriorContentHash(s.db, path)
			if perr != nil {
				return nil, perr
			}
			return nil, &ConflictError{Path: path, Revision: cur.Revision, Hash: cur.ContentHash, Deleted: true, PriorHash: prior}
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
		Path:         path,
		ContentHash:  actualHash,
		Size:         size,
		Mtime:        mtime,
		Revision:     newRevision,
		Deleted:      false,
		CreatedAt:    createdAt,
		UpdatedAt:    now,
		CanonicalKey: storage.CanonicalKey(path),
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
// v9：全程持 s.mu（所有写入方都持同一把锁），epoch/head/水位线/changes 是同一
// 时刻的一致读——绝不返回「与内容不对应的 sequence」。
func (s *Service) Changes(since, limit int64) (*ChangesResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if since < rs.MinRetainedSequence {
		return &ChangesResult{
			RepoEpoch:      rs.RepoEpoch,
			LatestSequence: rs.HeadSequence,
			ResyncRequired: true,
			MinSequence:    rs.MinRetainedSequence,
		}, nil
	}
	changes, err := db.ListChanges(s.db, since, limit)
	if err != nil {
		return nil, err
	}
	hasMore := len(changes) > 0 && changes[len(changes)-1].Sequence < rs.HeadSequence
	return &ChangesResult{RepoEpoch: rs.RepoEpoch, LatestSequence: rs.HeadSequence, HasMore: hasMore, Changes: changes}, nil
}

// LatestSequence 返回权威 head_sequence（repo_state，不再依赖可裁剪的 changes 表）。
func (s *Service) LatestSequence() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return 0, err
	}
	return rs.HeadSequence, nil
}

// RepoInfo 返回 /api/v1/info 所需的仓库权威信息（单锁内一致读出）。
func (s *Service) RepoInfo() (*RepoInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vaultID, err := s.vaultIDLocked()
	if err != nil {
		return nil, err
	}
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	return &RepoInfo{
		VaultID:         vaultID,
		RepoEpoch:       rs.RepoEpoch,
		HeadSequence:    rs.HeadSequence,
		EncryptionState: rs.EncryptionState,
		KeyEpoch:        rs.KeyEpoch,
	}, nil
}

// WithGlobalLock 短暂持有全局写锁执行 fn（备份一致性快照用）：
// fn 执行期间没有任何元数据写入与 blob GC，保证快照内部一致。
func (s *Service) WithGlobalLock(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn()
}

// Snapshot 返回当前所有未删除文件的元数据与最新 sequence。
// v9：持 s.mu 保证文件列表与 sequence 严格对应同一时刻——修复
// 「ListFiles 与 LatestSequence 之间的写入使客户端游标跳过一次变更」的漏同步。
func (s *Service) Snapshot() (*SnapshotResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	files, err := db.ListFiles(s.db)
	if err != nil {
		return nil, err
	}
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	return &SnapshotResult{RepoEpoch: rs.RepoEpoch, Sequence: rs.HeadSequence, Files: files}, nil
}

// E2EE 状态机（v9）---------------------------------------------------------
//
// plaintext → (Begin) → migrating → (Complete，全部 HEAD 验证为密文) → encrypted
// migrating/encrypted 状态下 Upload 拒绝非 LSE1 内容（明文写冻结）。

// BeginE2eeMigration 进入迁移状态并冻结明文写；重复调用幂等（断点续传）。
func (s *Service) BeginE2eeMigration() (*db.RepoState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	switch rs.EncryptionState {
	case db.EncryptionMigrating:
		return rs, nil // 幂等：迁移中断后重新执行
	case db.EncryptionEncrypted:
		return nil, ErrEncryptionState
	}
	if err := db.SetEncryptionState(s.db, db.EncryptionMigrating, true); err != nil {
		return nil, err
	}
	return db.GetRepoState(s.db)
}

// CompleteE2eeMigration 验证所有未删除 HEAD 均为 LSE1 密文后切换到 encrypted。
// 任何一个 HEAD 仍是明文都拒绝完成——绝不允许「标记已加密但仓库里还有明文」。
func (s *Service) CompleteE2eeMigration() (*db.RepoState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if rs.EncryptionState != db.EncryptionMigrating {
		return nil, ErrEncryptionState
	}
	files, err := db.ListFiles(s.db)
	if err != nil {
		return nil, err
	}
	for i := range files {
		f, err := s.blobs.Open(files[i].ContentHash)
		if err != nil {
			return nil, fmt.Errorf("verify %q: blob missing: %w", files[i].Path, err)
		}
		head := make([]byte, len(lse1Magic))
		_, rerr := io.ReadFull(f, head)
		f.Close()
		if rerr != nil || !bytes.Equal(head, lse1Magic) {
			return nil, fmt.Errorf("%w: %q is not encrypted", ErrEncryptionState, files[i].Path)
		}
	}
	if err := db.SetEncryptionState(s.db, db.EncryptionEncrypted, false); err != nil {
		return nil, err
	}
	return db.GetRepoState(s.db)
}

// AbortE2eeMigration 放弃迁移，回到 plaintext（仅 migrating 状态下允许）。
func (s *Service) AbortE2eeMigration() (*db.RepoState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if rs.EncryptionState != db.EncryptionMigrating {
		return nil, ErrEncryptionState
	}
	if err := db.SetEncryptionState(s.db, db.EncryptionPlaintext, false); err != nil {
		return nil, err
	}
	return db.GetRepoState(s.db)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// fileHasMagic 检查磁盘文件是否以 magic 开头（E2EE 明文冻结用）。
func fileHasMagic(path string, magic []byte) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, len(magic))
	if _, err := io.ReadFull(f, head); err != nil {
		return false
	}
	return bytes.Equal(head, magic)
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

// VaultKeyFingerprint 计算 key 文档的指纹（CAS 用；空文档返回 ""）。
func VaultKeyFingerprint(doc string) string {
	if doc == "" {
		return ""
	}
	sum := sha256Hex([]byte(doc))
	return sum
}

// SetVaultKey 保存 vault key 文档。
// v9 CAS：replace=true 时必须携带当前文档的指纹（expectedFingerprint），
// 不匹配返回 ErrVaultKeyCAS——防止并发迁移/误操作无条件覆盖导致密文永久不可读。
func (s *Service) SetVaultKey(doc string, replace bool, expectedFingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, exists, err := db.GetMeta(s.db, vaultKeyMetaKey)
	if err != nil {
		return err
	}
	if exists {
		if !replace {
			return ErrVaultKeyExists
		}
		if expectedFingerprint == "" || expectedFingerprint != VaultKeyFingerprint(cur) {
			return ErrVaultKeyCAS
		}
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

// BackfillCanonicalKeys 为旧库行补 canonical_key（幂等，启动时调用）。
// 已存在的归一化碰撞只告警不中断——历史数据保留，新增碰撞由上传路径拒绝。
func (s *Service) BackfillCanonicalKeys() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT path FROM files WHERE canonical_key = ''`)
	if err != nil {
		return err
	}
	var paths []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return err
		}
		paths = append(paths, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, p := range paths {
		if _, err := s.db.Exec(`UPDATE files SET canonical_key = ? WHERE path = ?`, storage.CanonicalKey(p), p); err != nil {
			return err
		}
	}
	if len(paths) > 0 {
		s.log.Info("canonical key backfill", "count", len(paths))
	}
	// 已存在的碰撞检查（只告警）
	dup, err := s.db.Query(
		`SELECT canonical_key, COUNT(*) FROM files WHERE deleted = 0 GROUP BY canonical_key HAVING COUNT(*) > 1`)
	if err != nil {
		return err
	}
	defer dup.Close()
	for dup.Next() {
		var key string
		var n int
		if err := dup.Scan(&key, &n); err != nil {
			return err
		}
		s.log.Warn("existing path collision (case/normalization); these files may overwrite each other on Windows/macOS",
			"canonicalKey", key, "count", n)
	}
	return dup.Err()
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
