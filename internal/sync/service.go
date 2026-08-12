// Package sync 实现同步核心逻辑（协议 v6）。
//
// v6 的核心变化（ADR-001）：**身份与展示名彻底分离**。
//   - 所有数据表以 file_id 为主键；pseudonym 只是服务器可见的寻址名
//     （plain 模式 = 真实路径，meta-encrypted 模式 = file_id）
//   - revision 属于对象，跨改名 / 元数据迁移 / 删除恢复连续递增
//   - 删除进入独立的 tombstones 台账（ADR-002），绝不删行
//   - 改名与元数据迁移退化为一次元数据更新，不再产生 tombstone
//
// 存储模型不变：Blob Store 是唯一内容存储（内容寻址、不可变、去重），
// file_heads.blob_id 指向当前 HEAD，object_versions.blob_id 指向历史。
package sync

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	gosync "sync"
	"sync/atomic"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/failpoint"
	"github.com/KJoner/litesync-server/internal/storage"
)

var (
	ErrNotFound       = errors.New("file not found")
	ErrVaultKeyExists = errors.New("vault key already exists")
	// ErrPlaintextRejected：E2EE migrating/encrypted 状态下拒绝明文上传
	//（明文写冻结：旧设备不能在迁移中/迁移后把明文写回仓库）
	ErrPlaintextRejected = errors.New("plaintext upload rejected: vault encryption is enabled")
	// ErrVaultKeyCAS：vault key 替换时的 CAS 校验失败（fingerprint 不匹配或缺失）
	ErrVaultKeyCAS = errors.New("vault key fingerprint mismatch")
	// ErrEncryptionState：加密/元数据状态机转换非法
	ErrEncryptionState = errors.New("invalid encryption state transition")
	// ErrMetaRequired（meta-encrypted 态）：路径必须是伪名（=fileId）且建档必须携带
	// 加密元数据与 canonical HMAC——任何明文路径都无法再进入仓库
	ErrMetaRequired = errors.New("metadata encryption is enabled: pseudonymous path and encrypted metadata required")
	// ErrMetaCAS：元数据更新的 metaGeneration CAS 失败（并发改名）
	ErrMetaCAS = errors.New("metadata generation mismatch")
	// ErrEnvelopeTooOld（ADR-006）：写入的信封版本低于仓库级下限。
	// 信封只许升级不许降级（INV-07）——一次降级写入就会让 fileId-AAD 与
	// contentGeneration 抗回退保护失效
	ErrEnvelopeTooOld = errors.New("envelope version is below the repository minimum")
	// ErrFileIDConflict：客户端预生成的 fileId 已被占用
	ErrFileIDConflict = errors.New("file id already in use")
	// ErrTombstonePlaintext（ADR-002）：仍有携带明文寻址名的 tombstone
	ErrTombstonePlaintext = errors.New("plaintext tombstones present: convert them before erasing paths")
	// ErrTombstonePurged：tombstone 已被合法清理，无法按 restore 语义恢复
	ErrTombstonePurged = errors.New("tombstone has been purged; explicit recovery required")
	// ErrStaleRevision：restore 的 expectedTombstoneRevision 与台账不符
	ErrStaleRevision = errors.New("stale revision")
	// ErrFormatEpoch（ADR-006）：客户端携带的 formatEpoch 与仓库不符
	ErrFormatEpoch = errors.New("format epoch mismatch")
	// ErrUpgradeRequired：旧协议客户端在 formatEpoch > 1 的仓库上尝试写入
	ErrUpgradeRequired = errors.New("client upgrade required")
	// ErrRepoEpoch（计划书 §5.3）：客户端携带的 repoEpoch 与仓库不符——
	// 服务器从备份恢复过，该客户端的游标与 baseRevision 全部作废
	ErrRepoEpoch = errors.New("repo epoch mismatch")
	// ErrKeyEpoch：客户端携带的 keyEpoch 与仓库不符（密钥世代已轮换）
	ErrKeyEpoch = errors.New("key epoch mismatch")
	// ErrCorrupted（v0.13.3 / §7.2）：该内容已被判定损坏并隔离，不再对外返回。
	// 与 NotFound 分开是有意的：客户端必须能区分「服务器上没有」和
	// 「服务器上有但坏了」——后者绝不能触发本地的删除跟随
	ErrCorrupted = errors.New("content failed integrity verification and is quarantined")
	// ErrMigrationNotOwner：非 owner 设备试图推进迁移
	ErrMigrationNotOwner = errors.New("only the migration owner may perform this action")
	// ErrLeaseActive：租约仍然有效，不允许接管
	ErrLeaseActive = errors.New("migration lease is still active")
	// ErrMigrationLocked：另一台设备持有未过期的迁移租约
	ErrMigrationLocked = errors.New("another migration is in progress")
	// ErrMigrationIncomplete：journal 中仍有未完成条目
	ErrMigrationIncomplete = errors.New("migration journal still has unfinished entries")
	// ErrMigrationMismatch：complete 携带的 migrationId 与当前迁移不符
	ErrMigrationMismatch = errors.New("migration id mismatch")
)

// 协议版本（插件与服务器独立发版，兼容性由区间判定）。
// 定义在服务层：逐请求校验（计划书 §5.3）发生在这里，api 层只做转发。
//
// v2（v9 一阶段）：repoEpoch/headSequence、tombstone 拒绝 base 0、
// E2EE 状态机与明文冻结、vault-key CAS。
// v3（v9 二阶段）：设备级凭据与配对包 v2、LSE2 加密信封。
// v4（v9 三阶段二期）：LSE3 信封（fileId-AAD + contentGeneration 抗回退重放）。
// v5（v9 三阶段三期）：元数据加密——伪名路径 + LSM1 加密元数据。
// v6（v10 阶段 1）：fileId 为主键的对象模型、隐私 tombstone 与显式 restore、
// 四态迁移状态机、仓库级 minimumEnvelopeVersion 与 formatEpoch。
const (
	ProtocolVersion    = 6
	MinProtocolVersion = 6
)

const vaultKeyMetaKey = "vault-key"

// LiteSync 加密文件格式头（客户端 crypto.ts 同源常量）。
// LSE1：AAD 仅绑定 path；LSE2：AAD 绑定 vaultId+keyEpoch+path；
// LSE3：AAD 绑定 vaultId+keyEpoch+fileId+contentGeneration——路径不入 AAD，
// E2EE 下改名无需重新加密；generation 单调，抗回退重放。
var (
	lse1Magic = []byte{0x4c, 0x53, 0x45, 0x31} // "LSE1"
	lse2Magic = []byte{0x4c, 0x53, 0x45, 0x32} // "LSE2"
	lse3Magic = []byte{0x4c, 0x53, 0x45, 0x33} // "LSE3"
)

// envelopeVersion 返回内容的信封版本：1/2/3；非 LSE 内容返回 0。
func envelopeVersion(head []byte) int64 {
	switch {
	case bytes.Equal(head, lse3Magic):
		return 3
	case bytes.Equal(head, lse2Magic):
		return 2
	case bytes.Equal(head, lse1Magic):
		return 1
	default:
		return 0
	}
}

// PathCollisionError：新路径与现有 live 对象在归一化后冲突。
type PathCollisionError struct {
	Path     string
	Existing string
}

func (e *PathCollisionError) Error() string {
	return fmt.Sprintf("path %q collides with existing object %q", e.Path, e.Existing)
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
	// FileID：冲突对象的稳定身份（客户端据此走 restore 而不是新建）
	FileID string
	// ContentGeneration：tombstone 冲突时删除时的内容世代——
	// 客户端 restore 必须提交严格大于它的世代（抗回退），因此必须告诉它
	ContentGeneration int64
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("revision conflict on %q (server revision %d)", e.Path, e.Revision)
}

type UploadResult struct {
	Path              string
	Revision          int64
	Hash              string
	Size              int64
	Sequence          int64
	FileID            string
	ContentGeneration int64
	MetaGeneration    int64
}

type DeleteResult struct {
	Path     string
	Revision int64
	Sequence int64
	FileID   string
}

type ChangesResult struct {
	RepoEpoch      string
	FormatEpoch    int64
	LatestSequence int64 // = repo_state.head_sequence（与响应内容同一事务读出）
	HasMore        bool
	Changes        []db.ObjectChange
	// ResyncRequired：客户端游标早于已裁剪的水位线，必须走 snapshot 全量对账
	ResyncRequired bool
	MinSequence    int64
}

// SnapshotResult：与 sequence 严格对应同一时刻状态的全量快照。
type SnapshotResult struct {
	RepoEpoch   string
	FormatEpoch int64
	Sequence    int64
	Objects     []db.ObjectHead
}

// RepoInfo：/api/v1/info 的仓库权威信息（单锁内一致读出）。
type RepoInfo struct {
	VaultID                string
	RepoEpoch              string
	HeadSequence           int64
	EncryptionState        string
	KeyEpoch               int64
	MetaState              string
	FormatEpoch            int64
	MinimumEnvelopeVersion int64
	SchemaVersion          int64
	MigrationID            string
	MigrationOwnerDeviceID string
}

// Options 控制历史保留与资源治理。
type Options struct {
	HistoryEnabled    bool
	HistoryDays       int // Markdown 历史保留天数（0 = 不限）
	HistoryMaxPerFile int // Markdown 每文件版本数（0 = 不限）

	HistoryAttachmentDays int   // 附件历史保留天数
	HistoryAttachmentMax  int   // 附件每文件版本数
	HistoryMaxBytes       int64 // 非 HEAD 历史总字节硬上限（0 = 不限）

	ChangesDays int // changes 保留天数（0 = 不裁剪）
	ChangesMax  int // changes 最大行数（0 = 不限）

	// TombstoneRetentionDays（ADR-002 §3.4）：0 = 永久保留（默认）。
	// 即使设置了期限，清理仍需「所有未撤销设备都已确认越过删除点」这第二个条件。
	TombstoneRetentionDays int

	// StrictBlobVerify（v0.13.3 / §7.1）：去重命中时全量重算现有 blob 的 hash。
	// 能抓到位腐坏，但每次命中都要完整读一遍文件——大附件仓库上会明显变慢，
	// 因此默认关闭，由管理员按存储介质的可靠性决定。
	StrictBlobVerify bool

	// QuarantineRetentionDays（§7.3）：隔离区独立清理策略。0 = 永久保留。
	// 隔离区里的东西不参与普通 GC——它们是取证材料，不是垃圾。
	QuarantineRetentionDays int
}

type Service struct {
	// 单用户场景：互斥锁串行化元数据写；收流与哈希在锁外完成，
	// 大文件慢速上传不再阻塞其他请求。
	mu gosync.Mutex
	// busyOps（v0.13.3 / §7.3）：正在进行的 scrub / backup 数量。
	// 大于 0 时整轮 GC 跳过——这两者都在读一份「某一时刻的全量视图」，
	// 中途删文件会让它们得出错误结论（假的 missing、不一致的备份）。
	busyOps atomic.Int32
	db      *sql.DB
	store   *storage.Storage // 旧版 vault 文件目录（仅读取回退用）
	blobs   *storage.BlobStore
	shares  *storage.ShareStore
	opts    Options
	log     *slog.Logger
	// blobID 域分隔密钥（§10.3）。只加载一次并缓存：换掉它会让去重失效。
	secretOnce gosync.Once
	secret     []byte
	secretErr  error
	// access token 的签名密钥（§10.5）。与上面的 blobID 密钥刻意分开：
	// 共用一把会让「轮换签名密钥」这种日常运维动作顺带把所有 blob 的名字算错。
	tokenSecretOnce gosync.Once
	tokenSecret     []byte
	tokenSecretErr  error
}

// vaultSecret 惰性加载本 Vault 的 blobID 域分隔密钥。
//
// 注意：它会读/写数据库，因此**不能在事务里调用**（单连接下会死锁）。
// 正常路径上 InitVaultSecret 已经在启动时把它填好了。
func (s *Service) vaultSecret() ([]byte, error) {
	s.secretOnce.Do(func() {
		s.secret, s.secretErr = db.EnsureVaultSecret(s.db, s.scope(), db.DefaultVaultID)
	})
	return s.secret, s.secretErr
}

// InitVaultSecret 在启动时预热密钥，让请求路径上永远走不到惰性加载。
func (s *Service) InitVaultSecret() error {
	_, err := s.vaultSecret()
	return err
}

// blobIDOf 把内容哈希映射成本 Vault 的存储 id（§10.3）。
//
// 空哈希返回空——「没有内容」和「内容的 id」是两回事，
// 对空串做 HMAC 会得到一个指向不存在文件的合法 id。
func (s *Service) blobIDOf(contentHash string) (string, error) {
	if contentHash == "" {
		return "", nil
	}
	secret, err := s.vaultSecret()
	if err != nil {
		return "", err
	}
	return storage.BlobIDFor(secret, contentHash), nil
}

func New(database *sql.DB, store *storage.Storage, blobs *storage.BlobStore, shares *storage.ShareStore, opts Options, logger *slog.Logger) *Service {
	return &Service{db: database, store: store, blobs: blobs, shares: shares, opts: opts, log: logger}
}

// BlobProbe 让 db 包在不反向依赖 storage 的前提下读取信封信息（v5 → v6 迁移用）。
func (s *Service) BlobProbe() db.BlobProbe { return blobProbe{s} }

type blobProbe struct{ s *Service }

func (p blobProbe) Has(hash string) bool { return p.s.blobs.Has(hash) }

func (p blobProbe) EnvelopeVersion(hash string) int64 { return p.s.envelopeVersionOfBlob(hash) }

func (p blobProbe) ContentGeneration(hash string) (int64, bool) {
	h, ok := p.s.lse3HeaderOfBlob(hash)
	if !ok {
		return 0, false
	}
	return h.generation, true
}

func (p blobProbe) KeyEpoch(hash string) (int64, bool) {
	h, ok := p.s.lse3HeaderOfBlob(hash)
	if !ok {
		return 0, false
	}
	return h.keyEpoch, true
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

// retentionFor 返回该对象适用的（保留天数, 版本数上限）。
//
// meta-encrypted 态下服务器只看得到伪名，**无法**再按后缀判断 Markdown 还是附件
// （v10 计划 §4.6）。按伪名猜测会把笔记误判为附件、把三方合并需要的 base version
// 提前裁掉。因此统一使用两种策略中**最长**的那一组，宁可多留。
func (s *Service) retentionFor(metaState, pseudonym string) (days, maxPerFile int) {
	if metaState == db.MetaEncrypted || metaState == db.MetaVerifying {
		return maxInt(s.opts.HistoryDays, s.opts.HistoryAttachmentDays),
			maxInt(s.opts.HistoryMaxPerFile, s.opts.HistoryAttachmentMax)
	}
	if isMarkdownPath(pseudonym) {
		return s.opts.HistoryDays, s.opts.HistoryMaxPerFile
	}
	return s.opts.HistoryAttachmentDays, s.opts.HistoryAttachmentMax
}

// maxInt：0 表示「不限」，因此 0 永远胜出。
func maxInt(a, b int) int {
	if a == 0 || b == 0 {
		return 0
	}
	if a > b {
		return a
	}
	return b
}

// ClientContext 是每个写请求都必须携带的协议/世代上下文（计划书 §5.3）。
//
// 逐请求校验而不是「会话首轮查一次」：服务器可能在两次请求之间从备份恢复
// （repoEpoch 变）、完成元数据迁移（formatEpoch 变）或轮换密钥（keyEpoch 变），
// 而客户端此刻仍拿着旧判断在写入。
type ClientContext struct {
	ProtocolVersion int64
	RepoEpoch       string
	FormatEpoch     int64
	KeyEpoch        int64
	OperationID     string
}

// UploadParams：上传参数。
type UploadParams struct {
	// Path 是服务器可见的寻址名（pseudonym）
	Path         string
	BaseRevision int64
	ClaimedHash  string
	Mtime        int64
	DeviceID     string
	Action       string
	// ClientFileID：E2EE 客户端为新对象预生成的稳定身份——
	// LSE3 密文的 AAD 绑定 fileId，必须在加密前确定
	ClientFileID string
	// MetaEnc：LSM1 加密元数据（真实路径等，base64）。meta-encrypted 态下建档必带
	MetaEnc string
	// CanonicalHash：客户端 HMAC 的 canonical 碰撞键
	CanonicalHash string
	// Client：逐请求协议/世代上下文（含幂等键）
	Client ClientContext
}

// Upload 处理内容上传。
// 流程：收流 + SHA-256（锁外）→ 加锁 → 状态/信封/revision 校验 → blob 原子提交 → SQLite 事务。
func (s *Service) Upload(p UploadParams, body io.Reader) (*UploadResult, error) {
	if err := storage.ValidatePath(p.Path); err != nil {
		return nil, err
	}
	if p.ClientFileID != "" && !isHex32(p.ClientFileID) {
		return nil, storage.ErrInvalidPath
	}
	action := p.Action
	if action == "" {
		action = "upsert"
	}
	if !validAction(action) {
		return nil, storage.ErrInvalidPath
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
	if actualHash != p.ClaimedHash {
		return nil, storage.ErrHashMismatch
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if err := s.guardWrite(rs, p.Client, p.DeviceID, p.Path); err != nil {
		return nil, err
	}

	env := envelopeVersionOfFile(tmp)
	// E2EE 明文写冻结：migrating/encrypted 状态下内容必须是 LSE 密文
	if rs.EncryptionState != db.EncryptionPlaintext && env == 0 {
		return nil, ErrPlaintextRejected
	}
	// 仓库级信封下限（ADR-006）：覆盖新建、更新、删除后重建的**全部**写入路径。
	// v0.12.1 只看「当前 HEAD 是否 LSE3」，挡不住新建与重建；这里在落库前统一校验。
	if env < rs.MinimumEnvelopeVersion {
		return nil, ErrEnvelopeTooOld
	}

	cur, err := db.GetHeadByPseudonym(s.db, p.Path)
	if err != nil {
		return nil, err
	}
	// 单对象降级冻结（v0.12.1 LS-121-S01 保留）：仓库下限还没提到 3 的仓库里，
	// 单个已经是 LSE3 的对象同样不允许被旧信封覆盖。两道检查互补——
	// 下限管「全仓库、含新建与重建」，这一条管「尚未提升下限时的既有对象」。
	if cur != nil && cur.EnvelopeVersion == 3 && env < 3 {
		return nil, ErrEnvelopeTooOld
	}

	// 元数据加密态：服务器可见 path 只能是 32-hex 伪名（=file_id），
	// 建档必须携带加密元数据与 canonical HMAC
	if rs.MetaState == db.MetaEncrypted || rs.MetaState == db.MetaVerifying {
		if !isHex32(p.Path) {
			return nil, ErrMetaRequired
		}
		if cur == nil {
			if p.MetaEnc == "" || p.CanonicalHash == "" {
				return nil, ErrMetaRequired
			}
			if p.ClientFileID != "" && p.ClientFileID != p.Path {
				return nil, ErrMetaRequired // 伪名约定：path 必须等于 fileId
			}
			p.ClientFileID = p.Path
		}
	}

	// 幂等 ①：内容与当前 HEAD 完全一致 → 直接成功（覆盖重复提交同一 change）
	if cur != nil && cur.ContentHash == actualHash {
		return &UploadResult{
			Path: p.Path, Revision: cur.Revision, Hash: cur.ContentHash, Size: cur.Size,
			Sequence: rs.HeadSequence, FileID: cur.FileID,
			ContentGeneration: cur.ContentGeneration, MetaGeneration: cur.MetaGeneration,
		}, nil
	}

	// 幂等 ②：同一 operationId 已经提交过 → 返回那次的结果，绝不产生第二个 revision
	if cur != nil && p.Client.OperationID != "" {
		if prev, err := db.FindChangeByOperation(s.db, cur.FileID, p.Client.OperationID); err != nil {
			return nil, err
		} else if prev != nil {
			return &UploadResult{
				Path: cur.Pseudonym, Revision: prev.Revision, Hash: prev.ContentHash, Size: cur.Size,
				Sequence: prev.Sequence, FileID: cur.FileID,
				ContentGeneration: prev.ContentGeneration, MetaGeneration: prev.MetaGeneration,
			}, nil
		}
	}

	newGen, hasGen := lse3GenerationFromFile(tmp)
	// LSE3 generation 单调性：信封头是明文，服务器无需密钥即可读。
	// 同一对象上 generation 不增反降 = 客户端状态异常或回退重放 → 按冲突拒绝
	if cur != nil && hasGen && cur.ContentGeneration > 0 && newGen <= cur.ContentGeneration {
		return nil, &ConflictError{Path: p.Path, Revision: cur.Revision, Hash: cur.ContentHash, FileID: cur.FileID}
	}

	// canonical 碰撞键：明文模式服务器计算；meta 模式用客户端 HMAC
	canonicalKey := storage.CanonicalKey(p.Path)
	if p.CanonicalHash != "" {
		canonicalKey = "h:" + p.CanonicalHash
	} else if cur != nil {
		canonicalKey = cur.CanonicalPathHmac
	}

	// revision 校验（数据安全红线）
	if cur == nil {
		// 防复活（ADR-002）必须**先于** baseRevision 判断：否则带着任意 base
		// 撞上墓碑的请求会拿到一个不含 deleted/priorHash/fileId 的空洞冲突，
		// 客户端无从判断「这是被删过的对象，要走 restore」
		if tomb, err := s.findTombstone(p.Path, canonicalKey); err != nil {
			return nil, err
		} else if tomb != nil {
			return nil, &ConflictError{
				Path: p.Path, Revision: tomb.DeletionRevision, Deleted: true,
				PriorHash: tomb.PriorContentHash, FileID: tomb.FileID,
				ContentGeneration: tomb.ContentGeneration,
			}
		}
		if p.BaseRevision != 0 {
			return nil, &ConflictError{Path: p.Path, Revision: 0}
		}
		// 跨平台路径碰撞：与现有 live 对象归一化后相同 → 拒绝并存
		if other, err := db.FindCanonicalCollision(s.db, canonicalKey, ""); err != nil {
			return nil, err
		} else if other != "" {
			return nil, &PathCollisionError{Path: p.Path, Existing: other}
		}
	} else if p.BaseRevision != cur.Revision {
		return nil, &ConflictError{Path: p.Path, Revision: cur.Revision, Hash: cur.ContentHash, FileID: cur.FileID}
	}

	now := time.Now().Unix()
	head := &db.ObjectHead{VaultID: db.DefaultVaultID}
	if cur != nil {
		*head = *cur
		head.Revision = cur.Revision + 1
	} else {
		fileID, err := s.resolveNewFileID(p.ClientFileID)
		if err != nil {
			return nil, err
		}
		head.FileID = fileID
		head.Revision = 1
		head.CreatedAt = now
		head.MetaGeneration = 0
		if p.MetaEnc != "" {
			head.EncryptedMetadata = p.MetaEnc
			head.MetaGeneration = 1
		}
	}
	if newGen > 0 {
		head.ContentGeneration = newGen
	} else if hasGen {
		head.ContentGeneration = newGen
	}
	blobID, err := s.blobIDOf(actualHash)
	if err != nil {
		return nil, err
	}
	head.BlobID = blobID
	head.ContentHash = actualHash
	head.Size = size
	head.Mtime = p.Mtime
	if head.Mtime <= 0 {
		head.Mtime = time.Now().UnixMilli()
	}
	head.Pseudonym = p.Path
	head.CanonicalPathHmac = canonicalKey
	head.EnvelopeVersion = env
	head.KeyEpoch = lse3KeyEpochOfFile(tmp)
	head.UpdatedAt = now

	// blob 原子入库（同时充当 HEAD 与历史内容，单份存储）。
	// §7.1：去重命中时校验现有副本；损坏则隔离旧副本、用这次校验过的内容替换
	commitRes, err := s.blobs.CommitAs(tmp, blobID, actualHash, s.opts.StrictBlobVerify)
	if err != nil {
		return nil, err
	}
	committed = true
	if commitRes.Repaired {
		s.recordBlobRepairLocked(blobID, commitRes)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	if err := db.UpsertObject(tx, head.FileID, db.ObjectLive, head.CreatedAt, 0); err != nil {
		return nil, err
	}
	if err := db.UpsertHead(tx, head); err != nil {
		return nil, err
	}
	seq, err := db.InsertChange(tx, &db.ObjectChange{
		FileID: head.FileID, Action: "upsert", Revision: head.Revision,
		ContentGeneration: head.ContentGeneration, MetaGeneration: head.MetaGeneration,
		Pseudonym: head.Pseudonym, ContentHash: actualHash, OperationID: p.Client.OperationID, CreatedAt: now,
	})
	if err != nil {
		return nil, err
	}

	var prunedBlobs []string
	if s.opts.HistoryEnabled {
		if err := db.InsertVersion(tx, &db.ObjectVersion{
			FileID: head.FileID, Revision: head.Revision, ContentGeneration: head.ContentGeneration,
			BlobID: blobID, ContentHash: actualHash, Size: size, Mtime: head.Mtime,
			Action: action, DeviceID: p.DeviceID, KeyEpoch: head.KeyEpoch,
			OperationID: p.Client.OperationID, CreatedAt: now,
		}); err != nil {
			return nil, err
		}
		days, maxPerFile := s.retentionFor(rs.MetaState, head.Pseudonym)
		prunedBlobs, err = s.pruneVersionsTx(tx, head.FileID, now, days, maxPerFile)
		if err != nil {
			return nil, err
		}
	}
	// §8.1 注入点：事务提交之前。此刻崩溃 → 事务回滚，blob 变成无引用孤儿，
	// 客户端拿到失败可以安全重试（同一个 operationId 与 fileId）
	if err := failpoint.Eval(failpoint.DBBeforeCommit); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	// §8.1 注入点：事务已提交、响应尚未返回。这是最难处理的窗口——
	// 服务器上数据已经生效，但客户端会看到失败并重试。
	// 重试必须靠 operationId 幂等收敛，而不是产生第二个 revision
	if err := failpoint.Eval(failpoint.DBAfterCommit); err != nil {
		return nil, err
	}
	s.gcBlobs(prunedBlobs)

	return &UploadResult{
		Path: head.Pseudonym, Revision: head.Revision, Hash: actualHash, Size: size,
		Sequence: seq, FileID: head.FileID,
		ContentGeneration: head.ContentGeneration, MetaGeneration: head.MetaGeneration,
	}, nil
}

// guardWrite 是所有写路径共用的前置校验（ADR-003 §3.4 / ADR-006 §2.3）。
func (s *Service) guardWrite(rs *db.RepoState, c ClientContext, deviceID, pseudonym string) error {
	// 协议版本：低于最低要求的客户端一律不得写入（计划书 §5.3）
	if c.ProtocolVersion != 0 && c.ProtocolVersion < MinProtocolVersion {
		return ErrUpgradeRequired
	}
	// 旧客户端写冻结：寻址格式已经变过，不带 formatEpoch 的写请求一律拒绝
	if rs.FormatEpoch > 1 && c.FormatEpoch == 0 {
		return ErrUpgradeRequired
	}
	if c.FormatEpoch != 0 && c.FormatEpoch != rs.FormatEpoch {
		return ErrFormatEpoch
	}
	// repoEpoch：客户端拿的是灾备恢复前的世代 → 它的 baseRevision / 游标全部作废，
	// 必须先走恢复合并；放行等于让它用旧世代的判断覆盖恢复后的内容
	if c.RepoEpoch != "" && c.RepoEpoch != rs.RepoEpoch {
		return ErrRepoEpoch
	}
	// keyEpoch：密钥世代不符说明客户端要写的密文用的是别的世代的密钥，
	// 写进去以后当前世代的设备都解不开
	if c.KeyEpoch != 0 && rs.KeyEpoch != 0 && c.KeyEpoch != rs.KeyEpoch {
		return ErrKeyEpoch
	}
	// 迁移期间的写入冻结：非 owner 只能写**已经伪名化**的对象——
	// 那不会把任何真实路径写回服务器；未伪名化的对象只有 owner 能动
	if rs.MetaState == db.MetaMigrating || rs.MetaState == db.MetaVerifying {
		if rs.MigrationOwnerDeviceID != "" && deviceID != rs.MigrationOwnerDeviceID && !isHex32(pseudonym) {
			return ErrMigrationLocked
		}
		if rs.MetaState == db.MetaVerifying && deviceID != rs.MigrationOwnerDeviceID {
			return ErrMigrationLocked
		}
	}
	return nil
}

// findTombstone 按寻址名或 canonical 键查删除记录（防复活判定）。
func (s *Service) findTombstone(pseudonym, canonicalKey string) (*db.Tombstone, error) {
	if t, err := db.GetTombstoneByPseudonym(s.db, pseudonym); err != nil || t != nil {
		return t, err
	}
	return db.GetTombstoneByCanonical(s.db, canonicalKey)
}

// resolveNewFileID 决定新对象的身份：客户端预生成优先（LSE3 的 AAD 必须在加密前确定）。
func (s *Service) resolveNewFileID(clientFileID string) (string, error) {
	if clientFileID != "" {
		used, err := db.FileIDInUse(s.db, clientFileID)
		if err != nil {
			return "", err
		}
		if used {
			return "", ErrFileIDConflict
		}
		return clientFileID, nil
	}
	for i := 0; i < 4; i++ {
		id, err := db.NewFileID()
		if err != nil {
			return "", err
		}
		used, err := db.FileIDInUse(s.db, id)
		if err != nil {
			return "", err
		}
		if !used {
			return id, nil
		}
	}
	return "", ErrFileIDConflict
}

// isHex32 校验 16 字节 hex 身份格式。
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

type lse3Header struct {
	keyEpoch   int64
	generation int64
}

// parseLse3Header 读取 LSE3 信封头：'LSE3'(4B) | keyEpoch u32 BE | generation u64 BE。
func parseLse3Header(r io.Reader) (lse3Header, bool) {
	head := make([]byte, 16)
	if _, err := io.ReadFull(r, head); err != nil {
		return lse3Header{}, false
	}
	if !bytes.Equal(head[:4], lse3Magic) {
		return lse3Header{}, false
	}
	return lse3Header{
		keyEpoch:   int64(binary.BigEndian.Uint32(head[4:8])),
		generation: int64(binary.BigEndian.Uint64(head[8:16])),
	}, true
}

func lse3HeaderOfFile(path string) (lse3Header, bool) {
	f, err := os.Open(path)
	if err != nil {
		return lse3Header{}, false
	}
	defer f.Close()
	return parseLse3Header(f)
}

func (s *Service) lse3HeaderOfBlob(hash string) (lse3Header, bool) {
	f, err := s.blobs.Open(hash)
	if err != nil {
		return lse3Header{}, false
	}
	defer f.Close()
	return parseLse3Header(f)
}

func lse3GenerationFromFile(path string) (int64, bool) {
	h, ok := lse3HeaderOfFile(path)
	return h.generation, ok
}

func lse3KeyEpochOfFile(path string) int64 {
	h, _ := lse3HeaderOfFile(path)
	return h.keyEpoch
}

func envelopeVersionOfFile(path string) int64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	head := make([]byte, 4)
	if _, err := io.ReadFull(f, head); err != nil {
		return 0
	}
	return envelopeVersion(head)
}

func (s *Service) envelopeVersionOfBlob(hash string) int64 {
	f, err := s.blobs.Open(hash)
	if err != nil {
		return 0
	}
	defer f.Close()
	head := make([]byte, 4)
	if _, err := io.ReadFull(f, head); err != nil {
		return 0
	}
	return envelopeVersion(head)
}

// DeleteParams：删除参数。
type DeleteParams struct {
	Path         string
	BaseRevision int64
	DeviceID     string
	Client       ClientContext
}

// Delete 删除对象：HEAD 行移入 tombstones 台账（ADR-002），历史版本保留（恢复仍可用）。
func (s *Service) Delete(p DeleteParams) (*DeleteResult, error) {
	if err := storage.ValidatePath(p.Path); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if err := s.guardWrite(rs, p.Client, p.DeviceID, p.Path); err != nil {
		return nil, err
	}

	cur, err := db.GetHeadByPseudonym(s.db, p.Path)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		// 幂等：已经删过了 → 返回 tombstone 的 revision
		if t, err := db.GetTombstoneByPseudonym(s.db, p.Path); err != nil {
			return nil, err
		} else if t != nil {
			return &DeleteResult{Path: p.Path, Revision: t.DeletionRevision, Sequence: t.DeletionSequence, FileID: t.FileID}, nil
		}
		return nil, ErrNotFound
	}
	if p.BaseRevision != cur.Revision {
		return nil, &ConflictError{Path: p.Path, Revision: cur.Revision, Hash: cur.ContentHash, FileID: cur.FileID}
	}

	now := time.Now().Unix()
	newRevision := cur.Revision + 1
	prior, err := db.PriorContentHash(s.db, cur.FileID)
	if err != nil {
		return nil, err
	}
	if prior == "" {
		prior = cur.ContentHash
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	seq, err := db.InsertChange(tx, &db.ObjectChange{
		FileID: cur.FileID, Action: "delete", Revision: newRevision,
		ContentGeneration: cur.ContentGeneration, MetaGeneration: cur.MetaGeneration,
		Pseudonym: cur.Pseudonym, OperationID: p.Client.OperationID, CreatedAt: now,
	})
	if err != nil {
		return nil, err
	}
	if err := db.UpsertTombstone(tx, &db.Tombstone{
		FileID:            cur.FileID,
		LastPseudonym:     cur.Pseudonym,
		CanonicalPathHmac: cur.CanonicalPathHmac,
		DeletionRevision:  newRevision,
		ContentGeneration: cur.ContentGeneration,
		MetaGeneration:    cur.MetaGeneration,
		KeyEpoch:          cur.KeyEpoch,
		PriorContentHash:  prior,
		DeletedAt:         now,
		DeletionSequence:  seq,
		RetainUntil:       s.tombstoneRetainUntil(now),
	}); err != nil {
		return nil, err
	}
	if err := db.DeleteHead(tx, cur.FileID); err != nil {
		return nil, err
	}
	if err := db.UpsertObject(tx, cur.FileID, db.ObjectDeleted, cur.CreatedAt, now); err != nil {
		return nil, err
	}
	if s.opts.HistoryEnabled {
		if err := db.InsertVersion(tx, &db.ObjectVersion{
			FileID: cur.FileID, Revision: newRevision, BlobID: "", ContentHash: "",
			Size: 0, Mtime: cur.Mtime, Action: "delete", DeviceID: p.DeviceID,
			OperationID: p.Client.OperationID, CreatedAt: now,
		}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &DeleteResult{Path: p.Path, Revision: newRevision, Sequence: seq, FileID: cur.FileID}, nil
}

// tombstoneRetainUntil：0 = 永久保留（默认）。即使配置了期限，实际清理仍需
// 「所有未撤销设备都已确认越过删除点」这第二个条件（ADR-002 §3.4）。
func (s *Service) tombstoneRetainUntil(now int64) int64 {
	if s.opts.TombstoneRetentionDays <= 0 {
		return 0
	}
	return now + int64(s.opts.TombstoneRetentionDays)*86400
}

// FileInfo 返回 live 对象的 HEAD（轻量，改名流用）。
func (s *Service) FileInfo(pseudonym string) (*db.ObjectHead, error) {
	if err := storage.ValidatePath(pseudonym); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := db.GetHeadByPseudonym(s.db, pseudonym)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, ErrNotFound
	}
	return h, nil
}

// OpenFile 返回对象元数据与内容读取器。
func (s *Service) OpenFile(pseudonym string) (*db.ObjectHead, io.ReadCloser, error) {
	if err := storage.ValidatePath(pseudonym); err != nil {
		return nil, nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cur, err := db.GetHeadByPseudonym(s.db, pseudonym)
	if err != nil {
		return nil, nil, err
	}
	if cur == nil {
		// 告知客户端「已删除」以及 tombstone revision（用于显式重建）
		if t, terr := db.GetTombstoneByPseudonym(s.db, pseudonym); terr == nil && t != nil {
			return &db.ObjectHead{FileID: t.FileID, Revision: t.DeletionRevision, Pseudonym: pseudonym},
				nil, ErrNotFound
		}
		return nil, nil, ErrNotFound
	}
	// §7.2：已知损坏的内容绝不再对外返回。客户端拿到明确的错误会重试或报警；
	// 拿到损坏字节则会把它当成真实内容写进用户的 Vault
	if !s.blobServable(cur.BlobID) {
		s.log.Error("refusing to serve quarantined blob", "fileId", truncateID(cur.FileID), "blob", cur.BlobID)
		return nil, nil, ErrCorrupted
	}
	f, err := s.blobs.Open(cur.BlobID)
	if err != nil {
		s.log.Error("content missing in blob store", "fileId", truncateID(cur.FileID))
		return nil, nil, ErrNotFound
	}
	return cur, f, nil
}

// History / OpenVersion --------------------------------------------------

func (s *Service) History(pseudonym string) ([]db.ObjectVersion, error) {
	if err := storage.ValidatePath(pseudonym); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fileID, err := s.fileIDForLocked(pseudonym)
	if err != nil {
		return nil, err
	}
	return db.ListVersions(s.db, fileID)
}

func (s *Service) OpenVersion(pseudonym string, revision int64) (*db.ObjectVersion, io.ReadCloser, error) {
	if err := storage.ValidatePath(pseudonym); err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	fileID, err := s.fileIDForLocked(pseudonym)
	s.mu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	v, err := db.GetVersion(s.db, fileID, revision)
	if err != nil {
		return nil, nil, err
	}
	if v == nil || v.BlobID == "" {
		return nil, nil, ErrNotFound
	}
	if !s.blobServable(v.BlobID) {
		s.log.Error("refusing to serve quarantined version blob", "blob", v.BlobID, "revision", revision)
		return nil, nil, ErrCorrupted
	}
	f, err := s.blobs.Open(v.BlobID)
	if err != nil {
		return nil, nil, ErrNotFound
	}
	return v, f, nil
}

// fileIDForLocked 把服务器可见寻址名解析为对象身份（含已删除对象——
// 历史与恢复必须在删除之后仍然可达）。调用方需持锁。
func (s *Service) fileIDForLocked(pseudonym string) (string, error) {
	if h, err := db.GetHeadByPseudonym(s.db, pseudonym); err != nil {
		return "", err
	} else if h != nil {
		return h.FileID, nil
	}
	if t, err := db.GetTombstoneByPseudonym(s.db, pseudonym); err != nil {
		return "", err
	} else if t != nil {
		return t.FileID, nil
	}
	// meta 模式下寻址名就是 fileId：对象可能已被改名但历史仍在
	if isHex32(pseudonym) {
		if state, err := db.ObjectState(s.db, pseudonym); err != nil {
			return "", err
		} else if state != "" {
			return pseudonym, nil
		}
	}
	return "", ErrNotFound
}

// Changes -----------------------------------------------------------------

// Changes 返回 since 之后的变更；since 早于裁剪水位线时要求客户端走 snapshot 对账。
// 全程持 s.mu（所有写入方都持同一把锁）：epoch/head/水位线/changes 是同一时刻的
// 一致读——绝不返回「与内容不对应的 sequence」（INV-02）。
func (s *Service) Changes(since, limit int64) (*ChangesResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if since < rs.MinRetainedSequence {
		return &ChangesResult{
			RepoEpoch: rs.RepoEpoch, FormatEpoch: rs.FormatEpoch,
			LatestSequence: rs.HeadSequence, ResyncRequired: true, MinSequence: rs.MinRetainedSequence,
		}, nil
	}
	changes, err := db.ListChanges(s.db, since, limit)
	if err != nil {
		return nil, err
	}
	hasMore := len(changes) > 0 && changes[len(changes)-1].Sequence < rs.HeadSequence
	return &ChangesResult{
		RepoEpoch: rs.RepoEpoch, FormatEpoch: rs.FormatEpoch,
		LatestSequence: rs.HeadSequence, HasMore: hasMore, Changes: changes,
	}, nil
}

// LatestSequence 返回权威 head_sequence（repo_state，不依赖可裁剪的 changes 表）。
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
		VaultID:                vaultID,
		RepoEpoch:              rs.RepoEpoch,
		HeadSequence:           rs.HeadSequence,
		EncryptionState:        rs.EncryptionState,
		KeyEpoch:               rs.KeyEpoch,
		MetaState:              rs.MetaState,
		FormatEpoch:            rs.FormatEpoch,
		MinimumEnvelopeVersion: rs.MinimumEnvelopeVersion,
		SchemaVersion:          rs.SchemaVersion,
		MigrationID:            rs.MigrationID,
		MigrationOwnerDeviceID: rs.MigrationOwnerDeviceID,
	}, nil
}

// WithGlobalLock 短暂持有全局写锁执行 fn（备份一致性快照用）。
func (s *Service) WithGlobalLock(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn()
}

// Snapshot 返回当前所有 live 对象与最新 sequence（严格对应同一时刻，INV-02）。
func (s *Service) Snapshot() (*SnapshotResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	objects, err := db.ListHeads(s.db)
	if err != nil {
		return nil, err
	}
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	return &SnapshotResult{
		RepoEpoch: rs.RepoEpoch, FormatEpoch: rs.FormatEpoch,
		Sequence: rs.HeadSequence, Objects: objects,
	}, nil
}

// E2EE 状态机 -------------------------------------------------------------

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

// CompleteE2eeMigration 验证所有 HEAD 均为 LSE 密文后切换到 encrypted，
// 并把仓库信封下限提升到至少 1（ADR-006 §2.1）。
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
	heads, err := db.ListHeads(s.db)
	if err != nil {
		return nil, err
	}
	for i := range heads {
		if s.envelopeVersionOfBlob(heads[i].BlobID) == 0 {
			return nil, fmt.Errorf("%w: object %s is not encrypted", ErrEncryptionState, truncateID(heads[i].FileID))
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := db.SetEncryptionState(tx, db.EncryptionEncrypted, false); err != nil {
		return nil, err
	}
	if err := db.RaiseMinimumEnvelopeVersion(tx, db.EnvelopeLSE1); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
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

// CompleteEnvelopeUpgrade 验证全部 live HEAD 均为 LSE3 后把信封下限提升到 3。
// 提升之后**任何**写入路径（含新建与删除后重建）都不再接受旧信封（ADR-006）。
func (s *Service) CompleteEnvelopeUpgrade() (*db.RepoState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := db.GetRepoState(s.db)
	if err != nil {
		return nil, err
	}
	if rs.EncryptionState != db.EncryptionEncrypted {
		return nil, ErrEncryptionState
	}
	heads, err := db.ListHeads(s.db)
	if err != nil {
		return nil, err
	}
	for i := range heads {
		if s.envelopeVersionOfBlob(heads[i].BlobID) < 3 {
			return nil, ErrEnvelopeTooOld
		}
	}
	if err := db.RaiseMinimumEnvelopeVersion(s.db, db.EnvelopeLSE3); err != nil {
		return nil, err
	}
	return db.GetRepoState(s.db)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// truncateID 只输出身份前 8 位（日志隐私，ADR-008 §3.5）。
func truncateID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
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
	return sha256Hex([]byte(doc))
}

// SetVaultKey 保存 vault key 文档。
// CAS：replace=true 时必须携带当前文档的指纹，不匹配返回 ErrVaultKeyCAS——
// 防止并发迁移/误操作无条件覆盖导致密文永久不可读。
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

// PruneHistoryBefore（E2EE 迁移用）：删除某对象 revision < before 的历史版本。
func (s *Service) PruneHistoryBefore(pseudonym string, before int64) (int, error) {
	if err := storage.ValidatePath(pseudonym); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	fileID, err := s.fileIDForLocked(pseudonym)
	if err != nil {
		return 0, err
	}
	versions, err := db.ListVersions(s.db, fileID)
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
		if _, err := tx.Exec(`DELETE FROM object_versions WHERE id = ?`, v.ID); err != nil {
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

// 内部工具 -----------------------------------------------------------------

// pruneVersionsTx 按 retention 规则裁剪某对象的历史（事务内），返回待 GC 的 blob。
// 最新版本永远保留。
func (s *Service) pruneVersionsTx(tx *sql.Tx, fileID string, now int64, days, maxPerFile int) ([]string, error) {
	if days <= 0 && maxPerFile <= 0 {
		return nil, nil
	}
	versions, err := db.ListVersions(tx, fileID) // revision 降序
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
			if _, err := tx.Exec(`DELETE FROM object_versions WHERE id = ?`, v.ID); err != nil {
				return nil, err
			}
			if v.BlobID != "" {
				pruneBlobs = append(pruneBlobs, v.BlobID)
			}
		}
	}
	return pruneBlobs, nil
}

// gcBlobs 删除不再被引用的 blob（引用 = 任何历史版本 或 任何 live HEAD）。
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
