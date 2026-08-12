package db

// 协议 v6 对象模型访问层（ADR-001 / ADR-002）。
//
// 全部以 file_id 为主键。pseudonym 只是「服务器可见的寻址名」：
// plain 模式下等于真实路径，meta-encrypted 模式下等于 file_id。

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
)

// NewFileID 生成随机稳定文件身份（16B hex）。
func NewFileID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// 对象生命周期状态。
const (
	ObjectLive    = "live"
	ObjectDeleted = "deleted"
)

// ObjectHead 是一个 live 对象的当前状态（file_heads 一行）。
type ObjectHead struct {
	VaultID string
	FileID  string
	// Revision 属于**对象**：跨改名、元数据迁移、删除恢复连续递增（INV-05）
	Revision int64
	// ContentGeneration 内容世代：LSE3 信封头里的值，抗回退重放
	ContentGeneration int64
	BlobID            string
	ContentHash       string
	Size              int64
	Mtime             int64
	// MetaGeneration 元数据世代：改名 = +1，内容不变
	MetaGeneration int64
	// Pseudonym 服务器可见寻址名（plain=真实路径，encrypted=file_id）
	Pseudonym string
	// EncryptedMetadata LSM1 密文（真实路径在里面）；plain 模式为空
	EncryptedMetadata string
	// CanonicalPathHmac 同名判定键：plain 模式为归一化路径，encrypted 模式为客户端 HMAC
	CanonicalPathHmac string
	KeyEpoch          int64
	// EnvelopeVersion 内容信封版本：0=明文，1/2/3=LSE1/2/3（ADR-006 下限校验用）
	EnvelopeVersion int64
	CreatedAt       int64
	UpdatedAt       int64
}

// Tombstone 是一条删除记录（ADR-002）。删除事实、防复活锚点与恢复所需身份。
type Tombstone struct {
	VaultID           string
	FileID            string
	LastPseudonym     string
	CanonicalPathHmac string
	DeletionRevision  int64
	ContentGeneration int64
	MetaGeneration    int64
	KeyEpoch          int64
	PriorContentHash  string
	DeletedAt         int64
	DeletionSequence  int64
	RetainUntil       int64
	DeleteProof       string
	NeedsReview       bool
}

// ObjectVersion 是一条不可变历史版本（object_versions 一行）。
type ObjectVersion struct {
	ID                int64
	VaultID           string
	FileID            string
	Revision          int64
	ContentGeneration int64
	BlobID            string
	ContentHash       string
	Size              int64
	Mtime             int64
	Action            string
	DeviceID          string
	KeyEpoch          int64
	OperationID       string
	CreatedAt         int64
}

// ObjectChange 是一条变更日志（object_changes 一行）。
type ObjectChange struct {
	Sequence          int64
	VaultID           string
	FileID            string
	Action            string
	Revision          int64
	ContentGeneration int64
	MetaGeneration    int64
	Pseudonym         string
	ContentHash       string
	OperationID       string
	CreatedAt         int64
}

const headColumns = `vault_id, file_id, revision, content_generation, blob_id, content_hash, size, mtime,
	meta_generation, pseudonym, encrypted_metadata, canonical_path_hmac, key_epoch, envelope_version,
	created_at, updated_at`

func scanHead(row interface{ Scan(...any) error }) (*ObjectHead, error) {
	h := &ObjectHead{}
	err := row.Scan(&h.VaultID, &h.FileID, &h.Revision, &h.ContentGeneration, &h.BlobID, &h.ContentHash,
		&h.Size, &h.Mtime, &h.MetaGeneration, &h.Pseudonym, &h.EncryptedMetadata, &h.CanonicalPathHmac,
		&h.KeyEpoch, &h.EnvelopeVersion, &h.CreatedAt, &h.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return h, nil
}

// GetHead 按身份取当前 HEAD；对象不存在或已删除返回 (nil, nil)。
func GetHead(q dbtx, fileID string) (*ObjectHead, error) {
	return scanHead(q.QueryRow(
		`SELECT `+headColumns+` FROM file_heads WHERE vault_id = ? AND file_id = ?`,
		DefaultVaultID, fileID))
}

// GetHeadByPseudonym 按服务器可见寻址名取当前 HEAD。
func GetHeadByPseudonym(q dbtx, pseudonym string) (*ObjectHead, error) {
	return scanHead(q.QueryRow(
		`SELECT `+headColumns+` FROM file_heads WHERE vault_id = ? AND pseudonym = ?`,
		DefaultVaultID, pseudonym))
}

// ListHeads 返回全部 live 对象（snapshot 用），按 pseudonym 升序。
func ListHeads(q dbtx) ([]ObjectHead, error) {
	rows, err := q.Query(
		`SELECT ` + headColumns + ` FROM file_heads WHERE vault_id = '` + DefaultVaultID + `' ORDER BY pseudonym ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ObjectHead, 0, 64)
	for rows.Next() {
		h, err := scanHead(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *h)
	}
	return out, rows.Err()
}

// UpsertHead 写入/更新 HEAD。
func UpsertHead(q dbtx, h *ObjectHead) error {
	if h.VaultID == "" {
		h.VaultID = DefaultVaultID
	}
	_, err := q.Exec(
		`INSERT INTO file_heads (`+headColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(vault_id, file_id) DO UPDATE SET
		   revision = excluded.revision,
		   content_generation = excluded.content_generation,
		   blob_id = excluded.blob_id,
		   content_hash = excluded.content_hash,
		   size = excluded.size,
		   mtime = excluded.mtime,
		   meta_generation = excluded.meta_generation,
		   pseudonym = excluded.pseudonym,
		   encrypted_metadata = excluded.encrypted_metadata,
		   canonical_path_hmac = excluded.canonical_path_hmac,
		   key_epoch = excluded.key_epoch,
		   envelope_version = excluded.envelope_version,
		   updated_at = excluded.updated_at`,
		h.VaultID, h.FileID, h.Revision, h.ContentGeneration, h.BlobID, h.ContentHash, h.Size, h.Mtime,
		h.MetaGeneration, h.Pseudonym, h.EncryptedMetadata, h.CanonicalPathHmac, h.KeyEpoch,
		h.EnvelopeVersion, h.CreatedAt, h.UpdatedAt)
	return err
}

// DeleteHead 移除 HEAD 行（删除流程：先取出内容写 tombstone，再删这行）。
func DeleteHead(q dbtx, fileID string) error {
	_, err := q.Exec(`DELETE FROM file_heads WHERE vault_id = ? AND file_id = ?`, DefaultVaultID, fileID)
	return err
}

// FindCanonicalCollision 返回与 canonicalKey 冲突的其他 live 对象的 pseudonym；
// 无冲突返回 ""。meta 模式下 canonicalKey 是客户端 HMAC——服务器不知路径仍能拒绝同名并存。
func FindCanonicalCollision(q dbtx, canonicalKey, excludeFileID string) (string, error) {
	if canonicalKey == "" {
		return "", nil
	}
	var pseudonym string
	err := q.QueryRow(
		`SELECT pseudonym FROM file_heads
		 WHERE vault_id = ? AND canonical_path_hmac = ? AND file_id != ? LIMIT 1`,
		DefaultVaultID, canonicalKey, excludeFileID,
	).Scan(&pseudonym)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return pseudonym, err
}

// ---------- 对象台账 ----------

// UpsertObject 写入/更新对象生命周期状态。
func UpsertObject(q dbtx, fileID, state string, createdAt, deletedAt int64) error {
	_, err := q.Exec(
		`INSERT INTO file_objects (vault_id, file_id, created_at, deleted_at, object_state)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(vault_id, file_id) DO UPDATE SET
		   deleted_at = excluded.deleted_at,
		   object_state = excluded.object_state`,
		DefaultVaultID, fileID, createdAt, deletedAt, state)
	return err
}

// ObjectState 返回对象的生命周期状态；对象不存在返回 ""。
func ObjectState(q dbtx, fileID string) (string, error) {
	var s string
	err := q.QueryRow(
		`SELECT object_state FROM file_objects WHERE vault_id = ? AND file_id = ?`,
		DefaultVaultID, fileID).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return s, err
}

// FileIDInUse 判断某 file_id 是否已被任何对象（live 或 deleted）占用。
func FileIDInUse(q dbtx, fileID string) (bool, error) {
	var n int64
	err := q.QueryRow(
		`SELECT COUNT(*) FROM file_objects WHERE vault_id = ? AND file_id = ?`,
		DefaultVaultID, fileID).Scan(&n)
	return n > 0, err
}

// ---------- Tombstone 台账（ADR-002） ----------

const tombstoneColumns = `vault_id, file_id, last_pseudonym, canonical_path_hmac, deletion_revision,
	content_generation, meta_generation, key_epoch, prior_content_hash, deleted_at, deletion_sequence,
	retain_until, delete_proof, needs_review`

func scanTombstone(row interface{ Scan(...any) error }) (*Tombstone, error) {
	t := &Tombstone{}
	var needsReview int64
	err := row.Scan(&t.VaultID, &t.FileID, &t.LastPseudonym, &t.CanonicalPathHmac, &t.DeletionRevision,
		&t.ContentGeneration, &t.MetaGeneration, &t.KeyEpoch, &t.PriorContentHash, &t.DeletedAt,
		&t.DeletionSequence, &t.RetainUntil, &t.DeleteProof, &needsReview)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.NeedsReview = needsReview != 0
	return t, nil
}

// DeleteProofOf 计算不可逆删除证明（仅用于擦除报告与审计，不参与任何安全判断）。
func DeleteProofOf(fileID string, deletionRevision int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("litesync/v6/tombstone:%s:%s:%d", DefaultVaultID, fileID, deletionRevision)))
	return hex.EncodeToString(sum[:])
}

func UpsertTombstone(q dbtx, t *Tombstone) error {
	if t.VaultID == "" {
		t.VaultID = DefaultVaultID
	}
	if t.DeleteProof == "" {
		t.DeleteProof = DeleteProofOf(t.FileID, t.DeletionRevision)
	}
	needsReview := 0
	if t.NeedsReview {
		needsReview = 1
	}
	_, err := q.Exec(
		`INSERT INTO tombstones (`+tombstoneColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(vault_id, file_id) DO UPDATE SET
		   last_pseudonym = excluded.last_pseudonym,
		   canonical_path_hmac = excluded.canonical_path_hmac,
		   deletion_revision = excluded.deletion_revision,
		   content_generation = excluded.content_generation,
		   meta_generation = excluded.meta_generation,
		   key_epoch = excluded.key_epoch,
		   prior_content_hash = excluded.prior_content_hash,
		   deleted_at = excluded.deleted_at,
		   deletion_sequence = excluded.deletion_sequence,
		   retain_until = excluded.retain_until,
		   delete_proof = excluded.delete_proof,
		   needs_review = excluded.needs_review`,
		t.VaultID, t.FileID, t.LastPseudonym, t.CanonicalPathHmac, t.DeletionRevision,
		t.ContentGeneration, t.MetaGeneration, t.KeyEpoch, t.PriorContentHash, t.DeletedAt,
		t.DeletionSequence, t.RetainUntil, t.DeleteProof, needsReview)
	return err
}

func GetTombstone(q dbtx, fileID string) (*Tombstone, error) {
	return scanTombstone(q.QueryRow(
		`SELECT `+tombstoneColumns+` FROM tombstones WHERE vault_id = ? AND file_id = ?`,
		DefaultVaultID, fileID))
}

// GetTombstoneByPseudonym 按最后可见寻址名查 tombstone（旧设备按旧名字上传时用）。
func GetTombstoneByPseudonym(q dbtx, pseudonym string) (*Tombstone, error) {
	return scanTombstone(q.QueryRow(
		`SELECT `+tombstoneColumns+` FROM tombstones WHERE vault_id = ? AND last_pseudonym = ? LIMIT 1`,
		DefaultVaultID, pseudonym))
}

// GetTombstoneByCanonical 按同名判定键查 tombstone（防止用不同大小写复活已删文件）。
func GetTombstoneByCanonical(q dbtx, canonicalKey string) (*Tombstone, error) {
	if canonicalKey == "" {
		return nil, nil
	}
	return scanTombstone(q.QueryRow(
		`SELECT `+tombstoneColumns+` FROM tombstones WHERE vault_id = ? AND canonical_path_hmac = ? LIMIT 1`,
		DefaultVaultID, canonicalKey))
}

// ListTombstones 返回全部删除记录。
func ListTombstones(q dbtx) ([]Tombstone, error) {
	rows, err := q.Query(`SELECT ` + tombstoneColumns + ` FROM tombstones WHERE vault_id = '` + DefaultVaultID + `'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Tombstone, 0, 16)
	for rows.Next() {
		t, err := scanTombstone(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// PlaintextTombstoneCount 返回仍带明文寻址名的 tombstone 数量
// （`last_pseudonym != file_id` 即尚未转换为隐私格式）。
func PlaintextTombstoneCount(q dbtx) (int64, error) {
	var n int64
	err := q.QueryRow(
		`SELECT COUNT(*) FROM tombstones WHERE vault_id = ? AND last_pseudonym != file_id`,
		DefaultVaultID).Scan(&n)
	return n, err
}

// ConvertTombstoneToPrivate 把 tombstone 转成隐私格式（ADR-002 §3.2）：
// 明文寻址名换成 file_id，归一化路径换成客户端 HMAC。删除屏障本身完全保留。
func ConvertTombstoneToPrivate(q dbtx, fileID, canonicalHash string) error {
	t, err := GetTombstone(q, fileID)
	if err != nil {
		return err
	}
	if t == nil {
		return sql.ErrNoRows
	}
	_, err = q.Exec(
		`UPDATE tombstones
		    SET last_pseudonym = file_id,
		        canonical_path_hmac = ?,
		        delete_proof = ?
		  WHERE vault_id = ? AND file_id = ?`,
		canonicalHash, DeleteProofOf(fileID, t.DeletionRevision), DefaultVaultID, fileID)
	return err
}

// RemoveTombstone 删除一条 tombstone（仅用于恢复流程与经双条件确认的清理）。
func RemoveTombstone(q dbtx, fileID string) error {
	_, err := q.Exec(`DELETE FROM tombstones WHERE vault_id = ? AND file_id = ?`, DefaultVaultID, fileID)
	return err
}

// ---------- 历史版本 ----------

const versionColumns = `vault_id, file_id, revision, content_generation, blob_id, content_hash, size, mtime,
	action, device_id, key_epoch, operation_id, created_at`

func scanVersion(row interface{ Scan(...any) error }) (*ObjectVersion, error) {
	v := &ObjectVersion{}
	err := row.Scan(&v.ID, &v.VaultID, &v.FileID, &v.Revision, &v.ContentGeneration, &v.BlobID,
		&v.ContentHash, &v.Size, &v.Mtime, &v.Action, &v.DeviceID, &v.KeyEpoch, &v.OperationID, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

const versionSelect = `SELECT id, vault_id, file_id, revision, content_generation, COALESCE(blob_id,''),
	COALESCE(content_hash,''), size, mtime, action, COALESCE(device_id,''), key_epoch,
	COALESCE(operation_id,''), created_at FROM object_versions`

// InsertVersion 追加历史版本。同 (file_id, revision) 重复插入是幂等的
// （重试与响应丢失后的重放不会产生重复历史，ADR-001 §4）。
func InsertVersion(q dbtx, v *ObjectVersion) error {
	if v.VaultID == "" {
		v.VaultID = DefaultVaultID
	}
	_, err := q.Exec(
		`INSERT INTO object_versions (`+versionColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(vault_id, file_id, revision) DO NOTHING`,
		v.VaultID, v.FileID, v.Revision, v.ContentGeneration, v.BlobID, v.ContentHash, v.Size, v.Mtime,
		v.Action, v.DeviceID, v.KeyEpoch, v.OperationID, v.CreatedAt)
	return err
}

// ListVersions 按 revision 降序返回某对象的全部历史版本。
func ListVersions(q dbtx, fileID string) ([]ObjectVersion, error) {
	rows, err := q.Query(versionSelect+` WHERE vault_id = ? AND file_id = ? ORDER BY revision DESC`,
		DefaultVaultID, fileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ObjectVersion, 0, 8)
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

// GetVersion 返回某对象某 revision 的版本；不存在返回 (nil, nil)。
func GetVersion(q dbtx, fileID string, revision int64) (*ObjectVersion, error) {
	return scanVersion(q.QueryRow(versionSelect+` WHERE vault_id = ? AND file_id = ? AND revision = ?`,
		DefaultVaultID, fileID, revision))
}

// PriorContentHash 返回该对象最近一个有内容版本的 hash（陈旧副本复活判定用）。
func PriorContentHash(q dbtx, fileID string) (string, error) {
	var h string
	err := q.QueryRow(
		`SELECT content_hash FROM object_versions
		 WHERE vault_id = ? AND file_id = ? AND action != 'delete' AND COALESCE(content_hash,'') != ''
		 ORDER BY revision DESC LIMIT 1`, DefaultVaultID, fileID,
	).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return h, err
}

// BlobReferenced 判断 blob 是否仍被引用：任何历史版本，或任何 live HEAD。
func BlobReferenced(q dbtx, blobID string) (bool, error) {
	var n int64
	err := q.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM object_versions WHERE blob_id = ?)
		     OR EXISTS(SELECT 1 FROM file_heads WHERE blob_id = ?)`,
		blobID, blobID,
	).Scan(&n)
	return n != 0, err
}

// DistinctVersionFileIDs 返回拥有历史版本的全部对象身份（维护任务用）。
func DistinctVersionFileIDs(q dbtx) ([]string, error) {
	rows, err := q.Query(`SELECT DISTINCT file_id FROM object_versions WHERE vault_id = ?`, DefaultVaultID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		ids = append(ids, s)
	}
	return ids, rows.Err()
}

// NonHeadHistoryBytes 返回非最新版本的历史总字节（字节预算裁剪用）。
func NonHeadHistoryBytes(q dbtx) (int64, error) {
	var n int64
	err := q.QueryRow(
		`SELECT COALESCE(SUM(size), 0) FROM object_versions v
		 WHERE v.revision < (SELECT MAX(revision) FROM object_versions
		                      WHERE vault_id = v.vault_id AND file_id = v.file_id)`,
	).Scan(&n)
	return n, err
}

// OldestNonHeadVersions 返回最旧的一批非 HEAD 历史版本。
func OldestNonHeadVersions(q dbtx, limit int) ([]ObjectVersion, error) {
	rows, err := q.Query(versionSelect+` v
		 WHERE v.revision < (SELECT MAX(revision) FROM object_versions
		                      WHERE vault_id = v.vault_id AND file_id = v.file_id)
		 ORDER BY v.created_at ASC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ObjectVersion, 0, limit)
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

// ---------- 变更日志 ----------

// InsertChange 追加一条变更并返回其 sequence。
// sequence 由 repo_state.head_sequence 在同一事务内分配（全局时钟，INV-02）。
func InsertChange(q dbtx, c *ObjectChange) (int64, error) {
	seq, err := NextSequence(q, LegacyDefaultScope())
	if err != nil {
		return 0, err
	}
	if c.VaultID == "" {
		c.VaultID = DefaultVaultID
	}
	_, err = q.Exec(
		`INSERT INTO object_changes (sequence, vault_id, file_id, action, revision, content_generation,
			meta_generation, pseudonym, content_hash, operation_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		seq, c.VaultID, c.FileID, c.Action, c.Revision, c.ContentGeneration, c.MetaGeneration,
		c.Pseudonym, c.ContentHash, c.OperationID, c.CreatedAt)
	if err != nil {
		return 0, err
	}
	return seq, nil
}

// ListChanges 返回 sequence > since 的变更，升序，最多 limit 条。
func ListChanges(q dbtx, since, limit int64) ([]ObjectChange, error) {
	rows, err := q.Query(
		`SELECT sequence, vault_id, file_id, action, revision, content_generation, meta_generation,
		        pseudonym, COALESCE(content_hash,''), COALESCE(operation_id,''), created_at
		 FROM object_changes WHERE vault_id = ? AND sequence > ? ORDER BY sequence ASC LIMIT ?`,
		DefaultVaultID, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ObjectChange, 0, 16)
	for rows.Next() {
		var c ObjectChange
		if err := rows.Scan(&c.Sequence, &c.VaultID, &c.FileID, &c.Action, &c.Revision,
			&c.ContentGeneration, &c.MetaGeneration, &c.Pseudonym, &c.ContentHash,
			&c.OperationID, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LastSequenceForFile 返回某对象最近一次变更的 sequence，没有记录时为 0。
func LastSequenceForFile(q dbtx, fileID string) (int64, error) {
	var seq int64
	err := q.QueryRow(
		`SELECT COALESCE(MAX(sequence), 0) FROM object_changes WHERE vault_id = ? AND file_id = ?`,
		DefaultVaultID, fileID).Scan(&seq)
	return seq, err
}

// FindChangeByOperation 按幂等键查已提交的变更（响应丢失后重试用）。
func FindChangeByOperation(q dbtx, fileID, operationID string) (*ObjectChange, error) {
	if operationID == "" {
		return nil, nil
	}
	var c ObjectChange
	err := q.QueryRow(
		`SELECT sequence, vault_id, file_id, action, revision, content_generation, meta_generation,
		        pseudonym, COALESCE(content_hash,''), COALESCE(operation_id,''), created_at
		 FROM object_changes WHERE vault_id = ? AND file_id = ? AND operation_id = ? LIMIT 1`,
		DefaultVaultID, fileID, operationID).Scan(&c.Sequence, &c.VaultID, &c.FileID, &c.Action,
		&c.Revision, &c.ContentGeneration, &c.MetaGeneration, &c.Pseudonym, &c.ContentHash,
		&c.OperationID, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}
