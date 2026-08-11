package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
)

// NewFileID 生成随机稳定文件身份（16B hex）。
func NewFileID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// File 对应 files 表的一行。
type File struct {
	ID          int64
	Path        string
	ContentHash string
	Size        int64
	Mtime       int64 // 客户端文件修改时间（毫秒）
	Revision    int64
	Deleted     bool
	CreatedAt   int64
	UpdatedAt   int64
	// CanonicalKey：跨平台归一化后的路径（NFC + 小写），用于拒绝
	// 大小写/Unicode 规范化不同但会在 Windows/macOS 上映射为同一文件的路径并存
	CanonicalKey string
	// FileID：稳定文件身份（v9.3）——path 可变，file_id 跟随内容跨 MOVE 不变
	FileID string
}

// Change 对应 changes 表的一行。
type Change struct {
	Sequence    int64
	Path        string
	Revision    int64
	Action      string // "upsert" | "delete"
	ContentHash string // delete 时为空
	CreatedAt   int64
}

// dbtx 同时兼容 *sql.DB 和 *sql.Tx。
type dbtx interface {
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
	Exec(query string, args ...any) (sql.Result, error)
}

// GetFile 返回指定路径的文件记录；不存在时返回 (nil, nil)。
func GetFile(q dbtx, path string) (*File, error) {
	f := &File{}
	var deleted int64
	err := q.QueryRow(
		`SELECT id, path, content_hash, size, mtime, revision, deleted, created_at, updated_at, canonical_key, file_id
		 FROM files WHERE path = ?`, path,
	).Scan(&f.ID, &f.Path, &f.ContentHash, &f.Size, &f.Mtime, &f.Revision, &deleted, &f.CreatedAt, &f.UpdatedAt, &f.CanonicalKey, &f.FileID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f.Deleted = deleted != 0
	return f, nil
}

// FindCanonicalCollision 返回与 canonicalKey 冲突的其他未删除路径；无冲突返回 ""。
func FindCanonicalCollision(q dbtx, canonicalKey, excludePath string) (string, error) {
	var path string
	err := q.QueryRow(
		`SELECT path FROM files WHERE canonical_key = ? AND deleted = 0 AND path != ? LIMIT 1`,
		canonicalKey, excludePath,
	).Scan(&path)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return path, err
}

// UpsertFile 插入或按 path 更新文件记录。
func UpsertFile(q dbtx, f *File) error {
	deleted := 0
	if f.Deleted {
		deleted = 1
	}
	_, err := q.Exec(
		`INSERT INTO files (path, content_hash, size, mtime, revision, deleted, created_at, updated_at, canonical_key, file_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(path) DO UPDATE SET
		   content_hash = excluded.content_hash,
		   size = excluded.size,
		   mtime = excluded.mtime,
		   revision = excluded.revision,
		   deleted = excluded.deleted,
		   updated_at = excluded.updated_at,
		   canonical_key = excluded.canonical_key,
		   file_id = excluded.file_id`,
		f.Path, f.ContentHash, f.Size, f.Mtime, f.Revision, deleted, f.CreatedAt, f.UpdatedAt, f.CanonicalKey, f.FileID,
	)
	return err
}

// InsertChange 追加一条 change 记录并返回其 sequence。
// v9：sequence 由 repo_state.head_sequence 在同一事务内分配（全局时钟），
// changes 只是可裁剪日志——绝不能再用 MAX(changes.sequence) 当时钟。
func InsertChange(q dbtx, path string, revision int64, action, contentHash string, now int64) (int64, error) {
	seq, err := NextSequence(q)
	if err != nil {
		return 0, err
	}
	_, err = q.Exec(
		`INSERT INTO changes (sequence, path, revision, action, content_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		seq, path, revision, action, contentHash, now,
	)
	if err != nil {
		return 0, err
	}
	return seq, nil
}

// LastSequenceForPath 返回某路径最近一次 change 的 sequence，没有记录时为 0。
func LastSequenceForPath(q dbtx, path string) (int64, error) {
	var seq int64
	err := q.QueryRow(`SELECT COALESCE(MAX(sequence), 0) FROM changes WHERE path = ?`, path).Scan(&seq)
	return seq, err
}

// ListChanges 返回 sequence > since 的 change，按 sequence 升序，最多 limit 条。
func ListChanges(q dbtx, since, limit int64) ([]Change, error) {
	rows, err := q.Query(
		`SELECT sequence, path, revision, action, COALESCE(content_hash, ''), created_at
		 FROM changes WHERE sequence > ? ORDER BY sequence ASC LIMIT ?`, since, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	changes := make([]Change, 0, 16)
	for rows.Next() {
		var c Change
		if err := rows.Scan(&c.Sequence, &c.Path, &c.Revision, &c.Action, &c.ContentHash, &c.CreatedAt); err != nil {
			return nil, err
		}
		changes = append(changes, c)
	}
	return changes, rows.Err()
}
