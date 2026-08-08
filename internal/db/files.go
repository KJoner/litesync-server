package db

import (
	"database/sql"
	"errors"
)

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
		`SELECT id, path, content_hash, size, mtime, revision, deleted, created_at, updated_at
		 FROM files WHERE path = ?`, path,
	).Scan(&f.ID, &f.Path, &f.ContentHash, &f.Size, &f.Mtime, &f.Revision, &deleted, &f.CreatedAt, &f.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f.Deleted = deleted != 0
	return f, nil
}

// UpsertFile 插入或按 path 更新文件记录。
func UpsertFile(q dbtx, f *File) error {
	deleted := 0
	if f.Deleted {
		deleted = 1
	}
	_, err := q.Exec(
		`INSERT INTO files (path, content_hash, size, mtime, revision, deleted, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(path) DO UPDATE SET
		   content_hash = excluded.content_hash,
		   size = excluded.size,
		   mtime = excluded.mtime,
		   revision = excluded.revision,
		   deleted = excluded.deleted,
		   updated_at = excluded.updated_at`,
		f.Path, f.ContentHash, f.Size, f.Mtime, f.Revision, deleted, f.CreatedAt, f.UpdatedAt,
	)
	return err
}

// InsertChange 追加一条 change 记录并返回其 sequence。
func InsertChange(q dbtx, path string, revision int64, action, contentHash string, now int64) (int64, error) {
	res, err := q.Exec(
		`INSERT INTO changes (path, revision, action, content_hash, created_at) VALUES (?, ?, ?, ?, ?)`,
		path, revision, action, contentHash, now,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// LatestSequence 返回当前最大的 sequence，没有记录时为 0。
func LatestSequence(q dbtx) (int64, error) {
	var seq int64
	err := q.QueryRow(`SELECT COALESCE(MAX(sequence), 0) FROM changes`).Scan(&seq)
	return seq, err
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
