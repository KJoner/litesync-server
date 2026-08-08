package db

import (
	"database/sql"
	"errors"
)

// Share 对应 shares 表的一行。内容本身（密文）在磁盘 shares/ 目录，
// 服务器不知道 Share Key，无法解密。
type Share struct {
	ID        string
	Name      string // 客户端自选的显示名（通常是文件路径，服务器本就知道路径）
	Size      int64
	ExpiresAt int64 // 0 = 永不过期
	CreatedAt int64
	Revoked   bool
}

func InsertShare(q dbtx, s *Share) error {
	revoked := 0
	if s.Revoked {
		revoked = 1
	}
	_, err := q.Exec(
		`INSERT INTO shares (id, name, size, expires_at, created_at, revoked) VALUES (?, ?, ?, ?, ?, ?)`,
		s.ID, s.Name, s.Size, s.ExpiresAt, s.CreatedAt, revoked,
	)
	return err
}

func GetShare(q dbtx, id string) (*Share, error) {
	s := &Share{}
	var revoked int64
	err := q.QueryRow(
		`SELECT id, name, size, expires_at, created_at, revoked FROM shares WHERE id = ?`, id,
	).Scan(&s.ID, &s.Name, &s.Size, &s.ExpiresAt, &s.CreatedAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.Revoked = revoked != 0
	return s, nil
}

func ListShares(q dbtx) ([]Share, error) {
	rows, err := q.Query(
		`SELECT id, name, size, expires_at, created_at, revoked FROM shares ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	shares := make([]Share, 0, 8)
	for rows.Next() {
		var s Share
		var revoked int64
		if err := rows.Scan(&s.ID, &s.Name, &s.Size, &s.ExpiresAt, &s.CreatedAt, &revoked); err != nil {
			return nil, err
		}
		s.Revoked = revoked != 0
		shares = append(shares, s)
	}
	return shares, rows.Err()
}

func MarkShareRevoked(q dbtx, id string) error {
	_, err := q.Exec(`UPDATE shares SET revoked = 1 WHERE id = ?`, id)
	return err
}

// ListFiles 返回当前所有未删除文件的元数据（snapshot API 用）。
func ListFiles(q dbtx) ([]File, error) {
	rows, err := q.Query(
		`SELECT id, path, content_hash, size, mtime, revision, deleted, created_at, updated_at
		 FROM files WHERE deleted = 0 ORDER BY path ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	files := make([]File, 0, 64)
	for rows.Next() {
		var f File
		var deleted int64
		if err := rows.Scan(&f.ID, &f.Path, &f.ContentHash, &f.Size, &f.Mtime,
			&f.Revision, &deleted, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		f.Deleted = deleted != 0
		files = append(files, f)
	}
	return files, rows.Err()
}
