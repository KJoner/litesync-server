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

// UpdateShareExpiry 延长分享的有效期（§11.3 分享恢复）。
//
// 只允许往**后**延：把有效期改早等于撤销，而撤销有它自己的入口
// （MarkShareRevoked），两条路径混在一起会让审计记录说不清发生了什么。
func UpdateShareExpiry(q dbtx, id string, expiresAt int64) error {
	res, err := q.Exec(
		`UPDATE shares SET expires_at = ?
		 WHERE id = ? AND revoked = 0 AND (expires_at = 0 OR expires_at < ?)`,
		expiresAt, id, expiresAt)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 { //nolint:errcheck
		return errors.New("分享不存在、已撤销，或新的有效期并不比原来更晚")
	}
	return nil
}
