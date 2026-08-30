package db

import (
	"database/sql"
	"errors"
)

// Share 对应 shares 表的一行。内容本身（密文）在磁盘 shares/ 目录，
// 服务器不知道 Share Key，无法解密。
//
// VaultID（v0.18）：分享归属的租户。创建/列表/撤销按归属隔离；
// 公开读取（GET /share/{id}）不看归属——id 不可猜测即隔离，与现状一致。
type Share struct {
	ID        string
	VaultID   string
	Name      string // 客户端自选的显示名（通常是文件路径，服务器本就知道路径）
	Size      int64
	ExpiresAt int64 // 0 = 永不过期
	CreatedAt int64
	Revoked   bool
}

func InsertShare(q dbtx, s VaultScope, sh *Share) error {
	if !s.Valid() {
		return ErrVaultScopeMissing
	}
	revoked := 0
	if sh.Revoked {
		revoked = 1
	}
	sh.VaultID = s.ID()
	_, err := q.Exec(
		`INSERT INTO shares (id, name, size, expires_at, created_at, revoked, vault_id) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sh.ID, sh.Name, sh.Size, sh.ExpiresAt, sh.CreatedAt, revoked, sh.VaultID,
	)
	return err
}

const shareColumns = `id, COALESCE(vault_id, 'default'), name, size, expires_at, created_at, revoked`

func scanShare(row interface{ Scan(...any) error }) (*Share, error) {
	s := &Share{}
	var revoked int64
	err := row.Scan(&s.ID, &s.VaultID, &s.Name, &s.Size, &s.ExpiresAt, &s.CreatedAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.Revoked = revoked != 0
	return s, nil
}

// GetShare 按 id 取分享（公开读取路径：id 即凭证，不做归属过滤）。
func GetShare(q dbtx, id string) (*Share, error) {
	return scanShare(q.QueryRow(`SELECT `+shareColumns+` FROM shares WHERE id = ?`, id))
}

// ListShares 列出某 Vault 的分享（用户视图）。
func ListShares(q dbtx, s VaultScope) ([]Share, error) {
	if !s.Valid() {
		return nil, ErrVaultScopeMissing
	}
	return scanShares(q.Query(
		`SELECT `+shareColumns+` FROM shares WHERE COALESCE(vault_id, 'default') = ? ORDER BY created_at DESC`, s.ID()))
}

// AdminListShares 列出全实例的分享（运维页：滥用处置需要全局视图）。
func AdminListShares(q dbtx) ([]Share, error) {
	return scanShares(q.Query(`SELECT ` + shareColumns + ` FROM shares ORDER BY created_at DESC`))
}

func scanShares(rows *sql.Rows, err error) ([]Share, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	shares := make([]Share, 0, 8)
	for rows.Next() {
		s, serr := scanShare(rows)
		if serr != nil {
			return nil, serr
		}
		shares = append(shares, *s)
	}
	return shares, rows.Err()
}

// MarkShareRevoked 撤销某 Vault 自己的分享；跨 Vault 的 id 视同不存在（返回 false）。
func MarkShareRevoked(q dbtx, s VaultScope, id string) (bool, error) {
	if !s.Valid() {
		return false, ErrVaultScopeMissing
	}
	res, err := q.Exec(`UPDATE shares SET revoked = 1 WHERE id = ? AND COALESCE(vault_id, 'default') = ?`,
		id, s.ID())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return n > 0, nil
}

// AdminMarkShareRevoked 按 id 撤销任意分享（管理员滥用处置）。
func AdminMarkShareRevoked(q dbtx, id string) error {
	_, err := q.Exec(`UPDATE shares SET revoked = 1 WHERE id = ?`, id)
	return err
}

// UpdateShareExpiry 延长分享的有效期（§11.3 分享恢复；管理员操作，按 id）。
//
// 只允许往**后**延：把有效期改早等于撤销，而撤销有它自己的入口，
// 两条路径混在一起会让审计记录说不清发生了什么。
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
