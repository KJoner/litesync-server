package db

// v5 数据模型的只读访问（仅供 v5 → v6 迁移与核对使用）。
//
// v5 表在迁移完成后被重命名为 v5_files / v5_changes / v5_file_versions 只读保留，
// 直到用户显式执行 `obsync migration finalize` 才删除（ADR-001 §5 的回滚窗口）。

import "database/sql"

// dbtx 同时兼容 *sql.DB 和 *sql.Tx。
type dbtx interface {
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
	Exec(query string, args ...any) (sql.Result, error)
}

// Queryer 是 dbtx 的导出别名，供其他包命名「*sql.DB 或 *sql.Tx」这个类型。
//
// 存在的理由很具体：连接池上限是 1，事务开着时任何走 *sql.DB 的查询都会
// 永远等那条被占用的连接。调用方必须**能够**把手上的 tx 传下去，
// 而不是只能传 s.db——后者是一个悄无声息的死锁。
type Queryer = dbtx

// LegacyFile 是 v5 `files` 表的一行。
type LegacyFile struct {
	Path           string
	ContentHash    string
	Size           int64
	Mtime          int64
	Revision       int64
	Deleted        bool
	CreatedAt      int64
	UpdatedAt      int64
	CanonicalKey   string
	FileID         string
	MetaEnc        string
	MetaGeneration int64
}

// LegacyVersion 是 v5 `file_versions` 表的一行。
type LegacyVersion struct {
	ID          int64
	Path        string
	Revision    int64
	BlobID      string
	ContentHash string
	Size        int64
	Mtime       int64
	Action      string
	DeviceID    string
	CreatedAt   int64
	FileID      string
}

// TableExists 判断某张表是否存在（迁移分支判断用）。
func TableExists(q dbtx, name string) (bool, error) {
	var n int64
	err := q.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n)
	return n > 0, err
}

// ListLegacyFiles 返回 v5 `files` 表的全部行（含 tombstone）。
func ListLegacyFiles(q dbtx) ([]LegacyFile, error) {
	rows, err := q.Query(
		`SELECT path, content_hash, size, mtime, revision, deleted, created_at, updated_at,
		        COALESCE(canonical_key,''), COALESCE(file_id,''), COALESCE(meta_enc,''),
		        COALESCE(meta_generation, 0)
		 FROM files ORDER BY path ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]LegacyFile, 0, 64)
	for rows.Next() {
		var f LegacyFile
		var deleted int64
		if err := rows.Scan(&f.Path, &f.ContentHash, &f.Size, &f.Mtime, &f.Revision, &deleted,
			&f.CreatedAt, &f.UpdatedAt, &f.CanonicalKey, &f.FileID, &f.MetaEnc, &f.MetaGeneration); err != nil {
			return nil, err
		}
		f.Deleted = deleted != 0
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListLegacyVersions 返回 v5 `file_versions` 表的全部行。
func ListLegacyVersions(q dbtx) ([]LegacyVersion, error) {
	rows, err := q.Query(
		`SELECT id, path, revision, COALESCE(blob_id,''), COALESCE(content_hash,''), size, mtime,
		        action, COALESCE(device_id,''), created_at, COALESCE(file_id,'')
		 FROM file_versions ORDER BY path ASC, revision ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]LegacyVersion, 0, 64)
	for rows.Next() {
		var v LegacyVersion
		if err := rows.Scan(&v.ID, &v.Path, &v.Revision, &v.BlobID, &v.ContentHash, &v.Size,
			&v.Mtime, &v.Action, &v.DeviceID, &v.CreatedAt, &v.FileID); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
