package db

import (
	"database/sql"
	"errors"
)

// FileVersion 对应 file_versions 表的一行（不可变历史版本元数据）。
type FileVersion struct {
	ID          int64
	Path        string
	Revision    int64
	BlobID      string // 内容寻址 blob 的 SHA-256；delete 版本为空
	ContentHash string
	Size        int64
	Mtime       int64
	Action      string // upsert | delete | restore | merge
	DeviceID    string
	CreatedAt   int64
}

func InsertVersion(q dbtx, v *FileVersion) error {
	_, err := q.Exec(
		`INSERT INTO file_versions (path, revision, blob_id, content_hash, size, mtime, action, device_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.Path, v.Revision, v.BlobID, v.ContentHash, v.Size, v.Mtime, v.Action, v.DeviceID, v.CreatedAt,
	)
	return err
}

// ListVersions 按 revision 降序返回某路径的全部历史版本。
func ListVersions(q dbtx, path string) ([]FileVersion, error) {
	rows, err := q.Query(
		`SELECT id, path, revision, COALESCE(blob_id,''), COALESCE(content_hash,''), size, mtime, action, COALESCE(device_id,''), created_at
		 FROM file_versions WHERE path = ? ORDER BY revision DESC`, path,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	versions := make([]FileVersion, 0, 8)
	for rows.Next() {
		var v FileVersion
		if err := rows.Scan(&v.ID, &v.Path, &v.Revision, &v.BlobID, &v.ContentHash,
			&v.Size, &v.Mtime, &v.Action, &v.DeviceID, &v.CreatedAt); err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// GetVersion 返回某路径某 revision 的版本；不存在时返回 (nil, nil)。
func GetVersion(q dbtx, path string, revision int64) (*FileVersion, error) {
	v := &FileVersion{}
	err := q.QueryRow(
		`SELECT id, path, revision, COALESCE(blob_id,''), COALESCE(content_hash,''), size, mtime, action, COALESCE(device_id,''), created_at
		 FROM file_versions WHERE path = ? AND revision = ?`, path, revision,
	).Scan(&v.ID, &v.Path, &v.Revision, &v.BlobID, &v.ContentHash,
		&v.Size, &v.Mtime, &v.Action, &v.DeviceID, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

// CountBlobRefs 返回仍引用该 blob 的版本数量。
func CountBlobRefs(q dbtx, blobID string) (int64, error) {
	var n int64
	err := q.QueryRow(`SELECT COUNT(*) FROM file_versions WHERE blob_id = ?`, blobID).Scan(&n)
	return n, err
}
