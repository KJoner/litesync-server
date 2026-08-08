package db

import (
	"database/sql"
	"errors"
)

// GetMeta 读取 vault_meta 中的键值；不存在时返回 ("", false, nil)。
func GetMeta(q dbtx, key string) (string, bool, error) {
	var value string
	err := q.QueryRow(`SELECT value FROM vault_meta WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// SetMeta 写入（或覆盖）vault_meta 键值。
func SetMeta(q dbtx, key, value string, now int64) error {
	_, err := q.Exec(
		`INSERT INTO vault_meta (key, value, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, now,
	)
	return err
}
