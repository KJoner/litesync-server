package db

// 迁移逐对象台账（ADR-003 §3.3）。
//
// 迁移进度必须落库：服务端重启、客户端换机器、owner 接管都要能从这里继续。
// 绝不依赖内存中的遍历位置（INV-11）。

import "time"

// Journal stage 取值。
const (
	StagePending = "pending"
	StageDone    = "done"
	StageFailed  = "failed"
	StageSkipped = "skipped"
)

// Journal kind 取值。
const (
	KindObject    = "object"
	KindTombstone = "tombstone"
	KindVersion   = "version"
)

// SchemaMigrationID 是 v5 → v6 数据库迁移复用的固定 migration_id。
const SchemaMigrationID = "schema-v6"

// JournalEntry 是一条逐对象迁移记录。
type JournalEntry struct {
	MigrationID  string
	VaultID      string
	FileID       string
	Kind         string
	SourceFormat string
	TargetFormat string
	Stage        string
	LastError    string
	AttemptCount int64
	UpdatedAt    int64
}

// EnqueueJournal 登记一条待迁移条目（幂等：已存在则不覆盖 stage）。
func EnqueueJournal(q dbtx, migrationID, fileID, kind, sourceFormat, targetFormat string) error {
	_, err := q.Exec(
		`INSERT INTO migration_journal
		   (migration_id, vault_id, file_id, kind, source_format, target_format, stage, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
		 ON CONFLICT(migration_id, vault_id, file_id, kind) DO NOTHING`,
		migrationID, DefaultVaultID, fileID, kind, sourceFormat, targetFormat, time.Now().Unix())
	return err
}

// MarkJournalDone 标记完成。必须与对应的数据变更在**同一事务**内提交，
// 否则会出现「数据已改但 journal 说没改」（重跑产生重复）或反之（漏迁移）。
func MarkJournalDone(q dbtx, migrationID, fileID, kind string) error {
	_, err := q.Exec(
		`UPDATE migration_journal SET stage = 'done', last_error = '', updated_at = ?
		  WHERE migration_id = ? AND vault_id = ? AND file_id = ? AND kind = ?`,
		time.Now().Unix(), migrationID, DefaultVaultID, fileID, kind)
	return err
}

// MarkJournalFailed 记录失败原因并累加尝试次数（不阻止后续重试）。
func MarkJournalFailed(q dbtx, migrationID, fileID, kind, reason string) error {
	_, err := q.Exec(
		`UPDATE migration_journal
		    SET stage = 'failed', last_error = ?, attempt_count = attempt_count + 1, updated_at = ?
		  WHERE migration_id = ? AND vault_id = ? AND file_id = ? AND kind = ?`,
		truncateError(reason), time.Now().Unix(), migrationID, DefaultVaultID, fileID, kind)
	return err
}

// MarkJournalSkipped 标记为无需迁移（例如 v5 迁移遗留的伪 tombstone）。
func MarkJournalSkipped(q dbtx, migrationID, fileID, kind, reason string) error {
	_, err := q.Exec(
		`UPDATE migration_journal SET stage = 'skipped', last_error = ?, updated_at = ?
		  WHERE migration_id = ? AND vault_id = ? AND file_id = ? AND kind = ?`,
		truncateError(reason), time.Now().Unix(), migrationID, DefaultVaultID, fileID, kind)
	return err
}

// JournalCounts 返回各 stage 的条目数。
func JournalCounts(q dbtx, migrationID string) (map[string]int64, error) {
	rows, err := q.Query(
		`SELECT stage, COUNT(*) FROM migration_journal WHERE migration_id = ? GROUP BY stage`, migrationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var stage string
		var n int64
		if err := rows.Scan(&stage, &n); err != nil {
			return nil, err
		}
		out[stage] = n
	}
	return out, rows.Err()
}

// PendingJournal 返回尚未完成（pending / failed）的条目，用于续跑。
func PendingJournal(q dbtx, migrationID string, limit int) ([]JournalEntry, error) {
	rows, err := q.Query(
		`SELECT migration_id, vault_id, file_id, kind, source_format, target_format,
		        stage, last_error, attempt_count, updated_at
		 FROM migration_journal
		 WHERE migration_id = ? AND stage IN ('pending','failed')
		 ORDER BY attempt_count ASC, file_id ASC LIMIT ?`, migrationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]JournalEntry, 0, limit)
	for rows.Next() {
		var e JournalEntry
		if err := rows.Scan(&e.MigrationID, &e.VaultID, &e.FileID, &e.Kind, &e.SourceFormat,
			&e.TargetFormat, &e.Stage, &e.LastError, &e.AttemptCount, &e.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UnfinishedJournalCount 返回 pending + failed 的总数（verify 的前置条件）。
func UnfinishedJournalCount(q dbtx, migrationID string) (int64, error) {
	var n int64
	err := q.QueryRow(
		`SELECT COUNT(*) FROM migration_journal WHERE migration_id = ? AND stage IN ('pending','failed')`,
		migrationID).Scan(&n)
	return n, err
}

// ClearJournal 清空某次迁移的台账（迁移最终完成或放弃后调用）。
func ClearJournal(q dbtx, migrationID string) error {
	_, err := q.Exec(`DELETE FROM migration_journal WHERE migration_id = ?`, migrationID)
	return err
}

// truncateError 限制存入库的错误文本长度，并且绝不记录路径类信息由调用方保证。
func truncateError(s string) string {
	const max = 500
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
