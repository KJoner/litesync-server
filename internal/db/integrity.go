package db

import (
	"database/sql"
	"time"
)

// 完整性事件账本（v0.13.3 / 计划书 §7.1、§7.2）。
//
// 为什么需要一张表而不是只写日志：
//
//  1. 「这个 blob 已知是坏的」必须能被**下载路径**便宜地查到——发现损坏之后
//     还继续把损坏内容返回给客户端，是这一节明确禁止的；
//  2. 日志会轮转，而「某份内容曾经损坏过」是需要长期保留的事实；
//  3. 运维接口要能列出待处理的完整性问题，而不是让人去 grep 日志。
//
// 表里只存 blob hash 与错误分类——不存路径、不存 fileId 之外的任何用户信息。

// IntegrityEvent 是一条完整性事件。
type IntegrityEvent struct {
	BlobID     string
	Kind       string // missing / size-mismatch / hash-mismatch / unreadable
	Detail     string // 隔离副本位置等（不含用户路径）
	DetectedAt int64
	// Serving 为 false 表示该 blob 不得再对外返回
	Serving  bool
	Resolved bool
	// AffectedRefs：检测时该 blob 被多少个 HEAD/版本引用（重新检查引用的结果）
	AffectedRefs int
}

const integritySchema = `
CREATE TABLE IF NOT EXISTS integrity_events (
	blob_id       TEXT PRIMARY KEY,
	kind          TEXT NOT NULL,
	detail        TEXT NOT NULL DEFAULT '',
	detected_at   INTEGER NOT NULL,
	serving       INTEGER NOT NULL DEFAULT 0,
	resolved      INTEGER NOT NULL DEFAULT 0,
	affected_refs INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_integrity_unresolved ON integrity_events(resolved, detected_at);
`

// RecordIntegrityEvent 登记（或更新）一条完整性事件。
//
// serving=false 会立刻让下载路径拒绝这个 blob。这是有意为之的「宁可报错也不
// 返回可疑内容」：客户端拿到 404/500 会重试或报警，拿到损坏内容则会把它
// 当成真实内容写进用户的 Vault。
func RecordIntegrityEvent(q dbtx, e *IntegrityEvent) error {
	if e.DetectedAt == 0 {
		e.DetectedAt = time.Now().Unix()
	}
	_, err := q.Exec(`
		INSERT INTO integrity_events (blob_id, kind, detail, detected_at, serving, resolved, affected_refs)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(blob_id) DO UPDATE SET
			kind = excluded.kind,
			detail = excluded.detail,
			detected_at = excluded.detected_at,
			serving = excluded.serving,
			resolved = excluded.resolved,
			affected_refs = excluded.affected_refs`,
		e.BlobID, e.Kind, e.Detail, e.DetectedAt, boolToInt(e.Serving), boolToInt(e.Resolved), e.AffectedRefs)
	return err
}

// ResolveIntegrityEvent 在 blob 被正确内容替换后把它标记为已恢复并重新可服务。
func ResolveIntegrityEvent(q dbtx, blobID string) error {
	_, err := q.Exec(`UPDATE integrity_events SET resolved = 1, serving = 1 WHERE blob_id = ?`, blobID)
	return err
}

// BlobServable 返回该 blob 是否允许对外返回。
// 没有事件记录 = 从未发现问题 = 可服务（绝大多数调用走这条路径）。
func BlobServable(q dbtx, blobID string) (bool, error) {
	var serving int
	err := q.QueryRow(`SELECT serving FROM integrity_events WHERE blob_id = ? AND resolved = 0`, blobID).Scan(&serving)
	if err == sql.ErrNoRows {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return serving == 1, nil
}

// ListIntegrityEvents 列出事件（运维接口用）；onlyUnresolved 为 true 时只列未恢复的。
func ListIntegrityEvents(q dbtx, onlyUnresolved bool) ([]IntegrityEvent, error) {
	query := `SELECT blob_id, kind, detail, detected_at, serving, resolved, affected_refs
		FROM integrity_events`
	if onlyUnresolved {
		query += ` WHERE resolved = 0`
	}
	query += ` ORDER BY detected_at DESC`
	rows, err := q.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IntegrityEvent
	for rows.Next() {
		var e IntegrityEvent
		var serving, resolved int
		if err := rows.Scan(&e.BlobID, &e.Kind, &e.Detail, &e.DetectedAt, &serving, &resolved, &e.AffectedRefs); err != nil {
			return nil, err
		}
		e.Serving = serving == 1
		e.Resolved = resolved == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountBlobReferences 统计某个 blob 被多少个 live HEAD 与历史版本引用。
// §7.1 第 6 步「重新检查所有引用」用它来说明这次损坏影响了多大范围。
func CountBlobReferences(q dbtx, blobID string) (int, error) {
	return CountBlobReferencesIn(q, LegacyDefaultScope(), blobID)
}

// CountBlobReferencesIn 统计**某个租户内**引用该 blob 的 HEAD 与历史版本数量。
//
// 必须带范围。不带的话，「这个 blob 被引用了几次」会跨租户求和——
// 那不只是数字不准：它把「别的租户有没有这份内容」变成一个可观测量，
// 正是 §10.3 花力气关掉的那个存在性预言机。
//
// 域化之后跨租户撞上同一个 blobID 在密码学上不可能，所以今天这里返回的
// 结果不会变；带上范围是为了让这条查询**在结构上**就问不出别人的事。
func CountBlobReferencesIn(q dbtx, s VaultScope, blobID string) (int, error) {
	if !s.Valid() {
		return 0, ErrVaultScopeMissing
	}
	var heads, versions int
	if err := q.QueryRow(`SELECT COUNT(*) FROM file_heads WHERE vault_id = ? AND blob_id = ?`,
		s.ID(), blobID).Scan(&heads); err != nil {
		return 0, err
	}
	if err := q.QueryRow(`SELECT COUNT(*) FROM object_versions WHERE vault_id = ? AND blob_id = ?`,
		s.ID(), blobID).Scan(&versions); err != nil {
		return 0, err
	}
	return heads + versions, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
