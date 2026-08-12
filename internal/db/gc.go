package db

import (
	"time"
)

// GC 候选台账（v0.13.3 / 计划书 §7.3）。
//
// 「保留两轮确认」如果只放在内存里，重启就会清零——而一台经常重启的服务器
// 会永远攒不够两轮，孤儿 blob 于是永不回收。所以候选状态必须落盘。
//
// 反过来，落盘也让这条规则可测试：先跑一轮确认候选入册，再跑一轮确认删除。

const gcSchema = `
CREATE TABLE IF NOT EXISTS gc_candidates (
	blob_id       TEXT PRIMARY KEY,
	first_seen_at INTEGER NOT NULL,
	rounds        INTEGER NOT NULL DEFAULT 1
);
`

// MarkGCCandidate 记录「本轮认为这个 blob 无引用」，返回它累计被确认了几轮。
// 返回 >= 2 时调用方才允许删除。
func MarkGCCandidate(q dbtx, blobID string, now int64) (int, error) {
	if now == 0 {
		now = time.Now().Unix()
	}
	if _, err := q.Exec(`
		INSERT INTO gc_candidates (blob_id, first_seen_at, rounds) VALUES (?, ?, 1)
		ON CONFLICT(blob_id) DO UPDATE SET rounds = rounds + 1`, blobID, now); err != nil {
		return 0, err
	}
	var rounds int
	if err := q.QueryRow(`SELECT rounds FROM gc_candidates WHERE blob_id = ?`, blobID).Scan(&rounds); err != nil {
		return 0, err
	}
	return rounds, nil
}

// ClearGCCandidate 在 blob 重新被引用（去重命中、restore 等）时撤销候选状态。
// 漏掉这一步会让一个「曾经无引用、现在有引用」的 blob 攒够轮次后被删掉。
func ClearGCCandidate(q dbtx, blobID string) error {
	_, err := q.Exec(`DELETE FROM gc_candidates WHERE blob_id = ?`, blobID)
	return err
}

// CountGCCandidates 返回当前候选数量（运维可见性）。
func CountGCCandidates(q dbtx) (int, error) {
	var n int
	err := q.QueryRow(`SELECT COUNT(*) FROM gc_candidates`).Scan(&n)
	return n, err
}
