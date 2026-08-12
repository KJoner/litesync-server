package db

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"
)

// 存量 blob 的 Vault 域化迁移（v0.16.0 / 计划书 §10.3、ADR-010 §8 第 4 步）。
//
// 单用户阶段 blobID 就是内容 sha256。多租户上线后要改成
// HMAC(vaultSecret, contentHash)，因此磁盘上每个 blob 都要改名，
// 并且 file_heads / object_versions 里的 blob_id 引用要同步更新。
//
// # 为什么必须走 journal
//
// 这一步会逐个改名成千上万个文件。中途崩溃是必然要考虑的，而失败模式
// 只允许是「改到一半，journal 记着进度，续跑即可」——**绝不能**是
// 「一半的 HEAD 指向不存在的 blob」。
//
// # 为什么单向不可回滚
//
// 改名之后，旧代码按裸 contentHash 找不到任何 blob。因此：
//   - 迁移前必须有一次完整备份；
//   - 触发时要求**显式确认**，和 metadata migration 的 complete 一样。

// BlobIDMigrationID 是这次迁移在 journal 里的标识。
const BlobIDMigrationID = "blobid-vault-domain"

// BlobRenamer 由 storage 层实现：把一个 blob 从旧 id 改名到新 id。
//
// 实现必须是**幂等**的：新 id 已存在且旧 id 已不在时返回 nil，
// 这样续跑时重做同一条不会失败。
type BlobRenamer interface {
	RenameBlob(oldID, newID string) error
	// NewBlobID 按该 Vault 的 secret 计算新 id
	NewBlobID(vaultSecret []byte, contentHash string) string
}

// BlobIDMigrationReport 是一次迁移的结果。
type BlobIDMigrationReport struct {
	Planned  int
	Renamed  int
	Skipped  int // 已经是新 id（续跑时重做的那些）
	Failed   int
	Duration time.Duration
}

// NeedsBlobIDMigration 报告是否还有未迁移的 blob 引用。
func NeedsBlobIDMigration(d *sql.DB) (bool, error) {
	n, err := UnfinishedJournalCount(d, BlobIDMigrationID)
	if err != nil {
		return false, err
	}
	if n > 0 {
		return true, nil
	}
	// journal 为空且从未跑过 → 看有没有 blob 引用存在
	var total int
	if err := d.QueryRow(`SELECT COUNT(*) FROM file_heads WHERE blob_id != ''`).Scan(&total); err != nil {
		return false, err
	}
	var done int
	if err := d.QueryRow(
		`SELECT COUNT(*) FROM migration_journal WHERE migration_id = ? AND stage = 'done'`,
		BlobIDMigrationID).Scan(&done); err != nil {
		return false, err
	}
	return total > 0 && done == 0, nil
}

// MigrateBlobIDs 把某个 Vault 的全部 blob 引用改为域化 id。
//
// confirm 为 false 时只做 dry-run（登记 journal、报告计划量，不改任何文件）。
// 这与 metadata migration 的 complete 一致：不可逆的动作必须显式确认。
func MigrateBlobIDs(d *sql.DB, s VaultScope, secret []byte, r BlobRenamer, confirm bool, log *slog.Logger) (*BlobIDMigrationReport, error) {
	if !s.Valid() {
		return nil, ErrVaultScopeMissing
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("vault secret is required")
	}
	start := time.Now()
	rep := &BlobIDMigrationReport{}

	// 1) 收集全部待迁移引用：live HEAD 与历史版本共用同一个 blob，
	//    因此按 (blob_id, content_hash) 去重，一个 blob 只改一次名
	type ref struct{ blobID, contentHash string }
	rows, err := d.Query(`
		SELECT DISTINCT blob_id, content_hash FROM file_heads
		 WHERE vault_id = ? AND blob_id != ''
		UNION
		SELECT DISTINCT blob_id, content_hash FROM object_versions
		 WHERE vault_id = ? AND blob_id != ''`, s.ID(), s.ID())
	if err != nil {
		return nil, err
	}
	var refs []ref
	for rows.Next() {
		var x ref
		if err := rows.Scan(&x.blobID, &x.contentHash); err != nil {
			rows.Close()
			return nil, err
		}
		refs = append(refs, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rep.Planned = len(refs)

	if !confirm {
		log.Info("blobid migration dry-run", "vault", s.ID(), "planned", rep.Planned)
		rep.Duration = time.Since(start)
		return rep, nil
	}

	// 2) 逐个改名。每条都是「先改文件、再改引用、最后记 done」——
	//    顺序反过来的话，崩溃会留下指向不存在 blob 的引用
	for _, x := range refs {
		newID := r.NewBlobID(secret, x.contentHash)
		if newID == x.blobID {
			rep.Skipped++ // 续跑时已经改过的
			continue
		}
		if err := EnqueueJournal(d, BlobIDMigrationID, x.blobID, "blob", "sha256", "vault-hmac"); err != nil {
			return rep, err
		}
		if err := r.RenameBlob(x.blobID, newID); err != nil {
			rep.Failed++
			MarkJournalFailed(d, BlobIDMigrationID, x.blobID, "blob", err.Error()) //nolint:errcheck
			log.Error("blobid migration: rename failed", "blob", x.blobID[:12], "error", err)
			continue
		}
		if err := repointBlobReferences(d, s, x.blobID, newID); err != nil {
			// 文件已改名但引用没改：这是最危险的中间态。
			// 立刻把文件改回去，回到可重试的状态
			if rerr := r.RenameBlob(newID, x.blobID); rerr != nil {
				return rep, fmt.Errorf(
					"引用更新失败且未能回滚改名（blob %s → %s）；必须人工处理: %w", x.blobID[:12], newID[:12], err)
			}
			rep.Failed++
			MarkJournalFailed(d, BlobIDMigrationID, x.blobID, "blob", err.Error()) //nolint:errcheck
			continue
		}
		if err := MarkJournalDone(d, BlobIDMigrationID, x.blobID, "blob"); err != nil {
			return rep, err
		}
		rep.Renamed++
	}

	rep.Duration = time.Since(start)
	log.Info("blobid migration complete", "vault", s.ID(),
		"planned", rep.Planned, "renamed", rep.Renamed, "skipped", rep.Skipped, "failed", rep.Failed)
	return rep, nil
}

// repointBlobReferences 在一个事务里把某 Vault 的所有引用指向新 id。
func repointBlobReferences(d *sql.DB, s VaultScope, oldID, newID string) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec(`UPDATE file_heads SET blob_id = ? WHERE vault_id = ? AND blob_id = ?`,
		newID, s.ID(), oldID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE object_versions SET blob_id = ? WHERE vault_id = ? AND blob_id = ?`,
		newID, s.ID(), oldID); err != nil {
		return err
	}
	return tx.Commit()
}
