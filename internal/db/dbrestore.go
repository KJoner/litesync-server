package db

// 恢复到 PostgreSQL 与 epoch 协调（批次 G / MG-04 PG 分支 / ADR-007）。

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// RotatedEpoch 记录一次 repoEpoch 旋转（恢复报告用）。
type RotatedEpoch struct {
	VaultID  string `json:"vaultId"`
	OldEpoch string `json:"oldEpoch"`
	NewEpoch string `json:"newEpoch"`
}

// RotateAllEpochs 旋转**全部**仓库的 repoEpoch（ADR-007：恢复之后必须做）。
//
// 只转 default 是错的：多仓库部署里其他仓库的客户端会带着恢复点之前的旧游标继续增量
// 同步，静默跳过「恢复点之后曾经存在」的那段 sequence。仓库集合 = vaults 表 ∪ repo_state
// （旧库可能只有 repo_state 里的 default 行）。
func RotateAllEpochs(q dbtx) ([]RotatedEpoch, error) {
	scopes, err := AllVaultScopes(q)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, s := range scopes {
		seen[s.ID()] = true
	}
	rows, err := q.Query(`SELECT vault_id FROM repo_state`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		if !seen[id] {
			seen[id] = true
			scopes = append(scopes, VaultScope{vaultID: id})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].ID() < scopes[j].ID() })
	out := make([]RotatedEpoch, 0, len(scopes))
	for _, s := range scopes {
		var old string
		err := q.QueryRow(`SELECT repo_epoch FROM repo_state WHERE vault_id = ?`, s.ID()).Scan(&old)
		if errors.Is(err, sql.ErrNoRows) {
			continue // vaults 里有、repo_state 里没有：还没有任何同步状态，无游标可作废
		}
		if err != nil {
			return nil, err
		}
		epoch, err := RotateEpoch(q, s)
		if err != nil {
			return nil, fmt.Errorf("rotate vault %s: %w", s.ID(), err)
		}
		out = append(out, RotatedEpoch{VaultID: s.ID(), OldEpoch: old, NewEpoch: epoch})
	}
	return out, nil
}

// RestoreSnapshotInto 把一份可移植快照（备份里的 sync.db：SQLite 部署的 VACUUM INTO，
// 或 PG 部署导出的 SQLite 文件）导入一个**空的**目标库，并在**同一个事务**里：
// 复制 → 逐表/每仓库校验 → 旋转全部仓库的 repoEpoch。
//
// 要么目标得到「已校验且已旋转」的完整数据，要么什么都没有——不存在「数据已在、
// epoch 没转」的中间态，也就不存在「服务被提前启动、旧游标增量同步漏掉变更」的窗口。
func RestoreSnapshotInto(snapshotPath string, dst *sql.DB) (*CopyReport, []RotatedEpoch, error) {
	start := time.Now()
	rep := newReport("snapshot->"+dialectOf(dst), "restore")
	src, err := OpenSQLiteReadOnly(snapshotPath)
	if err != nil {
		return rep, nil, fmt.Errorf("open snapshot: %w", err)
	}
	defer src.Close()
	if err := CreateSchemaOnly(dst); err != nil {
		return rep, nil, err
	}
	stx, err := beginSnapshot(src)
	if err != nil {
		return rep, nil, err
	}
	defer stx.Rollback() //nolint:errcheck
	s := copySide{q: stx}
	plan, err := planCopy(s, copySide{q: dst, pg: IsPostgres(dst)}, rep)
	if err != nil {
		return rep, nil, err
	}
	if n, err := nonEmptyTables(dst, plan); err != nil {
		return rep, nil, err
	} else if len(n) > 0 {
		rep.Problems = append(rep.Problems, "restore target is not empty: "+strings.Join(n, ", "))
		return rep, nil, ErrTargetNotEmpty
	}
	tx, err := dst.Begin()
	if err != nil {
		return rep, nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	for _, p := range plan {
		if err := copyTable(stx, tx, p); err != nil {
			return rep, nil, fmt.Errorf("copy %s: %w", p.table, err)
		}
	}
	hw, err := seqHighWater(s)
	if err != nil {
		return rep, nil, err
	}
	d := copySide{q: tx, pg: IsPostgres(dst)}
	if err := applySeqHighWater(d, hw); err != nil {
		return rep, nil, err
	}
	// 校验在事务内、旋转之前：比的是「快照原样」
	if err := verifyPlan(s, d, plan, rep); err != nil {
		return rep, nil, err
	}
	rotated, err := RotateAllEpochs(tx)
	if err != nil {
		return rep, nil, err
	}
	if err := tx.Commit(); err != nil {
		return rep, nil, err
	}
	rep.DurationMs = time.Since(start).Milliseconds()
	return rep, rotated, nil
}

// ReferencedBlobIDs 返回元数据引用的全部 blob id（HEAD 与历史版本，去重、排序）。
// 备份/恢复用它核对「元数据引用的 blob 都在」——缺失必须明确报告（MG-04）。
func ReferencedBlobIDs(q dbtx) ([]string, error) {
	rows, err := q.Query(`SELECT blob_id FROM file_heads WHERE blob_id <> ''
		UNION SELECT blob_id FROM object_versions WHERE blob_id <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id sql.NullString
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if id.Valid && id.String != "" {
			out = append(out, id.String)
		}
	}
	sort.Strings(out)
	return out, rows.Err()
}
