package db

// 恢复后旋转**全部**仓库的 repoEpoch（ADR-007）。批次 G 发现的既有缺陷的回归：
// `obsync backup restore` 原本调用按 os.Args 判断 --all 的 rotateEpoch()，从 restore 路径
// 进来永远只转 default——多仓库部署里其他仓库的客户端会带着恢复点之前的旧游标继续增量同步。
// 现在 CLI（SQLite 部署）与 PG 恢复（导入事务内）都走 RotateAllEpochs。
//
// 覆盖：INV-02（世代前进：恢复后每个仓库的 epoch 都变化）、INV-12（逐仓库：一个都不能漏）。

import (
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func repoEpochs(t *testing.T, q dbtx) map[string]string {
	t.Helper()
	rows, err := q.Query(`SELECT vault_id, repo_epoch FROM repo_state`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, epoch string
		if err := rows.Scan(&id, &epoch); err != nil {
			t.Fatal(err)
		}
		out[id] = epoch
	}
	return out
}

func TestRotateAllEpochsCoversEveryVault(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "sync.db")) // 两种测试模式都跑
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for _, id := range []string{"v-alpha", "v-beta", "v-gamma"} {
		if _, err := d.Exec(`INSERT INTO vaults (vault_id, owner_id, name, secret, created_at) VALUES (?, 'u1', ?, ?, 0)`,
			id, id, []byte{1, 2, 3}); err != nil {
			t.Fatal(err)
		}
		if err := initRepoState(d, VaultScope{vaultID: id}); err != nil {
			t.Fatal(err)
		}
	}
	// 有 vaults 行、还没有任何同步状态的仓库：没有游标可作废，跳过而不是报错
	if _, err := d.Exec(`INSERT INTO vaults (vault_id, owner_id, name, secret, created_at) VALUES ('v-empty', 'u1', '', ?, 0)`, []byte{9}); err != nil {
		t.Fatal(err)
	}
	before := repoEpochs(t, d)
	if len(before) != 4 { // default（Open 写入）+ 3 个用户仓库
		t.Fatalf("fixture: repo_state rows = %v", before)
	}

	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := RotateAllEpochs(tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	after := repoEpochs(t, d)
	if len(rotated) != len(before) {
		t.Fatalf("rotated %d vaults, want every vault with sync state (%d): %+v", len(rotated), len(before), rotated)
	}
	for _, r := range rotated {
		if r.VaultID == "v-empty" {
			t.Fatal("a vault without repo_state has no cursor to invalidate and must be skipped")
		}
		if r.OldEpoch != before[r.VaultID] || r.NewEpoch != after[r.VaultID] || r.NewEpoch == r.OldEpoch {
			t.Fatalf("vault %s: reported %s→%s, db %s→%s", r.VaultID, r.OldEpoch, r.NewEpoch, before[r.VaultID], after[r.VaultID])
		}
	}
	for id, old := range before {
		if after[id] == old {
			t.Fatalf("vault %s kept its repoEpoch after a restore: stale cursors would silently skip changes", id)
		}
	}
}

// 恢复导入：复制、校验、旋转在同一个事务里；目标非空一律拒绝（不覆盖任何已有数据）。
// 目标先用 SQLite（两种模式都跑），设置了 LITESYNC_TEST_PG_DSN 时再对 PG 跑一遍。
func TestRestoreSnapshotIntoRotatesEveryVault(t *testing.T) {
	src, path := newBareSQLite(t)
	fillGeneric(t, src, 4)
	before := repoEpochs(t, src)
	src.Close()

	targets := map[string]func(t *testing.T) *sql.DB{
		"sqlite": func(t *testing.T) *sql.DB { d, _ := newBareSQLite(t); return d },
	}
	if testPostgresDSN() != "" {
		targets["postgres"] = freshPGTarget
	}
	for name, mk := range targets {
		t.Run(name, func(t *testing.T) {
			dst := mk(t)
			rep, rotated, err := RestoreSnapshotInto(path, dst)
			if err != nil || !rep.OK {
				t.Fatalf("restore import: %v %+v", err, rep)
			}
			if len(rotated) != len(before) {
				t.Fatalf("rotated %d of %d vaults: %+v", len(rotated), len(before), rotated)
			}
			after := repoEpochs(t, dst)
			for id, old := range before {
				if after[id] == "" || after[id] == old {
					t.Fatalf("vault %s: epoch %q → %q, must be rotated by the restore", id, old, after[id])
				}
			}
			// 校验比的是「快照原样」（旋转之前），所以报告里的每仓库摘要仍是旧 epoch
			for _, v := range rep.TargetVaults {
				if v.RepoEpoch != before[v.VaultID] {
					t.Fatalf("verification must compare the snapshot as-is (pre-rotation): %s %s vs %s", v.VaultID, v.RepoEpoch, before[v.VaultID])
				}
			}
			// 再恢复一次：目标非空 → 拒绝，且不改动已恢复的数据
			if _, _, err := RestoreSnapshotInto(path, dst); !errors.Is(err, ErrTargetNotEmpty) {
				t.Fatalf("restore into a non-empty target must be refused, got %v", err)
			}
			if again := repoEpochs(t, dst); !reflect.DeepEqual(again, after) {
				t.Fatalf("a refused restore must not touch the target: %v vs %v", again, after)
			}
		})
	}
}
