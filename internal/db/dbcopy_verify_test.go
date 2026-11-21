package db

// 复审 SV-03：导入与校验在**同一个目标事务**里（参照 RestoreSnapshotInto）——
//   - 校验阶段失败（注入 / 目标写入的数据与源不一致）→ 整体回滚，目标没有任何提交，targetState=untouched；
//   - 修正后对同一个（仍为空的）目标重跑成功；
//   - 提交调用失败如实报告 commit-unknown；
//   - 目标非空一律拒绝且不写任何东西。
// SQLite 目标与真实 PostgreSQL 目标各跑一遍（PG 子测试在设置 LITESYNC_TEST_PG_DSN 的轮次运行）。
// 覆盖 INV-11（迁移可恢复、可重复、幂等；校验不通过不得留下半套数据）。

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/KJoner/litesync-server/internal/failpoint"
)

func rowTotal(t *testing.T, d *sql.DB) int64 {
	t.Helper()
	tables, err := listTables(copySide{q: d, pg: IsPostgres(d)})
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, tb := range tables {
		var n int64
		if err := d.QueryRow(`SELECT COUNT(*) FROM ` + quoteIdent(tb)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		total += n
	}
	return total
}

func copyTargets(t *testing.T) map[string]func(t *testing.T) *sql.DB {
	return map[string]func(t *testing.T) *sql.DB{
		"sqlite":   func(t *testing.T) *sql.DB { d, _ := newBareSQLite(t); return d },
		"postgres": freshPGTarget, // 没有 LITESYNC_TEST_PG_DSN 时跳过；PG 测试轮次必跑
	}
}

func TestCopyVerifyFailureCommitsNothingAndRerunSucceeds(t *testing.T) {
	for name, newTarget := range copyTargets(t) {
		t.Run(name, func(t *testing.T) {
			dst := newTarget(t)
			src, _ := newBareSQLite(t)
			fillGeneric(t, src, 3)

			off := failpoint.EnableError(failpoint.DBCopyVerify, 1)
			rep, err := CopyDatabase(src, dst)
			off()
			if err == nil || rep.TargetState != TargetUntouched || rep.OK {
				t.Fatalf("a verification failure must be reported as untouched: err=%v state=%q ok=%v", err, rep.TargetState, rep.OK)
			}
			if empty, n, err := TargetIsEmpty(dst); err != nil || !empty {
				t.Fatalf("verification failed but the target has data: %v %v", n, err)
			}

			// 修正后对同一个（仍为空的）目标重跑
			rep = mustCopy(t, src, dst)
			if rep.TargetState != TargetCommittedVerified {
				t.Fatalf("rerun state = %q", rep.TargetState)
			}

			// 目标非空保护：再跑直接拒绝，且一行都不写
			before := rowTotal(t, dst)
			if rep, err := CopyDatabase(src, dst); !errors.Is(err, ErrTargetNotEmpty) || rep.TargetState != TargetUntouched {
				t.Fatalf("copy into a non-empty target = %v (state %q), want ErrTargetNotEmpty / untouched", err, rep.TargetState)
			}
			if after := rowTotal(t, dst); after != before {
				t.Fatalf("a refused copy changed the target: %d -> %d rows", before, after)
			}
		})
	}
}

// 不是注入：目标在写入时把数据改了（SQLite 触发器），逐表摘要对不上 → 整体回滚，报告点名差异的表。
func TestCopyRealDivergenceInsideTheTransactionRollsBack(t *testing.T) {
	src, _ := newBareSQLite(t)
	fillGeneric(t, src, 3)
	dst, _ := newBareSQLite(t)
	if _, err := dst.Exec(`CREATE TRIGGER sv03_corrupt AFTER INSERT ON file_heads
		BEGIN UPDATE file_heads SET size = size + 1 WHERE rowid = NEW.rowid; END`); err != nil {
		t.Fatal(err)
	}
	rep, err := CopyDatabase(src, dst)
	if err == nil || rep.TargetState != TargetUntouched {
		t.Fatalf("divergent copy must fail and leave the target untouched: err=%v state=%q", err, rep.TargetState)
	}
	if !strings.Contains(strings.Join(rep.Problems, ";"), "file_heads") {
		t.Fatalf("the report must name the differing table: %v", rep.Problems)
	}
	if empty, n, err := TargetIsEmpty(dst); err != nil || !empty {
		t.Fatalf("divergent copy left data in the target: %v %v", n, err)
	}
}

// 提交调用本身失败：结果不确定，必须报告 commit-unknown（运维据此先检查目标再决定），而不是「没有提交」。
func TestCopyCommitFailureIsReportedAsUnknown(t *testing.T) {
	for name, newTarget := range copyTargets(t) {
		t.Run(name, func(t *testing.T) {
			dst := newTarget(t)
			src, _ := newBareSQLite(t)
			fillGeneric(t, src, 2)
			off := failpoint.EnableError(failpoint.DBCopyCommit, 1)
			rep, err := CopyDatabase(src, dst)
			off()
			if err == nil || rep.TargetState != TargetCommitUnknown {
				t.Fatalf("commit failure = %v, state %q; want commit-unknown", err, rep.TargetState)
			}
		})
	}
}
