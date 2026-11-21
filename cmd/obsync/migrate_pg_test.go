package main

// `obsync migrate-to-pg` 的失败语义（复审 SV-03），在真实 PostgreSQL 上逐项断言：
//   - 源库停写前置条件是机器检查：服务持有数据目录锁时直接拒绝，什么都不读不写；
//   - 校验阶段失败：报告 targetState=untouched，错误信息说明「事务已回滚、没有提交」，目标确实为空，不写标记；
//   - 迁移期间源库被写（二次快照比对失败）：targetState=copied-not-enabled，目标保留但不写标记；
//   - 对这个与源库不一致的非空目标重跑：拒绝，目标不动；
//   - 换一个新的空库重跑：committed-verified + 标记；再跑一次 = already-migrated（幂等）。
// 需要 LITESYNC_TEST_PG_DSN（scripts/test-pg.sh 的 PG 轮次与 CI 的 PG job 都会设置；SQLite 轮次跳过）。
// 覆盖 INV-11。

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KJoner/litesync-server/internal/datalock"
	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/failpoint"
)

func freshSchemaDSN(t *testing.T) string {
	t.Helper()
	base := os.Getenv("LITESYNC_TEST_PG_DSN")
	if base == "" {
		t.Skip("需要真实 PostgreSQL（LITESYNC_TEST_PG_DSN）：在 PG 测试轮次运行")
	}
	raw := make([]byte, 6)
	rand.Read(raw) //nolint:errcheck
	schema := "mig_" + hex.EncodeToString(raw)
	admin, err := db.OpenPostgresRaw(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) //nolint:errcheck
		admin.Close()
	})
	return db.WithSearchPath(base, schema)
}

func targetRows(t *testing.T, dsn string) (empty bool, tables []string) {
	t.Helper()
	d, err := db.OpenPostgresRaw(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if ok, err := db.TableExists(d, "users"); err != nil || !ok {
		return true, nil // 连表都还没建
	}
	empty, tables, err = db.TargetIsEmpty(d)
	if err != nil {
		t.Fatal(err)
	}
	return empty, tables
}

func TestMigrateToPGFailureSemantics(t *testing.T) {
	dsn := freshSchemaDSN(t)
	dataDir := t.TempDir()
	srcPath := filepath.Join(dataDir, "sync.db")
	src, err := db.OpenSQLiteFile(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.EnsureAdminUser(src, db.HashToken("migrate-test-token-0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.CreateOIDCUser(src, "https://idp.example/realms/x", "sub-1", db.IdentityProfile{Email: "a@example.org"}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	src.Close()
	t.Setenv("OBSYNC_DATA_DIR", dataDir)
	t.Setenv("OBSYNC_PG_DSN", dsn)
	reportPath := filepath.Join(t.TempDir(), "report.json")
	run := func() (error, migrationOutput) {
		t.Helper()
		os.Remove(reportPath) //nolint:errcheck
		err := runMigrateToPG([]string{"--report", reportPath})
		var out migrationOutput
		raw, rerr := os.ReadFile(reportPath)
		if rerr != nil {
			t.Fatalf("no report written: %v", rerr)
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return err, out
	}
	marker := filepath.Join(dataDir, migratedMarkerName)

	// 1) 服务还在运行（持有数据目录锁）→ 拒绝；目标一行都没写
	lk, err := datalock.Acquire(dataDir, "fake-running-server")
	if err != nil {
		t.Fatal(err)
	}
	err, out := run()
	lk.Release() //nolint:errcheck
	if err == nil || out.OK || !strings.Contains(out.Error, "still running") {
		t.Fatalf("a running server must block the migration: %v %+v", err, out)
	}
	if empty, n := targetRows(t, dsn); !empty {
		t.Fatalf("a refused migration wrote to the target: %v", n)
	}

	// 2) 校验阶段失败 → untouched，且这句话是真的
	off := failpoint.EnableError(failpoint.DBCopyVerify, 1)
	err, out = run()
	off()
	if err == nil || out.TargetState != db.TargetUntouched || !strings.Contains(out.Error, "nothing was committed") {
		t.Fatalf("verification failure: %v %+v", err, out)
	}
	if empty, n := targetRows(t, dsn); !empty {
		t.Fatalf("verification failed but the target has data: %v", n)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a failed migration must not write the marker")
	}
	if out.SourceLock != "held-by-this-run" {
		t.Fatalf("source lock = %q", out.SourceLock)
	}

	// 3) 迁移期间源库被写（绕过锁的写入）→ copied-not-enabled，不写标记
	failpoint.Enable(failpoint.MigrateBeforePostCheck, 1, func() error {
		w, err := db.OpenSQLiteFile(srcPath)
		if err != nil {
			return err
		}
		defer w.Close()
		_, err = w.Exec(`UPDATE users SET display_name = 'changed during migration' WHERE user_id = 'default'`)
		return err
	})
	err, out = run()
	failpoint.Disable(failpoint.MigrateBeforePostCheck)
	if err == nil || out.TargetState != "copied-not-enabled" || !strings.Contains(out.Error, "NOT enabled") {
		t.Fatalf("source changed during migration: %v %+v", err, out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("copied-not-enabled must not write the marker")
	}

	// 4) 对这个与源库不一致的非空目标重跑 → 拒绝，目标不动
	_, before := targetRows(t, dsn)
	err, out = run()
	if err == nil || !strings.Contains(out.Error, "not empty") {
		t.Fatalf("rerun against a divergent non-empty target must be refused: %v %+v", err, out)
	}
	if _, after := targetRows(t, dsn); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("a refused rerun changed the target: %v -> %v", before, after)
	}

	// 5) 新的空库：成功 + 标记；再跑一次 = 只校验
	t.Setenv("OBSYNC_PG_DSN", freshSchemaDSN(t))
	err, out = run()
	if err != nil || !out.OK || out.TargetState != db.TargetCommittedVerified {
		t.Fatalf("migration into a fresh database: %v %+v", err, out)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("marker missing after success: %v", err)
	}
	err, out = run()
	if err != nil || !out.OK || out.TargetState != "already-migrated" {
		t.Fatalf("idempotent rerun: %v %+v", err, out)
	}
}
