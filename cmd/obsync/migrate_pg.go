package main

// SQLite → PostgreSQL 迁移与反向导出（批次 G / 迁移方案 M6、M7、需求 §12.4）。
//
//	obsync migrate-to-pg --dry-run [--source PATH] [--report PATH]
//	obsync migrate-to-pg            [--source PATH] [--report PATH]
//	obsync export-sqlite --out PATH [--report PATH]
//
// 目标库连接串只从环境变量 OBSYNC_PG_DSN 取，不接受命令行参数（会进 shell 历史与进程
// 列表），也不出现在任何输出里。标准输出是机器可读的 JSON 报告；说明文字走标准错误。

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KJoner/litesync-server/internal/datalock"
	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/failpoint"
)

const migrateUsage = `用法：
  obsync migrate-to-pg --dry-run [--source PATH] [--report PATH]
      只读源库（默认 $OBSYNC_DATA_DIR/sync.db）：结构兼容性检查 + 逐表行数 + 每仓库摘要。不连接目标库。
  obsync migrate-to-pg [--source PATH] [--report PATH]
      正式导入到 OBSYNC_PG_DSN。目标库必须为空；若目标已有数据且与源库逐表一致，视为「已完成」，
      只校验（幂等）；不一致则拒绝，源库与目标库都不动。
      前置条件（机器检查）：源库所在数据目录的服务锁（.obsync-server.lock）必须能取得——运行中的
      LiteSync 服务持有它，拿不到即拒绝；迁移期间本命令持有它，服务无法在迁移中途启动。
      导入与校验在目标库的同一个事务里：校验不通过整体回滚，目标没有任何提交（targetState=untouched）。
  obsync export-sqlite --out PATH [--report PATH]
      PostgreSQL（OBSYNC_PG_DSN）→ 新的 SQLite 文件，导出后逐表校验：切换后的回退路径。
`

type migrationOutput struct {
	Tool      string         `json:"tool"`
	Version   string         `json:"version"`
	Source    string         `json:"source"`
	Target    string         `json:"target"`
	Result    *db.CopyReport `json:"result"`
	PostCheck *db.CopyReport `json:"postCheck,omitempty"`
	OK        bool           `json:"ok"`
	Error     string         `json:"error,omitempty"`
	// TargetState：目标库最后的状态（复审 SV-03：失败时如实告诉运维目标里有没有东西）——
	// untouched（没有任何提交）/ committed-verified / commit-unknown（提交结果不确定，先检查目标是否为空）/
	// copied-not-enabled（已复制并校验，但源库在迁移期间变了：目标保留、未启用，不得在它上面启动服务）/
	// already-migrated（目标与源库逐表一致，本次只校验）
	TargetState string `json:"targetState,omitempty"`
	// SourceLock：源库停写前置条件的机器检查结果（held-by-this-run / unsupported:<原因>）
	SourceLock string   `json:"sourceLock,omitempty"`
	Next       []string `json:"next,omitempty"`
}

// migrationSteps 是正式迁移的严格操作步骤（命令输出与 README 同一份）。
var migrationSteps = []string{
	"1. obsync backup create（或 cp 一份数据目录）——迁移是单向的，回退只能走 export-sqlite",
	"2. 停止 LiteSync 服务（docker compose stop obsync）；本命令会检查数据目录锁，服务没停会直接拒绝",
	"3. 准备一个空的 PostgreSQL 库（TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'），设置 OBSYNC_PG_DSN",
	"4. obsync migrate-to-pg --dry-run，确认报告 ok=true",
	"5. obsync migrate-to-pg；ok=true 且 targetState=committed-verified 才算成功",
	"6. 设置 OBSYNC_DB=postgres（保留 OBSYNC_PG_DSN）后启动服务；旧 sync.db 只读保留",
	"失败时看 targetState：untouched = 目标没有提交，修正问题后直接重跑；commit-unknown / copied-not-enabled = 不要在这个库上启动服务，换一个新的空库重跑",
}

func emitReport(out *migrationOutput, reportPath string) {
	raw, _ := json.MarshalIndent(out, "", "  ") //nolint:errcheck
	fmt.Println(string(raw))
	if reportPath != "" {
		if err := os.WriteFile(reportPath, raw, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "写报告失败：", err)
		} else {
			fmt.Fprintln(os.Stderr, "报告已写入", reportPath)
		}
	}
}

func runMigrateToPG(args []string) error {
	if hasFlag(args, "-h") || hasFlag(args, "--help") {
		fmt.Print(migrateUsage)
		return nil
	}
	dataDir := dataDirFromEnv()
	source := flagValue(args, "--source")
	if source == "" {
		source = filepath.Join(dataDir, "sync.db")
	}
	reportPath := flagValue(args, "--report")
	if reportPath == "" {
		reportPath = filepath.Join(dataDir, "migrate-to-pg-report.json")
	}
	out := &migrationOutput{Tool: "obsync migrate-to-pg", Version: version, Source: source,
		Target: "postgres (OBSYNC_PG_DSN, not shown)"}
	fail := func(err error) error {
		out.OK, out.Error = false, err.Error()
		emitReport(out, reportPath)
		return err
	}

	src, err := db.OpenSQLiteReadOnly(source)
	if err != nil {
		return fail(fmt.Errorf("open source %s: %w", source, err))
	}
	defer src.Close()

	if hasFlag(args, "--dry-run") {
		out.Target = "none (dry-run does not connect to the target)"
		rep, err := db.DryRunCopy(src)
		out.Result = rep
		if err != nil {
			return fail(err)
		}
		out.OK = rep.OK
		out.Next = []string{"stop the LiteSync server", "set OBSYNC_PG_DSN", "run `obsync migrate-to-pg` (without --dry-run)"}
		emitReport(out, reportPath)
		return nil
	}

	dsn := os.Getenv("OBSYNC_PG_DSN")
	if dsn == "" {
		return fail(errors.New("OBSYNC_PG_DSN is not set (the target connection string is read from the environment only)"))
	}
	fmt.Fprintln(os.Stderr, "正式迁移的严格步骤：")
	for _, step := range migrationSteps {
		fmt.Fprintln(os.Stderr, "  "+step)
	}
	// 源库停写的机器检查（复审 SV-03）：运行中的服务持有数据目录锁；拿不到 = 服务还在运行。
	// 拿到之后整个迁移期间持有，服务也无法在迁移中途被启动。
	lock, lerr := datalock.Acquire(filepath.Dir(source), "migrate-to-pg")
	switch {
	case errors.Is(lerr, datalock.ErrHeld):
		holder := strings.TrimSpace(datalock.Holder(filepath.Dir(source)))
		return fail(fmt.Errorf("the LiteSync server is still running on this data directory (lock held: %s); "+
			"stop it first (docker compose stop obsync) — nothing was read or written", holder))
	case lerr != nil:
		out.SourceLock = "unsupported: " + lerr.Error()
		fmt.Fprintln(os.Stderr, "警告：这个文件系统上取不到数据目录锁（"+lerr.Error()+"），无法机器确认服务已停止——"+
			"请人工确认服务已停止；迁移结束后的二次快照比对仍会发现迁移期间的写入。")
	default:
		out.SourceLock = "held-by-this-run"
		defer lock.Release() //nolint:errcheck
	}
	dst, err := db.OpenPostgresRaw(dsn)
	if err != nil {
		return fail(err)
	}
	defer dst.Close()
	if err := db.CreateSchemaOnly(dst); err != nil {
		return fail(fmt.Errorf("prepare target schema: %w", err))
	}
	empty, tables, err := db.TargetIsEmpty(dst)
	if err != nil {
		return fail(err)
	}

	var rep *db.CopyReport
	if empty {
		rep, err = db.CopyDatabase(src, dst)
		out.Result = rep
		if rep != nil {
			out.TargetState = rep.TargetState
		}
		if err != nil {
			switch out.TargetState {
			case db.TargetCommitUnknown:
				return fail(fmt.Errorf("the commit outcome is unknown: check whether the target database is empty; "+
					"if it is not, do NOT start the server on it — recreate an empty database and run again: %w", err))
			default:
				// 导入与校验在同一个目标事务里，失败即整体回滚（SV-03）：这句话现在是真的
				return fail(fmt.Errorf("migration failed; the import and its verification ran in one transaction "+
					"that was rolled back, so nothing was committed to the target (targetState=untouched); "+
					"fix the problem and run again: %w", err))
			}
		}
		// 复制在同一个源快照上已校验；再用一个**新**快照比一次，证明快照之后源库没再变
		//（锁检查不可用、或有人绕过锁写了源库时，这里会失败——目标里的数据缺了快照之后的写入）
		if ferr := failpoint.Eval(failpoint.MigrateBeforePostCheck); ferr != nil {
			return fail(ferr)
		}
		post, perr := db.VerifyDatabases(src, dst)
		out.PostCheck = post
		if perr != nil {
			out.TargetState = "copied-not-enabled"
			return fail(fmt.Errorf("the data was copied and verified against the first snapshot, but the source changed "+
				"while migrating; the target is kept but NOT enabled (no migration marker was written): "+
				"do not start the server on it — stop every writer, recreate an empty target database and run again: %w", perr))
		}
	} else {
		// 幂等：已完成的迁移再跑一次 = 只校验
		rep, err = db.VerifyDatabases(src, dst)
		out.Result = rep
		if err != nil {
			return fail(fmt.Errorf("%w %v and it differs from the source; refusing to touch it "+
				"(use a new empty database, or investigate the difference in the report)", db.ErrTargetNotEmpty, tables))
		}
		out.TargetState = "already-migrated"
		fmt.Fprintln(os.Stderr, "目标库已有与源库逐表一致的数据：迁移此前已完成，本次只做了校验。")
	}

	if err := writeMigratedMarker(dataDir, source, rep); err != nil {
		return fail(fmt.Errorf("migration verified, but writing the marker failed: %w", err))
	}
	out.OK = true
	out.Next = []string{
		"set OBSYNC_DB=postgres (keep OBSYNC_PG_DSN) and start the server",
		"keep the old SQLite file read-only; it is NOT a rollback target once new writes exist (use `obsync export-sqlite`)",
	}
	emitReport(out, reportPath)
	return nil
}

func writeMigratedMarker(dataDir, source string, rep *db.CopyReport) error {
	p := filepath.Join(dataDir, migratedMarkerName)
	if _, err := os.Stat(p); err == nil {
		return nil // 已有标记（重复运行）：保留第一次迁移的时间
	}
	m := migratedMarker{
		MigratedAt:      time.Now().UTC().Format(time.RFC3339),
		LitesyncVersion: version,
		Source:          source,
		Tables:          len(rep.Tables),
		TotalRows:       rep.TotalRows,
		Note:            "metadata now lives in PostgreSQL; this SQLite file is a read-only historical copy",
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, raw, 0o600)
}

func runExportSQLite(args []string) error {
	outPath := flagValue(args, "--out")
	if outPath == "" || hasFlag(args, "-h") || hasFlag(args, "--help") {
		fmt.Print(migrateUsage)
		if outPath == "" {
			return errors.New("--out PATH is required")
		}
		return nil
	}
	reportPath := flagValue(args, "--report")
	out := &migrationOutput{Tool: "obsync export-sqlite", Version: version,
		Source: "postgres (OBSYNC_PG_DSN, not shown)", Target: outPath}
	fail := func(err error) error {
		out.OK, out.Error = false, err.Error()
		emitReport(out, reportPath)
		return err
	}
	dsn := os.Getenv("OBSYNC_PG_DSN")
	if dsn == "" {
		return fail(errors.New("OBSYNC_PG_DSN is not set"))
	}
	src, err := db.OpenPostgresRaw(dsn)
	if err != nil {
		return fail(err)
	}
	defer src.Close()
	if ok, err := db.TableExists(src, "repo_state"); err != nil || !ok {
		return fail(fmt.Errorf("no LiteSync database at OBSYNC_PG_DSN: %v", err))
	}
	rep, err := db.ExportToSQLiteFile(src, outPath)
	out.Result = rep
	if err != nil {
		return fail(err)
	}
	out.OK = true
	out.Next = []string{
		"stop the server before installing the export (an export taken while it runs is consistent, but later writes are not in it)",
		"move the old sync.db aside, install the export as <data dir>/sync.db, delete " + migratedMarkerName,
		"set OBSYNC_DB=sqlite and start; epochs and sequences are preserved, clients continue without a recovery merge",
	}
	emitReport(out, reportPath)
	return nil
}
