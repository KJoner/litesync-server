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
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

const migrateUsage = `用法：
  obsync migrate-to-pg --dry-run [--source PATH] [--report PATH]
      只读源库（默认 $OBSYNC_DATA_DIR/sync.db）：结构兼容性检查 + 逐表行数 + 每仓库摘要。不连接目标库。
  obsync migrate-to-pg [--source PATH] [--report PATH]
      正式导入到 OBSYNC_PG_DSN（服务必须已停止）。目标库必须为空；若目标已有数据且与源库
      逐表一致，视为「已完成」，只校验（幂等）；不一致则拒绝，源库与目标库都不动。
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
	Next      []string       `json:"next,omitempty"`
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
	fmt.Fprintln(os.Stderr, "正式迁移：请确认 LiteSync 服务已停止（源库在一个读事务里取快照；迁移期间的新写入不会进入目标库）。")
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
		if err != nil {
			return fail(fmt.Errorf("migration failed, nothing was committed to the target: %w", err))
		}
		// 复制在同一个源快照上已校验；再用一个**新**快照比一次，证明快照之后源库没再变
		//（服务没停的话这里会失败——目标里的数据缺了快照之后的写入）
		post, perr := db.VerifyDatabases(src, dst)
		out.PostCheck = post
		if perr != nil {
			return fail(fmt.Errorf("the source changed while migrating (is the server still running?); "+
				"stop it, recreate an empty target database and run again: %w", perr))
		}
	} else {
		// 幂等：已完成的迁移再跑一次 = 只校验
		rep, err = db.VerifyDatabases(src, dst)
		out.Result = rep
		if err != nil {
			return fail(fmt.Errorf("%w %v and it differs from the source; refusing to touch it "+
				"(use a new empty database, or investigate the difference in the report)", db.ErrTargetNotEmpty, tables))
		}
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
