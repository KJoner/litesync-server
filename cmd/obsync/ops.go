package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KJoner/litesync-server/internal/backup"
	"github.com/KJoner/litesync-server/internal/config"
	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// 运维命令（v0.13.3 / 计划书 §7.8）。
//
//	obsync backup create
//	obsync backup verify
//	obsync backup restore --new-epoch <snapshot-id>
//	obsync integrity scan [--full]
//	obsync migration status
//	obsync migration resume
//	obsync migration abort
//
// 这些命令都在**服务停止时**或对着同一个数据目录运行；它们不经过 HTTP，
// 因此不受会话与 scope 影响，但也因此必须自己把「危险动作」讲清楚。

const opsUsage = `obsync 运维命令：

  backup create                  立即创建一次备份
  backup verify                  校验备份仓库（restic check）
  backup restore --new-epoch ID  从快照恢复，并旋转 repoEpoch（见下）
  integrity scan [--full]        完整性巡检；--full 会重算每个 blob 的 hash
  migration preflight            迁移前置检查（§15 第 3/6/7 步）：只读，任何时候跑都安全
  migration status               元数据迁移状态与 journal 进度
  migration resume               清掉过期租约，让任一设备可以接管续做
  migration abort                中止迁移并回到 plain（已迁移的对象保持可读）

  blobid status                  报告是否还有停留在裸 contentHash 上的 blob
  blobid migrate                 dry-run：只报告要改名多少个，不动任何文件
  blobid migrate --confirm       真正执行（**不可逆**，执行前请先 backup create）

restore 会做四件事，缺一不可：
  1. 用快照内容替换数据目录；
  2. 旋转 repoEpoch —— 所有客户端的游标与 baseRevision 随之作废；
  3. 客户端下次同步时进入灾备合并流程，而不是沿用旧游标；
  4. 服务器恢复出来的内容与客户端 post-backup 的内容都会被保留，
     两侧差异走冲突流程，绝不静默丢弃任何一方。
`

// runOps 处理运维子命令；返回 false 表示这不是运维命令，交回正常启动流程。
func runOps(args []string) (handled bool, err error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "backup":
		return true, opsBackup(args[1:])
	case "integrity":
		return true, opsIntegrity(args[1:])
	case "migration":
		return true, opsMigration(args[1:])
	case "blobid":
		return true, opsBlobID(args[1:])
	case "ops", "help", "-h", "--help":
		fmt.Print(opsUsage)
		return true, nil
	}
	return false, nil
}

// openDataDir 打开数据目录里的数据库与存储（运维命令共用）。
func openDataDir() (*syncsvc.Service, func(), error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, err
	}
	database, err := db.Open(filepath.Join(cfg.DataDir, "sync.db"))
	if err != nil {
		return nil, nil, err
	}
	store, err := storage.New(filepath.Join(cfg.DataDir, "vault"))
	if err != nil {
		database.Close()
		return nil, nil, err
	}
	blobs, err := storage.NewBlobStore(filepath.Join(cfg.DataDir, "blobs"))
	if err != nil {
		database.Close()
		return nil, nil, err
	}
	shares, err := storage.NewShareStore(filepath.Join(cfg.DataDir, "shares"))
	if err != nil {
		database.Close()
		return nil, nil, err
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	svc := syncsvc.New(database, store, blobs, shares, syncsvc.Options{
		StrictBlobVerify:        cfg.StrictBlobVerify,
		QuarantineRetentionDays: cfg.QuarantineRetentionDays,
	}, logger)
	if err := svc.InitVaultSecret(); err != nil {
		database.Close()
		return nil, nil, err
	}
	return svc, func() { database.Close() }, nil
}

func opsBlobID(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法：obsync blobid status|migrate [--confirm]")
	}
	svc, closeFn, err := openDataDir()
	if err != nil {
		return err
	}
	defer closeFn()

	switch args[0] {
	case "status":
		need, err := svc.NeedsBlobIDMigration()
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(map[string]any{
			"needsMigration": need,
			"note":           "未迁移不影响读写正确性；但 §10.3 的跨租户存在性隔离在迁移完成前对老数据不成立",
		}, "", "  ")
		fmt.Println(string(out))
		return nil

	case "migrate":
		confirm := hasFlag(args[1:], "--confirm")
		rep, err := svc.MigrateBlobIDs(confirm)
		if rep != nil {
			out, _ := json.MarshalIndent(map[string]any{
				"confirmed": confirm,
				"planned":   rep.Planned,
				"renamed":   rep.Renamed,
				"skipped":   rep.Skipped,
				"failed":    rep.Failed,
				"duration":  rep.Duration.String(),
			}, "", "  ")
			fmt.Println(string(out))
		}
		if err != nil {
			return err
		}
		if !confirm {
			fmt.Println("以上为 dry-run。这一步不可逆：确认已有可用备份后，再加 --confirm 执行。")
		}
		return nil
	}
	return fmt.Errorf("未知的 blobid 子命令：%s", args[0])
}

func opsIntegrity(args []string) error {
	if len(args) == 0 || args[0] != "scan" {
		return fmt.Errorf("用法：obsync integrity scan [--full]")
	}
	full := hasFlag(args[1:], "--full")

	svc, closeFn, err := openDataDir()
	if err != nil {
		return err
	}
	defer closeFn()

	rep, err := svc.Scrub(full)
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(map[string]any{
		"dbCheck":         rep.DBCheck,
		"headsChecked":    rep.HeadsChecked,
		"versionsChecked": rep.VersionsChecked,
		"sharesChecked":   rep.SharesChecked,
		"issues":          rep.Issues,
		"unservable":      rep.Unservable,
		"full":            full,
		"details":         rep.Details,
	}, "", "  ")
	fmt.Println(string(out))
	if rep.Issues > 0 {
		// 非零退出码：让 cron / CI 能直接把它当成告警信号
		return fmt.Errorf("发现 %d 个完整性问题（%d 份内容已停止对外提供）", rep.Issues, rep.Unservable)
	}
	return nil
}

func opsMigration(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法：obsync migration preflight|status|resume|abort")
	}
	svc, closeFn, err := openDataDir()
	if err != nil {
		return err
	}
	defer closeFn()

	switch args[0] {
	case "preflight":
		// §15 第 3/6/7 步。--client 给出要求的客户端版本；不给则只报告未知版本数
		rep, err := svc.MigrationPreflight(flagValue(args[1:], "--client"))
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(map[string]any{
			"blocked":             rep.Blocked(),
			"activeDevices":       rep.ActiveDevices,
			"staleDevices":        rep.StaleDevices,
			"unknownVersion":      rep.UnknownVersion,
			"outdatedClient":      rep.OutdatedClient,
			"metaState":           rep.MetaState,
			"formatEpoch":         rep.FormatEpoch,
			"envelopeFloor":       rep.EnvelopeFloor,
			"latestSequence":      rep.LatestSequence,
			"plaintextTombstones": rep.PlaintextTombstones,
			"orphanVersions":      rep.OrphanVersions,
			"missingBlobs":        rep.MissingBlobs,
			"issues":              preflightIssues(rep),
		}, "", "  ")
		fmt.Println(string(out))
		if rep.Blocked() {
			// 非零退出码：让 §15 的流程可以写成脚本，而不是靠人看输出
			return fmt.Errorf("前置检查未通过，不应继续迁移")
		}
		fmt.Println("前置检查通过。注意：这不代表迁移一定成功，只代表已知的阻塞项都不存在。")
		return nil

	case "status":
		st, err := svc.MigrationStatusOf()
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(st, "", "  ")
		fmt.Println(string(out))
		return nil

	case "resume":
		// 「续做」不是服务端替客户端做迁移——迁移需要密钥，服务器没有。
		// 这里能做的是把过期租约清掉，让任一在线设备可以接管
		n, err := svc.ExpireStaleMigrationLease(time.Now())
		if err != nil {
			return err
		}
		if n == 0 {
			fmt.Println("当前没有过期租约；如果迁移卡住，请在持有密钥的设备上继续操作。")
		} else {
			fmt.Println("已释放过期的迁移租约；任一设备现在都可以接管续做。")
		}
		return nil

	case "abort":
		if _, err := svc.AbortMetaMigration(); err != nil {
			return err
		}
		fmt.Println("迁移已中止，仓库回到 plain 状态；已迁移的对象仍然可读。")
		return nil
	}
	return fmt.Errorf("未知的 migration 子命令：%s", args[0])
}

func opsBackup(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法：obsync backup create|verify|restore --new-epoch <snapshot-id>")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.BackupKeyFile == "" {
		return fmt.Errorf("备份未配置：请设置 OBSYNC_BACKUP_KEY_FILE（该文件必须位于数据目录之外）")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	database, err := db.Open(filepath.Join(cfg.DataDir, "sync.db"))
	if err != nil {
		return err
	}
	defer database.Close()
	// 运维命令是在服务停止时跑的，没有活跃写入需要静默：quiesce 传一个空实现
	mgr := backup.New(database, cliQuiescer{db: database}, backup.NewRunner(""), cfg.DataDir, version, cfg.BackupKeyFile, logger)
	ctx := context.Background()

	switch args[0] {
	case "create":
		res, err := mgr.Backup(ctx, "cli")
		if err != nil {
			return err
		}
		fmt.Printf("备份完成：snapshot=%s 用时 %d ms\n", res.SnapshotID, res.DurationMs)
		return nil

	case "verify":
		if err := mgr.Check(ctx); err != nil {
			return err
		}
		fmt.Println("备份仓库校验通过。")
		return nil

	case "restore":
		id := flagValue(args[1:], "--snapshot")
		if id == "" {
			// 允许 `restore --new-epoch <id>` 这种把 id 放在末尾的写法
			id = lastNonFlag(args[1:])
		}
		if id == "" {
			return fmt.Errorf("请指定快照 id：obsync backup restore --new-epoch <snapshot-id>")
		}
		if !hasFlag(args[1:], "--new-epoch") {
			// 不加 --new-epoch 的恢复是危险的：客户端会带着旧游标继续增量同步，
			// 从而静默跳过「恢复点之后曾经存在」的那段 sequence
			return fmt.Errorf(
				"恢复必须带 --new-epoch：不旋转 repoEpoch 的话，客户端会沿用旧游标，" +
					"静默漏掉恢复点之后的所有变更")
		}
		return restoreWithNewEpoch(ctx, mgr, cfg.DataDir, id)
	}
	return fmt.Errorf("未知的 backup 子命令：%s", args[0])
}

// cliQuiescer：运维命令运行时服务是停的，没有并发写入需要静默。
// LatestSequence 仍然如实读库——它会写进备份 manifest，恢复时要靠它判断
// 「这份备份停在哪个 sequence」。
type cliQuiescer struct{ db *sql.DB }

func (cliQuiescer) WithGlobalLock(fn func() error) error { return fn() }

func (q cliQuiescer) LatestSequence() (int64, error) {
	var seq int64
	err := q.db.QueryRow(`SELECT COALESCE(MAX(sequence), 0) FROM object_changes`).Scan(&seq)
	return seq, err
}

// restoreWithNewEpoch 执行 §7.8 要求的完整恢复流程。
func restoreWithNewEpoch(ctx context.Context, mgr *backup.Manager, dataDir, snapshotID string) error {
	fmt.Fprintf(os.Stderr, "即将从快照 %s 恢复到 %s，并旋转 repoEpoch。\n", snapshotID, dataDir)
	fmt.Fprintln(os.Stderr, "请确认服务已停止；恢复后所有客户端都会进入灾备合并流程。")

	res, err := mgr.Restore(ctx, snapshotID)
	if err != nil {
		return fmt.Errorf("恢复失败: %w", err)
	}
	if res.PreviousDataDir != "" {
		fmt.Printf("原数据目录已挪到 %s\n", res.PreviousDataDir)
		fmt.Println("（确认恢复无误后再删除它——恢复错快照时那是唯一的退路）")
	}
	// 旋转 epoch：这一步不能省，也不能延后到服务启动之后——
	// 中间任何一次客户端同步都会带着作废的游标进来
	if err := rotateEpoch(); err != nil {
		return fmt.Errorf("恢复成功但 repoEpoch 旋转失败（必须手工执行 obsync rotate-epoch）: %w", err)
	}
	fmt.Println("恢复完成，repoEpoch 已旋转。")
	fmt.Println("客户端下次同步会进入灾备合并：服务器恢复出来的内容与客户端本地较新的内容都会保留。")
	return nil
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func flagValue(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, name+"=") {
			return strings.TrimPrefix(a, name+"=")
		}
	}
	return ""
}

func lastNonFlag(args []string) string {
	for i := len(args) - 1; i >= 0; i-- {
		if !strings.HasPrefix(args[i], "-") {
			return args[i]
		}
	}
	return ""
}

func preflightIssues(rep *syncsvc.PreflightReport) []map[string]any {
	out := make([]map[string]any, 0, len(rep.Issues))
	for i := range rep.Issues {
		out = append(out, map[string]any{
			"blocking": rep.Issues[i].Blocking,
			"code":     rep.Issues[i].Code,
			"detail":   rep.Issues[i].Detail,
		})
	}
	return out
}
