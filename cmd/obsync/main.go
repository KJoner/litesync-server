// obsync：单用户 Obsidian 私有同步服务器。
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/KJoner/litesync-server/internal/api"
	"github.com/KJoner/litesync-server/internal/backup"
	"github.com/KJoner/litesync-server/internal/config"
	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

const version = "0.11.0"

func main() {
	// rotate-epoch：灾备恢复后的必要步骤（服务停止时执行）。
	// 旋转 repo_epoch 使所有客户端进入恢复合并流程，而不是沿用旧游标
	// 静默跳过「恢复点之后曾经存在」的 sequence 区间。
	if len(os.Args) > 1 && os.Args[1] == "rotate-epoch" {
		if err := rotateEpoch(); err != nil {
			fmt.Fprintln(os.Stderr, "obsync rotate-epoch:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "obsync:", err)
		os.Exit(1)
	}
}

func rotateEpoch() error {
	dataDir := os.Getenv("OBSYNC_DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	dbPath := filepath.Join(dataDir, "sync.db")
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("database not found at %s (set OBSYNC_DATA_DIR): %w", dbPath, err)
	}
	database, err := db.Open(dbPath)
	if err != nil {
		return err
	}
	defer database.Close()
	epoch, err := db.RotateEpoch(database)
	if err != nil {
		return err
	}
	fmt.Printf("repo epoch rotated: %s\n", epoch)
	fmt.Println("clients will pause normal sync and enter recovery merge on next contact")
	return nil
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	// 数据目录权限收紧：metadata（路径/大小/设备等）即使在 E2EE 下也是敏感的
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	os.Chmod(cfg.DataDir, 0o700) //nolint:errcheck // 已存在目录也收紧；Windows 上是 no-op
	dbPath := filepath.Join(cfg.DataDir, "sync.db")
	database, err := db.OpenWithSync(dbPath, cfg.DurabilityStrict)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()
	os.Chmod(dbPath, 0o600) //nolint:errcheck

	store, err := storage.New(filepath.Join(cfg.DataDir, "vaults", "default"))
	if err != nil {
		return fmt.Errorf("init storage: %w", err)
	}
	// 清理上次崩溃可能遗留的临时文件
	if err := store.CleanTempFiles(); err != nil {
		logger.Warn("clean temp files", "error", err)
	}
	blobs, err := storage.NewBlobStore(filepath.Join(cfg.DataDir, "blobs"))
	if err != nil {
		return fmt.Errorf("init blob store: %w", err)
	}
	shares, err := storage.NewShareStore(filepath.Join(cfg.DataDir, "shares"))
	if err != nil {
		return fmt.Errorf("init share store: %w", err)
	}

	svc := syncsvc.New(database, store, blobs, shares, syncsvc.Options{
		HistoryEnabled:        cfg.HistoryEnabled,
		HistoryDays:           cfg.HistoryDays,
		HistoryMaxPerFile:     cfg.HistoryMaxPerFile,
		HistoryAttachmentDays: cfg.HistoryAttachmentDays,
		HistoryAttachmentMax:  cfg.HistoryAttachmentMax,
		HistoryMaxBytes:       cfg.HistoryMaxBytes,
		ChangesDays:           cfg.ChangesDays,
		ChangesMax:            cfg.ChangesMax,
	}, logger)
	// 为 v1 升级上来的旧文件补记当前版本（幂等；需在 HEAD 迁移前，因为要读 vault 文件）
	if err := svc.BackfillVersions(); err != nil {
		logger.Warn("backfill versions", "error", err)
	}
	// v9：为旧库补跨平台归一化 key，并对已存在的路径碰撞告警
	if err := svc.BackfillCanonicalKeys(); err != nil {
		logger.Warn("backfill canonical keys", "error", err)
	}
	// v4：HEAD 收编进 blob store，消除双份存储（幂等）
	if err := svc.MigrateHeadToBlobs(); err != nil {
		logger.Warn("head migration", "error", err)
	}
	// 资源治理：启动执行一次，之后每 N 小时一次
	svc.RunMaintenance()
	if cfg.MaintenanceHours > 0 {
		go func() {
			ticker := time.NewTicker(time.Duration(cfg.MaintenanceHours) * time.Hour)
			defer ticker.Stop()
			for range ticker.C {
				svc.RunMaintenance()
			}
		}()
	}
	// v6：备份管理器（restic → Cloudflare R2）。密钥文件不可用时功能禁用但服务照常运行
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bkp := backup.New(database, svc, backup.NewRunner(""), cfg.DataDir, version, cfg.BackupKeyFile, logger)
	bkp.StartScheduler(ctx)

	handler := api.New(api.Options{
		Token:          cfg.Token,
		MaxFileSize:    cfg.MaxFileSize,
		Version:        version,
		Logger:         logger,
		Backup:         bkp,
		TrustedProxies: cfg.TrustedProxies,
	}, svc)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("obsync listening", "addr", cfg.Listen, "dataDir", cfg.DataDir, "version", version)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
	}
	return nil
}
