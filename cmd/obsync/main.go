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

	"obsync/internal/api"
	"obsync/internal/config"
	"obsync/internal/db"
	"obsync/internal/storage"
	syncsvc "obsync/internal/sync"
)

const version = "0.5.0"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "obsync:", err)
		os.Exit(1)
	}
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
	database, err := db.Open(dbPath)
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
	handler := api.New(api.Options{
		Token:       cfg.Token,
		MaxFileSize: cfg.MaxFileSize,
		Version:     version,
		Logger:      logger,
	}, svc)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
