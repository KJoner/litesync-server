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

const version = "0.3.0"

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

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	database, err := db.Open(filepath.Join(cfg.DataDir, "sync.db"))
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()

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

	svc := syncsvc.New(database, store, blobs, syncsvc.Options{
		HistoryEnabled:    cfg.HistoryEnabled,
		HistoryDays:       cfg.HistoryDays,
		HistoryMaxPerFile: cfg.HistoryMaxPerFile,
	}, logger)
	// 为 v1 升级上来的旧文件补记当前版本（幂等）
	if err := svc.BackfillVersions(); err != nil {
		logger.Warn("backfill versions", "error", err)
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
