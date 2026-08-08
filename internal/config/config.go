// Package config 从环境变量加载服务端配置。
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Listen      string // OBSYNC_LISTEN, 默认 :8080
	DataDir     string // OBSYNC_DATA_DIR, 默认 ./data
	Token       string // OBSYNC_TOKEN, 必填
	MaxFileSize int64  // OBSYNC_MAX_FILE_SIZE, 默认 100MB
	LogLevel    slog.Level

	HistoryEnabled    bool // OBSYNC_HISTORY_ENABLED, 默认 true
	HistoryDays       int  // OBSYNC_HISTORY_DAYS, 默认 90（0 = 不按天数裁剪）
	HistoryMaxPerFile int  // OBSYNC_HISTORY_MAX_PER_FILE, 默认 100（0 = 不限数量）
}

func Load() (*Config, error) {
	cfg := &Config{
		Listen:      getenv("OBSYNC_LISTEN", ":8080"),
		DataDir:     getenv("OBSYNC_DATA_DIR", "./data"),
		Token:       os.Getenv("OBSYNC_TOKEN"),
		MaxFileSize: 100 << 20,
		LogLevel:    slog.LevelInfo,
	}

	if cfg.Token == "" {
		return nil, fmt.Errorf("OBSYNC_TOKEN is not set; generate one with: openssl rand -hex 32")
	}
	if len(cfg.Token) < 16 {
		return nil, fmt.Errorf("OBSYNC_TOKEN is too short (%d chars); use at least 32 random bytes", len(cfg.Token))
	}

	if v := os.Getenv("OBSYNC_MAX_FILE_SIZE"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("invalid OBSYNC_MAX_FILE_SIZE: %q", v)
		}
		cfg.MaxFileSize = n
	}

	cfg.HistoryEnabled = true
	cfg.HistoryDays = 90
	cfg.HistoryMaxPerFile = 100
	if v := strings.ToLower(os.Getenv("OBSYNC_HISTORY_ENABLED")); v != "" {
		switch v {
		case "true", "1", "yes":
			cfg.HistoryEnabled = true
		case "false", "0", "no":
			cfg.HistoryEnabled = false
		default:
			return nil, fmt.Errorf("invalid OBSYNC_HISTORY_ENABLED: %q", v)
		}
	}
	if v := os.Getenv("OBSYNC_HISTORY_DAYS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OBSYNC_HISTORY_DAYS: %q", v)
		}
		cfg.HistoryDays = n
	}
	if v := os.Getenv("OBSYNC_HISTORY_MAX_PER_FILE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OBSYNC_HISTORY_MAX_PER_FILE: %q", v)
		}
		cfg.HistoryMaxPerFile = n
	}

	switch strings.ToLower(getenv("OBSYNC_LOG_LEVEL", "info")) {
	case "debug":
		cfg.LogLevel = slog.LevelDebug
	case "info":
		cfg.LogLevel = slog.LevelInfo
	case "warn":
		cfg.LogLevel = slog.LevelWarn
	case "error":
		cfg.LogLevel = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid OBSYNC_LOG_LEVEL: %q (use debug/info/warn/error)", os.Getenv("OBSYNC_LOG_LEVEL"))
	}

	return cfg, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
