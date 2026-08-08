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
	Listen      string // OBSYNC_LISTEN, 默认 127.0.0.1:8080（防止误暴露公网；Docker 里显式设 :8080）
	DataDir     string // OBSYNC_DATA_DIR, 默认 ./data
	Token       string // OBSYNC_TOKEN, 必填
	MaxFileSize int64  // OBSYNC_MAX_FILE_SIZE, 默认 100MB
	LogLevel    slog.Level

	// Markdown 历史保留（同时是三方合并的 merge-base 数据库，保守保留）
	HistoryEnabled    bool // OBSYNC_HISTORY_ENABLED, 默认 true
	HistoryDays       int  // OBSYNC_HISTORY_DAYS, 默认 90（0 = 不按天数裁剪）
	HistoryMaxPerFile int  // OBSYNC_HISTORY_MAX_PER_FILE, 默认 100（0 = 不限数量）
	// 附件（二进制）历史保留：体积大、无合并价值，激进裁剪
	HistoryAttachmentDays int   // OBSYNC_HISTORY_ATTACHMENT_DAYS, 默认 30
	HistoryAttachmentMax  int   // OBSYNC_HISTORY_ATTACHMENT_MAX_PER_FILE, 默认 10
	HistoryMaxBytes       int64 // OBSYNC_HISTORY_MAX_BYTES, 默认 0（不限）：非 HEAD 历史总字节硬上限

	ChangesDays int // OBSYNC_CHANGES_DAYS, 默认 90（0 = 不裁剪）
	ChangesMax  int // OBSYNC_CHANGES_MAX, 默认 100000（0 = 不限）

	MaintenanceHours int // OBSYNC_MAINTENANCE_HOURS, 默认 24（0 = 关闭定时维护）
}

func Load() (*Config, error) {
	cfg := &Config{
		Listen:      getenv("OBSYNC_LISTEN", "127.0.0.1:8080"),
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

	cfg.HistoryAttachmentDays = 30
	cfg.HistoryAttachmentMax = 10
	cfg.ChangesDays = 90
	cfg.ChangesMax = 100000
	cfg.MaintenanceHours = 24
	intEnvs := []struct {
		name string
		dst  *int
	}{
		{"OBSYNC_HISTORY_ATTACHMENT_DAYS", &cfg.HistoryAttachmentDays},
		{"OBSYNC_HISTORY_ATTACHMENT_MAX_PER_FILE", &cfg.HistoryAttachmentMax},
		{"OBSYNC_CHANGES_DAYS", &cfg.ChangesDays},
		{"OBSYNC_CHANGES_MAX", &cfg.ChangesMax},
		{"OBSYNC_MAINTENANCE_HOURS", &cfg.MaintenanceHours},
	}
	for _, e := range intEnvs {
		if v := os.Getenv(e.name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("invalid %s: %q", e.name, v)
			}
			*e.dst = n
		}
	}
	if v := os.Getenv("OBSYNC_HISTORY_MAX_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OBSYNC_HISTORY_MAX_BYTES: %q", v)
		}
		cfg.HistoryMaxBytes = n
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
