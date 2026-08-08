package config

import (
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("OBSYNC_TOKEN", "0123456789abcdef0123456789abcdef")
	t.Setenv("OBSYNC_LISTEN", "")
	t.Setenv("OBSYNC_DATA_DIR", "")
	t.Setenv("OBSYNC_MAX_FILE_SIZE", "")
	t.Setenv("OBSYNC_LOG_LEVEL", "")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:8080" || cfg.DataDir != "./data" || cfg.MaxFileSize != 100<<20 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.ChangesDays != 90 || cfg.ChangesMax != 100000 || cfg.MaintenanceHours != 24 ||
		cfg.HistoryAttachmentDays != 30 || cfg.HistoryAttachmentMax != 10 || cfg.HistoryMaxBytes != 0 {
		t.Fatalf("unexpected v4 defaults: %+v", cfg)
	}
}

func TestLoadRequiresToken(t *testing.T) {
	t.Setenv("OBSYNC_TOKEN", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected error when OBSYNC_TOKEN is empty")
	}
	t.Setenv("OBSYNC_TOKEN", "short")
	if _, err := Load(); err == nil {
		t.Fatal("expected error when OBSYNC_TOKEN is too short")
	}
}

func TestLoadInvalidValues(t *testing.T) {
	t.Setenv("OBSYNC_TOKEN", "0123456789abcdef0123456789abcdef")
	t.Setenv("OBSYNC_MAX_FILE_SIZE", "not-a-number")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for invalid OBSYNC_MAX_FILE_SIZE")
	}
	t.Setenv("OBSYNC_MAX_FILE_SIZE", "1024")
	t.Setenv("OBSYNC_LOG_LEVEL", "verbose")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for invalid OBSYNC_LOG_LEVEL")
	}
}
