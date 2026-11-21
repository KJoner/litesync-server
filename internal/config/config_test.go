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

// v0.20 公开化配置：半套 OIDC 拒绝启动；非本机必须 https；回调基址不能带路径；
// 注册模式默认 invite（先邀请试运行），未知值拒绝。
func TestLoadPublicLaunchOptions(t *testing.T) {
	t.Setenv("OBSYNC_TOKEN", "0123456789abcdef0123456789abcdef")
	for _, k := range []string{"OBSYNC_PUBLIC_URL", "OBSYNC_OIDC_ISSUER", "OBSYNC_OIDC_CLIENT_ID",
		"OBSYNC_OIDC_CLIENT_SECRET", "OBSYNC_REGISTRATION_MODE", "OBSYNC_LEGACY_TOKEN_LOGIN",
		"OBSYNC_REQUIRE_E2EE_NEW_VAULTS"} {
		t.Setenv(k, "")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDCEnabled() || cfg.RegistrationMode != "invite" || !cfg.LegacyTokenLogin || !cfg.RequireE2EENewVaults {
		t.Fatalf("unexpected public-launch defaults: oidc=%v mode=%q legacy=%v e2ee=%v",
			cfg.OIDCEnabled(), cfg.RegistrationMode, cfg.LegacyTokenLogin, cfg.RequireE2EENewVaults)
	}

	t.Setenv("OBSYNC_OIDC_ISSUER", "https://accounts.example.com/realms/accounts")
	if _, err := Load(); err == nil {
		t.Fatal("half-configured OIDC (issuer only) must refuse to start")
	}
	t.Setenv("OBSYNC_OIDC_CLIENT_ID", "litesync-web")
	t.Setenv("OBSYNC_OIDC_CLIENT_SECRET", "s3cret")
	if _, err := Load(); err == nil {
		t.Fatal("OIDC without OBSYNC_PUBLIC_URL must refuse to start")
	}
	for _, bad := range []string{"http://sync.example.com", "https://sync.example.com/app", "https://sync.example.com?x=1", "sync.example.com"} {
		t.Setenv("OBSYNC_PUBLIC_URL", bad)
		if _, err := Load(); err == nil {
			t.Fatalf("OBSYNC_PUBLIC_URL %q must be rejected", bad)
		}
	}
	t.Setenv("OBSYNC_PUBLIC_URL", "http://127.0.0.1:8080") // 本机开发允许 http
	t.Setenv("OBSYNC_OIDC_ISSUER", "http://accounts.example.com/realms/accounts")
	if _, err := Load(); err == nil {
		t.Fatal("non-loopback http issuer must be rejected")
	}
	t.Setenv("OBSYNC_OIDC_ISSUER", "https://accounts.example.com/realms/accounts")
	t.Setenv("OBSYNC_PUBLIC_URL", "https://sync.example.com/")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.OIDCEnabled() || cfg.PublicURL != "https://sync.example.com" {
		t.Fatalf("expected OIDC enabled with trimmed public URL, got %v %q", cfg.OIDCEnabled(), cfg.PublicURL)
	}

	t.Setenv("OBSYNC_REGISTRATION_MODE", "everyone")
	if _, err := Load(); err == nil {
		t.Fatal("unknown registration mode must be rejected")
	}
	t.Setenv("OBSYNC_REGISTRATION_MODE", "open")
	t.Setenv("OBSYNC_LEGACY_TOKEN_LOGIN", "false")
	if cfg, err = Load(); err != nil || cfg.RegistrationMode != "open" || cfg.LegacyTokenLogin {
		t.Fatalf("explicit settings not honored: %v %+v", err, cfg)
	}
}
