package config

// 复审 SV-04：OBSYNC_SMTP_TLS 只接受合法枚举（大小写不敏感、空值 = starttls），拼写错误拒绝启动；
// none 只允许回环中继。与 mail.ParseTLSMode 交叉核对，保证配置层与 provider 构造用同一套规则。
// 不连接任何邮件服务。

import (
	"testing"

	"github.com/KJoner/litesync-server/internal/mail"
)

func smtpEnv(t *testing.T, host, mode string) {
	t.Helper()
	t.Setenv("OBSYNC_TOKEN", "review-only-token-not-a-real-secret")
	for _, k := range []string{"OBSYNC_OIDC_ISSUER", "OBSYNC_OIDC_CLIENT_ID", "OBSYNC_OIDC_CLIENT_SECRET", "OBSYNC_PUBLIC_URL",
		"OBSYNC_REGISTRATION_MODE", "OBSYNC_PEER_REVOCATION_URL", "OBSYNC_PEER_REVOCATION_SECRET"} {
		t.Setenv(k, "")
	}
	t.Setenv("OBSYNC_MAIL_PROVIDER", "smtp")
	t.Setenv("OBSYNC_MAIL_FROM", "test@example.invalid")
	t.Setenv("OBSYNC_SMTP_HOST", host)
	t.Setenv("OBSYNC_SMTP_TLS", mode)
}

// 审查反例转正（server-review-repro_test.go 的 TestReviewSMTPModeTypoAccepted）：
// 审查时 "startls" 被原样接受；现在必须拒绝启动。
func TestReviewSMTPModeTypoRejected(t *testing.T) {
	smtpEnv(t, "smtp.example.invalid", "startls")
	if cfg, err := Load(); err == nil {
		t.Fatalf("a mistyped OBSYNC_SMTP_TLS must refuse to start, got mode %q", cfg.SMTPTLS)
	}
}

func TestSMTPTLSModeIsStrictAndNormalized(t *testing.T) {
	for in, want := range map[string]string{
		"": "starttls", "  ": "starttls", "starttls": "starttls", "STARTTLS": "starttls", " StartTLS ": "starttls",
		"implicit": "implicit", "Implicit": "implicit",
	} {
		smtpEnv(t, "smtp.example.invalid", in)
		cfg, err := Load()
		if err != nil || cfg.SMTPTLS != want {
			t.Fatalf("OBSYNC_SMTP_TLS=%q -> %v %v, want %q", in, cfg, err, want)
		}
	}
	for _, bad := range []string{"startls", "ssl", "tls", "start-tls", "on", "off", "true", "starttls,implicit"} {
		smtpEnv(t, "smtp.example.invalid", bad)
		if _, err := Load(); err == nil {
			t.Fatalf("OBSYNC_SMTP_TLS=%q must refuse to start", bad)
		}
	}
	// 未选 smtp 渠道时拼写错误同样是错误配置：早发现比哪天切到 smtp 才发现好
	smtpEnv(t, "smtp.example.invalid", "startls")
	t.Setenv("OBSYNC_MAIL_PROVIDER", "log")
	if _, err := Load(); err == nil {
		t.Fatal("a mistyped OBSYNC_SMTP_TLS must be rejected even when the smtp provider is not selected")
	}
}

func TestSMTPTLSNoneOnlyForLoopback(t *testing.T) {
	for _, host := range []string{"smtp.example.invalid", "10.0.0.5", "mail"} {
		smtpEnv(t, host, "none")
		if _, err := Load(); err == nil {
			t.Fatalf("none with relay %q must refuse to start", host)
		}
	}
	for _, host := range []string{"127.0.0.1", "localhost", "::1"} {
		smtpEnv(t, host, "NONE")
		if cfg, err := Load(); err != nil || cfg.SMTPTLS != "none" {
			t.Fatalf("none with loopback relay %q -> %v %v", host, cfg, err)
		}
	}
}

// 配置层与 provider 构造的规则必须一致：同一个输入，要么都接受且结果相同，要么都拒绝。
func TestSMTPTLSConfigAndProviderAgree(t *testing.T) {
	for _, in := range []string{"", " ", "starttls", "STARTTLS", "implicit", "IMPLICIT", "none", "None",
		"startls", "ssl", "tls", "start-tls", "smtps", "plain", "\tstarttls\n"} {
		c, cerr := parseSMTPTLS(in)
		m, merr := mail.ParseTLSMode(in)
		if (cerr == nil) != (merr == nil) || c != m {
			t.Fatalf("%q: config=(%q,%v) provider=(%q,%v)", in, c, cerr, m, merr)
		}
	}
}
