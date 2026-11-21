// Package config 从环境变量加载服务端配置。
package config

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
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

	// BackupKeyFile 备份配置加密密钥文件路径（OBSYNC_BACKUP_KEY_FILE，默认空 = 备份功能不可用）。
	// 必须位于数据目录之外：单独复制 /data 无法解出 R2 凭据与 Restic 密码。
	BackupKeyFile string

	// DurabilityStrict（OBSYNC_DURABILITY，默认 strict）：
	// strict → SQLite synchronous=FULL（掉电后已确认事务绝不回滚）；
	// normal → synchronous=NORMAL（更快，但掉电可能丢最近已确认的事务）。
	DurabilityStrict bool

	// TrustedProxies（OBSYNC_TRUSTED_PROXIES，逗号分隔 IP/CIDR，默认 loopback）：
	// 只有来自这些地址的请求，其 X-Forwarded-Proto 才被信任。
	TrustedProxies []string

	// StrictBlobVerify（OBSYNC_STRICT_BLOB_VERIFY，默认 false）：
	// 去重命中时全量重算现有 blob 的 hash，能抓到位腐坏。
	// 代价是每次命中都要完整读一遍文件——附件多的仓库上传会明显变慢，
	// 因此默认关闭，由管理员按存储介质的可靠性决定。
	StrictBlobVerify bool

	// QuarantineRetentionDays（OBSYNC_QUARANTINE_DAYS，默认 0 = 永久保留）：
	// 隔离区里的坏副本是取证材料，不参与普通 GC，有独立的保留期。
	QuarantineRetentionDays int

	// HTTPReadTimeout / HTTPWriteTimeout（OBSYNC_HTTP_READ_TIMEOUT /
	// OBSYNC_HTTP_WRITE_TIMEOUT，秒，默认 1800 = 30 分钟）：§7.6。
	// 必须覆盖「慢速链路传大附件」这种正常场景，因此默认给得很宽松；
	// 设成 0 表示不限（不推荐：半开连接会一直占着 goroutine）。
	HTTPReadTimeout  time.Duration
	HTTPWriteTimeout time.Duration

	// ---- v0.20 公开化（ADR-011 / ADR-012） ----

	// PublicURL（OBSYNC_PUBLIC_URL）：本服务对外的规范地址，如 https://sync.example.com。
	// OIDC 回调地址必须与身份服务登记的**逐字一致**，因此从这里拼，绝不从请求的
	// Host 头推断（那是 Host 头注入与开放重定向的入口）。
	PublicURL string
	// OIDC（OBSYNC_OIDC_ISSUER / _CLIENT_ID / _CLIENT_SECRET）：三者都设置才启用统一登录。
	// client secret 只在服务端环境变量里，不进前端、插件或仓库。
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	// RegistrationMode（OBSYNC_REGISTRATION_MODE = closed|invite|open，默认 invite）：
	// 产品侧注册兜底开关（接口约定 §1.6）；先以邀请模式试运行，再开放。
	RegistrationMode string
	// LegacyTokenLogin（OBSYNC_LEGACY_TOKEN_LOGIN，默认 true）：是否保留
	// 「API Token 网页登录」。旧管理员认领统一账号之前必须保留；之后可关闭。
	LegacyTokenLogin bool
	// RequireE2EENewVaults（OBSYNC_REQUIRE_E2EE_NEW_VAULTS，默认 true）：新建仓库
	// 必须先完成 E2EE 初始化才能写入内容（ADR-012）。自托管且确实需要明文仓库
	// 的部署才关掉它；旧仓库不受影响。
	RequireE2EENewVaults bool
	// WebEditing（OBSYNC_WEB_EDITING，默认 false）：允许网页会话写入笔记（ADR-015）。
	// 需求 §14：网页写功能在完整数据安全与真机验收通过后**单独**开放，所以默认关闭。
	WebEditing bool

	// 产品通知邮件（ADR-018）。身份邮件由身份服务发送，不在这里。
	// 密钥只在服务端环境变量；默认 log 渠道（只记「有一封邮件」，不外发）。
	MailProvider        string // OBSYNC_MAIL_PROVIDER = log | smtp | resend
	MailFrom            string // OBSYNC_MAIL_FROM，例如 "LiteSync <no-reply@mail.example.com>"
	MailReplyTo         string // OBSYNC_MAIL_REPLY_TO
	SMTPHost            string // OBSYNC_SMTP_HOST
	SMTPPort            int    // OBSYNC_SMTP_PORT（默认 587）
	SMTPUser            string // OBSYNC_SMTP_USER
	SMTPPassword        string // OBSYNC_SMTP_PASSWORD
	SMTPTLS             string // OBSYNC_SMTP_TLS = starttls | implicit | none
	ResendAPIKey        string // OBSYNC_RESEND_API_KEY
	ResendWebhookSecret string // OBSYNC_RESEND_WEBHOOK_SECRET（whsec_…；空 = 回执端点关闭）

	// 配额与限流（v0.20 / 需求 §12；可被管理员逐用户覆盖）
	//
	// QuotaBytesPerUser（OBSYNC_QUOTA_BYTES_PER_USER，支持 KB/MB/GB/TB 后缀，-1 = 明确不限）：
	// 每个账号的存储上限（live + 历史，密文字节）；默认 0 = 不限，且只约束非管理员。
	// **开放注册（OBSYNC_REGISTRATION_MODE=open）时必须显式设置**——公开实例默认无限
	// 存储是一个等着被滥用的缺口，宁可启动失败让部署者做决定。
	QuotaBytesPerUser int64
	// QuotaVaultsPerUser（OBSYNC_QUOTA_VAULTS_PER_USER，默认 20）：每个账号可拥有的仓库数。
	QuotaVaultsPerUser int
	// RatePerUserPerMin（OBSYNC_RATE_PER_USER，默认 3000/分钟，突发 1/6；0 = 关闭）：
	// 按账号（设备按设备）限流，超出返回 429 RATE_LIMITED + Retry-After。
	RatePerUserPerMin int
	// UploadConcurrencyPerUser（OBSYNC_UPLOAD_CONCURRENCY_PER_USER，默认 8；0 = 不限）。
	UploadConcurrencyPerUser int
	// MailDailyBudget（OBSYNC_MAIL_DAILY_BUDGET，默认 500；0 = 不限）：全局每 24 小时
	// 最多发出的通知邮件数；超出的延后发送（不丢弃），并记 WARN。
	MailDailyBudget int

	// ---- v0.20.1 账号撤销（ADR-019） ----

	// PeerRevocationURL / PeerRevocationSecret（OBSYNC_PEER_REVOCATION_URL / _SECRET）：
	// 跨产品撤销。URL 是另一个产品的内部地址（例如 compose 网络里的 http://nexus:8787，接口路径
	// /api/internal/v1/account-revocations 自动补上）；Secret 是两个产品相同的共享密钥（≥ 32 字节，
	// 按字符串原始字节作 HMAC 密钥）。两者都设置才启用「退出所有产品与设备」的跨产品一步与接收端；
	// 只设置一个直接拒绝启动。
	PeerRevocationURL    string
	PeerRevocationSecret string
	// OIDCStatusClientID / OIDCStatusClientSecret（OBSYNC_OIDC_STATUS_CLIENT_ID / _SECRET）：
	// 中心状态检查（动作 D）用的**只读**服务账号——client credentials，只授 realm-management 的
	// view-users（client 的作用域映射里也要加上它）。两者都设置才启用；**开放公众注册必须配置**。
	OIDCStatusClientID     string
	OIDCStatusClientSecret string
	// OIDCAdminAPIURL（OBSYNC_OIDC_ADMIN_API_URL，可选）：Keycloak 管理接口基址
	// https://host/admin/realms/<realm>；默认从 OBSYNC_OIDC_ISSUER 推导（/realms/ → /admin/realms/）。
	OIDCAdminAPIURL string
}

// CentralStatusCheckEnabled 报告是否配置了中心状态检查（ADR-019 §2.5）。
func (c *Config) CentralStatusCheckEnabled() bool {
	return c.OIDCEnabled() && c.OIDCStatusClientID != "" && c.OIDCStatusClientSecret != ""
}

// PeerRevocationEnabled 报告是否配置了跨产品撤销（ADR-019 §2.4）。
func (c *Config) PeerRevocationEnabled() bool {
	return c.PeerRevocationURL != "" && c.PeerRevocationSecret != ""
}

// loadRevocation 解析 ADR-019 的配置。半套配置直接拒绝启动——「以为配好了其实没生效」
// 比启动失败更糟；开放注册而没有中心状态检查同样拒绝（ADR-019 §2.5：开放公众注册前必须配置）。
func loadRevocation(cfg *Config) error {
	cfg.PeerRevocationURL = strings.TrimRight(strings.TrimSpace(os.Getenv("OBSYNC_PEER_REVOCATION_URL")), "/")
	cfg.PeerRevocationSecret = os.Getenv("OBSYNC_PEER_REVOCATION_SECRET")
	switch {
	case cfg.PeerRevocationURL == "" && cfg.PeerRevocationSecret == "":
	case cfg.PeerRevocationURL == "" || cfg.PeerRevocationSecret == "":
		return fmt.Errorf("peer revocation is half-configured: OBSYNC_PEER_REVOCATION_URL and OBSYNC_PEER_REVOCATION_SECRET must both be set (or neither)")
	default:
		u, err := url.Parse(cfg.PeerRevocationURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("invalid OBSYNC_PEER_REVOCATION_URL: %q (use http(s)://host[:port], e.g. http://nexus:8787)", cfg.PeerRevocationURL)
		}
		if len(cfg.PeerRevocationSecret) < 32 {
			return fmt.Errorf("OBSYNC_PEER_REVOCATION_SECRET is too short (%d bytes); use at least 32 random bytes, the same value on both products", len(cfg.PeerRevocationSecret))
		}
	}

	cfg.OIDCStatusClientID = strings.TrimSpace(os.Getenv("OBSYNC_OIDC_STATUS_CLIENT_ID"))
	cfg.OIDCStatusClientSecret = os.Getenv("OBSYNC_OIDC_STATUS_CLIENT_SECRET")
	cfg.OIDCAdminAPIURL = strings.TrimRight(strings.TrimSpace(os.Getenv("OBSYNC_OIDC_ADMIN_API_URL")), "/")
	if (cfg.OIDCStatusClientID == "") != (cfg.OIDCStatusClientSecret == "") {
		return fmt.Errorf("central status check is half-configured: OBSYNC_OIDC_STATUS_CLIENT_ID and OBSYNC_OIDC_STATUS_CLIENT_SECRET must both be set (or neither)")
	}
	if cfg.OIDCStatusClientID != "" && !cfg.OIDCEnabled() {
		return fmt.Errorf("OBSYNC_OIDC_STATUS_CLIENT_ID is set but unified sign-in (OBSYNC_OIDC_*) is not configured")
	}
	if cfg.OIDCAdminAPIURL != "" {
		u, err := url.Parse(cfg.OIDCAdminAPIURL)
		if err != nil || u.Host == "" || (u.Scheme != "https" && !isLoopbackHost(u.Hostname())) {
			return fmt.Errorf("invalid OBSYNC_OIDC_ADMIN_API_URL: %q (https://host/admin/realms/<realm>; https required outside localhost)", cfg.OIDCAdminAPIURL)
		}
	}
	if cfg.CentralStatusCheckEnabled() && cfg.OIDCAdminAPIURL == "" {
		iu, _ := url.Parse(cfg.OIDCIssuer) //nolint:errcheck // 已在 loadPublicLaunch 校验
		if !strings.Contains(iu.Path, "/realms/") {
			return fmt.Errorf("cannot derive the identity-center admin API from OBSYNC_OIDC_ISSUER=%q (no /realms/<realm>); set OBSYNC_OIDC_ADMIN_API_URL", cfg.OIDCIssuer)
		}
	}
	if cfg.OIDCEnabled() && cfg.RegistrationMode == "open" && !cfg.CentralStatusCheckEnabled() {
		return fmt.Errorf("OBSYNC_REGISTRATION_MODE=open requires the central status check (ADR-019 §2.5): " +
			"set OBSYNC_OIDC_STATUS_CLIENT_ID / OBSYNC_OIDC_STATUS_CLIENT_SECRET to a read-only service account (realm-management/view-users); " +
			"without it, an account disabled or deleted in the identity center keeps its device credentials")
	}
	return nil
}

// OIDCEnabled 报告是否配置了统一登录。
func (c *Config) OIDCEnabled() bool {
	return c.OIDCIssuer != "" && c.OIDCClientID != "" && c.OIDCClientSecret != ""
}

// loadPublicLaunch 解析 v0.20 公开化相关配置。半套 OIDC 配置直接拒绝启动——
// 「以为开了统一登录其实没开」比启动失败更糟。
func loadPublicLaunch(cfg *Config) error {
	cfg.PublicURL = strings.TrimRight(strings.TrimSpace(os.Getenv("OBSYNC_PUBLIC_URL")), "/")
	cfg.OIDCIssuer = strings.TrimSpace(os.Getenv("OBSYNC_OIDC_ISSUER"))
	cfg.OIDCClientID = strings.TrimSpace(os.Getenv("OBSYNC_OIDC_CLIENT_ID"))
	cfg.OIDCClientSecret = os.Getenv("OBSYNC_OIDC_CLIENT_SECRET")

	set := 0
	for _, v := range []string{cfg.OIDCIssuer, cfg.OIDCClientID, cfg.OIDCClientSecret} {
		if v != "" {
			set++
		}
	}
	if set != 0 && set != 3 {
		return fmt.Errorf("OIDC is half-configured: OBSYNC_OIDC_ISSUER, OBSYNC_OIDC_CLIENT_ID and OBSYNC_OIDC_CLIENT_SECRET must all be set (or none)")
	}
	if cfg.OIDCEnabled() {
		if cfg.PublicURL == "" {
			return fmt.Errorf("OBSYNC_PUBLIC_URL is required when OIDC is enabled (the callback must be https://<host>/auth/callback exactly)")
		}
		u, err := url.Parse(cfg.PublicURL)
		if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("invalid OBSYNC_PUBLIC_URL: %q (use scheme://host[:port] with no path)", cfg.PublicURL)
		}
		if u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
			return fmt.Errorf("OBSYNC_PUBLIC_URL must use https outside localhost: %q", cfg.PublicURL)
		}
		iu, err := url.Parse(cfg.OIDCIssuer)
		if err != nil || iu.Host == "" || (iu.Scheme != "https" && !isLoopbackHost(iu.Hostname())) {
			return fmt.Errorf("invalid OBSYNC_OIDC_ISSUER: %q (https required outside localhost)", cfg.OIDCIssuer)
		}
	}

	switch mode := strings.ToLower(getenv("OBSYNC_REGISTRATION_MODE", "invite")); mode {
	case "closed", "invite", "open":
		cfg.RegistrationMode = mode
	default:
		return fmt.Errorf("invalid OBSYNC_REGISTRATION_MODE: %q (use closed/invite/open)", mode)
	}

	var err error
	if v := strings.TrimSpace(os.Getenv("OBSYNC_QUOTA_BYTES_PER_USER")); v != "" {
		n, perr := parseByteSize(v)
		if perr != nil {
			return fmt.Errorf("invalid OBSYNC_QUOTA_BYTES_PER_USER: %q (e.g. 2GB, 500MB, or -1 for unlimited)", v)
		}
		if n < 0 {
			n = 0 // -1：部署者明确选择不限
		}
		cfg.QuotaBytesPerUser = n
	} else if cfg.RegistrationMode == "open" {
		return fmt.Errorf("OBSYNC_REGISTRATION_MODE=open requires OBSYNC_QUOTA_BYTES_PER_USER " +
			"(e.g. 2GB; use -1 to explicitly allow unlimited storage per account)")
	}
	if cfg.QuotaVaultsPerUser, err = intEnv("OBSYNC_QUOTA_VAULTS_PER_USER", 20, 1); err != nil {
		return err
	}
	if cfg.RatePerUserPerMin, err = intEnv("OBSYNC_RATE_PER_USER", 3000, 0); err != nil {
		return err
	}
	if cfg.UploadConcurrencyPerUser, err = intEnv("OBSYNC_UPLOAD_CONCURRENCY_PER_USER", 8, 0); err != nil {
		return err
	}
	if cfg.MailDailyBudget, err = intEnv("OBSYNC_MAIL_DAILY_BUDGET", 500, 0); err != nil {
		return err
	}
	if cfg.LegacyTokenLogin, err = boolEnv("OBSYNC_LEGACY_TOKEN_LOGIN", true); err != nil {
		return err
	}
	if cfg.RequireE2EENewVaults, err = boolEnv("OBSYNC_REQUIRE_E2EE_NEW_VAULTS", true); err != nil {
		return err
	}
	if cfg.WebEditing, err = boolEnv("OBSYNC_WEB_EDITING", false); err != nil {
		return err
	}

	cfg.MailProvider = strings.ToLower(getenv("OBSYNC_MAIL_PROVIDER", "log"))
	cfg.MailFrom = os.Getenv("OBSYNC_MAIL_FROM")
	cfg.MailReplyTo = os.Getenv("OBSYNC_MAIL_REPLY_TO")
	cfg.SMTPHost = os.Getenv("OBSYNC_SMTP_HOST")
	cfg.SMTPUser = os.Getenv("OBSYNC_SMTP_USER")
	cfg.SMTPPassword = os.Getenv("OBSYNC_SMTP_PASSWORD")
	cfg.SMTPTLS = strings.ToLower(getenv("OBSYNC_SMTP_TLS", "starttls"))
	cfg.ResendAPIKey = os.Getenv("OBSYNC_RESEND_API_KEY")
	cfg.ResendWebhookSecret = os.Getenv("OBSYNC_RESEND_WEBHOOK_SECRET")
	if v := os.Getenv("OBSYNC_SMTP_PORT"); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil || n <= 0 || n > 65535 {
			return fmt.Errorf("invalid OBSYNC_SMTP_PORT: %q", v)
		}
		cfg.SMTPPort = n
	}
	switch cfg.MailProvider {
	case "log":
	case "smtp":
		if cfg.SMTPHost == "" || cfg.MailFrom == "" {
			return fmt.Errorf("OBSYNC_MAIL_PROVIDER=smtp needs OBSYNC_SMTP_HOST and OBSYNC_MAIL_FROM")
		}
		if cfg.SMTPTLS == "none" && !isLoopbackHost(cfg.SMTPHost) {
			return fmt.Errorf("OBSYNC_SMTP_TLS=none is only allowed for a loopback SMTP relay")
		}
	case "resend":
		if cfg.ResendAPIKey == "" || cfg.MailFrom == "" {
			return fmt.Errorf("OBSYNC_MAIL_PROVIDER=resend needs OBSYNC_RESEND_API_KEY and OBSYNC_MAIL_FROM")
		}
	default:
		return fmt.Errorf("invalid OBSYNC_MAIL_PROVIDER: %q (use log/smtp/resend)", cfg.MailProvider)
	}
	return nil
}

func intEnv(key string, def, min int) (int, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min {
		return 0, fmt.Errorf("invalid %s: %q (integer >= %d)", key, v, min)
	}
	return n, nil
}

// parseByteSize 解析「2GB / 500MB / 1048576 / -1」（1024 进制；大小写不敏感，B/KiB 写法都认）。
func parseByteSize(v string) (int64, error) {
	s := strings.ToUpper(strings.TrimSpace(v))
	if s == "-1" {
		return -1, nil
	}
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"TIB", 1 << 40}, {"GIB", 1 << 30}, {"MIB", 1 << 20}, {"KIB", 1 << 10}, {"TB", 1 << 40}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"T", 1 << 40}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || n > (1<<62)/mult {
		return 0, fmt.Errorf("invalid size %q", v)
	}
	return n * mult, nil
}

func boolEnv(key string, def bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("invalid %s: %q", key, v)
	}
	return b, nil
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func Load() (*Config, error) {
	cfg := &Config{
		Listen:        getenv("OBSYNC_LISTEN", "127.0.0.1:8080"),
		DataDir:       getenv("OBSYNC_DATA_DIR", "./data"),
		Token:         os.Getenv("OBSYNC_TOKEN"),
		MaxFileSize:   100 << 20,
		LogLevel:      slog.LevelInfo,
		BackupKeyFile: os.Getenv("OBSYNC_BACKUP_KEY_FILE"),
		// §7.6：宽松但有限——要覆盖慢速链路上传大附件，又不能让半开连接常驻
		HTTPReadTimeout:  30 * time.Minute,
		HTTPWriteTimeout: 30 * time.Minute,
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
	for _, e := range []struct {
		key string
		dst *time.Duration
	}{
		{"OBSYNC_HTTP_READ_TIMEOUT", &cfg.HTTPReadTimeout},
		{"OBSYNC_HTTP_WRITE_TIMEOUT", &cfg.HTTPWriteTimeout},
	} {
		if v := os.Getenv(e.key); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("invalid %s: %q", e.key, v)
			}
			*e.dst = time.Duration(n) * time.Second
		}
	}
	if v := os.Getenv("OBSYNC_STRICT_BLOB_VERIFY"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid OBSYNC_STRICT_BLOB_VERIFY: %q", v)
		}
		cfg.StrictBlobVerify = b
	}
	if v := os.Getenv("OBSYNC_QUARANTINE_DAYS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OBSYNC_QUARANTINE_DAYS: %q", v)
		}
		cfg.QuarantineRetentionDays = n
	}
	if v := os.Getenv("OBSYNC_HISTORY_MAX_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OBSYNC_HISTORY_MAX_BYTES: %q", v)
		}
		cfg.HistoryMaxBytes = n
	}

	switch strings.ToLower(getenv("OBSYNC_DURABILITY", "strict")) {
	case "strict":
		cfg.DurabilityStrict = true
	case "normal":
		cfg.DurabilityStrict = false
	default:
		return nil, fmt.Errorf("invalid OBSYNC_DURABILITY: %q (use strict/normal)", os.Getenv("OBSYNC_DURABILITY"))
	}

	for _, e := range strings.Split(getenv("OBSYNC_TRUSTED_PROXIES", "127.0.0.1,::1"), ",") {
		if e = strings.TrimSpace(e); e != "" {
			cfg.TrustedProxies = append(cfg.TrustedProxies, e)
		}
	}

	if err := loadPublicLaunch(cfg); err != nil {
		return nil, err
	}
	if err := loadRevocation(cfg); err != nil {
		return nil, err
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
