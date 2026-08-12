package backup

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// Config 备份配置。整个结构体以 AES-256-GCM 加密后保存在 vault_meta
// （key = backup-config），明文永不落盘。
type Config struct {
	Enabled  bool   `json:"enabled"`  // 自动备份开关
	Provider string `json:"provider"` // "r2"（S3 兼容）或 "local"（本地/挂载盘）

	// LocalPath（Provider = "local"）：restic 仓库所在目录。
	//
	// 为什么支持本地仓库：不是所有自建用户都愿意（或能够）用对象存储。
	// 备份到挂载的 NAS 或外接盘是完全正当的生产配置，而且它让**灾备恢复
	// 演练**成为一件随时可做的事——一个只能备份到付费云的系统，
	// 实际上等于没人会去演练恢复。
	//
	// 注意：本地仓库与数据目录放在同一块盘上时，同一次硬件故障会同时带走
	// 两者。这一点在 README 里明确警告，但不在代码里强制——挂载点是否
	// 独立，只有管理员知道。
	LocalPath string `json:"localPath"`

	AccountID string `json:"accountId"` // Cloudflare Account ID
	Bucket    string `json:"bucket"`
	Prefix    string `json:"prefix"`   // Repository 前缀，默认 restic
	Endpoint  string `json:"endpoint"` // 可选：覆盖 S3 Endpoint（B2/MinIO 等）

	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	ResticPassword  string `json:"resticPassword"`

	BudgetGB int `json:"budgetGb"` // 仓库预算（仅展示告警，绝不自动删除对象）
}

// View 是返回给 Web 的公开视图：绝不包含任何 Secret。
type View struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`

	AccountID string `json:"accountId"`
	Bucket    string `json:"bucket"`
	Prefix    string `json:"prefix"`
	Endpoint  string `json:"endpoint"`
	LocalPath string `json:"localPath"`

	AccessKeyConfigured      bool `json:"accessKeyConfigured"`
	SecretKeyConfigured      bool `json:"secretKeyConfigured"`
	ResticPasswordConfigured bool `json:"resticPasswordConfigured"`

	BudgetGB int `json:"budgetGb"`
}

func defaultConfig() Config {
	return Config{Provider: "r2", Prefix: "restic", BudgetGB: 10}
}

func (c Config) view() View {
	return View{
		Enabled:                  c.Enabled,
		Provider:                 c.Provider,
		AccountID:                c.AccountID,
		Bucket:                   c.Bucket,
		Prefix:                   c.Prefix,
		Endpoint:                 c.Endpoint,
		LocalPath:                c.LocalPath,
		AccessKeyConfigured:      c.AccessKeyID != "",
		SecretKeyConfigured:      c.SecretAccessKey != "",
		ResticPasswordConfigured: c.ResticPassword != "",
		BudgetGB:                 c.BudgetGB,
	}
}

// isLocal 报告是否使用本地仓库后端。
func (c Config) isLocal() bool { return c.Provider == "local" }

// configured 判断是否具备执行 restic 的全部条件。
func (c Config) configured() bool {
	if c.ResticPassword == "" {
		return false
	}
	if c.isLocal() {
		// 本地仓库不需要任何云凭据
		return c.LocalPath != ""
	}
	return c.Bucket != "" && c.AccessKeyID != "" && c.SecretAccessKey != "" &&
		(c.AccountID != "" || c.Endpoint != "")
}

// repository 返回 restic 的 -r 值。
func (c Config) repository() string {
	if c.isLocal() {
		return c.LocalPath
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s.r2.cloudflarestorage.com", c.AccountID)
	}
	prefix := c.Prefix
	if prefix == "" {
		prefix = "restic"
	}
	return fmt.Sprintf("s3:%s/%s/%s", strings.TrimRight(endpoint, "/"), c.Bucket, prefix)
}

// Update 是 PUT config 的请求体。Secret 字段留空 → 保持原值（Web 表单永远拿不到旧值）。
type Update struct {
	Enabled  *bool   `json:"enabled"`
	Provider *string `json:"provider"`

	AccountID *string `json:"accountId"`
	Bucket    *string `json:"bucket"`
	Prefix    *string `json:"prefix"`
	Endpoint  *string `json:"endpoint"`

	AccessKeyID     *string `json:"accessKeyId"`
	SecretAccessKey *string `json:"secretAccessKey"`
	ResticPassword  *string `json:"resticPassword"`

	LocalPath *string `json:"localPath"`

	BudgetGB *int `json:"budgetGb"`
}

// apply 把更新合并进现有配置：nil 字段不动；Secret 字段空字符串同样保持原值。
func (c Config) apply(u Update) (Config, error) {
	out := c
	if u.Enabled != nil {
		out.Enabled = *u.Enabled
	}
	if u.Provider != nil && *u.Provider != "" {
		if *u.Provider != "r2" && *u.Provider != "local" {
			return c, fmt.Errorf("unsupported provider %q (use r2 or local)", *u.Provider)
		}
		out.Provider = *u.Provider
	}
	if u.LocalPath != nil {
		p := strings.TrimSpace(*u.LocalPath)
		// 必须是绝对路径：相对路径会随服务的工作目录漂移，
		// 而备份仓库找不到这件事往往要到需要恢复的那天才被发现
		if p != "" && !filepath.IsAbs(p) {
			return c, fmt.Errorf("localPath must be an absolute path")
		}
		out.LocalPath = p
	}
	if u.AccountID != nil {
		out.AccountID = strings.TrimSpace(*u.AccountID)
	}
	if u.Bucket != nil {
		out.Bucket = strings.TrimSpace(*u.Bucket)
	}
	if u.Prefix != nil {
		p := strings.Trim(strings.TrimSpace(*u.Prefix), "/")
		if p == "" {
			p = "restic"
		}
		out.Prefix = p
	}
	if u.Endpoint != nil {
		ep := strings.TrimSpace(*u.Endpoint)
		if ep != "" && !strings.HasPrefix(ep, "https://") && !strings.HasPrefix(ep, "http://") {
			return c, fmt.Errorf("endpoint must start with https://")
		}
		out.Endpoint = ep
	}
	if u.AccessKeyID != nil && *u.AccessKeyID != "" {
		out.AccessKeyID = strings.TrimSpace(*u.AccessKeyID)
	}
	if u.SecretAccessKey != nil && *u.SecretAccessKey != "" {
		out.SecretAccessKey = strings.TrimSpace(*u.SecretAccessKey)
	}
	if u.ResticPassword != nil && *u.ResticPassword != "" {
		out.ResticPassword = *u.ResticPassword
	}
	if u.BudgetGB != nil && *u.BudgetGB >= 0 {
		out.BudgetGB = *u.BudgetGB
	}
	if out.Enabled && !out.configured() {
		return c, fmt.Errorf("cannot enable backup: R2 credentials or restic password missing")
	}
	return out, nil
}

func encodeConfig(key []byte, c Config) (string, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return seal(key, raw)
}

func decodeConfig(key []byte, encoded string) (Config, error) {
	raw, err := open(key, encoded)
	if err != nil {
		return Config{}, err
	}
	c := defaultConfig()
	if err := json.Unmarshal(raw, &c); err != nil {
		return Config{}, err
	}
	return c, nil
}
