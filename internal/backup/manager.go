package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	gosync "sync"
	"time"

	"obsync/internal/db"
)

const (
	configMetaKey = "backup-config" // AES-256-GCM 密文（base64）
	statusMetaKey = "backup-status" // 明文 JSON，不含 Secret

	// restic 快照按 host+paths 分组；容器重建会改变 hostname，固定 host 保证
	// forget 保留策略始终作用于同一组快照。
	resticHost = "litesync"

	quickTimeout  = 60 * time.Second
	statsTimeout  = 5 * time.Minute
	forgetTimeout = 30 * time.Minute
	longTimeout   = 2 * time.Hour // backup / prune / check
)

var (
	ErrJobRunning         = errors.New("another backup job is already running")
	ErrNotConfigured      = errors.New("backup is not configured")
	ErrRepoNotInitialized = errors.New("restic repository is not initialized")
)

// Manager 备份管理器：唯一的 restic 调用入口 + 单任务互斥 + 状态持久化。
// 备份是服务器旁路能力：任何失败都只标记 Backup=Failed，绝不影响同步。
type Manager struct {
	db      *sql.DB
	quiesce Quiescer
	runner  Runner
	log     *slog.Logger
	dataDir string
	version string

	key    []byte // backup-config.key；不可用时为 nil
	keyErr string

	// 配置与状态的内存镜像（persist 到 vault_meta）
	mu     gosync.Mutex
	cfg    Config
	status Status

	// 单任务互斥：backup / prune / check / forget 永不并发
	jobMu   gosync.Mutex
	jobBusy bool
}

// New 创建 Manager。keyFile 为空或不可用时备份功能整体禁用（Status 会说明原因）。
func New(database *sql.DB, quiesce Quiescer, runner Runner, dataDir, version, keyFile string, logger *slog.Logger) *Manager {
	m := &Manager{
		db:      database,
		quiesce: quiesce,
		runner:  runner,
		log:     logger,
		dataDir: dataDir,
		version: version,
		cfg:     defaultConfig(),
	}

	if keyFile == "" {
		m.keyErr = "backup key file not configured (OBSYNC_BACKUP_KEY_FILE)"
	} else if key, err := LoadOrCreateKey(keyFile); err != nil {
		m.keyErr = err.Error()
		logger.Warn("backup disabled", "reason", err)
	} else {
		m.key = key
	}

	m.loadPersisted()
	m.probeRestic()
	cleanStaging(dataDir) // 上次崩溃可能遗留 staging
	return m
}

// ---------- 持久化 ----------

func (m *Manager) loadPersisted() {
	if raw, ok, err := db.GetMeta(m.db, statusMetaKey); err == nil && ok {
		json.Unmarshal([]byte(raw), &m.status) //nolint:errcheck
	}
	m.status.Running = false // 崩溃恢复：不可能有任务还在跑
	m.status.RunningOp = ""

	if m.key != nil {
		if enc, ok, err := db.GetMeta(m.db, configMetaKey); err == nil && ok {
			if cfg, derr := decodeConfig(m.key, enc); derr == nil {
				m.cfg = cfg
			} else {
				m.log.Error("backup config undecryptable (key changed?)", "error", derr)
				m.keyErr = "backup config cannot be decrypted; backup-config.key may have changed"
				m.key = nil
			}
		}
	}
}

func (m *Manager) saveConfigLocked() error {
	enc, err := encodeConfig(m.key, m.cfg)
	if err != nil {
		return err
	}
	return db.SetMeta(m.db, configMetaKey, enc, time.Now().Unix())
}

func (m *Manager) saveStatusLocked() {
	raw, err := json.Marshal(m.status)
	if err != nil {
		return
	}
	if err := db.SetMeta(m.db, statusMetaKey, string(raw), time.Now().Unix()); err != nil {
		m.log.Warn("save backup status", "error", err)
	}
}

func (m *Manager) probeRestic() {
	ctx, cancel := context.WithTimeout(context.Background(), quickTimeout)
	defer cancel()
	out, err := m.runner.Run(ctx, []string{"version"}, nil)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.status.ResticOK = false
		m.log.Warn("restic not available", "error", err)
		return
	}
	m.status.ResticOK = true
	m.status.ResticVersion = strings.TrimSpace(strings.TrimPrefix(strings.SplitN(string(out), "\n", 2)[0], "restic "))
}

// ---------- 配置 ----------

func (m *Manager) GetConfig() View {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.view()
}

func (m *Manager) SetConfig(u Update) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.key == nil {
		return View{}, fmt.Errorf("%w: %s", ErrKeyUnavailable, m.keyErr)
	}
	next, err := m.cfg.apply(u)
	if err != nil {
		return View{}, err
	}
	prev := m.cfg
	m.cfg = next
	if err := m.saveConfigLocked(); err != nil {
		m.cfg = prev
		return View{}, err
	}
	m.status.Enabled = next.Enabled
	m.status.Configured = next.configured()
	if !next.Enabled {
		m.status.NextRunAt = 0
	}
	m.saveStatusLocked()
	return next.view(), nil
}

// Status 返回当前状态快照。
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	s.KeyAvailable = m.key != nil
	s.KeyError = m.keyErr
	s.Enabled = m.cfg.Enabled
	s.Configured = m.cfg.configured()
	s.BudgetBytes = int64(m.cfg.BudgetGB) << 30
	return s
}

// ---------- 任务互斥 ----------

// acquireJob 获取任务锁；已有任务在跑时返回 ErrJobRunning（绝不排队等待）。
func (m *Manager) acquireJob(op string) (release func(), err error) {
	m.jobMu.Lock()
	if m.jobBusy {
		m.jobMu.Unlock()
		return nil, ErrJobRunning
	}
	m.jobBusy = true
	m.jobMu.Unlock()

	m.mu.Lock()
	m.status.Running = true
	m.status.RunningOp = op
	m.mu.Unlock()

	return func() {
		m.mu.Lock()
		m.status.Running = false
		m.status.RunningOp = ""
		m.saveStatusLocked()
		m.mu.Unlock()
		m.jobMu.Lock()
		m.jobBusy = false
		m.jobMu.Unlock()
	}, nil
}

// snapshotCfg 返回可用于执行 restic 的配置副本。
func (m *Manager) snapshotCfg() (Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.key == nil {
		return Config{}, fmt.Errorf("%w: %s", ErrKeyUnavailable, m.keyErr)
	}
	if !m.cfg.configured() {
		return Config{}, ErrNotConfigured
	}
	return m.cfg, nil
}

// env 构建 restic 子进程环境。凭据只在这里出现，绝不进入命令行参数。
func (c Config) env(dataDir string) map[string]string {
	env := map[string]string{
		"RESTIC_REPOSITORY":     c.repository(),
		"RESTIC_PASSWORD":       c.ResticPassword,
		"AWS_ACCESS_KEY_ID":     c.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY": c.SecretAccessKey,
		"RESTIC_CACHE_DIR":      filepath.Join(dataDir, ".restic-cache"),
	}
	if c.Endpoint == "" {
		env["AWS_DEFAULT_REGION"] = "auto" // Cloudflare R2
	}
	return env
}

// ---------- 操作 ----------

// Test 验证连通性与凭据：能读到 repo config = Endpoint/凭据/密码全部正确。
// 仓库尚未初始化返回 ErrRepoNotInitialized（连接本身是通的）。
func (m *Manager) Test(ctx context.Context) error {
	cfg, err := m.snapshotCfg()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, quickTimeout)
	defer cancel()
	_, err = m.runner.Run(ctx, []string{"cat", "config"}, cfg.env(m.dataDir))
	if err != nil {
		if isNotInitialized(err) {
			return ErrRepoNotInitialized
		}
		return err
	}
	return nil
}

// Initialize 初始化 restic repository（只需执行一次）。
func (m *Manager) Initialize(ctx context.Context) error {
	cfg, err := m.snapshotCfg()
	if err != nil {
		return err
	}
	release, err := m.acquireJob("init")
	if err != nil {
		return err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, quickTimeout)
	defer cancel()
	if _, err := m.runner.Run(ctx, []string{"init"}, cfg.env(m.dataDir)); err != nil {
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "already initialized") {
			return fmt.Errorf("repository already initialized")
		}
		return err
	}
	m.log.Info("backup repository initialized")
	return nil
}

// Backup 执行一次完整备份：一致性 staging → restic backup → 清理 → 刷新统计。
func (m *Manager) Backup(ctx context.Context, reason string) (*BackupResult, error) {
	cfg, err := m.snapshotCfg()
	if err != nil {
		return nil, err
	}
	release, err := m.acquireJob("backup")
	if err != nil {
		return nil, err
	}
	defer release()

	start := time.Now()
	m.mu.Lock()
	m.status.LastStartedAt = start.Unix()
	m.saveStatusLocked()
	m.mu.Unlock()
	m.log.Info("backup started", "reason", reason)

	result, err := m.runBackup(ctx, cfg)

	m.mu.Lock()
	if err != nil {
		m.status.LastError = err.Error()
		m.log.Error("backup failed", "error", err)
	} else {
		m.status.LastError = ""
		m.status.LastCompletedAt = time.Now().Unix()
		m.status.LastDurationMs = time.Since(start).Milliseconds()
		m.status.LastSnapshotID = result.SnapshotID
	}
	m.saveStatusLocked()
	m.mu.Unlock()

	if err != nil {
		return nil, err
	}
	m.refreshStats(ctx, cfg) // best-effort
	m.log.Info("backup success", "snapshot", result.SnapshotID, "durMs", result.DurationMs, "dataAdded", result.DataAdded)
	return result, nil
}

func (m *Manager) runBackup(ctx context.Context, cfg Config) (*BackupResult, error) {
	staging, err := buildStaging(m.db, m.quiesce, m.dataDir, m.version)
	if err != nil {
		return nil, fmt.Errorf("snapshot staging: %w", err)
	}
	defer cleanStaging(m.dataDir)
	m.log.Info("snapshot prepared", "staging", staging)

	ctx, cancel := context.WithTimeout(ctx, longTimeout)
	defer cancel()
	out, err := m.runner.Run(ctx,
		[]string{"backup", staging, "--host", resticHost, "--tag", "litesync", "--json"},
		cfg.env(m.dataDir))
	if err != nil {
		return nil, err
	}

	result := &BackupResult{}
	// --json 输出为逐行 JSON，最后的 summary 行包含 snapshot_id
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var msg struct {
			MessageType  string `json:"message_type"`
			SnapshotID   string `json:"snapshot_id"`
			FilesNew     int64  `json:"files_new"`
			FilesChanged int64  `json:"files_changed"`
			DataAdded    int64  `json:"data_added"`
			TotalDur     float64 `json:"total_duration"`
		}
		if json.Unmarshal([]byte(line), &msg) == nil && msg.MessageType == "summary" {
			result.SnapshotID = msg.SnapshotID
			result.FilesNew = msg.FilesNew
			result.FilesChanged = msg.FilesChanged
			result.DataAdded = msg.DataAdded
			result.DurationMs = int64(msg.TotalDur * 1000)
		}
	}
	if result.SnapshotID == "" {
		return nil, errors.New("restic completed but no snapshot summary found")
	}
	return result, nil
}

// ListSnapshots 列出仓库中的快照。
func (m *Manager) ListSnapshots(ctx context.Context) ([]Snapshot, error) {
	cfg, err := m.snapshotCfg()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, statsTimeout)
	defer cancel()
	out, err := m.runner.Run(ctx, []string{"snapshots", "--host", resticHost, "--json"}, cfg.env(m.dataDir))
	if err != nil {
		if isNotInitialized(err) {
			return nil, ErrRepoNotInitialized
		}
		return nil, err
	}
	var snaps []Snapshot
	if err := json.Unmarshal(out, &snaps); err != nil {
		return nil, fmt.Errorf("parse snapshots: %w", err)
	}
	return snaps, nil
}

// Check 校验仓库完整性（restic check）。
func (m *Manager) Check(ctx context.Context) error {
	cfg, err := m.snapshotCfg()
	if err != nil {
		return err
	}
	release, err := m.acquireJob("check")
	if err != nil {
		return err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, longTimeout)
	defer cancel()
	if _, err := m.runner.Run(ctx, []string{"check"}, cfg.env(m.dataDir)); err != nil {
		m.mu.Lock()
		m.status.LastError = "check failed: " + err.Error()
		m.saveStatusLocked()
		m.mu.Unlock()
		return err
	}
	m.mu.Lock()
	m.status.LastCheckAt = time.Now().Unix()
	m.saveStatusLocked()
	m.mu.Unlock()
	m.log.Info("backup check ok")
	return nil
}

// Forget 应用保留策略（不做 prune，对象删除由每周 prune 完成）。
func (m *Manager) Forget(ctx context.Context) error {
	cfg, err := m.snapshotCfg()
	if err != nil {
		return err
	}
	release, err := m.acquireJob("forget")
	if err != nil {
		return err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, forgetTimeout)
	defer cancel()
	args := append([]string{"forget", "--host", resticHost}, retentionArgs()...)
	if _, err := m.runner.Run(ctx, args, cfg.env(m.dataDir)); err != nil {
		return err
	}
	m.mu.Lock()
	m.status.LastForgetAt = time.Now().Unix()
	m.saveStatusLocked()
	m.mu.Unlock()
	return nil
}

// Prune 清理仓库中不再引用的对象。
// 备份生命周期只允许 restic forget/prune 管理，绝不配置 R2 Lifecycle 直接删对象。
func (m *Manager) Prune(ctx context.Context) error {
	cfg, err := m.snapshotCfg()
	if err != nil {
		return err
	}
	release, err := m.acquireJob("prune")
	if err != nil {
		return err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, longTimeout)
	defer cancel()
	if _, err := m.runner.Run(ctx, []string{"prune"}, cfg.env(m.dataDir)); err != nil {
		return err
	}
	m.mu.Lock()
	m.status.LastPruneAt = time.Now().Unix()
	m.saveStatusLocked()
	m.mu.Unlock()
	m.log.Info("backup prune done")
	return nil
}

// refreshStats 备份成功后 best-effort 刷新仓库统计（快照数 + 估算大小）。
func (m *Manager) refreshStats(ctx context.Context, cfg Config) {
	sctx, cancel := context.WithTimeout(ctx, statsTimeout)
	defer cancel()

	count := -1
	if out, err := m.runner.Run(sctx, []string{"snapshots", "--host", resticHost, "--json"}, cfg.env(m.dataDir)); err == nil {
		var snaps []Snapshot
		if json.Unmarshal(out, &snaps) == nil {
			count = len(snaps)
		}
	}
	var size int64 = -1
	if out, err := m.runner.Run(sctx, []string{"stats", "--mode", "raw-data", "--json"}, cfg.env(m.dataDir)); err == nil {
		var stats struct {
			TotalSize int64 `json:"total_size"`
		}
		if json.Unmarshal(out, &stats) == nil {
			size = stats.TotalSize
		}
	}

	m.mu.Lock()
	if count >= 0 {
		m.status.SnapshotCount = count
	}
	if size >= 0 {
		m.status.RepositorySize = size
	}
	m.saveStatusLocked()
	m.mu.Unlock()
}

// isNotInitialized 识别「仓库不存在」类错误（restic 0.17+ 有专属 exit code 10，
// 同时兼容旧版本的 stderr 文案）。
func isNotInitialized(err error) bool {
	s := err.Error()
	return strings.Contains(s, "exit status 10") ||
		strings.Contains(s, "repository does not exist") ||
		strings.Contains(s, "unable to open config file") ||
		strings.Contains(s, "Is there a repository at the following location")
}
