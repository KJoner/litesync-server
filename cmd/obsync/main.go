// obsync：自托管 Obsidian 私有同步服务器（v0.18 起支持小范围多用户）。
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

	"github.com/KJoner/litesync-server/internal/api"
	"github.com/KJoner/litesync-server/internal/backup"
	"github.com/KJoner/litesync-server/internal/config"
	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/mail"
	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

const version = "0.20.0"

func main() {
	// rotate-epoch：灾备恢复后的必要步骤（服务停止时执行）。
	// 旋转 repo_epoch 使所有客户端进入恢复合并流程，而不是沿用旧游标
	// 静默跳过「恢复点之后曾经存在」的 sequence 区间。
	if len(os.Args) > 1 && os.Args[1] == "rotate-epoch" {
		if err := rotateEpoch(); err != nil {
			fmt.Fprintln(os.Stderr, "obsync rotate-epoch:", err)
			os.Exit(1)
		}
		return
	}
	// token reset：API Token 重置的 SSH 兜底（v0.18）。
	// 网页端的重置受 E2EE 重置凭证保护；shell 权限即最终授权，这里不设门禁。
	// identity / vaults：统一身份认领与初始化状态的 SSH 兜底（v0.20）
	if len(os.Args) > 1 && (os.Args[1] == "identity" || os.Args[1] == "vaults") {
		run := runIdentity
		if os.Args[1] == "vaults" {
			run = runVaults
		}
		if err := run(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "obsync "+os.Args[1]+":", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "token" {
		if err := runToken(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "obsync token:", err)
			os.Exit(1)
		}
		return
	}
	// 运维子命令（v0.13.3 / §7.8）：backup / integrity / migration
	if handled, err := runOps(os.Args[1:]); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "obsync:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "obsync:", err)
		os.Exit(1)
	}
}

func rotateEpoch() error {
	database, err := openExistingDB() // OBSYNC_DB=sqlite|postgres（批次 G）
	if err != nil {
		return err
	}
	defer database.Close()
	// rotate-epoch 是运维命令，没有 HTTP 认证上下文。
	// v0.18 多 Vault：默认作用于 default；--vault <id> 指定其他租户；
	// --all 逐个旋转（灾备恢复后应对所有 Vault 执行）。
	var scopes []db.VaultScope
	switch {
	case len(os.Args) > 3 && os.Args[2] == "--vault":
		scopes = []db.VaultScope{db.ScopeFromAuth(os.Args[3])}
	case len(os.Args) > 2 && os.Args[2] == "--all":
		var err error
		if scopes, err = db.AllVaultScopes(database); err != nil {
			return err
		}
	default:
		scopes = []db.VaultScope{db.LegacyDefaultScope()}
	}
	for _, scope := range scopes {
		epoch, err := db.RotateEpoch(database, scope)
		if err != nil {
			return fmt.Errorf("vault %s: %w", scope.ID(), err)
		}
		fmt.Printf("repo epoch rotated (vault %s): %s\n", scope.ID(), epoch)
	}
	fmt.Println("clients will pause normal sync and enter recovery merge on next contact")
	return nil
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
	// 批次 G：OBSYNC_DB=sqlite（默认，数据目录里的 sync.db）| postgres（OBSYNC_PG_DSN）
	database, dbc, err := openDatabase(cfg.DataDir, cfg.DurabilityStrict)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()
	logger.Info("metadata database", "driver", dbc.String())
	if dbc.Warning != "" {
		logger.Warn(dbc.Warning)
	}
	if !dbc.IsPostgres() {
		os.Chmod(dbPath, 0o600) //nolint:errcheck
	}

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
		// v0.13.3 §7.1 / §7.3
		StrictBlobVerify:        cfg.StrictBlobVerify,
		QuarantineRetentionDays: cfg.QuarantineRetentionDays,
		// 用户级配额默认值（需求 §12；管理员可逐用户覆盖）
		QuotaBytesPerUser:  cfg.QuotaBytesPerUser,
		QuotaVaultsPerUser: cfg.QuotaVaultsPerUser,
	}, logger)

	// v5 → v6 数据迁移（ADR-001 §5 / ADR-003 §5）。
	//
	// 放在这里而不是 db.Open 里：迁移要读 blob 的 LSE3 信封头才能推断
	// contentGeneration、keyEpoch 与信封版本，因此必须等 blob store 就绪。
	// 由 migration_journal 驱动，逐对象提交——中途崩溃重启后续跑，重复执行幂等。
	// 旧表迁移后重命名为 v5_* 只读保留（回滚窗口），由 `obsync migration finalize` 删除。
	if need, err := db.NeedsV6Migration(database); err != nil {
		return fmt.Errorf("check v6 migration: %w", err)
	} else if need {
		report, err := db.MigrateToV6(database, svc.BlobProbe(), logger)
		if err != nil {
			// 迁移失败绝不带病启动：旧表原样保留，换回上一版二进制即可继续服务
			return fmt.Errorf("v5→v6 migration failed (old tables are intact, you can roll back): %w", err)
		}
		if report != nil && (report.OrphanVersions > 0 || report.NeedsReview > 0 || report.MissingBlobs > 0) {
			logger.Warn("v6 migration needs attention",
				"orphanVersions", report.OrphanVersions,
				"tombstonesNeedingReview", report.NeedsReview,
				"missingBlobs", report.MissingBlobs)
		}
	}
	// blobID 域分隔密钥（v0.16.0 / §10.3）：首次启动生成并落库，之后固定不变。
	// 必须在开始服务之前就绪——上传路径要用它算存储 id。
	if err := svc.InitVaultSecret(); err != nil {
		return fmt.Errorf("init vault secret: %w", err)
	}
	// v0.18：管理员账号与 Token 哈希落库（幂等对账）。
	// OBSYNC_TOKEN 从「唯一凭据」降级为「首次初始化的种子」；
	// 网页端轮换过之后以库为准，环境变量失效（对账函数里会打醒目警告）。
	if _, err := svc.EnsureAdminAccount(cfg.Token); err != nil {
		return fmt.Errorf("reconcile admin account: %w", err)
	}
	// v0.20.1 账号撤销（ADR-019）：跨产品事件与中心状态检查。未配置时如实告知能力缺口
	if cfg.PeerRevocationEnabled() {
		svc.SetPeerRevocation(syncsvc.PeerRevocationConfig{URL: cfg.PeerRevocationURL, Secret: cfg.PeerRevocationSecret})
		logger.Info("cross-product revocation enabled", "peer", "nexus")
		if !cfg.OIDCEnabled() {
			logger.Warn("跨产品撤销已配置但未启用统一登录：没有可按 (issuer, subject) 匹配的账号，收到的事件只会记为 unknown-identity")
		}
	} else if cfg.OIDCEnabled() {
		logger.Warn("跨产品撤销未配置（OBSYNC_PEER_REVOCATION_URL / OBSYNC_PEER_REVOCATION_SECRET）：" +
			"「退出所有产品与设备」不会通知另一个产品（Nexus Portal），账户中心会把这一步显示为「未配置」")
	}
	if cfg.CentralStatusCheckEnabled() {
		logger.Info("central account status check enabled (read-only service account)", "client", cfg.OIDCStatusClientID)
	} else if cfg.OIDCEnabled() {
		logger.Warn("中心状态检查未配置（OBSYNC_OIDC_STATUS_CLIENT_ID / _SECRET）：身份中心停用或删除用户后，" +
			"只有网页会话会在刷新复核时结束，已连接的设备不会自动失效，需要在产品里撤销；开放公众注册前必须配置")
	}
	// v0.18 实测事故的自检：残留的「enabled 密钥文档 + plaintext 仓库」矛盾会挡停新设备
	svc.CheckE2eeConsistency()
	// 存量数据的域化迁移是**告警**而不是硬门槛：混合状态读写都正确
	// （每一行的 blob_id 自带「文件在哪」），只是老数据上还存在跨租户
	// 存在性预言机。拒绝启动只会逼运维在没备份的情况下跑一个不可逆迁移。
	if need, err := svc.NeedsBlobIDMigration(); err != nil {
		logger.Warn("check blobid migration failed", "error", err)
	} else if need {
		logger.Warn("存量 blob 仍使用裸 contentHash 命名：跨租户存在性隔离（§10.3）对老数据尚未生效。" +
			"先 `obsync backup create`，再 `obsync blobid migrate --confirm`")
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
	// v6：备份管理器（restic → Cloudflare R2）。密钥文件不可用时功能禁用但服务照常运行
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bkp := backup.New(database, svc, backup.NewRunner(""), cfg.DataDir, version, cfg.BackupKeyFile, logger)
	bkp.StartScheduler(ctx)
	// 跨产品撤销事件的后台重试（5 s、15 s、30 s…，7 天后记为失败；未配置时不启动）
	svc.StartRevocationWorker(ctx)

	// v0.20：产品通知邮件（ADR-018）。默认 log 渠道（不外发），配置了才真正投递
	mailCfg := mail.Config{
		Provider: cfg.MailProvider, From: cfg.MailFrom, ReplyTo: cfg.MailReplyTo,
		SMTPHost: cfg.SMTPHost, SMTPPort: cfg.SMTPPort, SMTPUser: cfg.SMTPUser,
		SMTPPassword: cfg.SMTPPassword, SMTPTLS: cfg.SMTPTLS,
		ResendAPIKey: cfg.ResendAPIKey, PublicURL: cfg.PublicURL,
		DailyBudget: cfg.MailDailyBudget,
	}
	mailProvider, err := mail.NewProvider(mailCfg, logger)
	if err != nil {
		logger.Error("mail provider", "error", err)
		os.Exit(1)
	}
	outbox := mail.NewOutbox(database, mailProvider, mailCfg, logger)
	outbox.Start(ctx)
	svc.SetNotifier(outbox)
	var mailWebhook http.Handler
	if cfg.ResendWebhookSecret != "" {
		mailWebhook = &mail.ResendWebhook{DB: database, Secret: cfg.ResendWebhookSecret, Log: logger}
	}
	logger.Info("product notifications", "provider", mailProvider.Name())

	handler := api.New(api.Options{
		Token:          cfg.Token,
		MaxFileSize:    cfg.MaxFileSize,
		Version:        version,
		Logger:         logger,
		Backup:         bkp,
		TrustedProxies: cfg.TrustedProxies,
		// v0.20 公开化：统一登录（ADR-011）与新仓库强制 E2EE（ADR-012）
		OIDC: api.OIDCOptions{
			Issuer:           cfg.OIDCIssuer,
			ClientID:         cfg.OIDCClientID,
			ClientSecret:     cfg.OIDCClientSecret,
			PublicURL:        cfg.PublicURL,
			RegistrationMode: cfg.RegistrationMode,
			// ADR-019 §2.5：中心状态检查的只读服务账号（未配置则不检查）
			StatusClientID:     cfg.OIDCStatusClientID,
			StatusClientSecret: cfg.OIDCStatusClientSecret,
			AdminAPIURL:        cfg.OIDCAdminAPIURL,
		},
		LegacyTokenLogin:     cfg.LegacyTokenLogin,
		RequireE2EENewVaults: cfg.RequireE2EENewVaults,
		WebEditing:           cfg.WebEditing,
		MailWebhook:          mailWebhook,
		// 配额与限流（需求 §12）
		RatePerUserPerMin:        cfg.RatePerUserPerMin,
		UploadConcurrencyPerUser: cfg.UploadConcurrencyPerUser,
	}, svc)
	if cfg.OIDCEnabled() {
		logger.Info("unified sign-in enabled", "issuer", cfg.OIDCIssuer,
			"registration", cfg.RegistrationMode, "legacyTokenLogin", cfg.LegacyTokenLogin)
	}

	// HTTP 超时与限额（v0.13.3 / 计划书 §7.6）。
	//
	// 取值上的权衡：ReadTimeout / WriteTimeout 必须覆盖「慢速链路上传大附件」
	// 这种正常场景，否则同步会在弱网下莫名其妙地失败；但又不能不设，
	// 否则一个半开连接可以无限期占着 goroutine 与文件句柄。
	// 因此给一个宽松但有限的值（默认 30 分钟），并允许管理员按自己的网络调整。
	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: handler,
		// 请求头必须很快读完——慢速发送 Header 是最典型的耗尽攻击
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.HTTPReadTimeout,
		WriteTimeout:      cfg.HTTPWriteTimeout,
		IdleTimeout:       120 * time.Second,
		// Header 总长度上限：默认 1 MiB 对一个只用少量自定义 Header 的协议
		// 来说远远够用，同时挡住「几万个 Header」这类请求
		MaxHeaderBytes: 64 << 10,
	}

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
