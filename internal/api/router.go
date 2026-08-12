// Package api 提供 HTTP 接口层：路由、认证、请求日志。
package api

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/KJoner/litesync-server/internal/backup"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
	"github.com/KJoner/litesync-server/internal/web"
)

type Options struct {
	Token       string
	MaxFileSize int64
	Version     string
	Logger      *slog.Logger
	Backup      *backup.Manager // 可为 nil（备份功能未启用）
	// TrustedProxies：允许信任其 X-Forwarded-Proto 的反向代理地址（IP 或 CIDR）。
	// 其余来源的该 Header 一律忽略（v9：不再无条件信任任意请求的转发头）。
	TrustedProxies []string
}

type handlers struct {
	svc     *syncsvc.Service
	opts    Options
	web     *sessionStore
	trusted []netip.Prefix // 可信反向代理（X-Forwarded-Proto 只信它们）
}

// New 构建完整的 HTTP handler。
// /api/* 要求 Bearer Token（完整权限）或 Web 只读会话（白名单 GET）。
func New(opts Options, svc *syncsvc.Service) http.Handler {
	h := &handlers{svc: svc, opts: opts, web: newSessionStore(), trusted: parseTrustedProxies(opts.TrustedProxies)}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /web/session", h.createSession)
	mux.HandleFunc("DELETE /web/session", h.destroySession)
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("GET /api/v1/info", h.info)
	mux.HandleFunc("GET /api/v1/changes", h.changes)
	mux.HandleFunc("GET /api/v1/file", h.getFile)
	mux.HandleFunc("PUT /api/v1/file", h.putFile)
	mux.HandleFunc("DELETE /api/v1/file", h.deleteFile)
	mux.HandleFunc("POST /api/v1/file/rename", h.renameFile)             // v6：改名 = 元数据更新，不产生 tombstone
	mux.HandleFunc("POST /api/v1/files/{fileId}/restore", h.restoreFile) // v6：显式恢复已删除对象
	mux.HandleFunc("GET /api/v1/history", h.history)
	mux.HandleFunc("DELETE /api/v1/history", h.purgeHistory)
	mux.HandleFunc("GET /api/v1/version", h.version)
	mux.HandleFunc("GET /api/v1/vault-key", h.getVaultKey)
	mux.HandleFunc("PUT /api/v1/vault-key", h.putVaultKey)
	mux.HandleFunc("GET /api/v1/snapshot", h.snapshot)

	// 多租户治理（v0.16 / §10.4、§10.5）
	mux.HandleFunc("POST /api/v1/token", h.issueAccessToken)
	mux.HandleFunc("DELETE /api/v1/members/{userId}", h.removeMember)
	mux.HandleFunc("GET /api/v1/audit", h.auditTrail)

	// E2EE 状态机（v9）：迁移期间冻结明文写，完成时验证全部 HEAD 均为密文
	mux.HandleFunc("POST /api/v1/e2ee/begin", h.e2eeBegin)
	mux.HandleFunc("POST /api/v1/e2ee/complete", h.e2eeComplete)
	mux.HandleFunc("POST /api/v1/e2ee/abort", h.e2eeAbort)
	// 信封升级完成：验证全部 HEAD 为 LSE3 后把仓库下限提升到 3（ADR-006）
	mux.HandleFunc("POST /api/v1/envelope/complete", h.envelopeComplete)

	// 元数据加密（v9.3 三期）：改名 = 元数据更新；complete = 明文路径抹除（单向）
	mux.HandleFunc("GET /api/v1/file/meta", h.getFileMeta)
	mux.HandleFunc("GET /api/v1/meta/status", h.metaStatus)
	mux.HandleFunc("POST /api/v1/meta/begin", h.metaBegin)
	mux.HandleFunc("POST /api/v1/meta/migrate", h.migrateObject)
	mux.HandleFunc("GET /api/v1/meta/tombstones", h.listPlaintextTombstones)
	mux.HandleFunc("POST /api/v1/meta/migrate-tombstone", h.migrateTombstone)
	mux.HandleFunc("POST /api/v1/meta/renew", h.metaRenew)
	mux.HandleFunc("POST /api/v1/meta/takeover", h.metaTakeover)
	mux.HandleFunc("POST /api/v1/meta/verify", h.metaVerify)
	mux.HandleFunc("GET /api/v1/meta/validate", h.metaValidate)
	mux.HandleFunc("POST /api/v1/meta/complete", h.metaComplete)
	mux.HandleFunc("POST /api/v1/meta/abort", h.metaAbort)
	mux.HandleFunc("GET /api/v1/admin/migration/report", h.erasureReport)

	// 完整性运维（v0.13.3 §7.2）：ADMIN capability
	mux.HandleFunc("GET /api/v1/admin/integrity/scan", h.integrityScan)
	mux.HandleFunc("GET /api/v1/admin/integrity/events", h.integrityEvents)
	mux.HandleFunc("POST /api/v1/admin/integrity/purge-quarantine", h.integrityPurgeQuarantine)
	// 签名 checkpoint（v0.15 / §9）：服务器只存与转发，不验证签名、不裁决分叉
	mux.HandleFunc("POST /api/v1/checkpoint", h.publishCheckpoint)
	mux.HandleFunc("GET /api/v1/checkpoints", h.getCheckpoints)
	mux.HandleFunc("PUT /api/v1/device/signing-key", h.registerSigningKey)

	mux.HandleFunc("POST /api/v1/share", h.createShare)
	mux.HandleFunc("GET /api/v1/shares", h.listShares)
	mux.HandleFunc("DELETE /api/v1/share", h.revokeShare)

	// 备份管理（v6）：ADMIN capability，只读会话触碰一律 403（见 authGate）
	mux.HandleFunc("GET /api/v1/admin/backup/status", h.backupStatus)
	mux.HandleFunc("GET /api/v1/admin/backup/config", h.backupGetConfig)
	mux.HandleFunc("PUT /api/v1/admin/backup/config", h.backupPutConfig)
	mux.HandleFunc("POST /api/v1/admin/backup/test", h.backupTest)
	mux.HandleFunc("POST /api/v1/admin/backup/init", h.backupInit)
	mux.HandleFunc("POST /api/v1/admin/backup/run", h.backupRun)
	mux.HandleFunc("POST /api/v1/admin/backup/check", h.backupCheck)
	mux.HandleFunc("GET /api/v1/admin/backup/snapshots", h.backupSnapshots)
	mux.HandleFunc("GET /api/v1/admin/backup/restore-plan", h.adminRestorePlan)

	// 管理 UI（v0.17 / §11.3）：出事时才会用到的那几件事，
	// 不该只能 SSH 上服务器敲命令
	mux.HandleFunc("GET /api/v1/admin/devices", h.adminDevices)
	mux.HandleFunc("DELETE /api/v1/admin/devices/{id}", h.adminRevokeDevice)
	mux.HandleFunc("GET /api/v1/admin/migration/status", h.adminMigrationStatus)
	mux.HandleFunc("GET /api/v1/admin/shares", h.adminShares)
	mux.HandleFunc("POST /api/v1/admin/shares/{id}/recover", h.adminRecoverShare)

	// 配对（v8 新设备接入）：创建/撤销需 Token；消费与落地页公开（一次性 + 5 分钟过期）
	mux.HandleFunc("POST /api/v1/pairing", h.createPairing)
	mux.HandleFunc("DELETE /api/v1/pairing/{id}", h.deletePairing)
	mux.HandleFunc("POST /pair/{id}/consume", h.consumePairing)
	mux.HandleFunc("GET /p/{id}", h.pairLanding)

	// 设备级凭据（v9.2）：配对包 v2 传一次性注册凭据，根 Token 不再下发到新设备
	mux.HandleFunc("POST /enroll", h.enrollDevice) // 公开：secret 即认证
	mux.HandleFunc("POST /api/v1/devices", h.createDevice)
	mux.HandleFunc("GET /api/v1/devices", h.listDevices)
	mux.HandleFunc("DELETE /api/v1/devices/{id}", h.revokeDevice)
	mux.HandleFunc("POST /api/v1/enrollments", h.createEnrollment)
	mux.HandleFunc("GET /api/v1/whoami", h.whoami)

	// 公开路径（不经过 Token 认证）：分享内容 + Web 静态资源
	mux.HandleFunc("GET /share/{id}", h.getShare)
	if dist, err := fs.Sub(web.Dist, "dist"); err == nil {
		mux.Handle("GET /", http.FileServerFS(dist))
	}

	return requestLog(opts.Logger, securityHeaders(authGate(opts.Token, h.web, svc, mux)))
}

// 协议版本由服务层定义（逐请求校验发生在那里）；这里只做转发。
const (
	ProtocolVersion    = syncsvc.ProtocolVersion
	MinProtocolVersion = syncsvc.MinProtocolVersion
)

func (h *handlers) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *handlers) info(w http.ResponseWriter, _ *http.Request) {
	// vaultId：本仓库的稳定身份（v8）。客户端 Bootstrap 后保存，
	// 发现同一 URL 上 vaultId 变化（服务器重装/换库）即停止自动同步重新接入。
	// repoEpoch（v9）：sequence 空间的世代——从备份恢复后旋转，
	// 客户端据此进入灾备合并而不是沿用旧游标漏掉变更。
	ri, err := h.svc.RepoInfo()
	if err != nil {
		h.internalError(w, "info", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":            h.opts.Version,
		"protocolVersion":    ProtocolVersion,
		"minProtocolVersion": MinProtocolVersion,
		"vaultId":            ri.VaultID,
		"repoEpoch":          ri.RepoEpoch,
		"headSequence":       ri.HeadSequence,
		"latestSequence":     ri.HeadSequence,
		"encryptionState":    ri.EncryptionState,
		"keyEpoch":           ri.KeyEpoch,
		"metaState":          ri.MetaState,
		// 协议 v6：寻址格式世代与仓库信封下限（ADR-006）。
		// formatEpoch 变化 → 客户端必须丢弃游标重新对账；
		// minimumEnvelopeVersion 告诉客户端「再产出旧信封会被拒」。
		"formatEpoch":            ri.FormatEpoch,
		"minimumEnvelopeVersion": ri.MinimumEnvelopeVersion,
		"schemaVersion":          ri.SchemaVersion,
		"migrationId":            ri.MigrationID,
		"migrationOwnerDeviceId": ri.MigrationOwnerDeviceID,
		"serverTime":             time.Now().Unix(),
	})
}

func (h *handlers) internalError(w http.ResponseWriter, op string, err error) {
	h.opts.Logger.Error("internal error", "op", op, "error", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// 机器可识别错误码（v0.12.1 / LS-121-S05）。
// 客户端逻辑只允许根据 code 分支，绝不解析 message 文案。
const (
	CodeInvalidPath         = "INVALID_PATH"
	CodeInvalidHeader       = "INVALID_HEADER"
	CodeInvalidBody         = "INVALID_BODY"
	CodeConflict            = "CONFLICT"
	CodeEnvelopeTooOld      = "ENVELOPE_TOO_OLD"
	CodePlaintextRejected   = "PLAINTEXT_REJECTED"
	CodeMetaRequired        = "META_REQUIRED"
	CodeMetaStateInvalid    = "META_STATE_INVALID"
	CodeStaleMetaGeneration = "STALE_META_GENERATION"
	CodeCanonicalCollision  = "CANONICAL_COLLISION"
	// CodeCorrupted（v0.13.3 / §7.2）：内容已被判定损坏并隔离，服务器拒绝返回。
	// 客户端必须把它与 NOT_FOUND 区别对待——「坏了」不等于「被删了」，
	// 绝不能因此触发本地的删除跟随。
	CodeCorrupted = "CONTENT_CORRUPTED"
	// CodeCheckpointRejected（v0.15 / §9.2）：checkpoint 发布被拒
	//（设备已撤销、未登记签名公钥等）
	CodeCheckpointRejected = "CHECKPOINT_REJECTED"
	CodeFileIDConflict     = "FILE_ID_CONFLICT"
	CodeTombstonePlaintext = "TOMBSTONE_PLAINTEXT"
	CodeHashMismatch       = "HASH_MISMATCH"
	// --- 协议 v6 新增（ADR-003 / ADR-006） ---
	CodeFormatEpochMismatch = "FORMAT_EPOCH_MISMATCH"
	CodeRepoEpochMismatch   = "REPO_EPOCH_MISMATCH"
	CodeKeyEpochMismatch    = "KEY_EPOCH_MISMATCH"
	CodeMigrationNotOwner   = "MIGRATION_NOT_OWNER"
	CodeLeaseActive         = "MIGRATION_LEASE_ACTIVE"
	CodeUpgradeRequired     = "UPGRADE_REQUIRED"
	CodeMigrationLocked     = "MIGRATION_LOCKED"
	CodeMigrationIncomplete = "MIGRATION_INCOMPLETE"
	CodeMigrationMismatch   = "MIGRATION_MISMATCH"
	CodeValidationFailed    = "MIGRATION_VALIDATION_FAILED"
	CodeStaleRevision       = "STALE_REVISION"
	CodeTombstonePurged     = "TOMBSTONE_PURGED"
	CodeNotFound            = "NOT_FOUND"
	CodeUnauthorized        = "UNAUTHORIZED"
	CodeForbidden           = "FORBIDDEN"
	CodeTooLarge            = "TOO_LARGE"
	CodeInternal            = "INTERNAL"
)

// writeCoded 统一错误响应体：{code, message, retryable}。
// 同时保留 error 字段，兼容 0.12.0 及更早只读 error 的客户端。
func writeCoded(w http.ResponseWriter, status int, code, msg string, retryable bool) {
	writeJSON(w, status, map[string]any{
		"code":      code,
		"message":   msg,
		"retryable": retryable,
		"error":     msg,
	})
}

// writeErr 按状态码推断默认错误码（逐步替换为显式 writeCoded）。
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeCoded(w, status, defaultCodeFor(status), msg, status >= http.StatusInternalServerError)
}

func defaultCodeFor(status int) string {
	switch status {
	case http.StatusBadRequest:
		return CodeInvalidBody
	case http.StatusUnauthorized:
		return CodeUnauthorized
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusConflict:
		return CodeConflict
	case http.StatusRequestEntityTooLarge:
		return CodeTooLarge
	case http.StatusUnprocessableEntity:
		return CodeCanonicalCollision
	default:
		if status >= http.StatusInternalServerError {
			return CodeInternal
		}
		return CodeInvalidBody
	}
}

// requestLog 记录每个请求。数据安全红线：绝不记录 Token 与文件内容。
func requestLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		level := slog.LevelInfo
		if r.URL.Path == "/health" {
			level = slog.LevelDebug
		}
		logger.Log(r.Context(), level, "http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"durMs", time.Since(start).Milliseconds(),
			"device", r.Header.Get("X-Device-ID"),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}
