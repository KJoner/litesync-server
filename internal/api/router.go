// Package api 提供 HTTP 接口层：路由、认证、请求日志。
package api

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"obsync/internal/backup"
	syncsvc "obsync/internal/sync"
	"obsync/internal/web"
)

type Options struct {
	Token       string
	MaxFileSize int64
	Version     string
	Logger      *slog.Logger
	Backup      *backup.Manager // 可为 nil（备份功能未启用）
}

type handlers struct {
	svc  *syncsvc.Service
	opts Options
	web  *sessionStore
}

// New 构建完整的 HTTP handler。
// /api/* 要求 Bearer Token（完整权限）或 Web 只读会话（白名单 GET）。
func New(opts Options, svc *syncsvc.Service) http.Handler {
	h := &handlers{svc: svc, opts: opts, web: newSessionStore()}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /web/session", h.createSession)
	mux.HandleFunc("DELETE /web/session", h.destroySession)
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("GET /api/v1/info", h.info)
	mux.HandleFunc("GET /api/v1/changes", h.changes)
	mux.HandleFunc("GET /api/v1/file", h.getFile)
	mux.HandleFunc("PUT /api/v1/file", h.putFile)
	mux.HandleFunc("DELETE /api/v1/file", h.deleteFile)
	mux.HandleFunc("GET /api/v1/history", h.history)
	mux.HandleFunc("DELETE /api/v1/history", h.purgeHistory)
	mux.HandleFunc("GET /api/v1/version", h.version)
	mux.HandleFunc("GET /api/v1/vault-key", h.getVaultKey)
	mux.HandleFunc("PUT /api/v1/vault-key", h.putVaultKey)
	mux.HandleFunc("GET /api/v1/snapshot", h.snapshot)
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

	// 公开路径（不经过 Token 认证）：分享内容 + Web 静态资源
	mux.HandleFunc("GET /share/{id}", h.getShare)
	if dist, err := fs.Sub(web.Dist, "dist"); err == nil {
		mux.Handle("GET /", http.FileServerFS(dist))
	}

	return requestLog(opts.Logger, securityHeaders(authGate(opts.Token, h.web, mux)))
}

func (h *handlers) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *handlers) info(w http.ResponseWriter, _ *http.Request) {
	latest, err := h.svc.LatestSequence()
	if err != nil {
		h.internalError(w, "info", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":        h.opts.Version,
		"latestSequence": latest,
		"serverTime":     time.Now().Unix(),
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

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
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
