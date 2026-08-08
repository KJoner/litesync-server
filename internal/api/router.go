// Package api 提供 HTTP 接口层：路由、认证、请求日志。
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	syncsvc "obsync/internal/sync"
)

type Options struct {
	Token       string
	MaxFileSize int64
	Version     string
	Logger      *slog.Logger
}

type handlers struct {
	svc  *syncsvc.Service
	opts Options
}

// New 构建完整的 HTTP handler。除 /health 外，/api/* 全部要求 Bearer Token。
func New(opts Options, svc *syncsvc.Service) http.Handler {
	h := &handlers{svc: svc, opts: opts}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("GET /api/v1/info", h.info)
	mux.HandleFunc("GET /api/v1/changes", h.changes)
	mux.HandleFunc("GET /api/v1/file", h.getFile)
	mux.HandleFunc("PUT /api/v1/file", h.putFile)
	mux.HandleFunc("DELETE /api/v1/file", h.deleteFile)
	mux.HandleFunc("GET /api/v1/history", h.history)
	mux.HandleFunc("GET /api/v1/version", h.version)

	return requestLog(opts.Logger, authGate(opts.Token, mux))
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
