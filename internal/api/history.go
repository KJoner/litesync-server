package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"obsync/internal/storage"
	syncsvc "obsync/internal/sync"
)

type apiVersion struct {
	Revision  int64  `json:"revision"`
	Action    string `json:"action"`
	Size      int64  `json:"size"`
	Mtime     int64  `json:"mtime"`
	Hash      string `json:"hash,omitempty"`
	DeviceID  string `json:"deviceId,omitempty"`
	CreatedAt int64  `json:"createdAt"`
}

// history 返回某路径的历史版本列表（revision 降序）。
// GET /api/v1/history?path=...
func (h *handlers) history(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeErr(w, http.StatusBadRequest, "missing path")
		return
	}
	versions, err := h.svc.History(path)
	if err != nil {
		if errors.Is(err, storage.ErrInvalidPath) {
			writeErr(w, http.StatusBadRequest, "invalid path")
			return
		}
		h.internalError(w, "history", err)
		return
	}
	out := make([]apiVersion, 0, len(versions))
	for _, v := range versions {
		out = append(out, apiVersion{
			Revision:  v.Revision,
			Action:    v.Action,
			Size:      v.Size,
			Mtime:     v.Mtime,
			Hash:      v.ContentHash,
			DeviceID:  v.DeviceID,
			CreatedAt: v.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": path, "versions": out})
}

// version 返回某历史版本的原始字节。
// GET /api/v1/version?path=...&revision=15
func (h *handlers) version(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeErr(w, http.StatusBadRequest, "missing path")
		return
	}
	revision, err := strconv.ParseInt(r.URL.Query().Get("revision"), 10, 64)
	if err != nil || revision <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid revision")
		return
	}
	meta, rc, err := h.svc.OpenVersion(path, revision)
	if err != nil {
		switch {
		case errors.Is(err, syncsvc.ErrNotFound):
			writeErr(w, http.StatusNotFound, "not found")
		case errors.Is(err, storage.ErrInvalidPath):
			writeErr(w, http.StatusBadRequest, "invalid path")
		default:
			h.internalError(w, "version", err)
		}
		return
	}
	defer rc.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(meta.Size, 10))
	w.Header().Set("X-Revision", strconv.FormatInt(meta.Revision, 10))
	w.Header().Set("X-Content-Hash", meta.ContentHash)
	w.Header().Set("X-File-Size", strconv.FormatInt(meta.Size, 10))
	w.Header().Set("X-File-Mtime", strconv.FormatInt(meta.Mtime, 10))
	w.Header().Set("X-Action", meta.Action)
	io.Copy(w, rc) //nolint:errcheck // 传输中断由客户端 hash 校验兜底
}
