package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"obsync/internal/storage"
	syncsvc "obsync/internal/sync"
)

// putFile 处理文件上传。
// Header：X-File-Path（percent-encoded，支持中文等非 ASCII 路径）、
// X-Base-Revision、X-Content-Hash（SHA-256 hex）、X-File-Mtime（毫秒，可选）。
// Body：原始文件字节。
func (h *handlers) putFile(w http.ResponseWriter, r *http.Request) {
	path, err := url.PathUnescape(r.Header.Get("X-File-Path"))
	if err != nil || path == "" {
		writeErr(w, http.StatusBadRequest, "missing or invalid X-File-Path")
		return
	}
	baseRevision, err := strconv.ParseInt(r.Header.Get("X-Base-Revision"), 10, 64)
	if err != nil || baseRevision < 0 {
		writeErr(w, http.StatusBadRequest, "missing or invalid X-Base-Revision")
		return
	}
	hash := strings.ToLower(r.Header.Get("X-Content-Hash"))
	if !isSHA256Hex(hash) {
		writeErr(w, http.StatusBadRequest, "X-Content-Hash must be a sha256 hex digest")
		return
	}
	var mtime int64
	if v := r.Header.Get("X-File-Mtime"); v != "" {
		mtime, _ = strconv.ParseInt(v, 10, 64)
	}
	action := r.Header.Get("X-Action") // ""/upsert/merge/restore
	deviceID := r.Header.Get("X-Device-ID")

	body := http.MaxBytesReader(w, r.Body, h.opts.MaxFileSize)
	res, err := h.svc.Upload(path, baseRevision, hash, body, mtime, deviceID, action)
	if err != nil {
		h.writeUploadError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":     res.Path,
		"revision": res.Revision,
		"hash":     res.Hash,
		"size":     res.Size,
		"sequence": res.Sequence,
	})
}

func (h *handlers) writeUploadError(w http.ResponseWriter, err error) {
	var conflict *syncsvc.ConflictError
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &conflict):
		writeConflict(w, conflict)
	case errors.As(err, &tooBig):
		writeErr(w, http.StatusRequestEntityTooLarge, "file too large")
	case errors.Is(err, storage.ErrInvalidPath):
		writeErr(w, http.StatusBadRequest, "invalid path")
	case errors.Is(err, storage.ErrHashMismatch):
		writeErr(w, http.StatusBadRequest, "content hash mismatch")
	default:
		h.internalError(w, "upload", err)
	}
}

// getFile 下载文件原始字节，元数据通过响应 Header 返回。
func (h *handlers) getFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeErr(w, http.StatusBadRequest, "missing path")
		return
	}
	meta, rc, err := h.svc.OpenFile(path)
	if err != nil {
		switch {
		case errors.Is(err, syncsvc.ErrNotFound):
			if meta != nil && meta.Deleted {
				// 告知客户端该文件已被删除以及 tombstone revision
				writeJSON(w, http.StatusNotFound, map[string]any{
					"error": "not found", "deleted": true, "revision": meta.Revision,
				})
				return
			}
			writeErr(w, http.StatusNotFound, "not found")
		case errors.Is(err, storage.ErrInvalidPath):
			writeErr(w, http.StatusBadRequest, "invalid path")
		default:
			h.internalError(w, "download", err)
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
	io.Copy(w, rc) //nolint:errcheck // 传输中断由客户端 hash 校验兜底
}

// deleteFile 逻辑删除文件。Body：{"path": "...", "baseRevision": N}
func (h *handlers) deleteFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path         string `json:"path"`
		BaseRevision int64  `json:"baseRevision"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.Path == "" {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	res, err := h.svc.Delete(req.Path, req.BaseRevision, r.Header.Get("X-Device-ID"))
	if err != nil {
		var conflict *syncsvc.ConflictError
		switch {
		case errors.As(err, &conflict):
			writeConflict(w, conflict)
		case errors.Is(err, syncsvc.ErrNotFound):
			writeErr(w, http.StatusNotFound, "not found")
		case errors.Is(err, storage.ErrInvalidPath):
			writeErr(w, http.StatusBadRequest, "invalid path")
		default:
			h.internalError(w, "delete", err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":     res.Path,
		"revision": res.Revision,
		"sequence": res.Sequence,
		"deleted":  true,
	})
}

func writeConflict(w http.ResponseWriter, c *syncsvc.ConflictError) {
	writeJSON(w, http.StatusConflict, map[string]any{
		"error":    "conflict",
		"path":     c.Path,
		"revision": c.Revision,
		"hash":     c.Hash,
		"deleted":  c.Deleted,
	})
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
