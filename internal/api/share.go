package api

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	syncsvc "obsync/internal/sync"
)

type apiShare struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	ExpiresAt int64  `json:"expiresAt"`
	CreatedAt int64  `json:"createdAt"`
	Revoked   bool   `json:"revoked"`
	Expired   bool   `json:"expired"`
}

// snapshot 返回当前所有未删除文件的元数据。
// GET /api/v1/snapshot
func (h *handlers) snapshot(w http.ResponseWriter, _ *http.Request) {
	latest, files, err := h.svc.Snapshot()
	if err != nil {
		h.internalError(w, "snapshot", err)
		return
	}
	type apiFile struct {
		Path     string `json:"path"`
		Revision int64  `json:"revision"`
		Hash     string `json:"hash"`
		Size     int64  `json:"size"`
		Mtime    int64  `json:"mtime"`
	}
	out := make([]apiFile, 0, len(files))
	for _, f := range files {
		out = append(out, apiFile{Path: f.Path, Revision: f.Revision, Hash: f.ContentHash, Size: f.Size, Mtime: f.Mtime})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sequence": latest, "files": out})
}

// createShare 保存分享密文（内容为客户端用独立 Share Key 加密的 opaque bytes）。
// POST /api/v1/share
// Header：X-Share-Name（percent-encoded，可选）、X-Share-Expires（unix 秒，0=永不过期）
func (h *handlers) createShare(w http.ResponseWriter, r *http.Request) {
	name, err := url.PathUnescape(r.Header.Get("X-Share-Name"))
	if err != nil || len(name) > 512 {
		writeErr(w, http.StatusBadRequest, "invalid X-Share-Name")
		return
	}
	var expiresAt int64
	if v := r.Header.Get("X-Share-Expires"); v != "" {
		expiresAt, err = strconv.ParseInt(v, 10, 64)
		if err != nil || expiresAt < 0 {
			writeErr(w, http.StatusBadRequest, "invalid X-Share-Expires")
			return
		}
		if expiresAt > 0 && expiresAt <= time.Now().Unix() {
			writeErr(w, http.StatusBadRequest, "X-Share-Expires is in the past")
			return
		}
	}

	body := http.MaxBytesReader(w, r.Body, h.opts.MaxFileSize)
	share, err := h.svc.CreateShare(name, expiresAt, body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, "share content too large")
			return
		}
		h.internalError(w, "share create", err)
		return
	}
	writeJSON(w, http.StatusOK, apiShare{
		ID: share.ID, Name: share.Name, Size: share.Size,
		ExpiresAt: share.ExpiresAt, CreatedAt: share.CreatedAt,
	})
}

// listShares 列出全部分享（含已撤销/过期，供管理界面）。
// GET /api/v1/shares
func (h *handlers) listShares(w http.ResponseWriter, _ *http.Request) {
	shares, err := h.svc.ListShares()
	if err != nil {
		h.internalError(w, "share list", err)
		return
	}
	now := time.Now().Unix()
	out := make([]apiShare, 0, len(shares))
	for _, s := range shares {
		out = append(out, apiShare{
			ID: s.ID, Name: s.Name, Size: s.Size,
			ExpiresAt: s.ExpiresAt, CreatedAt: s.CreatedAt,
			Revoked: s.Revoked,
			Expired: s.ExpiresAt > 0 && now > s.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"shares": out})
}

// revokeShare 撤销分享。DELETE /api/v1/share?id=...
func (h *handlers) revokeShare(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing id")
		return
	}
	if err := h.svc.RevokeShare(id); err != nil {
		if errors.Is(err, syncsvc.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		h.internalError(w, "share revoke", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

// getShare 公开读取分享密文（无需认证；Share Key 在链接 fragment 中，服务器拿不到）。
// GET /share/{id}
func (h *handlers) getShare(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	share, rc, err := h.svc.OpenShare(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(share.Size, 10))
	w.Header().Set("Cache-Control", "no-store")
	io.Copy(w, rc) //nolint:errcheck
}
