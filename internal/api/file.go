package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// putFile 处理文件上传。
// Header：X-File-Path（percent-encoded，支持中文等非 ASCII 路径）、
// X-Base-Revision、X-Content-Hash（SHA-256 hex）、X-File-Mtime（毫秒，可选）。
// Body：原始文件字节。
func (h *handlers) putFile(w http.ResponseWriter, r *http.Request) {
	path, err := url.PathUnescape(r.Header.Get("X-File-Path"))
	if err != nil || path == "" {
		writeCoded(w, http.StatusBadRequest, CodeInvalidHeader, "missing or invalid X-File-Path", false)
		return
	}
	baseRevision, err := strconv.ParseInt(r.Header.Get("X-Base-Revision"), 10, 64)
	if err != nil || baseRevision < 0 {
		writeCoded(w, http.StatusBadRequest, CodeInvalidHeader, "missing or invalid X-Base-Revision", false)
		return
	}
	hash := strings.ToLower(r.Header.Get("X-Content-Hash"))
	if !isSHA256Hex(hash) {
		writeCoded(w, http.StatusBadRequest, CodeInvalidHeader, "X-Content-Hash must be a sha256 hex digest", false)
		return
	}
	// 元数据 Header 的格式与长度上限（v0.12.1 / LS-121-S04）：
	// 不再依赖 HTTP Server 的总 Header 上限作为唯一保护
	if bad := validateMetaHeaders(r.Header); bad != "" {
		writeCoded(w, http.StatusBadRequest, CodeInvalidHeader, "invalid "+bad+" header", false)
		return
	}
	var mtime int64
	if v := r.Header.Get("X-File-Mtime"); v != "" {
		mtime, _ = strconv.ParseInt(v, 10, 64)
	}
	action := r.Header.Get("X-Action") // ""/upsert/merge/restore
	deviceID := auditDeviceID(r)

	body := http.MaxBytesReader(w, r.Body, h.opts.MaxFileSize)
	res, err := h.svc.Upload(syncsvc.UploadParams{
		Path:         path,
		BaseRevision: baseRevision,
		ClaimedHash:  hash,
		Mtime:        mtime,
		DeviceID:     deviceID,
		Action:       action,
		// X-File-Id（v9.3）：E2EE 客户端为新文件预生成的稳定身份
		ClientFileID: r.Header.Get("X-File-Id"),
		// v9.3 三期：加密元数据与 canonical HMAC（meta 模式建档必带）
		MetaEnc:       r.Header.Get("X-Meta-Enc"),
		CanonicalHash: r.Header.Get("X-Canonical-Hash"),
	}, body)
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
		"fileId":   res.FileID,
	})
}

func (h *handlers) writeUploadError(w http.ResponseWriter, err error) {
	var conflict *syncsvc.ConflictError
	var collision *syncsvc.PathCollisionError
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &conflict):
		writeConflict(w, conflict)
	case errors.As(err, &collision):
		// 422：请求合法但该路径与现有文件在大小写不敏感文件系统上冲突
		writeCollision(w, collision)
	case errors.Is(err, syncsvc.ErrEnvelopeTooOld):
		// 信封降级冻结（LS-121-S01）：HEAD 已是 LSE3，旧信封覆盖一律拒绝。
		// 机器码让客户端能区分「revision 冲突」与「协议级拒绝」
		writeCoded(w, http.StatusConflict, CodeEnvelopeTooOld,
			"current head uses the LSE3 envelope; downgrading to an older envelope is not allowed", false)
	case errors.Is(err, syncsvc.ErrFileIDConflict):
		writeCoded(w, http.StatusConflict, CodeFileIDConflict, "client-provided file id is already in use", false)
	case errors.Is(err, syncsvc.ErrPlaintextRejected):
		// E2EE 明文冻结：仓库已启用加密，明文上传一律拒绝
		writeCoded(w, http.StatusConflict, CodePlaintextRejected, err.Error(), false)
	case errors.Is(err, syncsvc.ErrMetaRequired):
		// 元数据加密态：伪名路径 + 加密元数据缺失
		writeCoded(w, http.StatusBadRequest, CodeMetaRequired, err.Error(), false)
	case errors.As(err, &tooBig):
		writeCoded(w, http.StatusRequestEntityTooLarge, CodeTooLarge, "file too large", false)
	case errors.Is(err, storage.ErrInvalidPath):
		writeCoded(w, http.StatusBadRequest, CodeInvalidPath, "invalid path", false)
	case errors.Is(err, storage.ErrHashMismatch):
		writeCoded(w, http.StatusBadRequest, CodeHashMismatch, "content hash mismatch", false)
	default:
		h.internalError(w, "upload", err)
	}
}

// writeCollision 422：canonical 归一化后与现有文件同名（meta 模式下比较的是 HMAC）。
func writeCollision(w http.ResponseWriter, c *syncsvc.PathCollisionError) {
	writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
		"code":      CodeCanonicalCollision,
		"message":   "path collision",
		"retryable": false,
		"error":     "path collision",
		"path":      c.Path,
		"existing":  c.Existing,
	})
}

// moveFile 原子改名（v9.3）。Body：{"fromPath","toPath","baseRevision"}
// 明文模式专用；E2EE / 目标占用 / revision 不符时客户端回退 delete+upsert。
func (h *handlers) moveFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FromPath     string `json:"fromPath"`
		ToPath       string `json:"toPath"`
		BaseRevision int64  `json:"baseRevision"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil ||
		req.FromPath == "" || req.ToPath == "" {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	res, err := h.svc.Move(req.FromPath, req.ToPath, req.BaseRevision, auditDeviceID(r))
	if err != nil {
		var conflict *syncsvc.ConflictError
		var collision *syncsvc.PathCollisionError
		switch {
		case errors.As(err, &conflict):
			writeConflict(w, conflict)
		case errors.As(err, &collision):
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"error": "path collision", "path": collision.Path, "existing": collision.Existing,
			})
		case errors.Is(err, syncsvc.ErrEncryptionState):
			writeErr(w, http.StatusConflict, "move is not supported while vault encryption is enabled")
		case errors.Is(err, syncsvc.ErrNotFound):
			writeErr(w, http.StatusNotFound, "not found")
		case errors.Is(err, storage.ErrInvalidPath):
			writeErr(w, http.StatusBadRequest, "invalid path")
		default:
			h.internalError(w, "move", err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"fromPath":          res.FromPath,
		"toPath":            res.ToPath,
		"revision":          res.Revision,
		"tombstoneRevision": res.TombstoneRevision,
		"sequence":          res.Sequence,
	})
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
	w.Header().Set("X-File-Id", meta.FileID)
	if meta.MetaEnc != "" {
		// v9.3 三期：加密元数据随下载返回（客户端解出真实路径）
		w.Header().Set("X-Meta-Enc", meta.MetaEnc)
		w.Header().Set("X-Meta-Generation", strconv.FormatInt(meta.MetaGeneration, 10))
	}
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
	res, err := h.svc.Delete(req.Path, req.BaseRevision, auditDeviceID(r))
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
	body := map[string]any{
		// code=CONFLICT 表示「这是 revision 冲突，响应里带着服务器当前状态」，
		// 与协议级的 409（如 ENVELOPE_TOO_OLD）区分开（LS-121-S05）
		"code":      CodeConflict,
		"message":   "conflict",
		"retryable": false,
		"error":     "conflict",
		"path":      c.Path,
		"revision":  c.Revision,
		"hash":      c.Hash,
		"deleted":   c.Deleted,
	}
	if c.PriorHash != "" {
		// tombstone 冲突：删除前最后一个版本的内容 hash，
		// 客户端据此区分「陈旧副本复活」与「同名新内容重建」
		body["priorHash"] = c.PriorHash
	}
	writeJSON(w, http.StatusConflict, body)
}

// auditDeviceID：历史记录里的设备身份。设备 Token 认证时用服务器侧的可信
// 设备 ID（v9.2，客户端自报的 X-Device-ID 不再作为审计身份）；根 Token 保留自报值。
func auditDeviceID(r *http.Request) string {
	if me := identityFrom(r); me != nil && me.DeviceID != "" {
		return me.DeviceID
	}
	return r.Header.Get("X-Device-ID")
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
