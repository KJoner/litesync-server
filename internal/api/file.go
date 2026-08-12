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

// putFile 处理内容上传。
// Header：X-File-Path（percent-encoded 的服务器可见寻址名）、X-Base-Revision、
// X-Content-Hash（SHA-256 hex）、X-File-Mtime（毫秒，可选）、
// X-Format-Epoch / X-LiteSync-Protocol（协议 v6 逐请求校验）、X-Operation-Id（幂等键）。
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
	// 元数据 Header 的格式与长度上限：不依赖 HTTP Server 的总 Header 上限兜底
	if bad := validateMetaHeaders(r.Header); bad != "" {
		writeCoded(w, http.StatusBadRequest, CodeInvalidHeader, "invalid "+bad+" header", false)
		return
	}
	var mtime int64
	if v := r.Header.Get("X-File-Mtime"); v != "" {
		mtime, _ = strconv.ParseInt(v, 10, 64)
	}

	body := http.MaxBytesReader(w, r.Body, h.opts.MaxFileSize)
	res, err := h.svc.Upload(syncsvc.UploadParams{
		Path:          path,
		BaseRevision:  baseRevision,
		ClaimedHash:   hash,
		Mtime:         mtime,
		DeviceID:      auditDeviceID(r),
		Action:        r.Header.Get("X-Action"), // ""/upsert/merge/restore
		ClientFileID:  r.Header.Get("X-File-Id"),
		MetaEnc:       r.Header.Get("X-Meta-Enc"),
		CanonicalHash: r.Header.Get("X-Canonical-Hash"),
		Client:        clientContext(r),
	}, body)
	if err != nil {
		h.writeUploadError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":              res.Path,
		"revision":          res.Revision,
		"hash":              res.Hash,
		"size":              res.Size,
		"sequence":          res.Sequence,
		"fileId":            res.FileID,
		"contentGeneration": res.ContentGeneration,
		"metaGeneration":    res.MetaGeneration,
	})
}

// clientContext 抽取逐请求协议/世代上下文（计划书 §5.3）。
//
// 服务器可能在两次请求之间从备份恢复（repoEpoch 变）、完成元数据迁移
//（formatEpoch 变）或轮换密钥（keyEpoch 变），而客户端此刻仍拿着旧判断在写。
// 因此这些必须**逐请求**校验，而不是「会话首轮查一次」。
func clientContext(r *http.Request) syncsvc.ClientContext {
	return syncsvc.ClientContext{
		ProtocolVersion: headerInt(r, "X-LiteSync-Protocol"),
		RepoEpoch:       safeEpochHeader(r.Header.Get("X-Repo-Epoch")),
		FormatEpoch:     headerInt(r, "X-Format-Epoch"),
		KeyEpoch:        headerInt(r, "X-Key-Epoch"),
		OperationID:     operationID(r),
	}
}

// safeEpochHeader：repoEpoch 是 32 位小写 hex；非法值按「未携带」处理，
// 绝不把任意字符串带进比较逻辑。
func safeEpochHeader(v string) string {
	if isLowerHexOfLen(v, 32) {
		return v
	}
	return ""
}

// operationID 幂等键：客户端在响应丢失后用同一个 id 重试，服务器返回首次结果。
func operationID(r *http.Request) string {
	v := r.Header.Get("X-Operation-Id")
	if len(v) > 64 || !isSafeToken(v) {
		return ""
	}
	return v
}

func isSafeToken(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func headerInt(r *http.Request, name string) int64 {
	v := r.Header.Get(name)
	if v == "" {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func (h *handlers) writeUploadError(w http.ResponseWriter, err error) {
	var conflict *syncsvc.ConflictError
	var collision *syncsvc.PathCollisionError
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &conflict):
		writeConflict(w, conflict)
	case errors.As(err, &collision):
		writeCollision(w, collision)
	case errors.Is(err, syncsvc.ErrEnvelopeTooOld):
		// 仓库级信封下限（ADR-006）：覆盖新建、更新与删除后重建的全部写入路径
		writeCoded(w, http.StatusConflict, CodeEnvelopeTooOld,
			"envelope version is below the repository minimum; upgrade the envelope first", false)
	case errors.Is(err, syncsvc.ErrFormatEpoch):
		writeCoded(w, http.StatusConflict, CodeFormatEpochMismatch,
			"format epoch mismatch; refresh repository state and reconcile", false)
	case errors.Is(err, syncsvc.ErrRepoEpoch):
		writeCoded(w, http.StatusConflict, CodeRepoEpochMismatch,
			"repo epoch mismatch; the server was restored from a backup — enter disaster recovery", false)
	case errors.Is(err, syncsvc.ErrKeyEpoch):
		writeCoded(w, http.StatusConflict, CodeKeyEpochMismatch,
			"key epoch mismatch; refresh the vault key binding before writing", false)
	case errors.Is(err, syncsvc.ErrUpgradeRequired):
		writeCoded(w, http.StatusUpgradeRequired, CodeUpgradeRequired,
			"this repository requires a newer client (protocol v6)", false)
	case errors.Is(err, syncsvc.ErrMigrationLocked):
		writeCoded(w, http.StatusConflict, CodeMigrationLocked,
			"a metadata migration is in progress; only the migration owner may write unmigrated objects", true)
	case errors.Is(err, syncsvc.ErrFileIDConflict):
		writeCoded(w, http.StatusConflict, CodeFileIDConflict, "client-provided file id is already in use", false)
	case errors.Is(err, syncsvc.ErrPlaintextRejected):
		writeCoded(w, http.StatusConflict, CodePlaintextRejected, err.Error(), false)
	case errors.Is(err, syncsvc.ErrMetaRequired):
		writeCoded(w, http.StatusBadRequest, CodeMetaRequired, err.Error(), false)
	case errors.As(err, &tooBig):
		writeCoded(w, http.StatusRequestEntityTooLarge, CodeTooLarge, "file too large", false)
	case errors.Is(err, storage.ErrInvalidPath):
		writeCoded(w, http.StatusBadRequest, CodeInvalidPath, "invalid path", false)
	case errors.Is(err, storage.ErrHashMismatch):
		writeCoded(w, http.StatusBadRequest, CodeHashMismatch, "content hash mismatch", false)
	case errors.Is(err, syncsvc.ErrNotFound):
		writeCoded(w, http.StatusNotFound, CodeNotFound, "not found", false)
	default:
		h.internalError(w, "upload", err)
	}
}

// writeCollision 422：canonical 归一化后与现有对象同名（meta 模式下比较的是 HMAC）。
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

// renameFile 改名（协议 v6）：一次元数据更新，**不产生 tombstone**（ADR-001 §3.4）。
// POST /api/v1/file/rename  Body: {"fromPath","toPath","baseMetaGeneration","metaEnc","canonicalHash"}
func (h *handlers) renameFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FromPath           string `json:"fromPath"`
		ToPath             string `json:"toPath"`
		BaseMetaGeneration int64  `json:"baseMetaGeneration"`
		MetaEnc            string `json:"metaEnc"`
		CanonicalHash      string `json:"canonicalHash"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxMetaEncSize+1024)).Decode(&req); err != nil ||
		req.FromPath == "" || req.ToPath == "" || req.BaseMetaGeneration < 0 ||
		len(req.MetaEnc) > maxMetaEncSize || !isBase64Header(req.MetaEnc) ||
		(req.CanonicalHash != "" && !isLowerHexOfLen(req.CanonicalHash, canonicalHashHexLen)) {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "invalid request body", false)
		return
	}
	res, err := h.svc.Rename(syncsvc.RenameParams{
		FromPseudonym:      req.FromPath,
		ToPseudonym:        req.ToPath,
		BaseMetaGeneration: req.BaseMetaGeneration,
		MetaEnc:            req.MetaEnc,
		CanonicalHash:      req.CanonicalHash,
		DeviceID:           auditDeviceID(r),
		Client:             clientContext(r),
	})
	if err != nil {
		h.metaError(w, "rename", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"fileId":         res.FileID,
		"fromPath":       res.FromPseudonym,
		"toPath":         res.ToPseudonym,
		"revision":       res.Revision,
		"metaGeneration": res.MetaGeneration,
		"sequence":       res.Sequence,
	})
}

// restoreFile 显式恢复已删除对象（ADR-002 §3.6）。
// POST /api/v1/files/{fileId}/restore
func (h *handlers) restoreFile(w http.ResponseWriter, r *http.Request) {
	fileID := r.PathValue("fileId")
	var req struct {
		ExpectedTombstoneRevision int64  `json:"expectedTombstoneRevision"`
		ContentGeneration         int64  `json:"contentGeneration"`
		Pseudonym                 string `json:"pseudonym"`
		MetaEnc                   string `json:"metaEnc"`
		CanonicalHash             string `json:"canonicalHash"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxMetaEncSize+1024)).Decode(&req); err != nil ||
		req.Pseudonym == "" || req.ExpectedTombstoneRevision <= 0 || req.ContentGeneration < 0 ||
		len(req.MetaEnc) > maxMetaEncSize || !isBase64Header(req.MetaEnc) ||
		(req.CanonicalHash != "" && !isLowerHexOfLen(req.CanonicalHash, canonicalHashHexLen)) {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "invalid request body", false)
		return
	}
	res, err := h.svc.Restore(syncsvc.RestoreParams{
		FileID:                    fileID,
		ExpectedTombstoneRevision: req.ExpectedTombstoneRevision,
		ContentGeneration:         req.ContentGeneration,
		Pseudonym:                 req.Pseudonym,
		MetaEnc:                   req.MetaEnc,
		CanonicalHash:             req.CanonicalHash,
		DeviceID:                  auditDeviceID(r),
		Client:                    clientContext(r),
	})
	if err != nil {
		h.metaError(w, "restore", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"fileId":   res.FileID,
		"path":     res.Pseudonym,
		"revision": res.Revision,
		"sequence": res.Sequence,
		"restored": true,
	})
}

// getFile 下载内容，元数据通过响应 Header 返回。
func (h *handlers) getFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeCoded(w, http.StatusBadRequest, CodeInvalidPath, "missing path", false)
		return
	}
	meta, rc, err := h.svc.OpenFile(path)
	if err != nil {
		switch {
		case errors.Is(err, syncsvc.ErrNotFound):
			if meta != nil {
				// 告知客户端该对象已被删除、tombstone revision 与身份，
				// 客户端据此走显式 restore 而不是当作新文件重建
				writeJSON(w, http.StatusNotFound, map[string]any{
					"code": CodeNotFound, "message": "not found", "retryable": false,
					"error": "not found", "deleted": true,
					"revision": meta.Revision, "fileId": meta.FileID,
				})
				return
			}
			writeCoded(w, http.StatusNotFound, CodeNotFound, "not found", false)
		case errors.Is(err, storage.ErrInvalidPath):
			writeCoded(w, http.StatusBadRequest, CodeInvalidPath, "invalid path", false)
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
	w.Header().Set("X-Content-Generation", strconv.FormatInt(meta.ContentGeneration, 10))
	if meta.EncryptedMetadata != "" {
		w.Header().Set("X-Meta-Enc", meta.EncryptedMetadata)
		w.Header().Set("X-Meta-Generation", strconv.FormatInt(meta.MetaGeneration, 10))
	}
	io.Copy(w, rc) //nolint:errcheck // 传输中断由客户端 hash 校验兜底
}

// deleteFile 删除对象：HEAD 移入 tombstone 台账（ADR-002），历史保留。
// Body：{"path": "...", "baseRevision": N}
func (h *handlers) deleteFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path         string `json:"path"`
		BaseRevision int64  `json:"baseRevision"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.Path == "" {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "invalid request body", false)
		return
	}
	res, err := h.svc.Delete(syncsvc.DeleteParams{
		Path:         req.Path,
		BaseRevision: req.BaseRevision,
		DeviceID:     auditDeviceID(r),
		Client:       clientContext(r),
	})
	if err != nil {
		var conflict *syncsvc.ConflictError
		switch {
		case errors.As(err, &conflict):
			writeConflict(w, conflict)
		case errors.Is(err, syncsvc.ErrNotFound):
			writeCoded(w, http.StatusNotFound, CodeNotFound, "not found", false)
		case errors.Is(err, syncsvc.ErrFormatEpoch):
			writeCoded(w, http.StatusConflict, CodeFormatEpochMismatch, "format epoch mismatch", false)
		case errors.Is(err, syncsvc.ErrRepoEpoch):
			writeCoded(w, http.StatusConflict, CodeRepoEpochMismatch, "repo epoch mismatch", false)
		case errors.Is(err, syncsvc.ErrKeyEpoch):
			writeCoded(w, http.StatusConflict, CodeKeyEpochMismatch, "key epoch mismatch", false)
		case errors.Is(err, syncsvc.ErrUpgradeRequired):
			writeCoded(w, http.StatusUpgradeRequired, CodeUpgradeRequired, "client upgrade required", false)
		case errors.Is(err, syncsvc.ErrMigrationLocked):
			writeCoded(w, http.StatusConflict, CodeMigrationLocked, "a metadata migration is in progress", true)
		case errors.Is(err, storage.ErrInvalidPath):
			writeCoded(w, http.StatusBadRequest, CodeInvalidPath, "invalid path", false)
		default:
			h.internalError(w, "delete", err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":     res.Path,
		"revision": res.Revision,
		"sequence": res.Sequence,
		"fileId":   res.FileID,
		"deleted":  true,
	})
}

func writeConflict(w http.ResponseWriter, c *syncsvc.ConflictError) {
	body := map[string]any{
		// code=CONFLICT 表示「这是 revision 冲突，响应里带着服务器当前状态」，
		// 与协议级的 409（如 ENVELOPE_TOO_OLD）区分开
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
	if c.FileID != "" {
		// 冲突对象的稳定身份：客户端据此走显式 restore
		body["fileId"] = c.FileID
	}
	if c.Deleted {
		// 删除时的内容世代：restore 必须提交严格大于它的世代（抗回退）
		body["contentGeneration"] = c.ContentGeneration
	}
	writeJSON(w, http.StatusConflict, body)
}

// auditDeviceID：历史记录里的设备身份。设备 Token 认证时用服务器侧的可信
// 设备 ID（客户端自报的 X-Device-ID 不再作为审计身份）；根 Token 保留自报值。
func auditDeviceID(r *http.Request) string {
	if me := identityFrom(r); me != nil && me.DeviceID != "" {
		return me.DeviceID
	}
	return r.Header.Get("X-Device-ID")
}

func isSHA256Hex(s string) bool {
	return isLowerHexOfLen(strings.ToLower(s), 64)
}
