package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/KJoner/litesync-server/internal/db"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// 元数据加密 API（v9.3 三期，协议 v5）：
//
//	PUT  /api/v1/file/meta      改名 = 元数据更新（metaGeneration CAS）
//	POST /api/v1/meta/migrate   单文件迁移：真实路径 → 伪名（断点续传安全）
//	POST /api/v1/meta/begin     plain → migrating
//	POST /api/v1/meta/complete  验证全量伪名化后抹除明文路径（单向，需显式确认）
//	POST /api/v1/meta/abort     migrating → plain（混合态保留，无破坏）

const maxMetaEncSize = 8 << 10 // 加密元数据尺寸上限（正常几百字节）

func (h *handlers) metaError(w http.ResponseWriter, op string, err error) {
	var conflict *syncsvc.ConflictError
	var collision *syncsvc.PathCollisionError
	switch {
	case errors.As(err, &conflict):
		writeConflict(w, conflict)
	case errors.As(err, &collision):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error": "path collision", "path": collision.Path, "existing": collision.Existing,
		})
	case errors.Is(err, syncsvc.ErrMetaCAS):
		writeErr(w, http.StatusPreconditionFailed, "metadata generation mismatch; refetch and retry")
	case errors.Is(err, syncsvc.ErrMetaRequired):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, syncsvc.ErrPlaintextRejected):
		writeErr(w, http.StatusConflict, "content must be LSE3 before metadata encryption")
	case errors.Is(err, syncsvc.ErrEncryptionState):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, syncsvc.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	default:
		h.internalError(w, op, err)
	}
}

// getFileMeta 轻量获取元数据（改名变更无需下载整个内容）。
// GET /api/v1/file/meta?path=<pseudonym>
func (h *handlers) getFileMeta(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeErr(w, http.StatusBadRequest, "missing path")
		return
	}
	f, err := h.svc.FileInfo(path)
	if err != nil {
		h.metaError(w, "meta get", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":           f.Path,
		"fileId":         f.FileID,
		"revision":       f.Revision,
		"metaEnc":        f.MetaEnc,
		"metaGeneration": f.MetaGeneration,
	})
}

// updateFileMeta 改名（元数据更新）。
// PUT /api/v1/file/meta  Body: {"path","baseMetaGeneration","metaEnc","canonicalHash"}
func (h *handlers) updateFileMeta(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path               string `json:"path"`
		BaseMetaGeneration int64  `json:"baseMetaGeneration"`
		MetaEnc            string `json:"metaEnc"`
		CanonicalHash      string `json:"canonicalHash"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxMetaEncSize+1024)).Decode(&req); err != nil ||
		req.Path == "" || len(req.MetaEnc) > maxMetaEncSize {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	res, err := h.svc.UpdateFileMeta(req.Path, req.BaseMetaGeneration, req.MetaEnc, req.CanonicalHash, auditDeviceID(r))
	if err != nil {
		h.metaError(w, "meta update", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":           res.Path,
		"revision":       res.Revision,
		"metaGeneration": res.MetaGeneration,
		"sequence":       res.Sequence,
	})
}

// migrateFileMeta 迁移单个文件（meta-migrating 态）。
// POST /api/v1/meta/migrate  Body: {"fromPath","metaEnc","canonicalHash"}
func (h *handlers) migrateFileMeta(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FromPath      string `json:"fromPath"`
		MetaEnc       string `json:"metaEnc"`
		CanonicalHash string `json:"canonicalHash"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxMetaEncSize+1024)).Decode(&req); err != nil ||
		req.FromPath == "" || len(req.MetaEnc) > maxMetaEncSize {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	res, err := h.svc.MigrateFileMeta(req.FromPath, req.MetaEnc, req.CanonicalHash, auditDeviceID(r))
	if err != nil {
		h.metaError(w, "meta migrate", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"fromPath": res.FromPath,
		"toPath":   res.ToPath,
		"revision": res.Revision,
		"sequence": res.Sequence,
	})
}

func (h *handlers) writeMetaState(w http.ResponseWriter, rs *db.RepoState) {
	writeJSON(w, http.StatusOK, map[string]any{"metaState": rs.MetaState})
}

func (h *handlers) metaBegin(w http.ResponseWriter, _ *http.Request) {
	rs, err := h.svc.BeginMetaMigration()
	if err != nil {
		h.metaError(w, "meta begin", err)
		return
	}
	h.writeMetaState(w, rs)
}

// metaComplete 抹除明文路径（单向）。必须显式确认：Body {"confirmErase":true}
func (h *handlers) metaComplete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ConfirmErase bool `json:"confirmErase"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || !req.ConfirmErase {
		writeErr(w, http.StatusBadRequest, "confirmErase:true required (plaintext path erasure is irreversible)")
		return
	}
	rs, err := h.svc.CompleteMetaMigration()
	if err != nil {
		h.metaError(w, "meta complete", err)
		return
	}
	h.writeMetaState(w, rs)
}

func (h *handlers) metaAbort(w http.ResponseWriter, _ *http.Request) {
	rs, err := h.svc.AbortMetaMigration()
	if err != nil {
		h.metaError(w, "meta abort", err)
		return
	}
	h.writeMetaState(w, rs)
}
