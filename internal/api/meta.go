package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// 元数据加密 API（协议 v6 / ADR-003）：
//
//	GET  /api/v1/file/meta            轻量读取对象元数据
//	POST /api/v1/file/rename          改名 = 元数据更新（metaGeneration CAS，不产生 tombstone）
//	GET  /api/v1/meta/status          迁移状态与 journal 进度
//	POST /api/v1/meta/begin           plain → migrating（记录 migrationId / owner / 租约 / cutoff）
//	POST /api/v1/meta/migrate         单对象伪名化（幂等，断点续传安全）
//	GET  /api/v1/meta/tombstones      列出仍带明文寻址名的删除记录
//	POST /api/v1/meta/migrate-tombstone  tombstone 转隐私格式（**不删除**）
//	POST /api/v1/meta/verify          migrating → verifying（journal 必须清空）
//	POST /api/v1/meta/complete        跑 11 项验证器 → 擦除 → encrypted（单向）
//	POST /api/v1/meta/abort           migrating/verifying → plain（无破坏）

const maxMetaEncSize = maxMetaEncHeader

func (h *handlers) metaError(w http.ResponseWriter, op string, err error) {
	var conflict *syncsvc.ConflictError
	var collision *syncsvc.PathCollisionError
	var validation *syncsvc.ValidationError
	switch {
	case errors.As(err, &conflict):
		writeConflict(w, conflict)
	case errors.As(err, &collision):
		writeCollision(w, collision)
	case errors.As(err, &validation):
		// 完整失败清单：用户需要一次看到全部问题，而不是修一个跑一次（ADR-003 §3.5）
		writeJSON(w, http.StatusConflict, map[string]any{
			"code":      CodeValidationFailed,
			"message":   "migration validation failed; repository state is unchanged",
			"retryable": false,
			"error":     "migration validation failed",
			"failures":  validation.Failures,
		})
	case errors.Is(err, syncsvc.ErrMetaCAS):
		writeCoded(w, http.StatusPreconditionFailed, CodeStaleMetaGeneration,
			"metadata generation mismatch; refetch and retry", true)
	case errors.Is(err, syncsvc.ErrStaleRevision):
		writeCoded(w, http.StatusPreconditionFailed, CodeStaleRevision,
			"expected tombstone revision does not match the ledger", false)
	case errors.Is(err, syncsvc.ErrTombstonePurged):
		writeCoded(w, http.StatusConflict, CodeTombstonePurged,
			"tombstone has been purged; explicit user confirmation is required to recreate this object", false)
	case errors.Is(err, syncsvc.ErrTombstonePlaintext):
		writeCoded(w, http.StatusConflict, CodeTombstonePlaintext,
			"tombstones still carry plaintext names; convert them via /meta/migrate-tombstone first", false)
	case errors.Is(err, syncsvc.ErrMetaRequired):
		writeCoded(w, http.StatusBadRequest, CodeMetaRequired, err.Error(), false)
	case errors.Is(err, syncsvc.ErrEnvelopeTooOld):
		writeCoded(w, http.StatusConflict, CodeEnvelopeTooOld,
			"all content must use the LSE3 envelope before metadata encryption", false)
	case errors.Is(err, syncsvc.ErrPlaintextRejected):
		writeCoded(w, http.StatusConflict, CodePlaintextRejected,
			"content must be LSE3 before metadata encryption", false)
	case errors.Is(err, syncsvc.ErrMigrationLocked):
		writeCoded(w, http.StatusConflict, CodeMigrationLocked,
			"another device owns the current migration lease", true)
	case errors.Is(err, syncsvc.ErrMigrationIncomplete):
		writeCoded(w, http.StatusConflict, CodeMigrationIncomplete,
			"migration journal still has unfinished entries", true)
	case errors.Is(err, syncsvc.ErrMigrationMismatch):
		writeCoded(w, http.StatusConflict, CodeMigrationMismatch, "migration id mismatch", false)
	case errors.Is(err, syncsvc.ErrFormatEpoch):
		writeCoded(w, http.StatusConflict, CodeFormatEpochMismatch, "format epoch mismatch", false)
	case errors.Is(err, syncsvc.ErrRepoEpoch):
		writeCoded(w, http.StatusConflict, CodeRepoEpochMismatch, "repo epoch mismatch", false)
	case errors.Is(err, syncsvc.ErrKeyEpoch):
		writeCoded(w, http.StatusConflict, CodeKeyEpochMismatch, "key epoch mismatch", false)
	case errors.Is(err, syncsvc.ErrMigrationNotOwner):
		writeCoded(w, http.StatusConflict, CodeMigrationNotOwner,
			"only the migration owner may perform this action", false)
	case errors.Is(err, syncsvc.ErrLeaseActive):
		writeCoded(w, http.StatusConflict, CodeLeaseActive,
			"the current migration lease is still active; takeover is not allowed yet", true)
	case errors.Is(err, syncsvc.ErrUpgradeRequired):
		writeCoded(w, http.StatusUpgradeRequired, CodeUpgradeRequired, "client upgrade required", false)
	case errors.Is(err, syncsvc.ErrEncryptionState):
		writeCoded(w, http.StatusConflict, CodeMetaStateInvalid, err.Error(), false)
	case errors.Is(err, syncsvc.ErrNotFound):
		writeCoded(w, http.StatusNotFound, CodeNotFound, "not found", false)
	case errors.Is(err, storage.ErrInvalidPath):
		writeCoded(w, http.StatusBadRequest, CodeInvalidPath, "invalid path", false)
	default:
		h.internalError(w, op, err)
	}
}

// getFileMeta 轻量读取对象元数据（改名变更无需下载整个内容）。
func (h *handlers) getFileMeta(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeCoded(w, http.StatusBadRequest, CodeInvalidPath, "missing path", false)
		return
	}
	f, err := h.svc.FileInfo(path)
	if err != nil {
		h.metaError(w, "meta get", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":              f.Pseudonym,
		"fileId":            f.FileID,
		"revision":          f.Revision,
		"metaEnc":           f.EncryptedMetadata,
		"metaGeneration":    f.MetaGeneration,
		"contentGeneration": f.ContentGeneration,
		"envelopeVersion":   f.EnvelopeVersion,
	})
}

// metaStatus 迁移进度（journal 汇总）。
func (h *handlers) metaStatus(w http.ResponseWriter, _ *http.Request) {
	st, err := h.svc.MigrationStatusOf()
	if err != nil {
		h.internalError(w, "meta status", err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (h *handlers) metaBegin(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.BeginMetaMigration(auditDeviceID(r))
	if err != nil {
		h.metaError(w, "meta begin", err)
		return
	}
	// 哨兵：擦除后必须在物理文件里找不到它（ADR-008 §3.2）
	if _, serr := h.svc.RegisterMigrationSentinel(st.MigrationID); serr != nil {
		h.opts.Logger.Warn("sentinel registration failed", "error", serr)
	}
	writeJSON(w, http.StatusOK, st)
}

// migrateObject 单对象伪名化。
func (h *handlers) migrateObject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FromPath      string `json:"fromPath"`
		MetaEnc       string `json:"metaEnc"`
		CanonicalHash string `json:"canonicalHash"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxMetaEncSize+1024)).Decode(&req); err != nil ||
		req.FromPath == "" || len(req.MetaEnc) > maxMetaEncSize || !isBase64Header(req.MetaEnc) ||
		!isLowerHexOfLen(req.CanonicalHash, canonicalHashHexLen) {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "invalid body", false)
		return
	}
	res, err := h.svc.MigrateObjectMeta(req.FromPath, req.MetaEnc, req.CanonicalHash, auditDeviceID(r))
	if err != nil {
		h.metaError(w, "meta migrate", err)
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

// listPlaintextTombstones 列出仍带明文寻址名的删除记录（仅 migrating 态、仅 owner）。
func (h *handlers) listPlaintextTombstones(w http.ResponseWriter, r *http.Request) {
	list, err := h.svc.ListPlaintextTombstones(auditDeviceID(r))
	if err != nil {
		h.metaError(w, "meta tombstones", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tombstones": list})
}

// migrateTombstone 把一条 tombstone 转成隐私格式（**不删除**，ADR-002）。
func (h *handlers) migrateTombstone(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FileID        string `json:"fileId"`
		CanonicalHash string `json:"canonicalHash"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil ||
		!isLowerHexOfLen(req.FileID, fileIDHexLen) ||
		!isLowerHexOfLen(req.CanonicalHash, canonicalHashHexLen) {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "invalid body", false)
		return
	}
	if err := h.svc.MigrateTombstone(req.FileID, req.CanonicalHash, auditDeviceID(r)); err != nil {
		h.metaError(w, "meta migrate tombstone", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"fileId": req.FileID, "converted": true})
}

// metaRenew 续租（计划书 §5.4）：owner 在长迁移中周期调用。
func (h *handlers) metaRenew(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.RenewMigrationLease(auditDeviceID(r))
	if err != nil {
		h.metaError(w, "meta renew", err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// metaTakeover 显式接管租约已过期的迁移（绝不自动发生）。
func (h *handlers) metaTakeover(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MigrationID string `json:"migrationId"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.MigrationID == "" {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "migrationId required", false)
		return
	}
	st, err := h.svc.TakeoverMigration(req.MigrationID, auditDeviceID(r))
	if err != nil {
		h.metaError(w, "meta takeover", err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// metaVerify migrating → verifying。进入后只接受验证读取与 complete。
func (h *handlers) metaVerify(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.VerifyMetaMigration(auditDeviceID(r))
	if err != nil {
		h.metaError(w, "meta verify", err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// metaValidate 只跑验证器不改状态（客户端在 complete 前预检）。
func (h *handlers) metaValidate(w http.ResponseWriter, _ *http.Request) {
	failures, err := h.svc.ValidateMetaMigration()
	if err != nil {
		h.internalError(w, "meta validate", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": len(failures) == 0, "failures": failures})
}

// metaComplete 跑验证器 → 擦除 → encrypted。必须显式确认。
func (h *handlers) metaComplete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ConfirmErase bool   `json:"confirmErase"`
		MigrationID  string `json:"migrationId"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || !req.ConfirmErase {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody,
			"confirmErase:true required (plaintext path erasure is irreversible)", false)
		return
	}
	st, err := h.svc.CompleteMetaMigration(req.MigrationID, auditDeviceID(r))
	if err != nil {
		h.metaError(w, "meta complete", err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (h *handlers) metaAbort(w http.ResponseWriter, _ *http.Request) {
	st, err := h.svc.AbortMetaMigration()
	if err != nil {
		h.metaError(w, "meta abort", err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// erasureReport 返回最近一次擦除报告（ADR-008 §3.3）。
func (h *handlers) erasureReport(w http.ResponseWriter, _ *http.Request) {
	data, err := h.svc.ErasureReportJSON()
	if err != nil {
		writeCoded(w, http.StatusNotFound, CodeNotFound, "no erasure report yet", false)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data) //nolint:errcheck
}
