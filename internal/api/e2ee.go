package api

import (
	"errors"
	"net/http"

	"github.com/KJoner/litesync-server/internal/db"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// E2EE 状态机接口（v9）：
//
//	POST /api/v1/e2ee/begin    plaintext → migrating（明文写冻结；重复调用幂等）
//	POST /api/v1/e2ee/complete migrating → encrypted（全部 HEAD 验证为 LSE1 密文）
//	POST /api/v1/e2ee/abort    migrating → plaintext
//
// 全部需要根 Token（authGate 中非白名单接口默认拒绝只读会话）。

func (h *handlers) writeEncryptionState(w http.ResponseWriter, rs *db.RepoState) {
	writeJSON(w, http.StatusOK, map[string]any{
		"encryptionState": rs.EncryptionState,
		"keyEpoch":        rs.KeyEpoch,
		// 仓库级信封下限（ADR-006）：客户端据此拒绝再产出旧信封
		"minimumEnvelopeVersion": rs.MinimumEnvelopeVersion,
	})
}

func (h *handlers) e2eeError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, syncsvc.ErrEncryptionState):
		writeCoded(w, http.StatusConflict, CodeMetaStateInvalid, err.Error(), false)
	case errors.Is(err, syncsvc.ErrEnvelopeTooOld):
		writeCoded(w, http.StatusConflict, CodeEnvelopeTooOld,
			"not all live objects use the LSE3 envelope yet", false)
	default:
		h.internalError(w, op, err)
	}
}

// envelopeComplete 验证全部 live HEAD 均为 LSE3 后把仓库信封下限提升到 3。
// 提升之后**任何**写入路径（含新建与删除后重建）都不再接受旧信封（ADR-006 §2.1）。
func (h *handlers) envelopeComplete(w http.ResponseWriter, _ *http.Request) {
	rs, err := h.svc.CompleteEnvelopeUpgrade()
	if err != nil {
		h.e2eeError(w, "envelope complete", err)
		return
	}
	h.writeEncryptionState(w, rs)
}

func (h *handlers) e2eeBegin(w http.ResponseWriter, _ *http.Request) {
	rs, err := h.svc.BeginE2eeMigration()
	if err != nil {
		h.e2eeError(w, "e2ee begin", err)
		return
	}
	h.writeEncryptionState(w, rs)
}

func (h *handlers) e2eeComplete(w http.ResponseWriter, _ *http.Request) {
	rs, err := h.svc.CompleteE2eeMigration()
	if err != nil {
		h.e2eeError(w, "e2ee complete", err)
		return
	}
	h.writeEncryptionState(w, rs)
}

func (h *handlers) e2eeAbort(w http.ResponseWriter, _ *http.Request) {
	rs, err := h.svc.AbortE2eeMigration()
	if err != nil {
		h.e2eeError(w, "e2ee abort", err)
		return
	}
	h.writeEncryptionState(w, rs)
}
