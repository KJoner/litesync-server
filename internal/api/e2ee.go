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
	})
}

func (h *handlers) e2eeError(w http.ResponseWriter, op string, err error) {
	if errors.Is(err, syncsvc.ErrEncryptionState) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	h.internalError(w, op, err)
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
