package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// vault key 文档大小上限：正常只有几百字节，64KB 足够宽裕。
const maxVaultKeySize = 64 << 10

// getVaultKey 返回客户端存放的加密 vault key（服务器不理解其内容）。
// GET /api/v1/vault-key
// v9：响应携带 X-Vault-Key-Fingerprint，replace 时作为 CAS 凭据传回。
func (h *handlers) getVaultKey(w http.ResponseWriter, _ *http.Request) {
	doc, err := h.svc.GetVaultKey()
	if err != nil {
		h.internalError(w, "vault-key get", err)
		return
	}
	if doc == "" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Vault-Key-Fingerprint", syncsvc.VaultKeyFingerprint(doc))
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, doc) //nolint:errcheck
}

// putVaultKey 保存加密 vault key 文档。
// PUT /api/v1/vault-key?replace=true + Header X-Expected-Fingerprint
// 已存在且未带 replace=true 时返回 409；replace 必须携带当前文档指纹（CAS），
// 防止并发迁移/误操作无条件覆盖导致密文数据永久不可读。
func (h *handlers) putVaultKey(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxVaultKeySize+1))
	if err != nil || len(raw) == 0 || len(raw) > maxVaultKeySize {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	// 只做最基本的完整性检查：必须是 JSON 对象；内容对服务器保持 opaque
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		writeErr(w, http.StatusBadRequest, "body must be a JSON object")
		return
	}
	replace := r.URL.Query().Get("replace") == "true"
	expected := r.Header.Get("X-Expected-Fingerprint")
	if err := h.svc.SetVaultKey(string(raw), replace, expected); err != nil {
		switch {
		case errors.Is(err, syncsvc.ErrVaultKeyExists):
			writeErr(w, http.StatusConflict, "vault key already exists; pass replace=true to overwrite")
		case errors.Is(err, syncsvc.ErrVaultKeyCAS):
			writeErr(w, http.StatusPreconditionFailed,
				"vault key fingerprint mismatch; fetch the current key document and retry with X-Expected-Fingerprint")
		default:
			h.internalError(w, "vault-key put", err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": true})
}

// purgeHistory 删除某路径 beforeRevision 之前的历史版本。
// DELETE /api/v1/history?path=...&beforeRevision=N
// 用于 E2EE 迁移：客户端验证密文完整后清理明文历史。
func (h *handlers) purgeHistory(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeErr(w, http.StatusBadRequest, "missing path")
		return
	}
	before, err := strconv.ParseInt(r.URL.Query().Get("beforeRevision"), 10, 64)
	if err != nil || before <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid beforeRevision")
		return
	}
	removed, err := h.svc.PruneHistoryBefore(path, before)
	if err != nil {
		if errors.Is(err, storage.ErrInvalidPath) {
			writeErr(w, http.StatusBadRequest, "invalid path")
			return
		}
		h.internalError(w, "history purge", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": path, "removed": removed})
}
