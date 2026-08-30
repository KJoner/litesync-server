package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/KJoner/litesync-server/internal/db"
)

// 单用户多仓库（v0.19）：
//
//	GET    /api/v1/vaults        列出本人名下仓库（设备凭据可列——只列自己主人的）
//	POST   /api/v1/vaults        新建仓库（用户 Token 专属；上限 20、同名拒绝）
//	PATCH  /api/v1/vaults/{id}   重命名自己的仓库（用户 Token 专属；只动展示名）
//	DELETE /api/v1/vaults/{id}   删除自己的仓库（confirmName 确认；不能删最后一个）
//
// 目标仓库的**选择**在 authGate 的 X-Vault-ID 解析里（resolveVaultChoice）；
// 这里只是仓库的生命周期。

// vaultsOwner 解析请求者对应的用户：用户级身份直接有；设备凭据查主人。
func (h *handlers) vaultsOwner(r *http.Request) (string, error) {
	me := identityFrom(r)
	if me == nil {
		return "", errors.New("no identity")
	}
	if me.UserID != "" {
		return me.UserID, nil
	}
	if me.DeviceID != "" {
		return h.svc.DeviceOwner(me.DeviceID)
	}
	return "", errors.New("no identity")
}

func (h *handlers) listVaults(w http.ResponseWriter, r *http.Request) {
	userID, err := h.vaultsOwner(r)
	if err != nil || userID == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	vaults, err := h.svc.ListUserVaults(userID)
	if err != nil {
		h.internalError(w, "vault list", err)
		return
	}
	me := identityFrom(r)
	out := make([]map[string]any, 0, len(vaults))
	for i := range vaults {
		v := &vaults[i]
		out = append(out, map[string]any{
			"id":              v.VaultID,
			"name":            v.Name,
			"createdAt":       v.CreatedAt,
			"fileCount":       v.FileCount,
			"bytesUsed":       v.BytesUsed,
			"updatedAt":       v.UpdatedAt,
			"encryptionState": v.EncryptionState,
			// current：本次请求的凭据当前指向的仓库（设备=绑定仓库；
			// 用户 Token/会话=默认或 X-Vault-ID 选中的）
			"current": me != nil && me.VaultID == v.VaultID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"vaults": out, "limit": db.MaxVaultsPerUser})
}

func (h *handlers) createVault(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	if me == nil || me.UserID == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 64 {
		writeErr(w, http.StatusBadRequest, "仓库名需为 1–64 个字符")
		return
	}
	id, err := h.svc.CreateUserVault(me.UserID, name)
	switch {
	case errors.Is(err, db.ErrVaultLimit):
		writeCoded(w, http.StatusConflict, CodeConflict, "已达到仓库数量上限", false)
		return
	case errors.Is(err, db.ErrVaultNameTaken):
		writeCoded(w, http.StatusConflict, CodeConflict, "同名仓库已存在，请换一个名字", false)
		return
	case err != nil:
		h.internalError(w, "vault create", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "name": name})
}

func (h *handlers) renameVault(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	if me == nil || me.UserID == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 64 {
		writeErr(w, http.StatusBadRequest, "仓库名需为 1–64 个字符")
		return
	}
	err := h.svc.RenameUserVault(me.UserID, r.PathValue("id"), name)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeErr(w, http.StatusNotFound, "vault not found")
		return
	case errors.Is(err, db.ErrVaultNameTaken):
		writeCoded(w, http.StatusConflict, CodeConflict, "同名仓库已存在，请换一个名字", false)
		return
	case err != nil:
		h.internalError(w, "vault rename", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": r.PathValue("id"), "name": name})
}

func (h *handlers) deleteVault(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	if me == nil || me.UserID == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		ConfirmName string `json:"confirmName"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req) //nolint:errcheck
	err := h.svc.DeleteUserVault(me.UserID, r.PathValue("id"), req.ConfirmName)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeErr(w, http.StatusNotFound, "vault not found")
		return
	case errors.Is(err, db.ErrLastVault):
		writeCoded(w, http.StatusConflict, CodeConflict, "不能删除最后一个仓库", false)
		return
	case err != nil && strings.Contains(err.Error(), "confirmName"):
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody,
			"confirmName 与仓库名不一致：删除不可逆，必须原样输入仓库名确认", false)
		return
	case err != nil:
		h.internalError(w, "vault delete", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": r.PathValue("id")})
}
