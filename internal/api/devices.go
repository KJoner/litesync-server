package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// 设备级凭据 API（v9.2，审查 14）：
//
//	POST /enroll                     公开：一次性注册凭据换设备凭据（secret 即认证）
//	POST /api/v1/devices             根 Token：直接创建设备凭据（首台设备自注册）
//	POST /api/v1/enrollments         pairing scope：生成一次性注册凭据（配对包 v2 用）
//	GET  /api/v1/devices             sync scope：设备列表（token hash 不返回）
//	DELETE /api/v1/devices/{id}      根 Token：撤销设备（下一个请求即 401）
//	GET  /api/v1/whoami              任何凭据：当前身份与 scopes

func writeCredential(w http.ResponseWriter, cred *syncsvc.DeviceCredential) {
	writeJSON(w, http.StatusOK, map[string]any{
		"deviceId":    cred.DeviceID,
		"name":        cred.Name,
		"deviceToken": cred.Token, // 明文只在本响应出现一次，服务器只存 hash
		"scopes":      cred.Scopes,
	})
}

// enrollDevice 公开注册端点：新设备此时还没有任何凭据，enrollment secret 即认证。
// POST /enroll  Body: {"secret":"...","name":"..."}
func (h *handlers) enrollDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Secret string `json:"secret"`
		Name   string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil ||
		req.Secret == "" || len(req.Name) > 128 {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	cred, err := h.svc.EnrollDevice(req.Secret, req.Name)
	if err != nil {
		if errors.Is(err, syncsvc.ErrEnrollmentInvalid) {
			// 与不存在同响应：不暴露凭据是否曾经有效
			writeErr(w, http.StatusNotFound, "enrollment not found or expired")
			return
		}
		h.internalError(w, "device enroll", err)
		return
	}
	writeCredential(w, cred)
}

// createDevice 根 Token 直接创建设备凭据（首台设备把根 Token 换下来）。
// POST /api/v1/devices  Body: {"name":"..."}
func (h *handlers) createDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || len(req.Name) > 128 {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	me := identityFrom(r)
	var vaultID, userID string
	var epoch int64
	if me != nil {
		vaultID, userID, epoch = me.VaultID, me.UserID, me.AuthEpoch
	}
	// 新设备记签发者（这张 API Token）的授权代次（ADR-019 §2.2）
	cred, err := h.svc.CreateDeviceAt(req.Name, vaultID, userID, epoch)
	if err != nil {
		h.internalError(w, "device create", err)
		return
	}
	writeCredential(w, cred)
}

// createEnrollment 生成一次性注册凭据（配对流程；secret 只返回一次）。
// POST /api/v1/enrollments  Body: {"ttlSeconds":900}（可选）
func (h *handlers) createEnrollment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TTLSeconds int64 `json:"ttlSeconds"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req) //nolint:errcheck // body 可为空
	me := identityFrom(r)
	var vaultID, userID, actorDevice string
	var epoch int64
	if me != nil {
		vaultID, userID, actorDevice, epoch = me.VaultID, me.UserID, me.DeviceID, me.AuthEpoch
	}
	id, secret, expiresAt, err := h.svc.CreateEnrollmentAt(
		time.Duration(req.TTLSeconds)*time.Second, vaultID, userID, actorDevice, epoch)
	if err != nil {
		h.internalError(w, "enrollment create", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "secret": secret, "expiresAt": expiresAt})
}

// listDevices 设备列表（不含任何凭据材料）。GET /api/v1/devices
//
// 只列**调用者本人**在当前仓库下的设备（v0.20 / 基线 PRE-01）。以前这里返回的是
// 全实例视图：多用户服务器上任何人都能看到所有人的设备名、scope 与设备 ID，
// 而设备 ID 恰好是撤销接口的参数。全实例视图只在 /api/v1/admin/devices。
func (h *handlers) listDevices(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	owner, err := h.requestOwner(me)
	if err != nil {
		h.internalError(w, "device list", err)
		return
	}
	devices, err := h.svc.ListDevicesFor(scopeOf(r), owner)
	if err != nil {
		h.internalError(w, "device list", err)
		return
	}
	type apiDevice struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Scopes     string `json:"scopes"`
		CreatedAt  int64  `json:"createdAt"`
		LastSeenAt int64  `json:"lastSeenAt"`
		Revoked    bool   `json:"revoked"`
		Current    bool   `json:"current"`
	}
	out := make([]apiDevice, 0, len(devices))
	for _, d := range devices {
		out = append(out, apiDevice{
			ID: d.DeviceID, Name: d.Name, Scopes: d.Scopes,
			CreatedAt: d.CreatedAt, LastSeenAt: d.LastSeenAt, Revoked: d.Revoked,
			Current: me != nil && me.DeviceID == d.DeviceID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

// revokeDevice 撤销设备（根 Token 专属，authGate 已拦截设备 Token）。
// DELETE /api/v1/devices/{id}
func (h *handlers) revokeDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	me := identityFrom(r)
	if me == nil || me.UserID == "" {
		writeErr(w, http.StatusForbidden, "user token required")
		return
	}
	// 只能撤销自己的设备（PRE-02）：别人的与不存在的同样 404
	ok, err := h.svc.RevokeUserDevice(me.UserID, id)
	if err != nil {
		h.internalError(w, "device revoke", err)
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "id": id})
}

// requestOwner 返回本次请求的账号主体：用户 Token / 网页会话直接带 UserID；
// 设备凭据与短期票的归属由服务端设备行决定（请求里声称的一律不作数）。
func (h *handlers) requestOwner(me *authIdentity) (string, error) {
	if me == nil {
		return "", nil
	}
	if me.UserID != "" {
		return me.UserID, nil
	}
	if me.DeviceID != "" {
		return h.svc.DeviceOwner(me.DeviceID)
	}
	return "", nil
}

// whoami 返回当前凭据身份（客户端据此判断是否需要把用户 Token 换成设备凭据）。
// GET /api/v1/whoami
//
// tokenType 的取值保持向后兼容："root" 对插件的含义是「这是一个应该被换成
// 设备凭据的用户级长期 Token」，v0.18 多用户后这个语义对普通用户 Token 同样成立。
func (h *handlers) whoami(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	if me == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	role := "user"
	if me.IsAdmin {
		role = "admin"
	}
	switch {
	case me.UserToken:
		writeJSON(w, http.StatusOK, map[string]any{
			"tokenType": "root", "role": role, "name": me.Name, "userId": me.UserID,
		})
	case me.UserID != "" && me.DeviceID == "":
		// 网页会话（v0.18 起会话随身携带用户归属；前端据此渲染角色相关 UI）
		writeJSON(w, http.StatusOK, map[string]any{
			"tokenType": "session", "role": role, "name": me.Name, "userId": me.UserID,
		})
	default:
		writeJSON(w, http.StatusOK, map[string]any{
			"tokenType": "device",
			"deviceId":  me.DeviceID,
			"name":      me.Name,
			"scopes":    me.Scopes,
		})
	}
}
