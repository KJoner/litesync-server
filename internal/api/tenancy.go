package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// 多租户治理接口（v0.16.0 / 计划书 §10.4、§10.5）。

// issueAccessToken 用长期设备凭据换一张分钟级 access token。
// POST /api/v1/token  Body: {"scopes":["sync"],"ttlSeconds":300}
//
// authGate 已经保证：走到这里的一定是长期设备凭据，不可能是另一张短期票。
func (h *handlers) issueAccessToken(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r)
	if id == nil || id.DeviceID == "" {
		// 根 Token 不换票：它本来就是全权限的长期凭据，换成短期票没有意义，
		// 反而会让「根 Token 只应存在于服务器与首台设备」这条约束变模糊
		writeErr(w, http.StatusForbidden, "access tokens are issued to devices only")
		return
	}
	var req struct {
		Scopes     []string `json:"scopes"`
		TTLSeconds int64    `json:"ttlSeconds"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck // 空 body 用默认值
	}

	token, claims, err := h.svc.IssueAccessToken(id.DeviceID, req.Scopes,
		time.Duration(req.TTLSeconds)*time.Second)
	switch {
	case errors.Is(err, syncsvc.ErrScopeEscalation):
		writeErr(w, http.StatusForbidden, err.Error())
		return
	case errors.Is(err, syncsvc.ErrAccessTokenInvalid):
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	case err != nil:
		h.internalError(w, "issue access token", err)
		return
	}
	// token 明文只在这里出现一次；服务器不存它（无状态签名）
	writeJSON(w, http.StatusOK, map[string]any{
		"accessToken": token,
		"tokenType":   "Bearer",
		"scopes":      strings.Split(claims.Scopes, ","),
		"expiresAt":   claims.ExpiresAt,
		"expiresIn":   claims.ExpiresAt - claims.IssuedAt,
	})
}

// removeMember 把成员移出 Vault，并触发密钥轮换。
// DELETE /api/v1/members/{userId}
func (h *handlers) removeMember(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimPrefix(r.URL.Path, "/api/v1/members/")
	if target == "" || strings.Contains(target, "/") {
		writeErr(w, http.StatusBadRequest, "missing user id")
		return
	}
	id := identityFrom(r)
	var actor syncsvc.Actor
	if id != nil {
		actor = syncsvc.Actor{Root: id.Root, DeviceID: id.DeviceID}
	}

	rep, err := h.svc.RemoveMember(actor, target)
	switch {
	case errors.Is(err, syncsvc.ErrNotAuthorized):
		writeErr(w, http.StatusForbidden, "owner or admin role required")
		return
	case errors.Is(err, db.ErrNotAMember):
		writeErr(w, http.StatusNotFound, "user is not a member of this vault")
		return
	case errors.Is(err, db.ErrLastOwner):
		writeErr(w, http.StatusConflict, "cannot remove the last owner")
		return
	case err != nil:
		h.internalError(w, "remove member", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"removed":        rep.UserID,
		"role":           string(rep.Role),
		"revokedDevices": rep.RevokedDevices,
		"keyEpoch":       rep.NewKeyEpoch,
		"pendingRewrap":  rep.PendingRewrap,
		// 这句话必须原样出现在响应里：客户端 UI 直接展示它，
		// 不允许各端自行改写成更好听的说法（§10.4 第 4 条）
		"localPlaintextNotice": rep.LocalPlaintext,
	})
}

// auditTrail 返回该 Vault 最近的治理审计记录。
// GET /api/v1/audit?limit=100
func (h *handlers) auditTrail(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit")) //nolint:errcheck
	events, err := h.svc.AuditTrail(limit)
	if err != nil {
		h.internalError(w, "audit trail", err)
		return
	}
	out := make([]map[string]any, 0, len(events))
	for i := range events {
		e := &events[i]
		out = append(out, map[string]any{
			"actor": e.Actor, "action": e.Action, "detail": e.Detail, "at": e.At,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}
