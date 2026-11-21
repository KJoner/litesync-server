package api

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
	"github.com/KJoner/litesync-server/internal/web"
)

// 多用户管理与邀请注册（v0.18 / v11 设计 §5.5–§5.7）。
//
//	POST   /api/v1/admin/invites          管理员生成邀请（随机 secret，一次性）
//	GET    /api/v1/admin/invites          邀请列表
//	DELETE /api/v1/admin/invites/{id}     撤销未使用的邀请
//	GET    /api/v1/join/{secret}          公开：邀请是否可用（注册页加载）
//	POST   /api/v1/join/{secret}          公开：消费邀请注册（Token 明文只在响应出现一次）
//	GET    /api/v1/admin/users            用户列表（含设备数与用量）
//	POST   /api/v1/admin/users/{id}/disable | /enable
//	DELETE /api/v1/admin/users/{id}       两步确认：body 必须带 confirmName
//
// 注册端点无效 secret 一律 404 且失败 sleep 300ms（与登录同款减速；
// 不区分「不存在/过期/已用」——区分即存在性预言机，ADR-010 §10）。

func (h *handlers) adminCreateInvite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ExpiresHours int    `json:"expiresHours"`
		ServerURL    string `json:"serverUrl"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req) //nolint:errcheck // body 可为空
	serverURL := strings.TrimSpace(req.ServerURL)
	if len(serverURL) > 512 {
		writeErr(w, http.StatusBadRequest, "serverUrl too long")
		return
	}
	id, secret, expiresAt, err := h.svc.CreateInvite(serverURL, time.Duration(req.ExpiresHours)*time.Hour)
	if err != nil {
		h.internalError(w, "invite create", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": id, "secret": secret, "path": "/join/" + secret, "expiresAt": expiresAt,
	})
}

func (h *handlers) adminListInvites(w http.ResponseWriter, r *http.Request) {
	invites, err := h.svc.ListInvites()
	if err != nil {
		h.internalError(w, "invite list", err)
		return
	}
	out := make([]map[string]any, 0, len(invites))
	for i := range invites {
		inv := &invites[i]
		out = append(out, map[string]any{
			"id": inv.ID, "serverUrl": inv.ServerURL, "createdAt": inv.CreatedAt,
			"expiresAt": inv.ExpiresAt, "usedAt": inv.UsedAt, "usedBy": inv.UsedBy,
			"revoked": inv.Revoked,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

func (h *handlers) adminRevokeInvite(w http.ResponseWriter, r *http.Request) {
	ok, err := h.svc.RevokeInvite(r.PathValue("id"))
	if err != nil {
		h.internalError(w, "invite revoke", err)
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "invite not found or already used")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

// joinLanding 公开：注册落地页（静态 join.html，secret 由前端从 location 取）。
func (h *handlers) joinLanding(w http.ResponseWriter, _ *http.Request) {
	raw, err := webDistFile("dist/join.html")
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(raw) //nolint:errcheck
}

// joinInfo 公开：注册页加载时确认邀请可用并取展示信息。
func (h *handlers) joinInfo(w http.ResponseWriter, r *http.Request) {
	inv, err := h.svc.InviteInfo(r.PathValue("secret"))
	if err != nil {
		h.internalError(w, "join info", err)
		return
	}
	if inv == nil {
		time.Sleep(300 * time.Millisecond)
		writeErr(w, http.StatusNotFound, "invite not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid": true, "serverUrl": inv.ServerURL, "expiresAt": inv.ExpiresAt,
	})
}

// joinRegister 公开：消费邀请完成注册。
func (h *handlers) joinRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	reg, err := h.svc.RegisterInvitedUser(r.PathValue("secret"), strings.TrimSpace(req.Name))
	switch {
	case errors.Is(err, syncsvc.ErrInvalidUserName):
		writeErr(w, http.StatusBadRequest, "用户名需为 1–32 个可见字符，不含空格")
		return
	case errors.Is(err, db.ErrNameTaken):
		// 重名不消耗邀请：换个名字重试即可
		writeCoded(w, http.StatusConflict, CodeConflict, "该用户名已被使用，请换一个", false)
		return
	case errors.Is(err, db.ErrInviteGone):
		time.Sleep(300 * time.Millisecond)
		writeErr(w, http.StatusNotFound, "invite not found")
		return
	case err != nil:
		h.internalError(w, "join register", err)
		return
	}
	// Token 明文只在这个响应里出现一次；服务器只存哈希
	writeJSON(w, http.StatusOK, map[string]any{
		"name":  reg.Name,
		"token": reg.Token,
	})
}

func (h *handlers) adminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.svc.ListUserAccounts()
	if err != nil {
		h.internalError(w, "user list", err)
		return
	}
	out := make([]map[string]any, 0, len(users))
	for i := range users {
		u := &users[i]
		row := map[string]any{
			"userId": u.UserID, "name": u.Name, "isAdmin": u.IsAdmin, "disabled": u.Disabled,
			"vaults": u.Vaults,
			"createdAt": u.CreatedAt, "lastSeenAt": u.LastSeenAt,
			"devices": u.Devices, "objects": u.Objects, "bytesUsed": u.BytesUsed,
		}
		// 配额口径的占用（含历史）与生效上限、覆盖值（需求 §12）
		if usage, err := h.svc.UserUsage(u.UserID); err == nil {
			row["usage"] = usageJSON(usage)
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (h *handlers) adminSetUserDisabled(disabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		me := identityFrom(r)
		actor := "admin"
		if me != nil && me.UserID != "" {
			actor = me.UserID
		}
		revoked, err := h.svc.SetUserDisabled(r.PathValue("id"), disabled, actor)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"disabled": disabled, "revokedDevices": revoked})
	}
}

func (h *handlers) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	var req struct {
		ConfirmName string `json:"confirmName"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req) //nolint:errcheck
	// 两步确认：必须原样输入用户名。删除是不可逆的（数据、历史、分享一并消失）
	users, err := h.svc.ListUserAccounts()
	if err != nil {
		h.internalError(w, "user delete", err)
		return
	}
	var name string
	for i := range users {
		if users[i].UserID == userID {
			name = users[i].Name
			break
		}
	}
	if name == "" {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if req.ConfirmName != name {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody,
			"confirmName 与用户名不一致：删除不可逆，必须原样输入用户名确认", false)
		return
	}
	me := identityFrom(r)
	actor := "admin"
	if me != nil && me.UserID != "" {
		actor = me.UserID
	}
	if err := h.svc.DeleteUser(userID, actor); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": userID})
}

// webDistFile 读取嵌入的前端产物（与 pairLanding 同源）。
func webDistFile(path string) ([]byte, error) { return fs.ReadFile(web.Dist, path) }
