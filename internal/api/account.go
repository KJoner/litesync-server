package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/KJoner/litesync-server/internal/db"
)

// 账户自救（v0.18.0 / v11 设计 §4.3）：
//
//	POST /api/v1/account/token-reset   重置自己的 API Token（用户 Token 或本人网页会话）
//	PUT  /api/v1/vault/reset-auth      登记重置凭证（E2EE 密码知识证明）
//
// 能走到这两个 handler 的身份（authGate + routeScope 已筛过）：
//   - token-reset：用户级 Token（rootOnly 路由，设备/access token 被拒）、网页会话（白名单）；
//   - reset-auth：以上两类，外加 sync scope 的设备凭据（解锁后自动补登记）。

// tokenReset 重置**发起者自己**的 API Token。
// 管理员与普通用户共用：重置的永远是自己的凭据，谁也不能替别人重置
//（管理员代重置被刻意排除——见 v11 设计 §5.7，Token 丢失即失去访问是明确设定）。
func (h *handlers) tokenReset(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	if me == nil || me.UserID == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		ResetAuth string `json:"resetAuth"`
	}
	// body 可为空（未启用 E2EE 的账户没有重置凭证可提交）
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req) //nolint:errcheck
	scope := db.ScopeFromAuth(me.VaultID)
	res, err := h.svc.ResetUserToken(scope, me.UserID, req.ResetAuth, me.UserID)
	if err != nil {
		if errors.Is(err, db.ErrResetAuthMismatch) {
			// 拿到 Token 但不知道 E2EE 密码的人在这里被拦下（v11 设计 §3.1）
			writeCoded(w, http.StatusForbidden, CodeResetAuthMismatch,
				"reset credential mismatch: unlock E2EE with the vault password first", false)
			return
		}
		h.internalError(w, "token reset", err)
		return
	}
	// 世代 +1、授权代次 +1 作废了该用户的全部网页会话、设备与待领取授权；唯独发起重置的
	// 这个会话要活下来，否则新 Token 还没展示页面就被登出了
	h.web.adoptGeneration(r, me.UserID, res.Generation, res.AuthEpoch)
	writeJSON(w, http.StatusOK, map[string]any{
		"token":             res.Token,
		"revokedDevices":    res.RevokedDevices,
		"revokedGrants":     res.RevokedGrants,
		"resetAuthEnforced": res.ResetAuthEnforced,
	})
}

// putResetAuth 登记（或持旧值更新）本 Vault 的重置凭证。
// 已登记的凭证不可被仅持会话/Token 者覆盖——规则在 db.RegisterVaultResetAuth。
func (h *handlers) putResetAuth(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	if me == nil || me.VaultID == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		ResetAuth string `json:"resetAuth"`
		Previous  string `json:"previous"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.ResetAuth == "" {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	scope := db.ScopeFromAuth(me.VaultID)
	if err := h.svc.RegisterResetAuth(scope, req.ResetAuth, req.Previous); err != nil {
		if errors.Is(err, db.ErrResetAuthMismatch) {
			writeCoded(w, http.StatusConflict, CodeResetAuthMismatch,
				"a different reset credential is already registered", false)
			return
		}
		h.internalError(w, "reset auth register", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
