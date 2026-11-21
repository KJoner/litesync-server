package api_test

// /api/v1/info 的 access（v0.20.1 / RC-1）：网页据此在只读成员打开仓库时就隐藏编辑 / 新建，
// 不让用户写了半天、保存时才收到 403（最终裁决仍在写路由的服务端检查，见 web_edit_test.go）。
// 只对账号身份给出；设备凭据的 info 响应与 0.20.0 完全相同（插件兼容：只加字段）。INV-12。

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
)

func TestInfoAccessReflectsMemberRole(t *testing.T) {
	e := newWebEditEnv(t, true)
	owner := tokenSession(t, e, testToken)
	readerToken, resp, _ := registerUser(t, e, adminCreateInvite(t, e), "reader")
	if resp.StatusCode != http.StatusOK {
		t.Fatal("register reader")
	}
	u, err := e.svc.AuthUserByToken(readerToken)
	if err != nil || u == nil {
		t.Fatal("reader lookup")
	}
	if err := db.UpsertMembership(e.db, &db.Membership{UserID: u.UserID, VaultID: db.DefaultVaultID, Role: db.RoleReader}); err != nil {
		t.Fatal(err)
	}
	reader := tokenSession(t, e, readerToken)
	infoOf := func(c *http.Client, vault string) map[string]any {
		req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/info", nil)
		if vault != "" {
			req.Header.Set("X-Vault-ID", vault)
		}
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(res.Body).Decode(&m)
		return m
	}
	if a, _ := infoOf(reader, db.DefaultVaultID)["access"].(map[string]any); a == nil || a["role"] != "reader" || a["canWrite"] != false {
		t.Fatalf("reader info.access = %v, want role=reader canWrite=false", a)
	}
	if a, _ := infoOf(owner, "")["access"].(map[string]any); a == nil || a["role"] != "owner" || a["canWrite"] != true {
		t.Fatalf("owner info.access = %v, want role=owner canWrite=true", a)
	}
	devToken, _ := e.enrollDevice(t, "plain-device")
	if _, body := e.doJSON(t, http.MethodGet, "/api/v1/info", devToken, nil); body["access"] != nil {
		t.Fatalf("device info must stay exactly as before (no access field): %v", body["access"])
	}
}
