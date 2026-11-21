package api_test

// v12.0.1 复审反例转正（public-launch-review/reproductions/server-review-repro_test.go）。
//
// 审查时这几条断言的是**错误行为**（PASS = 复现了缺陷）；这里沿用同样的合成场景，改为断言
// ADR-019 规定的正确行为，进入常规测试（SV-01 / SV-02）。SMTP 那一条在 internal/config（SV-04）。
// 覆盖 INV-12（撤销只作用于该账号）。

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/KJoner/litesync-server/internal/api"
)

// SV-02：「退出所有产品与设备」之前发出、尚未兑换的授权，之后不能再换出可用设备。
// 审查实测：logout-all 之后用旧 grant redeem 得到 200，新设备 whoami 200。
func TestReviewPendingGrantRejectedAfterLogoutAll(t *testing.T) {
	e := newPublicTestEnv(t)
	alice, _, _ := registerUser(t, e, adminCreateInvite(t, e), "review-alice")
	vault := createReadyVault(t, e, alice, "review-vault")
	oldGrant := grant(t, e, alice, vault)
	code, oldDevice := redeem(t, e, oldGrant["enrollmentSecret"].(string), "review_old_exchange_001", vault)
	if code != http.StatusOK {
		t.Fatalf("initial redeem: %d", code)
	}
	pending := grant(t, e, alice, vault)
	r, body := e.call(t, http.MethodPost, "/api/v2/account/logout-all", alice, "", nil)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("logout-all: %d %v", r.StatusCode, body)
	}
	mustRevoked(t, e, oldDevice["deviceCredential"].(string), "existing device")
	code, fresh := redeem(t, e, pending["enrollmentSecret"].(string), "review_new_exchange_001", vault)
	if code != http.StatusGone || fresh["code"] != "PAIRING_REVOKED" || fresh["deviceCredential"] != nil {
		t.Fatalf("pre-logout pending grant after logout-all = %d %v, want 410 PAIRING_REVOKED without a credential", code, fresh)
	}
	var n int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE vault_id = ?`, vault).Scan(&n); err != nil || n != 1 {
		t.Fatalf("devices in the vault = %d (err %v), want only the original one", n, err)
	}
}

// SV-01（back-channel）：只带 sub 的 back-channel logout 是动作 A——只结束网页会话。
// 审查观察到「web 401、device 200」并把它当作缺陷；ADR-019 R-3 规定这正是 A 的正确结果
// （普通退出不得断开全部 Obsidian）。缺陷的真正所在是「没有任何动作能撤销设备」：
// 这里接着断言 C（退出所有产品与设备）之后设备立即失效。
func TestReviewBackchannelIsActionAOnly(t *testing.T) {
	e := newOIDCEnv(t, "open", true)
	b := e.newBrowser(t)
	b.login("review-sub", nil)
	code, me := b.me()
	if code != http.StatusOK {
		t.Fatalf("login: %d", code)
	}
	userID := me["account"].(map[string]any)["id"].(string)
	if _, err := e.svc.CreateUserVault(userID, "review-vault"); err != nil {
		t.Fatal(err)
	}
	vaultID, _ := e.svc.OwnerVaultOf(userID)
	cred, err := e.svc.CreateDevice("review-device", vaultID, userID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token := e.idp.sign(map[string]any{
		"iss": e.idp.issuer, "aud": testClientID, "sub": "review-sub",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "review-logout-001",
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}, false)
	response, err := http.PostForm(e.ts.URL+"/auth/backchannel-logout", url.Values{"logout_token": {token}})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("backchannel: %d", response.StatusCode)
	}
	if webCode, _ := b.me(); webCode != http.StatusUnauthorized {
		t.Fatalf("web session after subject logout = %d, want 401", webCode)
	}
	mustWork(t, e.testEnv, cred.Token, "device after a back-channel logout (action A)")

	b2 := e.newBrowser(t)
	b2.login("review-sub", nil)
	if resp, out := b2.do(http.MethodPost, "/api/v2/account/logout-all", nil, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("logout-all = %d %v", resp.StatusCode, out)
	}
	mustRevoked(t, e.testEnv, cred.Token, "device after logout-all (action C)")
}

// SV-01（中心停用）：身份中心停用账号后，设备凭据也必须停止读写。
// 审查实测：refresh 被撤销后 web 401、device 200。
//   - 配置了中心状态检查：在线请求最迟 60 秒（加一次检查耗时）内被拒（R-7），并执行 B；
//   - 未配置：设备不会自动失效——这是 ADR-019 §2.5 明确写下的能力缺口（启动日志与账户中心
//     都如实提示；开放公众注册时 config 层拒绝启动），这里把它断言出来，防止有人误以为已覆盖。
func TestReviewCentralDisableRevokesDevice(t *testing.T) {
	setup := func(t *testing.T, e *oidcEnv, sub string) (*browser, string) {
		b := e.newBrowser(t)
		b.login(sub, nil)
		_, me := b.me()
		userID := me["account"].(map[string]any)["id"].(string)
		if _, err := e.svc.CreateUserVault(userID, "review-vault"); err != nil {
			t.Fatal(err)
		}
		vaultID, _ := e.svc.OwnerVaultOf(userID)
		cred, err := e.svc.CreateDevice("review-device", vaultID, userID)
		if err != nil {
			t.Fatal(err)
		}
		return b, cred.Token
	}

	t.Run("central status check configured", func(t *testing.T) {
		e := newRevocationEnv(t, nil, true)
		b, cred := setup(t, e, "review-frozen")
		e.idp.setUser("review-frozen", true, false) // 中心停用（refresh 也随之失败）
		e.idp.revokeAll("review-frozen")
		restore := api.ShiftCentralClock(61 * time.Second)
		defer restore()
		mustRevoked(t, e.testEnv, cred, "device after central disable")
		if webCode, _ := b.me(); webCode != http.StatusUnauthorized {
			t.Fatalf("web after central disable = %d", webCode)
		}
	})

	t.Run("not configured (documented gap)", func(t *testing.T) {
		e := newRevocationEnv(t, nil, false)
		b, cred := setup(t, e, "review-frozen")
		e.idp.setUser("review-frozen", true, false)
		e.idp.revokeAll("review-frozen")
		api.ForceSessionRevalidation(e.ts.Config.Handler)
		defer api.ResetOIDCClock()
		if webCode, _ := b.me(); webCode != http.StatusUnauthorized {
			t.Fatalf("web session must end through refresh revalidation, got %d", webCode)
		}
		mustWork(t, e.testEnv, cred, "device without the central status check (documented gap)")
	})
}
