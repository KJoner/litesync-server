package api_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// 短期 access token（v0.16.0 / 计划书 §10.5、ADR-010 §7）。
//
// 这一组测试要钉住的是这套机制存在的**理由**：一张票被动泄露之后，
// 攻击者能拿它做的事必须比拿到长期设备凭据小得多，而且窗口有限。
// 每一条都对应一种「如果实现松了，泄露就还是致命的」的具体方式。

// exchange 用长期设备凭据换一张短期票。
func (e *testEnv) exchange(t *testing.T, deviceToken string, body map[string]any) (*http.Response, map[string]any) {
	t.Helper()
	return e.doJSON(t, http.MethodPost, "/api/v1/token", deviceToken, body)
}

func TestAccessTokenExchangeAndUse(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, _ := e.enrollDevice(t, "laptop")

	resp, body := e.exchange(t, devToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("换票失败 = %d (%v)", resp.StatusCode, body)
	}
	token, _ := body["accessToken"].(string)
	if !strings.HasPrefix(token, "lst1.") {
		t.Fatalf("票据应当带可辨识前缀，得到 %q", token)
	}
	// 有效期必须是分钟级：能要到几天的话，这就是第二种长期凭据
	expiresIn, _ := body["expiresIn"].(float64)
	if expiresIn <= 0 || expiresIn > 900 {
		t.Fatalf("有效期应当在 15 分钟以内，得到 %v 秒", expiresIn)
	}

	// 票能用来做正常同步
	if resp, _ := e.doJSON(t, http.MethodGet, "/api/v1/info", token, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("持票访问 /info = %d", resp.StatusCode)
	}
}

// 票不能换票：允许的话，一张泄露的票可以无限续期，
// 「被动泄露后自动过期」这条性质就不存在了。
func TestAccessTokenCannotBeExchangedForAnother(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, _ := e.enrollDevice(t, "laptop")
	_, body := e.exchange(t, devToken, nil)
	token := body["accessToken"].(string)

	resp, _ := e.exchange(t, token, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("用票换票必须被拒，得到 %d", resp.StatusCode)
	}
}

// scope 只能收窄，不能扩大。
func TestAccessTokenScopesCanOnlyNarrow(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, _ := e.enrollDevice(t, "laptop")

	// 收窄成只读同步：这张票即使泄露也改不了 vault-key、建不了分享
	resp, body := e.exchange(t, devToken, map[string]any{"scopes": []string{"sync"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("收窄 scope 应当成功 = %d (%v)", resp.StatusCode, body)
	}
	narrow := body["accessToken"].(string)

	if resp, _ := e.doJSON(t, http.MethodGet, "/api/v1/info", narrow, nil); resp.StatusCode != http.StatusOK {
		t.Fatal("只带 sync 的票应当仍能同步")
	}
	// share 需要 share scope → 必须被拒
	resp, _ = e.doJSON(t, http.MethodGet, "/api/v1/shares", narrow, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("收窄后的票不应能访问 share，得到 %d", resp.StatusCode)
	}

	// 要一个设备没有的权限 → 拒绝
	resp, _ = e.exchange(t, devToken, map[string]any{"scopes": []string{"backup-admin"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("越权申请必须被拒，得到 %d", resp.StatusCode)
	}
}

// backup-admin 永远不会被授予同步设备，也换不到（§10.5 最后一条）。
// 备份能读到整个仓库的密文与全部元数据——一台设备被攻破不该顺带交出它。
func TestBackupAdminIsNeverGrantedToDevices(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, _ := e.enrollDevice(t, "laptop")

	_, body := e.exchange(t, devToken, nil)
	scopes, _ := body["scopes"].([]any)
	for _, s := range scopes {
		if s == "backup-admin" {
			t.Fatal("设备票里出现了 backup-admin")
		}
	}
	token := body["accessToken"].(string)
	// 备份管理路径对任何设备身份都必须是根 Token 专属
	for _, path := range []string{"/api/v1/admin/backup/status", "/api/v1/admin/integrity/scan"} {
		resp, _ := e.doJSON(t, http.MethodGet, path, token, nil)
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s 对设备票应当拒绝，得到 %d", path, resp.StatusCode)
		}
		resp, _ = e.doJSON(t, http.MethodGet, path, devToken, nil)
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s 对设备 Token 应当拒绝，得到 %d", path, resp.StatusCode)
		}
	}
}

// 撤销设备必须**立刻**让在途的票失效，而不是等它自然过期。
//
// 这是无状态票据最容易做错的地方：只验签名的话，撤销一台被盗设备之后
// 攻击者手上那张票还能再用几分钟——而事故响应恰恰争的就是这几分钟。
func TestRevokingDeviceKillsItsAccessTokensImmediately(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, deviceID := e.enrollDevice(t, "stolen-laptop")
	_, body := e.exchange(t, devToken, nil)
	token := body["accessToken"].(string)

	if resp, _ := e.doJSON(t, http.MethodGet, "/api/v1/info", token, nil); resp.StatusCode != http.StatusOK {
		t.Fatal("撤销前票应当可用")
	}

	resp, _ := e.doJSON(t, http.MethodDelete, "/api/v1/devices/"+deviceID, testToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("撤销设备 = %d", resp.StatusCode)
	}

	resp, _ = e.doJSON(t, http.MethodGet, "/api/v1/info", token, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("撤销后在途的票必须立刻失效，得到 %d", resp.StatusCode)
	}
	// 长期凭据当然也没了
	resp, _ = e.doJSON(t, http.MethodGet, "/api/v1/info", devToken, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("撤销后设备 Token 必须失效，得到 %d", resp.StatusCode)
	}
}

// 伪造与篡改：改 payload 而不改签名、改签名、换前缀，全都必须被拒。
func TestForgedAccessTokensAreRejected(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, _ := e.enrollDevice(t, "laptop")
	_, body := e.exchange(t, devToken, map[string]any{"scopes": []string{"sync"}})
	token := body["accessToken"].(string)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("票据格式意外：%q", token)
	}

	// 把 scope 改成全权限，签名照抄
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	claims["s"] = "sync,share,key-admin,pairing,backup-admin"
	tampered, _ := json.Marshal(claims)
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(tampered) + "." + parts[2]

	for name, bad := range map[string]string{
		"篡改 payload": forged,
		"篡改签名":       parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2])),
		"缺少签名":       parts[0] + "." + parts[1],
		"空票":         "lst1..",
	} {
		resp, _ := e.doJSON(t, http.MethodGet, "/api/v1/info", bad, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s 必须被拒，得到 %d", name, resp.StatusCode)
		}
	}
}

// 根 Token 不换票：它是全权限长期凭据，换成短期票只会让
// 「根 Token 只应存在于服务器与首台设备」这条约束变模糊。
func TestRootTokenDoesNotExchangeForAccessToken(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	resp, _ := e.exchange(t, testToken, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("根 Token 换票应当被拒，得到 %d", resp.StatusCode)
	}
}
