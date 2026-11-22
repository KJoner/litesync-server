package api_test

import (
	"net/http"
	"testing"
)

// UI v2 / I1：账号中心把「用户名」「昵称」「邮箱」分开以后，LiteSync 的资料快照怎么取。
//   - 显示名：昵称 → 旧账号的 name → preferred_username；email 声明从不拿来当显示名
//   - 登录用户名：preferred_username 原样，只给账号页展示（/api/v2/me 的 account.username）
//   - 身份只认 (issuer, subject)：昵称相同的两个人是两个账号，改昵称不改本地账号
func TestOIDCNicknameAndUsernameSnapshot(t *testing.T) {
	e := newOIDCEnv(t, "open", true)

	login := func(sub string, extra map[string]any) map[string]any {
		t.Helper()
		b := e.newBrowser(t)
		if resp, page := b.login(sub, extra); resp.StatusCode != http.StatusOK {
			t.Fatalf("login %s = %d %s", sub, resp.StatusCode, page)
		}
		code, me := b.me()
		if code != http.StatusOK {
			t.Fatalf("/api/v2/me for %s = %d %v", sub, code, me)
		}
		return me["account"].(map[string]any)
	}

	// 新注册：有昵称和独立用户名
	a := login("nick-a", map[string]any{"nickname": "  同一个昵称 ", "preferred_username": "nick_a", "name": "Old Name A"})
	if a["displayName"] != "同一个昵称" {
		t.Fatalf("display name must prefer the trimmed nickname, got %v", a["displayName"])
	}
	if a["username"] != "nick_a" {
		t.Fatalf("account.username must be the preferred_username snapshot, got %v", a["username"])
	}

	// 另一个人用了同一个昵称：仍是另一个本地账号
	b := login("nick-b", map[string]any{"nickname": "同一个昵称", "preferred_username": "nick_b"})
	if b["id"] == a["id"] {
		t.Fatalf("two subjects with the same nickname must never share a local account: %v", a["id"])
	}
	if b["username"] != "nick_b" || b["displayName"] != "同一个昵称" {
		t.Fatalf("second account snapshot wrong: %v", b)
	}

	// 改昵称后重新登录：同一个本地账号，显示名跟着变，用户名不受影响
	a2 := login("nick-a", map[string]any{"nickname": "改过的昵称", "preferred_username": "nick_a"})
	if a2["id"] != a["id"] {
		t.Fatalf("changing the nickname must not change the local account: %v -> %v", a["id"], a2["id"])
	}
	if a2["displayName"] != "改过的昵称" || a2["username"] != "nick_a" {
		t.Fatalf("after a nickname change: %v", a2)
	}

	// 旧账号：用户名就是邮箱、没有昵称 → 显示名仍是原来的姓名，登录用户名如实显示
	legacy := login("legacy", map[string]any{"preferred_username": "legacy@example.org", "name": "旧 姓名"})
	if legacy["displayName"] != "旧 姓名" || legacy["username"] != "legacy@example.org" {
		t.Fatalf("legacy email-username account: %v", legacy)
	}

	// 只有用户名：显示名退到用户名（与改动前相同的兜底），不会用 email 声明
	bare := login("bare", map[string]any{"preferred_username": "bare_user", "name": "", "email": "someone@example.org"})
	if bare["displayName"] != "bare_user" {
		t.Fatalf("without nickname and name the display name falls back to the username, got %v", bare["displayName"])
	}

	// 身份服务没给 preferred_username：不出现 account.username（页面不显示这一行）
	none := login("no-username", map[string]any{"nickname": "只有昵称"})
	if _, ok := none["username"]; ok {
		t.Fatalf("account.username must be omitted when the IdP sent none: %v", none)
	}
}
