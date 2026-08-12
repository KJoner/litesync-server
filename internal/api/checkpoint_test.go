package api_test

import (
	"net/http"
	"strings"
	"testing"
)

// 签名 checkpoint 的服务端行为（v0.15.0 / 计划书 §9）。
//
// 这里要验证的核心是**服务器的角色边界**：它存、它转发、它拒绝已撤销设备，
// 但它不验证签名、不裁决分叉。任何一条越界，整套 freshness 机制都会退回到
// 「相信服务器」——而那正是本阶段要消除的前提。

// enrollDevice 创建一台设备并返回它的 Token 与 id。
func (e *testEnv) enrollDevice(t *testing.T, name string) (token, deviceID string) {
	t.Helper()
	resp, cred := e.doJSON(t, http.MethodPost, "/api/v1/devices", testToken, map[string]any{"name": name})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create device = %d", resp.StatusCode)
	}
	return cred["deviceToken"].(string), cred["deviceId"].(string)
}

// repoEpoch 取当前仓库的 sequence 世代（发布 checkpoint 时必须带上）。
func (e *testEnv) repoEpoch(t *testing.T) string {
	t.Helper()
	_, info := e.doJSON(t, http.MethodGet, "/api/v1/info", testToken, nil)
	return info["repoEpoch"].(string)
}

func TestCheckpointRequiresRegisteredSigningKey(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, _ := e.enrollDevice(t, "dev-1")

	// 还没登记签名公钥就发布 → 拒绝
	resp, _ := e.doJSON(t, http.MethodPost, "/api/v1/checkpoint", devToken, map[string]any{
		"hash":         strings.Repeat("a", 64),
		"repoEpoch":    e.repoEpoch(t),
		"headSequence": 10,
		"body":         "v=1\nhead=10",
		"signature":    "c2ln",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("未登记签名公钥的设备不应能发布 checkpoint，得到 %d", resp.StatusCode)
	}

	// 登记之后可以
	if r, _ := e.doJSON(t, http.MethodPut, "/api/v1/device/signing-key", devToken,
		map[string]any{"publicKey": "cHVibGljLWtleQ=="}); r.StatusCode != http.StatusOK {
		t.Fatalf("登记签名公钥失败: %d", r.StatusCode)
	}
	resp2, _ := e.doJSON(t, http.MethodPost, "/api/v1/checkpoint", devToken, map[string]any{
		"hash":         strings.Repeat("a", 64),
		"repoEpoch":    e.repoEpoch(t),
		"headSequence": 10,
		"body":         "v=1\nhead=10",
		"signature":    "c2ln",
	})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("登记之后应当可以发布，得到 %d", resp2.StatusCode)
	}
}

// §9.2：撤销之后不得再发布。
//
// 注意被撤销设备的私钥**仍然是有效私钥**——只靠客户端验签名拦不住它。
// 服务器这一层能减少这类 checkpoint 进入流通。
func TestRevokedDeviceCannotPublishCheckpoint(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, devID := e.enrollDevice(t, "dev-1")
	if r, _ := e.doJSON(t, http.MethodPut, "/api/v1/device/signing-key", devToken,
		map[string]any{"publicKey": "cHVibGljLWtleQ=="}); r.StatusCode != http.StatusOK {
		t.Fatal(r.StatusCode)
	}
	// 用根 Token 撤销该设备
	if r, _ := e.doJSON(t, http.MethodDelete, "/api/v1/devices/"+devID, testToken, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("撤销失败: %d", r.StatusCode)
	}
	// 撤销后设备 Token 本身已失效（401），这已经挡住了发布路径；
	// 服务层的显式拒绝由 sync 包的单元测试覆盖
	resp, _ := e.doJSON(t, http.MethodPost, "/api/v1/checkpoint", devToken, map[string]any{
		"hash": strings.Repeat("b", 64), "repoEpoch": e.repoEpoch(t), "headSequence": 20,
		"body": "v=1", "signature": "c2ln",
	})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("已撤销设备不得再发布 checkpoint")
	}
}

// §9.1：服务器原样保存与转发，不做任何解析或改写。
func TestCheckpointStoredVerbatim(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, devID := e.enrollDevice(t, "dev-1")
	if r, _ := e.doJSON(t, http.MethodPut, "/api/v1/device/signing-key", devToken,
		map[string]any{"publicKey": "cHVibGljLWtleQ=="}); r.StatusCode != http.StatusOK {
		t.Fatal(r.StatusCode)
	}

	const body = "v=1\nvault=vault-x\nhead=42\nroot=deadbeef"
	const sig = "c2lnbmF0dXJl"
	hash := strings.Repeat("c", 64)
	if r, _ := e.doJSON(t, http.MethodPost, "/api/v1/checkpoint", devToken, map[string]any{
		"hash": hash, "repoEpoch": e.repoEpoch(t), "headSequence": 42,
		"previousHash": "", "body": body, "signature": sig,
	}); r.StatusCode != http.StatusOK {
		t.Fatalf("发布失败: %d", r.StatusCode)
	}

	_, got := e.doJSON(t, http.MethodGet, "/api/v1/checkpoints?since=0", devToken, nil)
	list, _ := got["checkpoints"].([]any)
	if len(list) != 1 {
		t.Fatalf("应当取回 1 个 checkpoint，得到 %v", got["checkpoints"])
	}
	cp := list[0].(map[string]any)
	// 一个字节都不能变：客户端会用这段原文重算 canonical 来验签
	if cp["body"] != body {
		t.Fatalf("body 被改写了：\n want %q\n got  %q", body, cp["body"])
	}
	if cp["signature"] != sig || cp["hash"] != hash {
		t.Fatal("签名或 hash 被改写")
	}
	if cp["signingDeviceId"] != devID {
		t.Fatalf("签名设备记错了：want %s got %v", devID, cp["signingDeviceId"])
	}

	// 服务器交出它知道的公钥与撤销清单——但那只用于识别，不用于授信
	keys, _ := got["signingKeys"].(map[string]any)
	if keys[devID] != "cHVibGljLWtleQ==" {
		t.Fatalf("应当带上已登记的公钥，得到 %v", keys)
	}
}

// §9.4：同一位置上的多份 checkpoint 是分叉证据，服务器必须**都**交出去。
// 悄悄丢掉其中一份等于替用户隐瞒了一次 equivocation。
func TestServerExposesForkEvidence(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, _ := e.enrollDevice(t, "dev-1")
	if r, _ := e.doJSON(t, http.MethodPut, "/api/v1/device/signing-key", devToken,
		map[string]any{"publicKey": "cHVibGljLWtleQ=="}); r.StatusCode != http.StatusOK {
		t.Fatal(r.StatusCode)
	}
	epoch := e.repoEpoch(t)
	for _, h := range []string{strings.Repeat("d", 64), strings.Repeat("e", 64)} {
		if r, _ := e.doJSON(t, http.MethodPost, "/api/v1/checkpoint", devToken, map[string]any{
			"hash": h, "repoEpoch": epoch, "headSequence": 77,
			"body": "v=1\nhead=77\nroot=" + h[:8], "signature": "c2ln",
		}); r.StatusCode != http.StatusOK {
			t.Fatalf("发布 %s 失败: %d", h[:8], r.StatusCode)
		}
	}

	_, got := e.doJSON(t, http.MethodGet, "/api/v1/checkpoints?since=0", devToken, nil)
	conflicting, _ := got["conflicting"].([]any)
	if len(conflicting) != 2 {
		t.Fatalf("同一位置的两份 checkpoint 必须都作为分叉证据交出，得到 %v", got["conflicting"])
	}
}

// 根 Token 没有设备身份，因此不能登记签名密钥——签名密钥是设备的属性。
func TestRootTokenCannotRegisterSigningKey(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	resp, _ := e.doJSON(t, http.MethodPut, "/api/v1/device/signing-key", testToken,
		map[string]any{"publicKey": "cHVibGljLWtleQ=="})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("根 Token 不应能登记设备签名密钥，得到 %d", resp.StatusCode)
	}
}
