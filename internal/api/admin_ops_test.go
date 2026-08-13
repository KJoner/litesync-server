package api_test

import (
	"net/http"
	"testing"
	"time"
)

// 管理 UI 的后端行为（v0.17 / 计划书 §11.3）。
//
// 这些接口只在出事那天用。「只能 SSH 上服务器敲命令」是它们最常见的失败方式，
// 因此每一条都要在浏览器里就走得通；而「说得比能做的多」是第二常见的失败——
// 尤其是分享恢复，用户很容易以为管理员什么都救得回来。

func TestAdminDeviceListAndRevoke(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	devToken, deviceID := e.enrollDevice(t, "lost-laptop")

	resp, body := e.doJSON(t, http.MethodGet, "/api/v1/admin/devices", testToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("列设备 = %d", resp.StatusCode)
	}
	devices, _ := body["devices"].([]any)
	if len(devices) == 0 {
		t.Fatal("应当列出已注册设备")
	}

	// 撤销
	resp, _ = e.doJSON(t, http.MethodDelete, "/api/v1/admin/devices/"+deviceID, testToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("撤销 = %d", resp.StatusCode)
	}
	if resp, _ := e.doJSON(t, http.MethodGet, "/api/v1/info", devToken, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("撤销后设备凭据必须立刻失效")
	}

	// 已撤销的设备仍要列出来：撤销之后最该被回答的是「它最后一次活动是什么时候」，
	// 把行删掉就永远答不了
	_, body = e.doJSON(t, http.MethodGet, "/api/v1/admin/devices", testToken, nil)
	devices, _ = body["devices"].([]any)
	var found bool
	for _, d := range devices {
		m, _ := d.(map[string]any)
		if m["id"] == deviceID {
			found = true
			if m["revoked"] != true {
				t.Fatal("撤销后必须标记 revoked")
			}
		}
	}
	if !found {
		t.Fatal("已撤销设备必须仍出现在列表里")
	}

	// 不存在的设备返回 404 而不是静默成功
	resp, _ = e.doJSON(t, http.MethodDelete, "/api/v1/admin/devices/no-such-device", testToken, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("撤销不存在的设备应当 404，得到 %d", resp.StatusCode)
	}
}

func TestAdminMigrationStatus(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	resp, body := e.doJSON(t, http.MethodGet, "/api/v1/admin/migration/status", testToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("迁移状态 = %d", resp.StatusCode)
	}
	// 三件卡人的事必须都在同一个响应里：元数据迁移、blobID 域化、待重新封装
	for _, k := range []string{"meta", "needsBlobIdMigration", "pendingRewrapEpoch"} {
		if _, ok := body[k]; !ok {
			t.Errorf("响应缺少 %s —— 「现在到底卡在哪」就答不了了", k)
		}
	}
}

// 分享恢复能做的和不能做的，必须分得清清楚楚。
func TestAdminShareRecoveryTellsTheTruth(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "s.md", 0, []byte("shared note"))

	soon := time.Now().Unix() + 2
	resp, body := e.createShare(t, "s.md", soon, []byte("cipher"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("创建分享 = %d", resp.StatusCode)
	}
	shareID, _ := body["id"].(string)
	if shareID == "" {
		t.Fatal("缺少分享 id")
	}

	// 密文还在 → 可以延长有效期
	later := time.Now().Unix() + 3600
	resp, _ = e.doJSON(t, http.MethodPost, "/api/v1/admin/shares/"+shareID+"/recover", testToken,
		map[string]any{"expiresAt": later})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("延长有效期应当成功，得到 %d", resp.StatusCode)
	}

	// 列表里能看到它，并且标记为可恢复
	_, body = e.doJSON(t, http.MethodGet, "/api/v1/admin/shares", testToken, nil)
	shares, _ := body["shares"].([]any)
	var seen bool
	for _, s := range shares {
		m, _ := s.(map[string]any)
		if m["id"] == shareID {
			seen = true
			if m["recoverable"] != true {
				t.Error("密文还在的分享应当标记为可恢复")
			}
		}
	}
	if !seen {
		t.Fatal("分享应当出现在管理列表里")
	}

	// 往过去延 → 拒绝（那等于撤销，而撤销有它自己的入口）
	resp, _ = e.doJSON(t, http.MethodPost, "/api/v1/admin/shares/"+shareID+"/recover", testToken,
		map[string]any{"expiresAt": time.Now().Unix() - 1})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("把有效期往过去改应当被拒，得到 %d", resp.StatusCode)
	}

	// 主动撤销之后不能靠「恢复」推翻：撤销是一次明确的意图表达
	dreq, _ := http.NewRequest(http.MethodDelete, e.ts.URL+"/api/v1/share?id="+shareID, nil)
	dreq.Header.Set("Authorization", "Bearer "+testToken)
	resp, _ = e.do(t, dreq)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("撤销分享 = %d", resp.StatusCode)
	}
	resp, revokedBody := e.doJSON(t, http.MethodPost, "/api/v1/admin/shares/"+shareID+"/recover", testToken,
		map[string]any{"expiresAt": later})
	if resp.StatusCode != http.StatusConflict && resp.StatusCode != http.StatusGone {
		t.Fatalf("已撤销的分享不该能被恢复，得到 %d (%v)", resp.StatusCode, revokedBody)
	}
}

// admin 撤销分享：链接立刻失效、密文一并回收，且撤销是明确的意图表达——
// 之后不能再靠「恢复」推翻。
func TestAdminRevokeShare(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	resp, body := e.createShare(t, "note", time.Now().Unix()+3600, []byte("cipher"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("创建分享 = %d", resp.StatusCode)
	}
	shareID, _ := body["id"].(string)
	if shareID == "" {
		t.Fatal("缺少分享 id")
	}

	// 撤销前公开链接可达（对照组：没有它，后面的 404 可能只是「从来就打不开」）
	if r, _ := e.fetchShare(t, shareID); r.StatusCode != http.StatusOK {
		t.Fatalf("撤销前分享应当可达，得到 %d", r.StatusCode)
	}

	resp, _ = e.doJSON(t, http.MethodDelete, "/api/v1/admin/shares/"+shareID, testToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("撤销分享 = %d", resp.StatusCode)
	}

	// 链接立刻 404
	if r, _ := e.fetchShare(t, shareID); r.StatusCode != http.StatusNotFound {
		t.Fatalf("撤销后分享链接应当 404，得到 %d", r.StatusCode)
	}
	// 密文已回收：服务器不该继续替一个已撤销的分享保管密文
	if e.svc.ShareCiphertextExists(shareID) {
		t.Fatal("撤销后密文必须被回收")
	}
	// 撤销后延长有效期仍要 409
	resp, _ = e.doJSON(t, http.MethodPost, "/api/v1/admin/shares/"+shareID+"/recover", testToken,
		map[string]any{"expiresAt": time.Now().Unix() + 7200})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("撤销后恢复应当 409，得到 %d", resp.StatusCode)
	}
	// 不存在的分享 → 404 而不是静默成功
	resp, _ = e.doJSON(t, http.MethodDelete, "/api/v1/admin/shares/no-such-share", testToken, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("撤销不存在的分享应当 404，得到 %d", resp.StatusCode)
	}
}

// 不存在的分享必须明确告知「救不回来」，而不是含糊的 500 或静默成功。
func TestAdminRecoverMissingShareIsExplicit(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	resp, body := e.doJSON(t, http.MethodPost, "/api/v1/admin/shares/no-such-share/recover", testToken,
		map[string]any{"expiresAt": time.Now().Unix() + 3600})
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("不存在的分享应当 410 Gone，得到 %d", resp.StatusCode)
	}
	msg, _ := body["error"].(string)
	if msg == "" {
		msg, _ = body["message"].(string)
	}
	if msg == "" {
		t.Fatalf("必须带一条说明，实际响应：%v", body)
	}
}

// 恢复预检要给出准确的后果与可粘贴的命令，并说清为什么不是一个按钮。
func TestAdminRestorePlanIsHonest(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.enrollDevice(t, "a")
	e.enrollDevice(t, "b")

	resp, _ := e.doJSON(t, http.MethodGet, "/api/v1/admin/backup/restore-plan", testToken, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺少 snapshot 应当 400，得到 %d", resp.StatusCode)
	}

	resp, body := e.doJSON(t, http.MethodGet, "/api/v1/admin/backup/restore-plan?snapshot=abc123", testToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("预检 = %d", resp.StatusCode)
	}
	cmd, _ := body["command"].(string)
	if cmd == "" || cmd == "obsync backup restore " {
		t.Fatalf("必须给出可直接粘贴的命令，得到 %q", cmd)
	}
	cons, _ := body["consequences"].([]any)
	if len(cons) < 3 {
		t.Fatal("必须列出恢复的后果——repoEpoch 旋转、游标作废、设备进入灾备合并")
	}
	if why, _ := body["whyNotAButton"].(string); why == "" {
		t.Fatal("必须说明为什么恢复不是一个网页按钮")
	}
	// 在用设备数要真的算对：它决定了「有多少人会被卷进灾备合并」
	if n, _ := body["activeDevices"].(float64); int(n) != 2 {
		t.Fatalf("在用设备数应当是 2，得到 %v", n)
	}
}
