package api_test

// v9 架构加固专项测试：repoEpoch / headSequence、E2EE 状态机与明文冻结、
// 跨平台路径规则、可信代理。对应《一阶段架构审查》P0 1/2/5/7/8 与 P1 13/15。

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KJoner/litesync-server/internal/api"
	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

func (e *testEnv) info(t *testing.T) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/info", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	_, body := e.do(t, req)
	return body
}

func (e *testEnv) postE2ee(t *testing.T, action string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/e2ee/"+action, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	return e.do(t, req)
}

// info 必须携带 repoEpoch / headSequence / encryptionState，且与 changes、snapshot 一致。
func TestRepoEpochAndHeadSequence(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "a.md", 0, []byte("a"))
	e.upload(t, "b.md", 0, []byte("b"))

	info := e.info(t)
	epoch, _ := info["repoEpoch"].(string)
	if len(epoch) != 32 {
		t.Fatalf("repoEpoch = %q, want 32-hex", epoch)
	}
	if info["headSequence"].(float64) != 2 || info["latestSequence"].(float64) != 2 {
		t.Fatalf("headSequence/latestSequence = %v/%v", info["headSequence"], info["latestSequence"])
	}
	if info["encryptionState"] != "plaintext" || info["protocolVersion"].(float64) != 4 {
		t.Fatalf("encryptionState/protocolVersion = %v/%v", info["encryptionState"], info["protocolVersion"])
	}

	_, cbody := e.changes(t, "?since=0")
	if cbody["repoEpoch"] != epoch || cbody["headSequence"].(float64) != 2 {
		t.Fatalf("changes epoch/head = %v/%v", cbody["repoEpoch"], cbody["headSequence"])
	}

	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/snapshot", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	_, sbody := e.do(t, req)
	if sbody["repoEpoch"] != epoch || sbody["sequence"].(float64) != 2 {
		t.Fatalf("snapshot epoch/sequence = %v/%v", sbody["repoEpoch"], sbody["sequence"])
	}

	// 灾备恢复：旋转 epoch 后 info 立即反映新值（head 不变）
	newEpoch, err := db.RotateEpoch(e.db)
	if err != nil {
		t.Fatal(err)
	}
	info2 := e.info(t)
	if info2["repoEpoch"] != newEpoch || info2["repoEpoch"] == epoch {
		t.Fatalf("epoch after rotate = %v (old %v, new %v)", info2["repoEpoch"], epoch, newEpoch)
	}
	if info2["headSequence"].(float64) != 2 {
		t.Fatal("rotate must not change headSequence")
	}
}

// E2EE 状态机：begin 冻结明文写；complete 要求全部 HEAD 为 LSE1；abort 恢复。
func TestE2eeStateMachine(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	plain := []byte("plain content")
	lse1 := append([]byte("LSE1"), []byte("pretend-iv-and-ciphertext")...)

	e.upload(t, "a.md", 0, plain)

	// plaintext 状态：complete/abort 非法
	if resp, _ := e.postE2ee(t, "complete"); resp.StatusCode != http.StatusConflict {
		t.Fatalf("complete in plaintext = %d, want 409", resp.StatusCode)
	}
	if resp, _ := e.postE2ee(t, "abort"); resp.StatusCode != http.StatusConflict {
		t.Fatalf("abort in plaintext = %d, want 409", resp.StatusCode)
	}

	// begin → migrating，keyEpoch=1；重复 begin 幂等
	resp, body := e.postE2ee(t, "begin")
	if resp.StatusCode != http.StatusOK || body["encryptionState"] != "migrating" || body["keyEpoch"].(float64) != 1 {
		t.Fatalf("begin = %d %v", resp.StatusCode, body)
	}
	if _, body2 := e.postE2ee(t, "begin"); body2["keyEpoch"].(float64) != 1 {
		t.Fatalf("begin must be idempotent, keyEpoch = %v", body2["keyEpoch"])
	}

	// migrating：明文上传被冻结（新文件与已有文件都一样）
	if resp, _ := e.upload(t, "b.md", 0, plain); resp.StatusCode != http.StatusConflict {
		t.Fatalf("plaintext upload while migrating = %d, want 409", resp.StatusCode)
	}
	// 密文（LSE1 开头）允许
	if resp, _ := e.upload(t, "a.md", 1, lse1); resp.StatusCode != http.StatusOK {
		t.Fatalf("ciphertext upload while migrating = %d", resp.StatusCode)
	}

	// 还有明文 HEAD 时不允许 complete？—— a.md 已是密文，全部 HEAD 均密文 → 允许
	// 先构造一个仍是明文 HEAD 的场景：abort 后传明文，再 begin
	if resp, _ := e.postE2ee(t, "abort"); resp.StatusCode != http.StatusOK {
		t.Fatalf("abort = %d", resp.StatusCode)
	}
	e.upload(t, "c.md", 0, plain) // 明文 HEAD
	if _, body := e.postE2ee(t, "begin"); body["keyEpoch"].(float64) != 2 {
		t.Fatalf("second begin keyEpoch = %v, want 2", body["keyEpoch"])
	}
	if resp, _ := e.postE2ee(t, "complete"); resp.StatusCode != http.StatusConflict {
		t.Fatalf("complete with plaintext HEAD = %d, want 409", resp.StatusCode)
	}

	// 把明文 HEAD 换成密文 → complete 允许
	if resp, _ := e.upload(t, "c.md", 1, lse1); resp.StatusCode != http.StatusOK {
		t.Fatalf("re-encrypt c.md = %d", resp.StatusCode)
	}
	resp3, body3 := e.postE2ee(t, "complete")
	if resp3.StatusCode != http.StatusOK || body3["encryptionState"] != "encrypted" {
		t.Fatalf("complete = %d %v", resp3.StatusCode, body3)
	}

	// encrypted：明文永久冻结；密文照常（LSE1 与 v9.2 的 LSE2 信封均接受）；info 反映状态
	if resp, _ := e.upload(t, "d.md", 0, plain); resp.StatusCode != http.StatusConflict {
		t.Fatalf("plaintext upload while encrypted = %d, want 409", resp.StatusCode)
	}
	if resp, _ := e.upload(t, "d.md", 0, lse1); resp.StatusCode != http.StatusOK {
		t.Fatalf("ciphertext upload while encrypted = %d", resp.StatusCode)
	}
	lse2 := append([]byte("LSE2"), []byte("\x00\x00\x00\x01pretend-iv-and-ciphertext")...)
	if resp, _ := e.upload(t, "e.md", 0, lse2); resp.StatusCode != http.StatusOK {
		t.Fatalf("LSE2 upload while encrypted = %d", resp.StatusCode)
	}
	if info := e.info(t); info["encryptionState"] != "encrypted" {
		t.Fatalf("info encryptionState = %v", info["encryptionState"])
	}
	// encrypted 状态不允许 begin（需要显式的密钥轮换流程，当前协议不提供）
	if resp, _ := e.postE2ee(t, "begin"); resp.StatusCode != http.StatusConflict {
		t.Fatalf("begin while encrypted = %d, want 409", resp.StatusCode)
	}
}

// 跨平台路径规则：大小写/NFC 归一化碰撞拒绝并存；Windows 保留名与尾随句点拒绝。
func TestPathRules(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "Notes/Note.md", 0, []byte("x"))

	// 大小写碰撞 → 422
	resp, body := e.upload(t, "notes/note.md", 0, []byte("y"))
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("case collision = %d, want 422", resp.StatusCode)
	}
	if body["existing"] != "Notes/Note.md" {
		t.Fatalf("collision existing = %v", body["existing"])
	}

	// NFC/NFD 等价碰撞（é 的两种编码）→ 422
	e.upload(t, "café.md", 0, []byte("nfc"))
	if resp, _ := e.upload(t, "café.md", 0, []byte("nfd")); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("NFD collision = %d, want 422", resp.StatusCode)
	}

	// 同一路径自身更新不受影响
	if resp, _ := e.upload(t, "Notes/Note.md", 1, []byte("x2")); resp.StatusCode != http.StatusOK {
		t.Fatalf("self update = %d", resp.StatusCode)
	}

	// 原路径删除（tombstone）后，冲突路径允许创建
	e.delete(t, "Notes/Note.md", 2)
	if resp, _ := e.upload(t, "notes/note.md", 0, []byte("y")); resp.StatusCode != http.StatusOK {
		t.Fatalf("create after tombstone = %d", resp.StatusCode)
	}

	// Windows 保留名与尾随句点/空格 → 400
	for _, p := range []string{"CON.md", "notes/aux.txt", "com1", "end./x.md", "trail.md."} {
		if resp, _ := e.upload(t, p, 0, []byte("z")); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("reserved/invalid path %q = %d, want 400", p, resp.StatusCode)
		}
	}
}

// X-Forwarded-Proto 只信任配置的可信代理来源。
func TestTrustedProxySecureCookie(t *testing.T) {
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	store, _ := storage.New(filepath.Join(dir, "vault"))
	blobs, _ := storage.NewBlobStore(filepath.Join(dir, "blobs"))
	shares, _ := storage.NewShareStore(filepath.Join(dir, "shares"))
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := syncsvc.New(database, store, blobs, shares, syncsvc.Options{}, logger)

	login := func(handler http.Handler) *http.Response {
		ts := httptest.NewServer(handler)
		defer ts.Close()
		payload, _ := json.Marshal(map[string]any{"token": testToken})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/web/session", bytes.NewReader(payload))
		req.Header.Set("X-Forwarded-Proto", "https")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}

	hasSecureCookie := func(resp *http.Response) bool {
		for _, c := range resp.Cookies() {
			if c.Name == "litesync_session" {
				return c.Secure
			}
		}
		t.Fatal("no session cookie set")
		return false
	}

	// 默认（loopback 可信）：httptest 请求来自 127.0.0.1 → XFP 被信任 → Secure
	trusted := api.New(api.Options{Token: testToken, MaxFileSize: 1 << 20, Version: "t", Logger: logger,
		TrustedProxies: []string{"127.0.0.1", "::1"}}, svc)
	if !hasSecureCookie(login(trusted)) {
		t.Fatal("XFP from trusted loopback proxy must set Secure cookie")
	}

	// 无可信代理配置 → 同样的请求头被忽略 → 非 Secure
	untrusted := api.New(api.Options{Token: testToken, MaxFileSize: 1 << 20, Version: "t", Logger: logger,
		TrustedProxies: []string{"10.0.0.0/8"}}, svc)
	if hasSecureCookie(login(untrusted)) {
		t.Fatal("XFP from untrusted source must be ignored")
	}
}

// 上传响应错误信息包含碰撞路径（客户端可提示用户改名）。
func TestPathCollisionMessage(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	e.upload(t, "A.md", 0, []byte("x"))
	_, body := e.upload(t, "a.md", 0, []byte("y"))
	if !strings.Contains(body["error"].(string), "collision") {
		t.Fatalf("collision error message = %v", body["error"])
	}
}
