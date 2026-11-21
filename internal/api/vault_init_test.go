package api_test

// 仓库加密初始化（ADR-012）与指定仓库配对 v2（ADR-014）的接口测试。
// 覆盖验收 KY-05/KY-06（服务端部分）、PR-01…PR-04（服务端部分）；INV-12。

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	gosync "sync"
	"testing"
	"time"

	"github.com/KJoner/litesync-server/internal/api"
	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// newPublicTestEnv：公开模式（新仓库强制 E2EE）。
func newPublicTestEnv(t *testing.T) *testEnv {
	t.Helper()
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
	svc := syncsvc.New(database, store, blobs, shares, syncsvc.Options{HistoryEnabled: true, HistoryMaxPerFile: 100}, logger)
	ts := httptest.NewServer(api.New(api.Options{
		Token: testToken, MaxFileSize: 1 << 20, Version: "test", Logger: logger,
		RequireE2EENewVaults: true,
	}, svc))
	t.Cleanup(ts.Close)
	return &testEnv{ts: ts, svc: svc, db: database}
}

// call 发一个 JSON 请求：bearer 可空；vault 非空时带 X-Vault-ID。
func (e *testEnv) call(t *testing.T, method, path, bearer, vault string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, rd)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if vault != "" {
		req.Header.Set("X-Vault-ID", vault)
	}
	return e.do(t, req)
}

func (e *testEnv) putFileIn(t *testing.T, bearer, vault, path string, content []byte) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytes.NewReader(content))
	req.Header.Set("Authorization", "Bearer "+bearer)
	if vault != "" {
		req.Header.Set("X-Vault-ID", vault)
	}
	req.Header.Set("X-File-Path", url.PathEscape(path))
	req.Header.Set("X-Base-Revision", "0")
	req.Header.Set("X-Content-Hash", sha256Hex(content))
	return e.do(t, req)
}

func b64n(n int, fill byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, n)) }

// testKeyDoc 形状与插件 createVaultKeyDoc 一致（密文是假的：服务端不理解也不校验内容）。
func testKeyDoc(iterations int) map[string]any {
	return map[string]any{
		"version": 1, "kdf": "pbkdf2-sha256", "iterations": iterations,
		"salt": b64n(16, 1), "iv": b64n(12, 2), "wrappedKey": b64n(48, 3),
		"enabled": true, "createdAt": 1795132800000,
	}
}

var testProfile = map[string]any{"protocolVersion": 6, "keyDocVersion": 1, "writeEnvelope": "LSE3"}

func initCommit(op string, version int, doc map[string]any) map[string]any {
	return map[string]any{"phase": "commit", "opId": op, "expectedInitVersion": version,
		"keyDoc": doc, "cryptoProfile": testProfile, "resetAuth": strings.Repeat("ab", 32)}
}

// createReadyVault 走完一遍 v2 建库 + 初始化，返回 vaultId。
func createReadyVault(t *testing.T, e *testEnv, bearer, name string) string {
	t.Helper()
	r, b := e.call(t, http.MethodPost, "/api/v2/vaults", bearer, "", map[string]any{"name": name, "clientRequestId": "req_" + sha256Hex([]byte(name))[:32]})
	if r.StatusCode != http.StatusOK {
		t.Fatalf("create v2 = %d %v", r.StatusCode, b)
	}
	id := b["vaultId"].(string)
	op := "op_init_" + strings.Repeat("d", 10)
	if r, b := e.call(t, http.MethodPost, "/api/v2/vaults/"+id+"/initialization", bearer, "", map[string]any{"phase": "claim", "opId": op}); r.StatusCode != http.StatusOK {
		t.Fatalf("claim = %d %v", r.StatusCode, b)
	}
	if r, b := e.call(t, http.MethodPost, "/api/v2/vaults/"+id+"/initialization", bearer, "", initCommit(op, 1, testKeyDoc(600000))); r.StatusCode != http.StatusOK {
		t.Fatalf("commit = %d %v", r.StatusCode, b)
	}
	return id
}

func TestVaultInitV2Lifecycle(t *testing.T) {
	e := newPublicTestEnv(t)
	alice, _, _ := registerUser(t, e, adminCreateInvite(t, e), "alice")
	bob, _, _ := registerUser(t, e, adminCreateInvite(t, e), "bob")

	req := map[string]any{"name": "个人笔记", "clientRequestId": "req_demo_create_01"}
	r, created := e.call(t, http.MethodPost, "/api/v2/vaults", alice, "", req)
	if r.StatusCode != http.StatusOK || created["initState"] != "pending_encryption" || created["created"] != true {
		t.Fatalf("create = %d %v", r.StatusCode, created)
	}
	vault := created["vaultId"].(string)
	if created["vaultIdentity"] == "" || created["vaultIdentity"] == vault {
		t.Fatalf("vaultId (selector) and vaultIdentity (AAD binding) must be distinct: %v", created)
	}
	// 重复点击 / 刷新重试：同一 clientRequestId 不会建出第二个仓库
	if r, again := e.call(t, http.MethodPost, "/api/v2/vaults", alice, "", req); r.StatusCode != http.StatusOK || again["vaultId"] != vault || again["created"] != false {
		t.Fatalf("idempotent create = %d %v", r.StatusCode, again)
	}

	// 未就绪：任何内容写入都被服务端拒绝（明文与密文都不行）
	for _, content := range [][]byte{[]byte("plaintext note"), lse3Payload(1, 1, "early")} {
		if r, b := e.putFileIn(t, alice, vault, "a.md", content); r.StatusCode != http.StatusConflict || b["code"] != "VAULT_NOT_READY" {
			t.Fatalf("write to pending vault = %d %v, want 409 VAULT_NOT_READY", r.StatusCode, b)
		}
	}

	initPath := "/api/v2/vaults/" + vault + "/initialization"
	// 不认领直接提交 → 拒绝
	if r, b := e.call(t, http.MethodPost, initPath, alice, "", initCommit("op_tab_aaaaaaaaaaaa", 1, testKeyDoc(600000))); r.StatusCode != http.StatusConflict {
		t.Fatalf("commit without claim = %d %v", r.StatusCode, b)
	}
	opA, opB := "op_tab_aaaaaaaaaaaa", "op_tab_bbbbbbbbbbbb"
	if r, b := e.call(t, http.MethodPost, initPath, alice, "", map[string]any{"phase": "claim", "opId": opA}); r.StatusCode != http.StatusOK || b["initState"] != "initializing" {
		t.Fatalf("claim A = %d %v", r.StatusCode, b)
	}
	// 第二个标签页：租约未过期 → INIT_IN_PROGRESS
	if r, b := e.call(t, http.MethodPost, initPath, alice, "", map[string]any{"phase": "claim", "opId": opB}); r.StatusCode != http.StatusConflict || b["code"] != "INIT_IN_PROGRESS" {
		t.Fatalf("claim B = %d %v, want 409 INIT_IN_PROGRESS", r.StatusCode, b)
	}
	// 弱参数与畸形文档被拒
	if r, _ := e.call(t, http.MethodPost, initPath, alice, "", initCommit(opA, 1, testKeyDoc(1000))); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("weak KDF iterations = %d, want 400", r.StatusCode)
	}
	bad := testKeyDoc(600000)
	bad["wrappedKey"] = b64n(10, 9)
	if r, _ := e.call(t, http.MethodPost, initPath, alice, "", initCommit(opA, 1, bad)); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed wrappedKey = %d, want 400", r.StatusCode)
	}
	if r, b := e.call(t, http.MethodPost, initPath, alice, "", initCommit(opA, 7, testKeyDoc(600000))); r.StatusCode != http.StatusConflict || b["code"] != "INIT_VERSION_MISMATCH" {
		t.Fatalf("stale expectedInitVersion = %d %v", r.StatusCode, b)
	}
	// 他人：一律 404（不泄露存在性）
	if r, _ := e.call(t, http.MethodGet, initPath, bob, "", nil); r.StatusCode != http.StatusNotFound {
		t.Fatalf("bob reads alice's init status = %d, want 404", r.StatusCode)
	}
	if r, _ := e.call(t, http.MethodPost, initPath, bob, "", map[string]any{"phase": "claim", "opId": "op_bob_ccccccccccc"}); r.StatusCode != http.StatusNotFound {
		t.Fatalf("bob claims alice's vault = %d, want 404", r.StatusCode)
	}

	r, done := e.call(t, http.MethodPost, initPath, alice, "", initCommit(opA, 1, testKeyDoc(600000)))
	if r.StatusCode != http.StatusOK || done["initState"] != "ready" || done["replayed"] != false {
		t.Fatalf("commit = %d %v", r.StatusCode, done)
	}
	// 响应丢失后重试：同 opId 同请求 → 同一结果
	if r, again := e.call(t, http.MethodPost, initPath, alice, "", initCommit(opA, 1, testKeyDoc(600000))); r.StatusCode != http.StatusOK || again["replayed"] != true || again["vaultIdentity"] != done["vaultIdentity"] {
		t.Fatalf("commit replay = %d %v", r.StatusCode, again)
	}
	// 同 opId 不同载荷 → 拒绝盲重试
	other := testKeyDoc(700000)
	if r, b := e.call(t, http.MethodPost, initPath, alice, "", initCommit(opA, 1, other)); r.StatusCode != http.StatusConflict || b["code"] != "IDEMPOTENCY_KEY_REUSED" {
		t.Fatalf("opId reuse = %d %v", r.StatusCode, b)
	}
	// 已 ready：再认领 / 再初始化都不能换掉密钥文档
	if r, _ := e.call(t, http.MethodPost, initPath, alice, "", map[string]any{"phase": "claim", "opId": opB}); r.StatusCode != http.StatusConflict {
		t.Fatalf("claim after ready = %d, want 409", r.StatusCode)
	}
	if r, b := e.call(t, http.MethodGet, "/api/v1/vault-key", alice, vault, nil); r.StatusCode != http.StatusOK || b["iterations"].(float64) != 600000 {
		t.Fatalf("vault-key after init = %d %v", r.StatusCode, b)
	}
	r, info := e.call(t, http.MethodGet, "/api/v1/info", alice, vault, nil)
	if r.StatusCode != http.StatusOK || info["encryptionState"] != "encrypted" ||
		info["minimumEnvelopeVersion"].(float64) != 3 || info["keyEpoch"].(float64) != 1 ||
		info["vaultId"] != done["vaultIdentity"] || info["resetAuthConfigured"] != true {
		t.Fatalf("info after init = %v", info)
	}
	caps := fmt.Sprint(info["capabilities"])
	if !strings.Contains(caps, "vault-init-v2") || !strings.Contains(caps, "pairing-v2-redeem") {
		t.Fatalf("capabilities missing: %v", info["capabilities"])
	}
	// 就绪后：明文仍被既有 E2EE 机制拒绝，LSE3 密文可写
	if r, _ := e.putFileIn(t, alice, vault, "a.md", []byte("plaintext")); r.StatusCode != http.StatusConflict {
		t.Fatalf("plaintext into encrypted vault = %d, want 409", r.StatusCode)
	}
	if r, b := e.putFileIn(t, alice, vault, "a.md", lse3Payload(1, 1, "ok")); r.StatusCode != http.StatusOK {
		t.Fatalf("LSE3 write after ready = %d %v", r.StatusCode, b)
	}
	// 非空仓库不能再走初始化（即使有人伪造 pending 状态也不行，见 db 层）
}

// v1 兼容（ADR-012 §7）：0.19 插件经 POST /api/v1/vaults 建库 → pending；
// 它的既有序列 PUT vault-key → e2ee begin → complete 推进到 ready。
func TestV1CreateVaultCompatPath(t *testing.T) {
	e := newPublicTestEnv(t)
	alice, _, _ := registerUser(t, e, adminCreateInvite(t, e), "alice")
	r, b := e.call(t, http.MethodPost, "/api/v1/vaults", alice, "", map[string]any{"name": "旧插件建的库"})
	if r.StatusCode != http.StatusOK {
		t.Fatalf("v1 create = %d %v", r.StatusCode, b)
	}
	vault := b["id"].(string)
	state := func() string {
		_, list := e.call(t, http.MethodGet, "/api/v1/vaults", alice, "", nil)
		for _, v := range list["vaults"].([]any) {
			if m := v.(map[string]any); m["id"] == vault {
				return m["initState"].(string)
			}
		}
		return ""
	}
	if s := state(); s != "pending_encryption" {
		t.Fatalf("v1-created vault in public mode = %q, want pending_encryption", s)
	}
	if r, b := e.putFileIn(t, alice, vault, "x.md", []byte("plain")); r.StatusCode != http.StatusConflict || b["code"] != "VAULT_NOT_READY" {
		t.Fatalf("plaintext write before init = %d %v", r.StatusCode, b)
	}
	doc := testKeyDoc(600000)
	doc["enabled"] = false // 0.19 插件先存未启用的文档，最后 CAS 置 enabled
	if r, b := e.call(t, http.MethodPut, "/api/v1/vault-key", alice, vault, doc); r.StatusCode != http.StatusOK {
		t.Fatalf("v1 put vault-key = %d %v", r.StatusCode, b)
	}
	for _, step := range []string{"begin", "complete"} {
		if r, b := e.call(t, http.MethodPost, "/api/v1/e2ee/"+step, alice, vault, nil); r.StatusCode != http.StatusOK {
			t.Fatalf("e2ee %s = %d %v", step, r.StatusCode, b)
		}
	}
	if s := state(); s != "ready" {
		t.Fatalf("after v1 e2ee sequence init = %q, want ready", s)
	}
	if r, b := e.putFileIn(t, alice, vault, "x.md", lse3Payload(1, 1, "x")); r.StatusCode != http.StatusOK {
		t.Fatalf("encrypted write after v1 init = %d %v", r.StatusCode, b)
	}
	// 旧仓库（注册时建的默认库）不受影响：一直是 ready
	_, list := e.call(t, http.MethodGet, "/api/v1/vaults", alice, "", nil)
	for _, v := range list["vaults"].([]any) {
		if m := v.(map[string]any); m["id"] != vault && m["initState"] != "ready" {
			t.Fatalf("pre-existing vault changed state: %v", m)
		}
	}
}

func grant(t *testing.T, e *testEnv, bearer, vault string) map[string]any {
	t.Helper()
	r, b := e.call(t, http.MethodPost, "/api/v2/vaults/"+vault+"/pairing-grants", bearer, "", nil)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("pairing grant = %d %v", r.StatusCode, b)
	}
	return b
}

func uploadPairing(t *testing.T, e *testEnv, bearer, vault, grantID string) string {
	t.Helper()
	r, b := e.call(t, http.MethodPost, "/api/v2/pairings", bearer, vault, map[string]any{"grantId": grantID, "ciphertext": "Y2lwaGVydGV4dA=="})
	if r.StatusCode != http.StatusOK {
		t.Fatalf("upload pairing = %d %v", r.StatusCode, b)
	}
	return b["pairId"].(string)
}

func redeem(t *testing.T, e *testEnv, secret, exchange, expected string) (int, map[string]any) {
	t.Helper()
	r, b := e.call(t, http.MethodPost, "/api/v2/device-enrollments/redeem", "", "", map[string]any{
		"enrollmentSecret": secret, "exchangeId": exchange, "expectedVaultId": expected,
		"device": map[string]any{"name": "我的手机", "platform": "ios", "clientVersion": "0.20.0"},
	})
	return r.StatusCode, b
}

func envelopeStatus(t *testing.T, e *testEnv, pairID string) int {
	t.Helper()
	r, _ := e.call(t, http.MethodGet, "/api/v2/pairings/"+pairID+"/envelope", "", "", nil)
	return r.StatusCode
}

func TestPairingV2IssueEnvelopeRedeem(t *testing.T) {
	e := newPublicTestEnv(t)
	alice, _, _ := registerUser(t, e, adminCreateInvite(t, e), "alice")
	bob, _, _ := registerUser(t, e, adminCreateInvite(t, e), "bob")
	vault := createReadyVault(t, e, alice, "个人笔记")

	g := grant(t, e, alice, vault)
	gv := g["vault"].(map[string]any)
	if gv["vaultId"] != vault || gv["displayName"] != "个人笔记" || g["accountLabel"] == "" {
		t.Fatalf("grant must describe the bound vault for confirmation: %v", g)
	}
	if g["trust"].(map[string]any)["mode"] != "new_vault_genesis" {
		t.Fatalf("a fresh vault grant must say new_vault_genesis (never verified_transfer): %v", g["trust"])
	}
	secret := g["enrollmentSecret"].(string)
	// Bob 不能把配对包挂到 Alice 的 grant 上
	if r, _ := e.call(t, http.MethodPost, "/api/v2/pairings", bob, "", map[string]any{"grantId": g["grantId"], "ciphertext": "eA=="}); r.StatusCode != http.StatusNotFound {
		t.Fatalf("bob attaching a pairing to alice's grant = %d, want 404", r.StatusCode)
	}
	pairID := uploadPairing(t, e, alice, vault, g["grantId"].(string))

	// PR-03：落地页、预取、刷新都不消费
	for i := 0; i < 3; i++ {
		if code := envelopeStatus(t, e, pairID); code != http.StatusOK {
			t.Fatalf("envelope read #%d = %d (must not consume)", i, code)
		}
	}
	if r, _ := http.Get(e.ts.URL + "/p/" + pairID); r.StatusCode != http.StatusOK {
		t.Fatalf("landing page = %d", r.StatusCode)
	}
	// 兑换时声称的仓库不符 → 拒绝且不消费
	if code, b := redeem(t, e, secret, "exch_wrongvault_0001", "u-someone-else"); code != http.StatusConflict || b["code"] != "VAULT_MISMATCH" {
		t.Fatalf("redeem with wrong expectedVaultId = %d %v", code, b)
	}
	if code := envelopeStatus(t, e, pairID); code != http.StatusOK {
		t.Fatal("a VAULT_MISMATCH redeem must not consume the pairing")
	}

	code, first := redeem(t, e, secret, "exch_first_000000001", vault)
	if code != http.StatusOK || first["vaultId"] != vault || first["requiresVaultUnlock"] != true || first["replayed"] != false {
		t.Fatalf("redeem = %d %v", code, first)
	}
	cred := first["deviceCredential"].(string)
	// 新设备绑定在这个仓库：伪造 X-Vault-ID 也到不了别处
	if r, info := e.call(t, http.MethodGet, "/api/v1/info", cred, "u-whatever", nil); r.StatusCode != http.StatusOK || info["vaultId"] != gv["vaultIdentity"] {
		t.Fatalf("redeemed device info = %d %v", r.StatusCode, info)
	}
	// PR-04：成功但响应丢失 → 同 exchangeId 重试拿到同一份结果
	code, again := redeem(t, e, secret, "exch_first_000000001", vault)
	if code != http.StatusOK || again["deviceId"] != first["deviceId"] || again["deviceCredential"] != cred || again["replayed"] != true {
		t.Fatalf("redeem replay = %d %v", code, again)
	}
	// 不同 exchangeId 再兑换 → 已使用；只知道 exchangeId 而没有 secret → 404
	if code, b := redeem(t, e, secret, "exch_second_00000002", vault); code != http.StatusGone || b["code"] != "PAIRING_USED" {
		t.Fatalf("second redeem = %d %v", code, b)
	}
	if code, _ := redeem(t, e, strings.Repeat("0", 64), "exch_first_000000001", vault); code != http.StatusNotFound {
		t.Fatalf("redeem with exchangeId but wrong secret = %d, want 404", code)
	}
	if code := envelopeStatus(t, e, pairID); code != http.StatusNotFound {
		t.Fatalf("envelope after redeem = %d, want 404", code)
	}

	// 撤销：Bob 撤不掉，Alice 撤销后 envelope 404、兑换 410 REVOKED
	g2 := grant(t, e, alice, vault)
	p2 := uploadPairing(t, e, alice, vault, g2["grantId"].(string))
	e.call(t, http.MethodDelete, "/api/v2/pairings/"+p2, bob, "", nil)
	if code := envelopeStatus(t, e, p2); code != http.StatusOK {
		t.Fatal("bob must not be able to revoke alice's pairing")
	}
	if r, _ := e.call(t, http.MethodDelete, "/api/v2/pairings/"+p2, alice, vault, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("issuer revoke = %d", r.StatusCode)
	}
	if code := envelopeStatus(t, e, p2); code != http.StatusNotFound {
		t.Fatalf("envelope after revoke = %d, want 404", code)
	}
	if code, b := redeem(t, e, g2["enrollmentSecret"].(string), "exch_after_revoke_01", vault); code != http.StatusGone || b["code"] != "PAIRING_REVOKED" {
		t.Fatalf("redeem after revoke = %d %v", code, b)
	}

	// 兑换得到的设备凭据（pairing scope）只能为自己的仓库发行
	if r, _ := e.call(t, http.MethodPost, "/api/v2/vaults/"+vault+"/pairing-grants", cred, "", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("device grant for own vault = %d", r.StatusCode)
	}
	other := createReadyVault(t, e, alice, "工作资料")
	if r, _ := e.call(t, http.MethodPost, "/api/v2/vaults/"+other+"/pairing-grants", cred, "", nil); r.StatusCode != http.StatusNotFound {
		t.Fatalf("device grant for another vault = %d, want 404", r.StatusCode)
	}
	// 未就绪的仓库不能发行配对
	r, b := e.call(t, http.MethodPost, "/api/v2/vaults", alice, "", map[string]any{"name": "未初始化", "clientRequestId": "req_pending_vault_1"})
	if r.StatusCode != http.StatusOK {
		t.Fatalf("create = %d %v", r.StatusCode, b)
	}
	if r, b := e.call(t, http.MethodPost, "/api/v2/vaults/"+b["vaultId"].(string)+"/pairing-grants", alice, "", nil); r.StatusCode != http.StatusConflict || b["code"] != "VAULT_NOT_READY" {
		t.Fatalf("grant for pending vault = %d %v", r.StatusCode, b)
	}
}

// PR-02：并发兑换同一 grant，只有一个成功。
func TestPairingV2ConcurrentRedeem(t *testing.T) {
	e := newPublicTestEnv(t)
	alice, _, _ := registerUser(t, e, adminCreateInvite(t, e), "alice")
	vault := createReadyVault(t, e, alice, "个人笔记")
	g := grant(t, e, alice, vault)
	secret := g["enrollmentSecret"].(string)

	var wg gosync.WaitGroup
	var mu gosync.Mutex
	codes := map[int]int{}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			raw, _ := json.Marshal(map[string]any{"enrollmentSecret": secret, "exchangeId": fmt.Sprintf("exch_concurrent_%04d", i), "expectedVaultId": vault})
			resp, err := http.Post(e.ts.URL+"/api/v2/device-enrollments/redeem", "application/json", bytes.NewReader(raw))
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
			mu.Lock()
			codes[resp.StatusCode]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if codes[http.StatusOK] != 1 || codes[http.StatusGone] != 7 {
		t.Fatalf("concurrent redeem outcome %v, want exactly one 200 and seven 410", codes)
	}
	// 只多出一台设备
	var n int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE vault_id = ?`, vault).Scan(&n); err != nil || n != 1 {
		t.Fatalf("devices created = %d (err %v), want 1", n, err)
	}
}

// 公开端点限流：同一来源短时间大量请求 → 429 + Retry-After。
func TestPairingV2PublicEndpointsRateLimited(t *testing.T) {
	e := newPublicTestEnv(t)
	limited := false
	for i := 0; i < 40 && !limited; i++ {
		r, _ := e.call(t, http.MethodGet, "/api/v2/pairings/"+strings.Repeat("ab", 16)+"/envelope", "", "", nil)
		if r.StatusCode == http.StatusTooManyRequests {
			limited = r.Header.Get("Retry-After") != ""
		}
	}
	if !limited {
		t.Fatal("public pairing endpoints must be rate limited")
	}
	_ = time.Second
}
