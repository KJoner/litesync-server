package api_test

// 用户级配额与限流（v0.20 / 需求 §12；验收 TN-07 的 LiteSync 部分）：
//   - 存储配额在写锁内原子判定，历史计入总量；永久超限 413 QUOTA_EXCEEDED（retryable=false，
//     details 带 kind / limit / used）；响应丢失后的原样重试照常成功；读取与删除不受影响；
//   - 管理员默认不受存储默认值约束；管理员可逐用户覆盖（-1 不限 / 指定值 / 0 回到默认）；
//   - 仓库数配额可配置，409 QUOTA_EXCEEDED（与同名的 409 CONFLICT 区分）；
//   - 按账号限流 429 RATE_LIMITED + Retry-After（retryable=true），不影响其他账号。

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/KJoner/litesync-server/internal/api"
	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

func newQuotaEnv(t *testing.T, svcOpts syncsvc.Options, apiOpts api.Options) *testEnv {
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
	svcOpts.HistoryEnabled = true
	svcOpts.HistoryMaxPerFile = 100
	svc := syncsvc.New(database, store, blobs, shares, svcOpts, logger)
	apiOpts.Token, apiOpts.MaxFileSize, apiOpts.Version, apiOpts.Logger = testToken, 1<<20, "test", logger
	ts := httptest.NewServer(api.New(apiOpts, svc))
	t.Cleanup(ts.Close)
	return &testEnv{ts: ts, svc: svc, db: database}
}

// putAs 以某个凭据上传（带前置 revision），返回状态与响应体。
func putAs(t *testing.T, e *testEnv, bearer, path string, base int64, content []byte) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytes.NewReader(content))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-File-Path", url.PathEscape(path))
	req.Header.Set("X-Base-Revision", strconv.FormatInt(base, 10))
	req.Header.Set("X-Content-Hash", sha256Hex(content))
	req.Header.Set("X-File-Mtime", "1700000000000")
	return e.do(t, req)
}

func registerNamed(t *testing.T, e *testEnv, name string) (token, userID string) {
	t.Helper()
	token, resp, _ := registerUser(t, e, adminCreateInvite(t, e), name)
	if resp.StatusCode != http.StatusOK || token == "" {
		t.Fatalf("register %s = %d", name, resp.StatusCode)
	}
	u, err := e.svc.AuthUserByToken(token)
	if err != nil || u == nil {
		t.Fatalf("lookup %s: %v", name, err)
	}
	return token, u.UserID
}

func assertQuotaExceeded(t *testing.T, resp *http.Response, body map[string]any, status int, kind string, limit, used float64) {
	t.Helper()
	if resp.StatusCode != status || body["code"] != "QUOTA_EXCEEDED" || body["retryable"] != false {
		t.Fatalf("want %d QUOTA_EXCEEDED retryable=false, got %d %v", status, resp.StatusCode, body)
	}
	d, _ := body["details"].(map[string]any)
	if d["kind"] != kind || d["limit"] != limit || d["used"] != used {
		t.Fatalf("quota details = %v, want kind=%s limit=%v used=%v", d, kind, limit, used)
	}
}

func setQuota(t *testing.T, e *testEnv, userID string, bytesQ, vaults int64) {
	t.Helper()
	resp, body := e.doJSON(t, http.MethodPut, "/api/v1/admin/users/"+userID+"/quota", testToken, map[string]any{"bytes": bytesQ, "vaults": vaults})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set quota = %d %v", resp.StatusCode, body)
	}
}

func TestStorageQuotaIsEnforcedPerAccount(t *testing.T) {
	e := newQuotaEnv(t, syncsvc.Options{QuotaBytesPerUser: 100}, api.Options{})
	alice, aliceID := registerNamed(t, e, "alice")

	a60 := bytes.Repeat([]byte("a"), 60)
	if resp, body := putAs(t, e, alice, "a.md", 0, a60); resp.StatusCode != http.StatusOK {
		t.Fatalf("first upload = %d %v", resp.StatusCode, body)
	}
	// 响应丢失后的原样重试：命中幂等短路，照常成功
	if resp, _ := putAs(t, e, alice, "a.md", 0, a60); resp.StatusCode != http.StatusOK {
		t.Fatalf("idempotent retry = %d", resp.StatusCode)
	}
	resp, body := putAs(t, e, alice, "b.md", 0, bytes.Repeat([]byte("b"), 60))
	assertQuotaExceeded(t, resp, body, http.StatusRequestEntityTooLarge, "storage", 100, 60)

	// 覆盖 a.md：旧版本进历史并计入总量 → 60 + 30 = 90
	if resp, body := putAs(t, e, alice, "a.md", 1, bytes.Repeat([]byte("c"), 30)); resp.StatusCode != http.StatusOK {
		t.Fatalf("overwrite = %d %v", resp.StatusCode, body)
	}
	resp, body = putAs(t, e, alice, "c.md", 0, bytes.Repeat([]byte("d"), 20))
	assertQuotaExceeded(t, resp, body, http.StatusRequestEntityTooLarge, "storage", 100, 90)

	// 读取不受影响
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/file?path=a.md", nil)
	req.Header.Set("Authorization", "Bearer "+alice)
	if r, _ := e.do(t, req); r.StatusCode != http.StatusOK {
		t.Fatalf("read while over quota = %d", r.StatusCode)
	}
	// 部署者（管理员）不受默认值约束
	if r, _ := e.upload(t, "admin-big.md", 0, bytes.Repeat([]byte("x"), 500)); r.StatusCode != http.StatusOK {
		t.Fatalf("admin upload under default quota = %d", r.StatusCode)
	}
	// 管理员覆盖：-1 不限 → 可写；0 回到默认 → 再次受限
	setQuota(t, e, aliceID, -1, 0)
	if r, body := putAs(t, e, alice, "c.md", 0, bytes.Repeat([]byte("d"), 20)); r.StatusCode != http.StatusOK {
		t.Fatalf("upload with unlimited override = %d %v", r.StatusCode, body)
	}
	setQuota(t, e, aliceID, 0, 0)
	resp, body = putAs(t, e, alice, "d.md", 0, []byte("e"))
	assertQuotaExceeded(t, resp, body, http.StatusRequestEntityTooLarge, "storage", 100, 110)
	setQuota(t, e, aliceID, 200, 0)
	if r, _ := putAs(t, e, alice, "d.md", 0, []byte("e")); r.StatusCode != http.StatusOK {
		t.Fatalf("upload with raised override = %d", r.StatusCode)
	}

	// 账号页看得到用量与上限
	_, me := e.doJSON(t, http.MethodGet, "/api/v2/me", alice, nil)
	usage, _ := me["usage"].(map[string]any)
	if usage["bytesUsed"] != float64(111) || usage["bytesLimit"] != float64(200) || usage["overrideBytes"] != float64(200) {
		t.Fatalf("/api/v2/me usage = %v", usage)
	}
	// 管理员列表同样带用量
	_, list := e.doJSON(t, http.MethodGet, "/api/v1/admin/users", testToken, nil)
	found := false
	for _, u := range list["users"].([]any) {
		row := u.(map[string]any)
		if row["userId"] == aliceID {
			found = row["usage"].(map[string]any)["bytesUsed"] == float64(111)
		}
	}
	if !found {
		t.Fatalf("admin user list lacks usage for alice: %v", list)
	}
	// 非管理员不能改配额
	if r, _ := e.doJSON(t, http.MethodPut, "/api/v1/admin/users/"+aliceID+"/quota", alice, map[string]any{"bytes": -1, "vaults": -1}); r.StatusCode == http.StatusOK {
		t.Fatal("a regular user must not be able to change quotas")
	}
	// 覆盖值非法 → 400
	if r, _ := e.doJSON(t, http.MethodPut, "/api/v1/admin/users/"+aliceID+"/quota", testToken, map[string]any{"bytes": -5, "vaults": 0}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid override = %d", r.StatusCode)
	}
}

func TestVaultQuotaIsConfigurableAndOverridable(t *testing.T) {
	e := newQuotaEnv(t, syncsvc.Options{QuotaVaultsPerUser: 2}, api.Options{})
	alice, aliceID := registerNamed(t, e, "alice")
	_, me := e.doJSON(t, http.MethodGet, "/api/v2/me", alice, nil)
	have := int(me["usage"].(map[string]any)["vaults"].(float64))
	for i := have; i < 2; i++ {
		if r, body := e.doJSON(t, http.MethodPost, "/api/v1/vaults", alice, map[string]any{"name": "库" + strconv.Itoa(i)}); r.StatusCode != http.StatusOK {
			t.Fatalf("create vault %d = %d %v", i, r.StatusCode, body)
		}
	}
	resp, body := e.doJSON(t, http.MethodPost, "/api/v1/vaults", alice, map[string]any{"name": "超出"})
	assertQuotaExceeded(t, resp, body, http.StatusConflict, "vaults", 2, 2)
	setQuota(t, e, aliceID, 0, 3)
	if r, body := e.doJSON(t, http.MethodPost, "/api/v1/vaults", alice, map[string]any{"name": "超出"}); r.StatusCode != http.StatusOK {
		t.Fatalf("create vault after override = %d %v", r.StatusCode, body)
	}
}

func TestPerAccountRateLimit(t *testing.T) {
	e := newQuotaEnv(t, syncsvc.Options{}, api.Options{RatePerUserPerMin: 60}) // 突发 60
	alice, _ := registerNamed(t, e, "alice")
	bob, _ := registerNamed(t, e, "bob")
	whoami := func(bearer string) (*http.Response, map[string]any) {
		req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/v1/whoami", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		return e.do(t, req)
	}
	start := time.Now()
	for i := 0; i < 60; i++ {
		if r, _ := whoami(alice); r.StatusCode != http.StatusOK {
			t.Fatalf("request %d within burst = %d", i, r.StatusCode)
		}
	}
	// 令牌每秒回补 1 个：慢的数据库（例如 Windows 上的 Docker PG）跑完上面 60 个请求要几秒，
	// 这期间回补的令牌数 ≈ 已用秒数。继续请求直到被限流；多放行的次数不得超过回补上限（+1 容错），
	// 否则就是限流没生效（原来的写法假设 60 个请求在 1 秒内跑完，在慢环境里会误报）
	var resp *http.Response
	var body map[string]any
	extra := 0
	for {
		resp, body = whoami(alice)
		if resp.StatusCode != http.StatusOK || extra > 120 {
			break
		}
		extra++
	}
	if allowed := int(time.Since(start).Seconds()) + 1; extra > allowed {
		t.Fatalf("%d requests beyond the burst were allowed, more than the refill (%d) in %v", extra, allowed, time.Since(start))
	}
	if resp.StatusCode != http.StatusTooManyRequests || body["code"] != "RATE_LIMITED" || body["retryable"] != true || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("over the rate: %d %v Retry-After=%q", resp.StatusCode, body, resp.Header.Get("Retry-After"))
	}
	if d, _ := body["details"].(map[string]any); d["kind"] != "rate" {
		t.Fatalf("rate-limit details = %v", body["details"])
	}
	if r, _ := whoami(bob); r.StatusCode != http.StatusOK {
		t.Fatalf("another account must not be slowed by alice: %d", r.StatusCode)
	}
}
