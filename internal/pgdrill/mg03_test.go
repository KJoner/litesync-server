// Package pgdrill 是批次 G 的离线迁移演练（验收 MG-03）：只有测试文件。
//
// 流程：在 **SQLite** 上用真实 HTTP 接口造一个合成库（多用户、多仓库、历史、墓碑、
// LSM1 元数据加密仓库、设备、签名 checkpoint、v2 初始化状态、配对、外部身份映射、
// 邮件 outbox）→ 只读 dry-run → 导入一个全新的 PostgreSQL → 逐表/每仓库校验 →
// 在 PG 上启动服务（同一个 Blob 数据目录）→ 用同一套接口重新读一遍，与迁移前逐项比对
// （快照、changes 游标、info 世代、历史、内容字节、checkpoint、设备、配对状态）→
// 读写与越权抽查 → 记录实际耗时（不预写 RTO）。
//
// 需要 LITESYNC_TEST_PG_DSN（目标 PG；用其中一个全新 schema，结束时删除）。
// 可选：LITESYNC_MG03_FILES（每个仓库的文件数，默认 30）、LITESYNC_MG03_REPORT（JSON 报告路径）、
// LITESYNC_MG03_DATA_DIR（把合成的 SQLite 数据目录留下，供真实 obsync 二进制做 CLI 演练）、
// LITESYNC_MG03_TOKENS（导出合成凭据与迁移前视图，CLI 演练对照用）。
// 覆盖：INV-05（fileId / revision / generation / repo_epoch 迁移前后逐项相同）、
// INV-06（墓碑迁移后仍挡住旧 baseRevision 的重新上传）、INV-08（越权抽查：跨租户读写一律拒绝）、
// INV-11（迁移只读源库、目标非空拒绝、已完成只校验）、INV-12（v2 初始化状态原样保留）。
package pgdrill_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KJoner/litesync-server/internal/api"
	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

const rootToken = "mg03-root-token-0123456789abcdef0123456789"

// ---------------------------------------------------------------- 服务与 HTTP

type server struct{ ts *httptest.Server }

func startServer(t *testing.T, database *sql.DB, dataDir string) *server {
	t.Helper()
	store, err := storage.New(filepath.Join(dataDir, "vaults"))
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := storage.NewBlobStore(filepath.Join(dataDir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	shares, err := storage.NewShareStore(filepath.Join(dataDir, "shares"))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := syncsvc.New(database, store, blobs, shares, syncsvc.Options{HistoryEnabled: true, HistoryMaxPerFile: 100}, logger)
	if err := svc.InitVaultSecret(); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(api.New(api.Options{
		Token: rootToken, MaxFileSize: 4 << 20, Version: "mg03", Logger: logger, RequireE2EENewVaults: true,
	}, svc))
	t.Cleanup(ts.Close)
	return &server{ts: ts}
}

type resp struct {
	code int
	body map[string]any
	raw  []byte
}

func (s *server) do(t *testing.T, method, path, bearer, vault string, body []byte, hdr map[string]string) resp {
	t.Helper()
	req, _ := http.NewRequest(method, s.ts.URL+path, bytes.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if vault != "" {
		req.Header.Set("X-Vault-ID", vault)
	}
	if body != nil && hdr["Content-Type"] == "" && method != http.MethodPut {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer r.Body.Close()
	raw, _ := io.ReadAll(r.Body)
	var m map[string]any
	json.Unmarshal(raw, &m) //nolint:errcheck
	return resp{r.StatusCode, m, raw}
}

func (s *server) json(t *testing.T, method, path, bearer, vault string, body any) resp {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	} else if method != http.MethodGet {
		raw = []byte("{}")
	}
	return s.do(t, method, path, bearer, vault, raw, nil)
}

func (s *server) must(t *testing.T, r resp, what string) resp {
	t.Helper()
	if r.code != http.StatusOK {
		t.Fatalf("%s = %d %s", what, r.code, r.raw)
	}
	return r
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func lse3(gen uint64, tail string) []byte {
	out := []byte{'L', 'S', 'E', '3'}
	out = binary.BigEndian.AppendUint32(out, 1)
	out = binary.BigEndian.AppendUint64(out, gen)
	return append(out, []byte("iv-and-ciphertext-"+tail)...)
}

func (s *server) put(t *testing.T, bearer, vault, path string, base int64, content []byte, extra map[string]string) resp {
	t.Helper()
	hdr := map[string]string{
		"X-File-Path": url.PathEscape(path), "X-Base-Revision": strconv.FormatInt(base, 10),
		"X-Content-Hash": sha(content), "X-File-Mtime": "1700000000000",
	}
	for k, v := range extra {
		hdr[k] = v
	}
	return s.do(t, http.MethodPut, "/api/v1/file", bearer, vault, content, hdr)
}

func (s *server) del(t *testing.T, bearer, vault, path string, base int64) resp {
	t.Helper()
	return s.json(t, http.MethodDelete, "/api/v1/file", bearer, vault, map[string]any{"path": path, "baseRevision": base})
}

// ---------------------------------------------------------------- 一个租户视角的「可观察状态」

type principal struct {
	name, token, vault string
	historyPaths       []string
}

// view 是迁移前后必须**逐项相同**的东西：协议层能看到的全部身份与世代。
type view struct {
	Info      map[string]any            `json:"info"`
	Snapshot  map[string]map[string]any `json:"snapshot"`
	Changes   []map[string]any          `json:"changes"`
	History   map[string]int            `json:"history"`
	Contents  map[string]string         `json:"contents"` // path → sha256(下载字节)
	VaultList []string                  `json:"vaultList"`
}

func (s *server) observe(t *testing.T, p principal) view {
	t.Helper()
	v := view{Snapshot: map[string]map[string]any{}, History: map[string]int{}, Contents: map[string]string{}}
	info := s.must(t, s.json(t, http.MethodGet, "/api/v1/info", p.token, p.vault, nil), p.name+" info").body
	v.Info = map[string]any{}
	for _, k := range []string{"repoEpoch", "headSequence", "formatEpoch", "keyEpoch", "minimumEnvelopeVersion", "encryptionState", "metaState", "vaultId"} {
		v.Info[k] = info[k]
	}
	snap := s.must(t, s.json(t, http.MethodGet, "/api/v1/snapshot", p.token, p.vault, nil), p.name+" snapshot").body
	files, _ := snap["files"].([]any)
	for _, f := range files {
		m := f.(map[string]any)
		delete(m, "mtime") // mtime 是客户端提供的展示值，比较身份与世代即可
		v.Snapshot[m["path"].(string)] = m
	}
	for since := 0.0; ; {
		ch := s.must(t, s.json(t, http.MethodGet, fmt.Sprintf("/api/v1/changes?since=%d&limit=2000", int64(since)), p.token, p.vault, nil), p.name+" changes").body
		list, _ := ch["changes"].([]any)
		for _, c := range list {
			m := c.(map[string]any)
			v.Changes = append(v.Changes, m)
			since = m["sequence"].(float64)
		}
		if ch["hasMore"] != true || len(list) == 0 {
			if ch["resyncRequired"] == true {
				v.Changes = append(v.Changes, map[string]any{"resyncRequired": true, "minSequence": ch["minSequence"]})
			}
			break
		}
	}
	for path := range v.Snapshot {
		r := s.do(t, http.MethodGet, "/api/v1/file?path="+url.QueryEscape(path), p.token, p.vault, nil, nil)
		if r.code != http.StatusOK {
			t.Fatalf("%s download %s = %d", p.name, path, r.code)
		}
		v.Contents[path] = sha(r.raw)
	}
	for _, path := range p.historyPaths {
		h := s.must(t, s.json(t, http.MethodGet, "/api/v1/history?path="+url.QueryEscape(path), p.token, p.vault, nil), p.name+" history").body
		vs, _ := h["versions"].([]any)
		v.History[path] = len(vs)
	}
	vl := s.json(t, http.MethodGet, "/api/v1/vaults", p.token, "", nil).body
	if arr, ok := vl["vaults"].([]any); ok {
		for _, x := range arr {
			if m, ok := x.(map[string]any); ok {
				v.VaultList = append(v.VaultList, fmt.Sprint(m["id"], "/", m["initState"]))
			}
		}
	}
	sort.Strings(v.VaultList)
	return v
}

// ---------------------------------------------------------------- 夹具

type fixture struct {
	principals []principal
	devToken   string
	checkpoint string
	pairID     string
	aliceID    string
	pendingVlt string
	deleted    map[string]string // principal → 一个被删除的路径（旧 baseRevision = 1）
}

func filesPerVault() int {
	if n, err := strconv.Atoi(os.Getenv("LITESYNC_MG03_FILES")); err == nil && n > 0 {
		return n
	}
	return 30
}

func seed(t *testing.T, s *server, srcDB *sql.DB) *fixture {
	t.Helper()
	n := filesPerVault()
	fx := &fixture{deleted: map[string]string{}}

	// ---- 管理员默认仓库：LSE3 内容 + 历史 + 删除 → 再迁成 LSM1 元数据加密仓库 ----
	var rootHist []string
	for i := 0; i < n; i++ {
		path := fmt.Sprintf("笔记/日记-%03d.md", i)
		s.must(t, s.put(t, rootToken, "", path, 0, lse3(1, fmt.Sprintf("root-%d-v1", i)), nil), "root put")
		if i%3 == 0 {
			s.must(t, s.put(t, rootToken, "", path, 1, lse3(2, fmt.Sprintf("root-%d-v2", i)), nil), "root put v2")
			s.must(t, s.put(t, rootToken, "", path, 2, lse3(3, fmt.Sprintf("root-%d-v3", i)), nil), "root put v3")
			if len(rootHist) < 3 && (i-1)%5 != 0 { // 只挑不会被删除的文件看历史
				rootHist = append(rootHist, path)
			}
		}
	}
	for i := 1; i < n; i += 5 {
		base := int64(1)
		if i%3 == 0 {
			base = 3
		}
		s.must(t, s.del(t, rootToken, "", fmt.Sprintf("笔记/日记-%03d.md", i), base), "root delete")
	}
	// E2EE + 信封下限 LSE3 → 元数据迁移 begin → 逐对象 → 墓碑 → verify → complete（擦除）
	s.must(t, s.json(t, http.MethodPost, "/api/v1/e2ee/begin", rootToken, "", nil), "e2ee begin")
	s.must(t, s.json(t, http.MethodPost, "/api/v1/e2ee/complete", rootToken, "", nil), "e2ee complete")
	s.must(t, s.json(t, http.MethodPost, "/api/v1/envelope/complete", rootToken, "", nil), "envelope complete")
	s.must(t, s.json(t, http.MethodPost, "/api/v1/meta/begin", rootToken, "", nil), "meta begin")
	snap := s.must(t, s.json(t, http.MethodGet, "/api/v1/snapshot", rootToken, "", nil), "snapshot").body
	pathToID := map[string]string{}
	for _, f := range snap["files"].([]any) {
		m := f.(map[string]any)
		path := m["path"].(string)
		pathToID[path] = m["fileId"].(string)
		metaEnc := base64.StdEncoding.EncodeToString([]byte("LSM1-fake-meta-" + path))
		s.must(t, s.json(t, http.MethodPost, "/api/v1/meta/migrate", rootToken, "", map[string]any{
			"fromPath": path, "metaEnc": metaEnc, "canonicalHash": sha([]byte("canon:" + path)),
		}), "meta migrate "+path)
	}
	tl := s.must(t, s.json(t, http.MethodGet, "/api/v1/meta/tombstones", rootToken, "", nil), "meta tombstones").body
	var rootDeletedID string
	for _, x := range tl["tombstones"].([]any) {
		id := x.(map[string]any)["fileId"].(string)
		rootDeletedID = id
		s.must(t, s.json(t, http.MethodPost, "/api/v1/meta/migrate-tombstone", rootToken, "", map[string]any{
			"fileId": id, "canonicalHash": sha([]byte("canon-tomb:" + id)),
		}), "migrate tombstone")
	}
	s.must(t, s.json(t, http.MethodPost, "/api/v1/meta/verify", rootToken, "", nil), "meta verify")
	s.must(t, s.json(t, http.MethodPost, "/api/v1/meta/complete", rootToken, "", map[string]any{"confirmErase": true}), "meta complete")
	var rootHistIDs []string
	for _, p := range rootHist {
		rootHistIDs = append(rootHistIDs, pathToID[p])
	}
	fx.principals = append(fx.principals, principal{name: "root(LSM1)", token: rootToken, historyPaths: rootHistIDs})
	fx.deleted["root(LSM1)"] = rootDeletedID

	// ---- 设备 + 签名 checkpoint ----
	dev := s.must(t, s.json(t, http.MethodPost, "/api/v1/devices", rootToken, "", map[string]any{"name": "mg03-laptop"}), "enroll").body
	fx.devToken = dev["deviceToken"].(string)
	s.must(t, s.json(t, http.MethodPost, "/api/v1/devices", rootToken, "", map[string]any{"name": "mg03-phone"}), "enroll 2")
	s.must(t, s.json(t, http.MethodPut, "/api/v1/device/signing-key", fx.devToken, "", map[string]any{"publicKey": "cHVibGljLWtleQ=="}), "signing key")
	info := s.must(t, s.json(t, http.MethodGet, "/api/v1/info", rootToken, "", nil), "info").body
	fx.checkpoint = sha([]byte("mg03-checkpoint"))
	s.must(t, s.json(t, http.MethodPost, "/api/v1/checkpoint", fx.devToken, "", map[string]any{
		"hash": fx.checkpoint, "repoEpoch": info["repoEpoch"], "headSequence": info["headSequence"],
		"body": fmt.Sprintf("v=1\nhead=%v", info["headSequence"]), "signature": "c2ln",
	}), "checkpoint")

	// ---- 多用户：邀请注册 alice / bob，各自建 v2 仓库并初始化 ----
	register := func(name string) string {
		inv := s.must(t, s.json(t, http.MethodPost, "/api/v1/admin/invites", rootToken, "", map[string]any{}), "invite").body
		r := s.must(t, s.json(t, http.MethodPost, "/join/"+inv["secret"].(string)+"/register", "", "", map[string]any{"name": name}), "register "+name)
		return r.body["token"].(string)
	}
	readyVault := func(token, name string) string {
		rid := "req_" + sha([]byte(name))[:32]
		v := s.must(t, s.json(t, http.MethodPost, "/api/v2/vaults", token, "", map[string]any{"name": name, "clientRequestId": rid}), "create v2").body
		id := v["vaultId"].(string)
		op := "op_init_" + sha([]byte("op" + name))[:16]
		s.must(t, s.json(t, http.MethodPost, "/api/v2/vaults/"+id+"/initialization", token, "", map[string]any{"phase": "claim", "opId": op}), "claim")
		b64 := func(n int, fill byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, n)) }
		s.must(t, s.json(t, http.MethodPost, "/api/v2/vaults/"+id+"/initialization", token, "", map[string]any{
			"phase": "commit", "opId": op, "expectedInitVersion": 1,
			"keyDoc": map[string]any{"version": 1, "kdf": "pbkdf2-sha256", "iterations": 600000,
				"salt": b64(16, 1), "iv": b64(12, 2), "wrappedKey": b64(48, 3), "enabled": true, "createdAt": 1795132800000},
			"cryptoProfile": map[string]any{"protocolVersion": 6, "keyDocVersion": 1, "writeEnvelope": "LSE3"},
			"resetAuth":     strings.Repeat("ab", 32),
		}), "commit")
		return id
	}
	alice, bob := register("alice"), register("bob")
	aliceVault := readyVault(alice, "Alice 笔记")
	bobVault := readyVault(bob, "Bob Notes")
	pending := s.must(t, s.json(t, http.MethodPost, "/api/v2/vaults", alice, "", map[string]any{"name": "Alice 待初始化", "clientRequestId": "req_" + sha([]byte("pending"))[:32]}), "pending vault").body
	fx.pendingVlt = pending["vaultId"].(string)

	for _, u := range []struct{ name, token, vault string }{{"alice", alice, aliceVault}, {"bob", bob, bobVault}} {
		var hist []string
		for i := 0; i < n; i++ {
			path := fmt.Sprintf("%s/n%03d.md", u.name, i)
			s.must(t, s.put(t, u.token, u.vault, path, 0, lse3(1, path), nil), u.name+" put")
			if i%4 == 0 {
				s.must(t, s.put(t, u.token, u.vault, path, 1, lse3(2, path+"-v2"), nil), u.name+" put v2")
				if len(hist) < 3 && (i-2)%7 != 0 {
					hist = append(hist, path)
				}
			}
		}
		for i := 2; i < n; i += 7 {
			base := int64(1)
			if i%4 == 0 {
				base = 2
			}
			s.must(t, s.del(t, u.token, u.vault, fmt.Sprintf("%s/n%03d.md", u.name, i), base), u.name+" delete")
		}
		fx.deleted[u.name] = fmt.Sprintf("%s/n%03d.md", u.name, 2)
		fx.principals = append(fx.principals, principal{name: u.name, token: u.token, vault: u.vault, historyPaths: hist})
	}

	// ---- v2 配对（指定仓库） ----
	g := s.must(t, s.json(t, http.MethodPost, "/api/v2/vaults/"+aliceVault+"/pairing-grants", alice, "", nil), "grant").body
	pr := s.must(t, s.json(t, http.MethodPost, "/api/v2/pairings", alice, aliceVault, map[string]any{"grantId": g["grantId"], "ciphertext": "Y2lwaGVydGV4dA=="}), "pairing").body
	fx.pairID = pr["pairId"].(string)

	// ---- 外部身份映射 + 邮件 outbox（直接走 db 层：合成数据） ----
	if err := srcDB.QueryRow(`SELECT user_id FROM users WHERE name = 'alice'`).Scan(&fx.aliceID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if err := db.LinkIdentity(srcDB, "https://idp.example", "sub-alice", fx.aliceID, db.IdentityProfile{Email: "alice@example.com", EmailVerified: true, DisplayName: "Alice"}, now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := db.EnqueueMail(srcDB, fmt.Sprintf("mg03-%d", i), "welcome", fmt.Sprintf("user%d@example.com", i), "欢迎", "正文", now); err != nil {
			t.Fatal(err)
		}
	}
	return fx
}

// ---------------------------------------------------------------- 演练

type drillReport struct {
	FilesPerVault int               `json:"filesPerVault"`
	SeedMs        int64             `json:"seedMs"`
	DryRunMs      int64             `json:"dryRunMs"`
	CopyMs        int64             `json:"copyMs"`
	PostVerifyMs  int64             `json:"postVerifyMs"`
	StartOnPGMs   int64             `json:"startOnPostgresMs"`
	ObserveMs     int64             `json:"observeAndCompareMs"`
	TotalRows     int64             `json:"totalRows"`
	Tables        int               `json:"tables"`
	Vaults        int               `json:"vaults"`
	TableRows     map[string]int64  `json:"tableRows"`
	Checks        map[string]string `json:"checks"`
}

func TestMG03OfflineMigrationDrill(t *testing.T) {
	base := os.Getenv("LITESYNC_TEST_PG_DSN")
	if base == "" {
		t.Skip("未设置 LITESYNC_TEST_PG_DSN：MG-03 离线迁移演练需要真实 PostgreSQL")
	}
	rep := drillReport{FilesPerVault: filesPerVault(), Checks: map[string]string{}, TableRows: map[string]int64{}}
	check := func(name string, ok bool, detail string) {
		if !ok {
			rep.Checks[name] = "FAIL: " + detail
			t.Errorf("%s: %s", name, detail)
			return
		}
		rep.Checks[name] = "ok"
	}

	// ---- 1. 合成 SQLite 源库（真实接口写入） ----
	dataDir := filepath.Join(t.TempDir(), "data")
	// LITESYNC_MG03_DATA_DIR：把合成的 SQLite 数据目录留在指定位置（供 CLI 实机演练：
	// 真实 obsync 二进制跑 migrate-to-pg 并在 PG 上启动），必须是不存在或空的目录
	if keep := os.Getenv("LITESYNC_MG03_DATA_DIR"); keep != "" {
		if entries, _ := os.ReadDir(keep); len(entries) > 0 {
			t.Fatalf("LITESYNC_MG03_DATA_DIR %s must be empty", keep)
		}
		dataDir = keep
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	srcPath := filepath.Join(dataDir, "sync.db")
	src, err := db.OpenSQLiteFile(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close() })
	s1 := startServer(t, src, dataDir)
	t0 := time.Now()
	fx := seed(t, s1, src)
	rep.SeedMs = time.Since(t0).Milliseconds()
	before := map[string]view{}
	for _, p := range fx.principals {
		before[p.name] = s1.observe(t, p)
	}
	if p := os.Getenv("LITESYNC_MG03_TOKENS"); p != "" {
		// 合成数据的凭据与迁移前视图（CLI 实机演练用来对照）；只在显式要求时写出
		type exported struct {
			Name, Token, Vault string
			Info               map[string]any
			SnapshotCount      int
		}
		var list []exported
		for _, p := range fx.principals {
			list = append(list, exported{p.name, p.token, p.vault, before[p.name].Info, len(before[p.name].Snapshot)})
		}
		raw, _ := json.MarshalIndent(list, "", "  ")
		os.WriteFile(p, raw, 0o600) //nolint:errcheck
	}
	cpBefore := s1.json(t, http.MethodGet, "/api/v1/checkpoints?since=0", fx.devToken, "", nil)
	devBefore := s1.json(t, http.MethodGet, "/api/v1/devices", rootToken, "", nil)
	pairBefore := s1.json(t, http.MethodGet, "/api/v2/pairings/"+fx.pairID+"/envelope", "", "", nil).code
	initBefore := s1.json(t, http.MethodGet, "/api/v2/vaults/"+fx.pendingVlt+"/initialization", fx.principals[1].token, "", nil)
	mailBefore, err := db.GetMailStats(src)
	if err != nil {
		t.Fatal(err)
	}
	s1.ts.Close()
	src.Close() // 「冻结写入」：服务停止，源库只读打开

	// ---- 2. dry-run（只读） ----
	ro, err := db.OpenSQLiteReadOnly(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	t1 := time.Now()
	dry, err := db.DryRunCopy(ro)
	rep.DryRunMs = time.Since(t1).Milliseconds()
	if err != nil || !dry.OK {
		t.Fatalf("dry-run: %v %+v", err, dry)
	}
	for _, tr := range dry.Tables {
		rep.TableRows[tr.Table] = tr.SourceRows
	}
	rep.Vaults = len(dry.SourceVaults)
	for _, want := range []string{"file_heads", "object_versions", "tombstones", "object_changes", "checkpoints", "devices", "pairings", "external_identities", "vault_init_ops", "mail_outbox", "vaults", "memberships", "users"} {
		check("synthetic data covers "+want, rep.TableRows[want] > 0, fmt.Sprintf("%s has %d rows", want, rep.TableRows[want]))
	}

	// ---- 3. 导入全新 PG + 校验 ----
	raw := make([]byte, 6)
	rand.Read(raw) //nolint:errcheck
	schema := "mg03_" + hex.EncodeToString(raw)
	admin, err := db.OpenPostgresRaw(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) //nolint:errcheck
		admin.Close()
	})
	dsn := db.WithSearchPath(base, schema)
	dst, err := db.OpenPostgresRaw(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSchemaOnly(dst); err != nil {
		t.Fatal(err)
	}
	t2 := time.Now()
	cp, err := db.CopyDatabase(ro, dst)
	rep.CopyMs = time.Since(t2).Milliseconds()
	if err != nil || !cp.OK {
		t.Fatalf("copy: %v %+v", err, cp.Problems)
	}
	rep.TotalRows, rep.Tables = cp.TotalRows, len(cp.Tables)
	t3 := time.Now()
	post, err := db.VerifyDatabases(ro, dst)
	rep.PostVerifyMs = time.Since(t3).Milliseconds()
	check("post-verify on a fresh source snapshot", err == nil && post.OK, fmt.Sprint(err))
	_, err = db.CopyDatabase(ro, dst)
	check("re-run refuses a non-empty target", err != nil, "second copy was accepted")
	dst.Close()

	// ---- 4. 在 PG 上启动服务（同一个 Blob 目录） ----
	t4 := time.Now()
	pg, err := db.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	s2 := startServer(t, pg, dataDir)
	defer s2.ts.Close()
	rep.StartOnPGMs = time.Since(t4).Milliseconds()

	// ---- 5. 迁移前后逐项比对 ----
	t5 := time.Now()
	for _, p := range fx.principals {
		after := s2.observe(t, p)
		b := before[p.name]
		check(p.name+": info (repoEpoch/head/format/key/envelope)", reflect.DeepEqual(b.Info, after.Info), fmt.Sprintf("%v vs %v", b.Info, after.Info))
		check(p.name+": snapshot identity+generations", reflect.DeepEqual(b.Snapshot, after.Snapshot), fmt.Sprintf("%d vs %d entries", len(b.Snapshot), len(after.Snapshot)))
		check(p.name+": changes feed from 0", reflect.DeepEqual(b.Changes, after.Changes), fmt.Sprintf("%d vs %d", len(b.Changes), len(after.Changes)))
		check(p.name+": content bytes", reflect.DeepEqual(b.Contents, after.Contents), "downloaded bytes differ")
		check(p.name+": history", reflect.DeepEqual(b.History, after.History), fmt.Sprintf("%v vs %v", b.History, after.History))
		check(p.name+": vault list + init states", reflect.DeepEqual(b.VaultList, after.VaultList), fmt.Sprintf("%v vs %v", b.VaultList, after.VaultList))
	}
	rep.ObserveMs = time.Since(t5).Milliseconds()
	cpAfter := s2.json(t, http.MethodGet, "/api/v1/checkpoints?since=0", fx.devToken, "", nil)
	check("signed checkpoints", cpAfter.code == 200 && bytes.Equal(cpBefore.raw, cpAfter.raw) && strings.Contains(string(cpAfter.raw), fx.checkpoint), string(cpAfter.raw))
	devAfter := s2.json(t, http.MethodGet, "/api/v1/devices", rootToken, "", nil)
	check("devices", devAfter.code == 200 && bytes.Equal(devBefore.raw, devAfter.raw), "device list differs")
	check("pairing envelope state", s2.json(t, http.MethodGet, "/api/v2/pairings/"+fx.pairID+"/envelope", "", "", nil).code == pairBefore, "pairing status changed")
	initAfter := s2.json(t, http.MethodGet, "/api/v2/vaults/"+fx.pendingVlt+"/initialization", fx.principals[1].token, "", nil)
	check("v2 init state (pending vault)", initAfter.code == initBefore.code && bytes.Equal(initAfter.raw, initBefore.raw), string(initAfter.raw))
	ident, err := db.GetIdentity(pg, "https://idp.example", "sub-alice")
	check("external identity mapping", err == nil && ident != nil && ident.UserID == fx.aliceID, fmt.Sprint(ident, err))
	mailAfter, err := db.GetMailStats(pg)
	check("mail outbox", err == nil && reflect.DeepEqual(mailBefore, mailAfter), fmt.Sprintf("%+v vs %+v", mailBefore, mailAfter))

	// ---- 6. 唯一约束与幂等在 PG 上照常生效 ----
	err = db.LinkIdentity(pg, "https://idp.example", "sub-alice", "u-someone-else", db.IdentityProfile{}, time.Now().Unix())
	check("unique: identity cannot be re-linked", err == db.ErrIdentityTaken, fmt.Sprint(err))
	inserted, err := db.EnqueueMail(pg, "mg03-0", "welcome", "user0@example.com", "x", "y", time.Now().Unix())
	check("unique: mail idempotency key", err == nil && !inserted, fmt.Sprint(inserted, err))

	// ---- 7. 读写与越权抽查 ----
	alice, bob := fx.principals[1], fx.principals[2]
	head := int64(before[alice.name].Info["headSequence"].(float64))
	r := s2.put(t, alice.token, alice.vault, "alice/after-migration.md", 0, lse3(1, "after"), nil)
	check("write after migration", r.code == http.StatusOK, string(r.raw))
	ch := s2.json(t, http.MethodGet, fmt.Sprintf("/api/v1/changes?since=%d", head), alice.token, alice.vault, nil).body
	list, _ := ch["changes"].([]any)
	okCursor := len(list) == 1 && list[0].(map[string]any)["sequence"].(float64) == float64(head+1)
	check("old cursor continues (sequence head+1, no resync)", okCursor && ch["resyncRequired"] != true, fmt.Sprint(ch))
	r = s2.put(t, alice.token, alice.vault, fx.deleted["alice"], 1, lse3(5, "resurrect"), nil)
	check("tombstone still blocks a stale re-upload", r.code != http.StatusOK, string(r.raw))
	r = s2.put(t, alice.token, alice.vault, "alice/n000.md", 0, lse3(9, "stale"), nil)
	check("stale baseRevision is a conflict, not an overwrite", r.code == http.StatusConflict, fmt.Sprint(r.code, string(r.raw)))
	for _, probe := range []struct {
		name string
		r    resp
	}{
		{"alice reads bob's snapshot", s2.json(t, http.MethodGet, "/api/v1/snapshot", alice.token, bob.vault, nil)},
		{"bob reads alice's file", s2.do(t, http.MethodGet, "/api/v1/file?path="+url.QueryEscape("alice/n001.md"), bob.token, alice.vault, nil, nil)},
		{"bob writes into alice's vault", s2.put(t, bob.token, alice.vault, "intrusion.md", 0, lse3(1, "x"), nil)},
		{"alice reads the admin vault", s2.json(t, http.MethodGet, "/api/v1/snapshot", alice.token, db.DefaultVaultID, nil)},
	} {
		check("cross-tenant: "+probe.name, probe.r.code == http.StatusForbidden || probe.r.code == http.StatusNotFound, fmt.Sprint(probe.r.code))
	}
	bobList := s2.json(t, http.MethodGet, "/api/v1/vaults", bob.token, "", nil)
	check("cross-tenant: bob's vault list has no alice vault", !strings.Contains(string(bobList.raw), alice.vault), string(bobList.raw))

	out, _ := json.MarshalIndent(rep, "", "  ")
	t.Logf("MG-03 演练报告：\n%s", out)
	if p := os.Getenv("LITESYNC_MG03_REPORT"); p != "" {
		os.WriteFile(p, out, 0o600) //nolint:errcheck
	}
}
