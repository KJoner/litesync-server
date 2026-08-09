package backup

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	gosync "sync"
	"testing"
	"time"

	"obsync/internal/db"
)

// ---------- crypto ----------

func TestKeyCreateAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup-config.key")
	k1, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(k1) != 32 {
		t.Fatalf("key len = %d", len(k1))
	}
	k2, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(k1) != string(k2) {
		t.Fatal("reloaded key differs")
	}
}

func TestKeyRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.key")
	os.WriteFile(path, []byte("not-hex"), 0o600) //nolint:errcheck
	if _, err := LoadOrCreateKey(path); err == nil {
		t.Fatal("expected error for garbage key file")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	enc, err := seal(key, []byte("secret-payload"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := open(key, enc)
	if err != nil || string(got) != "secret-payload" {
		t.Fatalf("round trip failed: %v %q", err, got)
	}
	// 篡改必须失败
	tampered := []byte(enc)
	tampered[len(tampered)-5] ^= 'x'
	if _, err := open(key, string(tampered)); err == nil {
		t.Fatal("tampered ciphertext must not decrypt")
	}
	// 错误密钥必须失败
	other := make([]byte, 32)
	other[0] = 1
	if _, err := open(other, enc); err == nil {
		t.Fatal("wrong key must not decrypt")
	}
}

// ---------- config ----------

func fullUpdate() Update {
	enabled := false
	acc, bucket := "acct123", "litesync-backup"
	ak, sk, rp := "AKIA_TEST", "s3cret-key", "restic-pw"
	return Update{
		Enabled: &enabled, AccountID: &acc, Bucket: &bucket,
		AccessKeyID: &ak, SecretAccessKey: &sk, ResticPassword: &rp,
	}
}

func TestConfigApplyKeepsSecretsWhenEmpty(t *testing.T) {
	cfg := defaultConfig()
	cfg, err := cfg.apply(fullUpdate())
	if err != nil {
		t.Fatal(err)
	}
	empty := ""
	next, err := cfg.apply(Update{SecretAccessKey: &empty, ResticPassword: &empty})
	if err != nil {
		t.Fatal(err)
	}
	if next.SecretAccessKey != "s3cret-key" || next.ResticPassword != "restic-pw" {
		t.Fatalf("empty secret must keep old value, got %+v", next)
	}
}

func TestConfigEnableRequiresCredentials(t *testing.T) {
	enabled := true
	if _, err := defaultConfig().apply(Update{Enabled: &enabled}); err == nil {
		t.Fatal("enable without credentials must fail")
	}
}

func TestViewNeverContainsSecrets(t *testing.T) {
	cfg, _ := defaultConfig().apply(fullUpdate())
	raw, err := json.Marshal(cfg.view())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"s3cret-key", "restic-pw"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("view leaked secret %q: %s", secret, raw)
		}
	}
	var v View
	json.Unmarshal(raw, &v) //nolint:errcheck
	if !v.SecretKeyConfigured || !v.ResticPasswordConfigured {
		t.Fatalf("configured flags wrong: %+v", v)
	}
}

func TestRepositoryURL(t *testing.T) {
	cfg, _ := defaultConfig().apply(fullUpdate())
	want := "s3:https://acct123.r2.cloudflarestorage.com/litesync-backup/restic"
	if got := cfg.repository(); got != want {
		t.Fatalf("repository = %q, want %q", got, want)
	}
	ep := "https://minio.local:9000"
	cfg2, _ := cfg.apply(Update{Endpoint: &ep})
	if got := cfg2.repository(); got != "s3:https://minio.local:9000/litesync-backup/restic" {
		t.Fatalf("custom endpoint repository = %q", got)
	}
}

// ---------- runner helpers ----------

func TestRedact(t *testing.T) {
	out := redact("error: key s3cret-key rejected", []string{"s3cret-key", ""})
	if strings.Contains(out, "s3cret-key") {
		t.Fatalf("redact failed: %s", out)
	}
}

// ---------- manager（fake runner） ----------

type call struct {
	args []string
	env  map[string]string
}

type fakeRunner struct {
	mu      gosync.Mutex
	calls   []call
	results map[string]string // 首个 arg → stdout
	errs    map[string]error  // 首个 arg → err
	block   chan struct{}     // 非 nil 时 backup 调用阻塞直到关闭
}

func (f *fakeRunner) Run(_ context.Context, args []string, env map[string]string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, call{args: args, env: env})
	block := f.block
	f.mu.Unlock()
	if block != nil && args[0] == "backup" {
		<-block
	}
	if err, ok := f.errs[args[0]]; ok {
		return nil, err
	}
	return []byte(f.results[args[0]]), nil
}

func (f *fakeRunner) callsFor(op string) []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []call
	for _, c := range f.calls {
		if c.args[0] == op {
			out = append(out, c)
		}
	}
	return out
}

type fakeQuiescer struct{}

func (fakeQuiescer) WithGlobalLock(fn func() error) error { return fn() }
func (fakeQuiescer) LatestSequence() (int64, error)       { return 42, nil }

const backupSummary = `{"message_type":"status","percent_done":1}
{"message_type":"summary","snapshot_id":"abc123","files_new":3,"files_changed":1,"data_added":1024,"total_duration":1.5}`

func newTestManager(t *testing.T, runner Runner) (*Manager, string) {
	t.Helper()
	dataDir := t.TempDir()
	database, err := db.Open(filepath.Join(dataDir, "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	// 造一点数据：blobs 目录 + shares 目录
	blobDir := filepath.Join(dataDir, "blobs", "ab")
	os.MkdirAll(blobDir, 0o700)                                                       //nolint:errcheck
	os.WriteFile(filepath.Join(blobDir, strings.Repeat("ab", 32)), []byte("x"), 0o600) //nolint:errcheck

	keyFile := filepath.Join(t.TempDir(), "backup-config.key") // /data 之外
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := New(database, fakeQuiescer{}, runner, dataDir, "test", keyFile, logger)
	if m.Status().KeyAvailable != true {
		t.Fatalf("key should be available: %+v", m.Status())
	}
	if _, err := m.SetConfig(fullUpdate()); err != nil {
		t.Fatalf("set config: %v", err)
	}
	return m, dataDir
}

func TestManagerBackupFlow(t *testing.T) {
	runner := &fakeRunner{results: map[string]string{
		"version":   "restic 0.17.3 compiled with go1.22",
		"backup":    backupSummary,
		"snapshots": `[{"id":"abc123","short_id":"abc","time":"2026-08-09T00:00:00Z"}]`,
		"stats":     `{"total_size":2048}`,
	}}
	m, dataDir := newTestManager(t, runner)

	res, err := m.Backup(context.Background(), "test")
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if res.SnapshotID != "abc123" || res.DataAdded != 1024 {
		t.Fatalf("bad result: %+v", res)
	}

	// staging 备份后必须被清理
	if _, err := os.Stat(filepath.Join(dataDir, ".backup-staging")); !os.IsNotExist(err) {
		t.Fatal("staging must be cleaned after backup")
	}

	// 校验 restic 调用：凭据只在 env、绝不在 args；备份路径固定（forget 分组稳定）
	bcalls := runner.callsFor("backup")
	if len(bcalls) != 1 {
		t.Fatalf("backup calls = %d", len(bcalls))
	}
	c := bcalls[0]
	joined := strings.Join(c.args, " ")
	for _, secret := range []string{"s3cret-key", "restic-pw", "AKIA_TEST"} {
		if strings.Contains(joined, secret) {
			t.Fatalf("secret leaked into args: %s", joined)
		}
	}
	if c.env["RESTIC_PASSWORD"] != "restic-pw" || c.env["AWS_SECRET_ACCESS_KEY"] != "s3cret-key" {
		t.Fatalf("env missing credentials: %+v", c.env)
	}
	if !strings.Contains(joined, "--host litesync") {
		t.Fatalf("backup must pin --host: %s", joined)
	}
	if !strings.Contains(joined, filepath.Join(".backup-staging", "current")) {
		t.Fatalf("backup must target fixed staging dir: %s", joined)
	}

	st := m.Status()
	if st.LastSnapshotID != "abc123" || st.LastError != "" || st.SnapshotCount != 1 || st.RepositorySize != 2048 {
		t.Fatalf("status not updated: %+v", st)
	}
}

func TestManagerStagingContent(t *testing.T) {
	// 用一个在 backup 阶段失败的 runner 中断流程没法检查 staging（已清理），
	// 所以直接调 buildStaging 验证内容。
	runner := &fakeRunner{results: map[string]string{"version": "restic 0.17.3"}}
	m, dataDir := newTestManager(t, runner)

	staging, err := buildStaging(m.db, fakeQuiescer{}, dataDir, "test")
	if err != nil {
		t.Fatalf("build staging: %v", err)
	}
	defer cleanStaging(dataDir)

	for _, want := range []string{
		"sync.db",
		"backup-manifest.json",
		filepath.Join("blobs", "ab", strings.Repeat("ab", 32)),
	} {
		if _, err := os.Stat(filepath.Join(staging, want)); err != nil {
			t.Fatalf("staging missing %s: %v", want, err)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(staging, "backup-manifest.json")) //nolint:errcheck
	var mf Manifest
	if err := json.Unmarshal(raw, &mf); err != nil {
		t.Fatal(err)
	}
	if mf.Format != 1 || mf.LatestSequence != 42 || mf.LitesyncVersion != "test" {
		t.Fatalf("bad manifest: %+v", mf)
	}
	// manifest 绝不能包含 secrets
	for _, secret := range []string{"s3cret-key", "restic-pw"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("manifest leaked secret")
		}
	}
	// staging 的 sync.db 是可独立打开的一致快照
	sdb, err := db.Open(filepath.Join(staging, "sync.db"))
	if err != nil {
		t.Fatalf("staged sync.db unreadable: %v", err)
	}
	sdb.Close()
}

func TestManagerSingleJob(t *testing.T) {
	block := make(chan struct{})
	runner := &fakeRunner{
		block:   block,
		results: map[string]string{"version": "restic 0.17.3", "backup": backupSummary},
	}
	m, _ := newTestManager(t, runner)

	done := make(chan error, 1)
	go func() {
		_, err := m.Backup(context.Background(), "bg")
		done <- err
	}()
	// 等第一个任务真正进入 restic backup
	deadline := time.Now().Add(5 * time.Second)
	for len(runner.callsFor("backup")) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("first backup never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := m.Backup(context.Background(), "again"); err != ErrJobRunning {
		t.Fatalf("second backup should be rejected, got %v", err)
	}
	if err := m.Check(context.Background()); err != ErrJobRunning {
		t.Fatalf("check during backup should be rejected, got %v", err)
	}
	close(block)
	if err := <-done; err != nil {
		t.Fatalf("first backup failed: %v", err)
	}
}

func TestManagerTestClassifiesRepoMissing(t *testing.T) {
	runner := &fakeRunner{
		results: map[string]string{"version": "restic 0.17.3"},
		errs:    map[string]error{"cat": errFromRestic("Fatal: repository does not exist: unable to open config file")},
	}
	m, _ := newTestManager(t, runner)
	if err := m.Test(context.Background()); err != ErrRepoNotInitialized {
		t.Fatalf("want ErrRepoNotInitialized, got %v", err)
	}
}

func TestManagerConfigPersistsEncrypted(t *testing.T) {
	runner := &fakeRunner{results: map[string]string{"version": "restic 0.17.3"}}
	m, _ := newTestManager(t, runner)

	// 数据库中的配置必须是密文：任何 secret 都不能以明文出现
	enc, ok, err := db.GetMeta(m.db, configMetaKey)
	if err != nil || !ok {
		t.Fatalf("config not persisted: %v", err)
	}
	for _, secret := range []string{"s3cret-key", "restic-pw", "AKIA_TEST", "acct123"} {
		if strings.Contains(enc, secret) {
			t.Fatalf("vault_meta stores plaintext secret %q", secret)
		}
	}
	// status 明文 JSON 也不能包含 secret
	if raw, ok, _ := db.GetMeta(m.db, statusMetaKey); ok { //nolint:errcheck
		for _, secret := range []string{"s3cret-key", "restic-pw"} {
			if strings.Contains(raw, secret) {
				t.Fatal("backup-status leaked secret")
			}
		}
	}
}

func TestNextBoundary(t *testing.T) {
	now := time.Date(2026, 8, 9, 7, 30, 0, 0, time.UTC)
	next := nextBoundary(now)
	if next != time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC) {
		t.Fatalf("next boundary = %v", next)
	}
}

type resticErr string

func (e resticErr) Error() string { return string(e) }

func errFromRestic(msg string) error { return resticErr(msg) }
