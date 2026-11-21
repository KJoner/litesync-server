package backup_test

// 灾备恢复实机演练 · PostgreSQL 分支（批次 G / 验收 MG-04 PG 分支 / ADR-007）。
//
// PG 数据 → 备份（真 restic + 真本地仓库，元数据走只读快照事务导出）→ 恢复到一个
// **全新的、空的** PG 库 → 在恢复出的库上启动服务 → 从「恢复前离线的旧设备」视角检查：
//   - repoEpoch 已旋转，changes 响应里带的是新 epoch（按协议的客户端据此进入灾备合并）；
//   - 带旧 epoch 的写入被拒（REPO_EPOCH_MISMATCH），带新 epoch 的写入通过；
//   - 备份点之前的删除不复活：墓碑仍挡住旧 baseRevision 的重新上传；
//   - 备份点之后的变更在服务器上不存在（旧设备在灾备合并里把它们补回来，不会被静默丢弃）；
//   - 元数据引用的 blob 全部在位（缺失会被明确报告，另一条用例注入缺失验证报告）。
//
// 需要：restic、LITESYNC_TEST_PG_DSN（源库）。恢复目标优先用 LITESYNC_TEST_PG_RESTORE_DSN
//（第二个 PG 实例 = 「新实例」），未设置时在源实例里建一个全新 schema。
// 覆盖：INV-02（世代单调：恢复后 epoch 前进、旧 epoch 写入被拒）、INV-06（墓碑在恢复后仍生效）、
// INV-11（恢复可重复：目标非空拒绝、失败不动现场）。

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
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
	"strings"
	"testing"
	"time"

	"github.com/KJoner/litesync-server/internal/api"
	"github.com/KJoner/litesync-server/internal/backup"
	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

const pgDrillToken = "pg-drill-token-0123456789abcdef0123456789"

type pgDrillServer struct {
	ts  *httptest.Server
	svc *syncsvc.Service
}

func startDrillServer(t *testing.T, database *sql.DB, dataDir string) *pgDrillServer {
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
	ts := httptest.NewServer(api.New(api.Options{Token: pgDrillToken, MaxFileSize: 1 << 20, Version: "drill", Logger: logger}, svc))
	return &pgDrillServer{ts: ts, svc: svc}
}

func (s *pgDrillServer) req(t *testing.T, method, path string, body []byte, hdr map[string]string) (int, map[string]any, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, s.ts.URL+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+pgDrillToken)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	json.Unmarshal(raw, &m) //nolint:errcheck
	return resp.StatusCode, m, raw
}

func (s *pgDrillServer) put(t *testing.T, path string, base int64, content []byte, epoch string) (int, map[string]any) {
	t.Helper()
	sum := sha256.Sum256(content)
	hdr := map[string]string{
		"X-File-Path": url.PathEscape(path), "X-Base-Revision": fmt.Sprint(base),
		"X-Content-Hash": hex.EncodeToString(sum[:]), "X-File-Mtime": "1700000000000",
	}
	if epoch != "" {
		hdr["X-Repo-Epoch"] = epoch
	}
	code, m, _ := s.req(t, http.MethodPut, "/api/v1/file", content, hdr)
	return code, m
}

func (s *pgDrillServer) del(t *testing.T, path string, base int64) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"path": path, "baseRevision": base})
	code, _, _ := s.req(t, http.MethodDelete, "/api/v1/file", body, map[string]string{"Content-Type": "application/json"})
	return code
}

func (s *pgDrillServer) info(t *testing.T) map[string]any {
	t.Helper()
	_, m, _ := s.req(t, http.MethodGet, "/api/v1/info", nil, nil)
	return m
}

func (s *pgDrillServer) snapshot(t *testing.T) map[string]map[string]any {
	t.Helper()
	_, m, _ := s.req(t, http.MethodGet, "/api/v1/snapshot", nil, nil)
	out := map[string]map[string]any{}
	files, _ := m["files"].([]any)
	for _, f := range files {
		fm := f.(map[string]any)
		out[fm["path"].(string)] = fm
	}
	return out
}

// freshRestoreTarget：恢复目标——第二个 PG 实例（若配置）或源实例里的新 schema；结束时删除。
func freshRestoreTarget(t *testing.T) (dsn, where string) {
	t.Helper()
	base, where := os.Getenv("LITESYNC_TEST_PG_RESTORE_DSN"), "second PostgreSQL instance (LITESYNC_TEST_PG_RESTORE_DSN)"
	if base == "" {
		base, where = os.Getenv("LITESYNC_TEST_PG_DSN"), "fresh schema in the source instance"
	}
	raw := make([]byte, 6)
	rand.Read(raw) //nolint:errcheck
	schema := "r_" + hex.EncodeToString(raw)
	admin, err := db.OpenPostgresRaw(base)
	if err != nil {
		t.Fatalf("restore target: %v", err)
	}
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) //nolint:errcheck
		admin.Close()
	})
	return db.WithSearchPath(base, schema), where
}

func newPGDrillManager(t *testing.T, database *sql.DB, q backup.Quiescer, root, dataDir string) *backup.Manager {
	t.Helper()
	resticBin := resticAvailable(t)
	keyFile := filepath.Join(root, "backup.key") // 必须在数据目录之外
	if err := os.WriteFile(keyFile, []byte(strings.Repeat("cd", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	mgr := backup.New(database, q, backup.NewRunner(resticBin), dataDir, "drill", keyFile, logger)
	if _, err := mgr.SetConfig(backup.Update{
		Provider: ptr("local"), LocalPath: ptr(filepath.Join(root, "restic-repo")),
		ResticPassword: ptr("pg-drill-password"), Enabled: ptrBool(true),
	}); err != nil {
		t.Fatalf("备份配置不被接受：%v", err)
	}
	if err := mgr.Initialize(context.Background()); err != nil {
		t.Skipf("restic init 失败（%v）", err)
	}
	return mgr
}

func TestDrillPostgresBackupRestoreToFreshInstance(t *testing.T) {
	if os.Getenv("LITESYNC_TEST_PG_DSN") == "" {
		t.Skip("未设置 LITESYNC_TEST_PG_DSN：PostgreSQL 恢复演练需要真实 PG")
	}
	resticAvailable(t)
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	source, err := db.Open(filepath.Join(dataDir, "sync.db")) // 测试模式下 = PG 上的独立 schema
	if err != nil {
		t.Fatal(err)
	}
	if !db.IsPostgres(source) {
		t.Fatal("LITESYNC_TEST_PG_DSN is set but db.Open did not return PostgreSQL")
	}
	srv := startDrillServer(t, source, dataDir)

	// ---- 1. 恢复点之前的数据：历史、删除 ----
	for _, step := range []struct {
		path    string
		base    int64
		content string
	}{{"a.md", 0, "A v1"}, {"a.md", 1, "A v2 —— 备份点内容"}, {"b.md", 0, "B"}, {"c.md", 0, "C 将在备份前删除"}} {
		if code, m := srv.put(t, step.path, step.base, []byte(step.content), ""); code != http.StatusOK {
			t.Fatalf("put %s = %d %v", step.path, code, m)
		}
	}
	if code := srv.del(t, "c.md", 1); code != http.StatusOK {
		t.Fatalf("delete c.md = %d", code)
	}
	oldEpoch := srv.info(t)["repoEpoch"].(string)

	// ---- 2. 真实备份（真实 Service 全局锁 + 只读快照事务导出） ----
	mgr := newPGDrillManager(t, source, srv.svc, root, dataDir)
	t0 := time.Now()
	bres, err := mgr.Backup(context.Background(), "drill")
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	backupMs := time.Since(t0).Milliseconds()
	if err := mgr.Check(context.Background()); err != nil {
		t.Fatalf("restic check: %v", err)
	}

	// ---- 3. 备份点之后：旧设备还看到了这些（它的游标停在这里），恢复会让服务器回到备份点 ----
	if code, _ := srv.put(t, "d.md", 0, []byte("D 备份之后才写"), ""); code != http.StatusOK {
		t.Fatal("put d.md")
	}
	if code := srv.del(t, "b.md", 1); code != http.StatusOK {
		t.Fatal("delete b.md")
	}
	oldCursor := int64(srv.info(t)["headSequence"].(float64))
	srv.ts.Close()

	// ---- 4. 灾难：源库整体不可用；恢复到一个全新的空库 ----
	source.Close()
	targetDSN, where := freshRestoreTarget(t)
	target, err := db.OpenPostgresRaw(targetDSN)
	if err != nil {
		t.Fatal(err)
	}
	t1 := time.Now()
	rr, err := mgr.RestoreToPostgres(context.Background(), bres.SnapshotID, target)
	if err != nil {
		t.Fatalf("restore to postgres: %v", err)
	}
	restoreMs := time.Since(t1).Milliseconds()
	target.Close()
	if rr.Import == nil || !rr.Import.OK || len(rr.RotatedEpochs) == 0 {
		t.Fatalf("restore must import+verify and rotate epochs: %+v", rr)
	}
	if rr.MissingBlobs != 0 || rr.ReferencedBlobs == 0 {
		t.Fatalf("all referenced blobs must be present after restore: ref=%d missing=%d %v", rr.ReferencedBlobs, rr.MissingBlobs, rr.MissingSample)
	}
	if rr.PreviousDataDir == "" {
		t.Fatal("the previous data dir must be kept")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "sync.db")); err == nil {
		t.Fatal("a PostgreSQL restore must not leave a stale sync.db in the data dir")
	}

	// ---- 5. 在恢复出的 PG 上启动服务 ----
	restored, err := db.OpenPostgres(targetDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	srv2 := startDrillServer(t, restored, dataDir)
	defer srv2.ts.Close()

	info := srv2.info(t)
	newEpoch := info["repoEpoch"].(string)
	if newEpoch == oldEpoch {
		t.Fatal("repoEpoch must be rotated by the restore")
	}
	// 旧设备带着旧游标来增量同步：响应里的 epoch 已变 → 按协议进入灾备合并，而不是信任「没有新变更」
	_, ch, _ := srv2.req(t, http.MethodGet, fmt.Sprintf("/api/v1/changes?since=%d", oldCursor), nil, nil)
	if ch["repoEpoch"] == oldEpoch {
		t.Fatal("changes must carry the rotated epoch so a stale cursor is detected")
	}
	// 旧 epoch 的写入被拒，且是因为 epoch
	if code, m := srv2.put(t, "d.md", 0, []byte("D 备份之后才写"), oldEpoch); code != http.StatusConflict || m["code"] != "REPO_EPOCH_MISMATCH" {
		t.Fatalf("stale-epoch write = %d %v, want 409 REPO_EPOCH_MISMATCH", code, m)
	}

	snap := srv2.snapshot(t)
	if _, ok := snap["c.md"]; ok {
		t.Fatal("c.md was deleted before the backup and must not come back")
	}
	if _, ok := snap["d.md"]; ok {
		t.Fatal("d.md was written after the backup; the restored server must not invent it")
	}
	if a := snap["a.md"]; a == nil || a["revision"].(float64) != 2 {
		t.Fatalf("a.md must be at its backup-point revision 2: %v", a)
	}
	if code, _, raw := srv2.req(t, http.MethodGet, "/api/v1/file?path="+url.QueryEscape("a.md"), nil, nil); code != http.StatusOK || string(raw) != "A v2 —— 备份点内容" {
		t.Fatalf("a.md content after restore = %d %q", code, raw)
	}
	// 删除不复活：一台从没见过删除的设备拿旧 baseRevision 重新上传 c.md → 必须被墓碑挡住
	if code, m := srv2.put(t, "c.md", 1, []byte("C 复活尝试"), newEpoch); code == http.StatusOK {
		t.Fatalf("tombstone must still block a stale re-upload of c.md after restore: %v", m)
	}
	// 灾备合并：旧设备用新 epoch 补回备份点之后的本地内容（不丢）、重放它见过的删除
	if code, m := srv2.put(t, "d.md", 0, []byte("D 备份之后才写"), newEpoch); code != http.StatusOK {
		t.Fatalf("recovery merge re-upload of d.md = %d %v", code, m)
	}
	if code := srv2.del(t, "b.md", 1); code != http.StatusOK {
		t.Fatalf("recovery merge re-delete of b.md = %d", code)
	}
	t.Logf("PG 恢复演练：目标=%s；备份 %d ms，恢复（含导入/校验/旋转 %d 个仓库）%d ms，导入 %d 行；epoch %s → %s",
		where, backupMs, len(rr.RotatedEpochs), restoreMs, rr.Import.TotalRows, oldEpoch[:8], newEpoch[:8])
}

// 注入缺失 Blob（MG-04）：恢复必须明确报告元数据引用了却不在的 blob，而不是静默成功。
// 恢复目标非空必须拒绝，且不动任何现场（INV-11）。
func TestDrillPostgresRestoreReportsMissingBlobsAndRefusesNonEmptyTarget(t *testing.T) {
	if os.Getenv("LITESYNC_TEST_PG_DSN") == "" {
		t.Skip("未设置 LITESYNC_TEST_PG_DSN")
	}
	resticAvailable(t)
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	source, err := db.Open(filepath.Join(dataDir, "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	srv := startDrillServer(t, source, dataDir)
	if code, _ := srv.put(t, "keep.md", 0, []byte("keep"), ""); code != http.StatusOK {
		t.Fatal("put keep.md")
	}
	if code, _ := srv.put(t, "lost.md", 0, []byte("this blob will vanish"), ""); code != http.StatusOK {
		t.Fatal("put lost.md")
	}
	// 注入：在备份之前删掉 lost.md 的 blob 文件（模拟存储层丢失）
	var blobID string
	if err := source.QueryRow(`SELECT blob_id FROM file_heads WHERE content_hash = ?`, sha256hex([]byte("this blob will vanish"))).Scan(&blobID); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dataDir, "blobs", blobID[:2], blobID)); err != nil {
		t.Fatal(err)
	}
	mgr := newPGDrillManager(t, source, srv.svc, root, dataDir)
	bres, err := mgr.Backup(context.Background(), "drill")
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	srv.ts.Close()

	// 非空目标：拒绝，且数据目录不被挪动
	busyDSN, _ := freshRestoreTarget(t)
	busy, err := db.OpenPostgres(busyDSN) // OpenPostgres 写入种子行 → 非空
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.RestoreToPostgres(context.Background(), bres.SnapshotID, busy); err == nil {
		t.Fatal("restore into a non-empty database must be refused")
	}
	busy.Close()
	if _, err := os.Stat(filepath.Join(dataDir, "blobs")); err != nil {
		t.Fatal("a refused restore must not move the data dir")
	}

	targetDSN, _ := freshRestoreTarget(t)
	target, err := db.OpenPostgresRaw(targetDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	rr, err := mgr.RestoreToPostgres(context.Background(), bres.SnapshotID, target)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if rr.MissingBlobs != 1 || len(rr.MissingSample) != 1 || rr.MissingSample[0] != blobID {
		t.Fatalf("the missing blob must be reported explicitly: missing=%d sample=%v", rr.MissingBlobs, rr.MissingSample)
	}
	t.Logf("缺失 blob 被明确报告：referenced=%d missing=%d (%s…)", rr.ReferencedBlobs, rr.MissingBlobs, blobID[:12])
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
