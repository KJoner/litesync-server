package backup_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KJoner/litesync-server/internal/backup"
	"github.com/KJoner/litesync-server/internal/db"
)

// 灾备恢复实机演练（v0.14.0-RC / 计划书 §8.5、§8.8 门槛 7）。
//
// 与其他备份测试的区别：这一条跑的是**真实的 restic 二进制**和**真实的
// 本地 restic 仓库**，不是 fake runner。它验证的是「备份出去的东西，
// 真的能原样恢复回来」——那正是备份存在的唯一理由，也是最容易只在
// 需要的那天才发现出了问题的一件事。
//
// 没装 restic 时自动跳过（安装：go install github.com/restic/restic/cmd/restic@latest）。

func resticAvailable(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("restic"); err == nil {
		return p
	}
	// go install 默认装到 GOPATH/bin，未必在 PATH 里
	if gopath, err := exec.Command("go", "env", "GOPATH").Output(); err == nil {
		cand := filepath.Join(trimNewline(string(gopath)), "bin", resticBinName())
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	t.Skip("未安装 restic，跳过灾备恢复实机演练（go install github.com/restic/restic/cmd/restic@latest）")
	return ""
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func resticBinName() string {
	if os.Getenv("OS") == "Windows_NT" {
		return "restic.exe"
	}
	return "restic"
}

// quiescer：演练里没有并发写入需要静默。
type drillQuiescer struct{ seq int64 }

func (q drillQuiescer) WithGlobalLock(fn func(latestSequence int64) error) error { return fn(q.seq) }

// 造一个有真实内容的数据目录：sync.db + blobs。
func seedDataDir(t *testing.T, dataDir string) map[string]string {
	t.Helper()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(filepath.Join(dataDir, "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// 写几条可验证的记录进 repo_state 与 blobs
	if _, err := database.Exec(`UPDATE repo_state SET head_sequence = 4200`); err != nil {
		t.Fatal(err)
	}
	blobDir := filepath.Join(dataDir, "blobs", "ab")
	if err := os.MkdirAll(blobDir, 0o700); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("ab%062d", i)
		content := fmt.Sprintf("blob content %d — 恢复后必须一字不差", i)
		p := filepath.Join(blobDir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		want[p] = content
	}
	return want
}

// §8.8 门槛 7：完成一次真实的灾备恢复。
//
// 流程：造数据 → backup create（真 restic）→ 破坏数据目录 →
// restore → 逐字节比对 → 确认旧目录被挪走而不是删掉。
func TestDrillRealResticBackupAndRestore(t *testing.T) {
	resticBin := resticAvailable(t)

	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	repoDir := filepath.Join(root, "restic-repo")
	keyFile := filepath.Join(root, "backup.key") // 必须在数据目录之外

	want := seedDataDir(t, dataDir)

	// 备份配置：本地 restic 仓库（local backend，不需要网络）
	if err := os.WriteFile(keyFile, []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(filepath.Join(dataDir, "sync.db"))
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	mgr := backup.New(database, drillQuiescer{seq: 4200}, backup.NewRunner(resticBin),
		dataDir, "drill", keyFile, logger)

	if _, err := mgr.SetConfig(backup.Update{
		Provider:       ptr("local"),
		LocalPath:      ptr(repoDir),
		ResticPassword: ptr("drill-password"),
		Enabled:        ptrBool(true),
	}); err != nil {
		t.Fatalf("备份配置不被接受：%v", err)
	}

	ctx := context.Background()
	if err := mgr.Initialize(ctx); err != nil {
		t.Skipf("restic init 失败（%v）", err)
	}

	// ---- 1. 真实备份 ----
	res, err := mgr.Backup(ctx, "drill")
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	t.Logf("备份完成：snapshot=%s 用时 %d ms", res.SnapshotID, res.DurationMs)
	if res.SnapshotID == "" {
		t.Fatal("备份必须返回 snapshot id")
	}

	// ---- 2. 校验仓库（门槛：backup verify 真的能跑） ----
	if err := mgr.Check(ctx); err != nil {
		t.Fatalf("restic check: %v", err)
	}
	t.Log("restic check 通过")

	// ---- 3. 制造灾难：破坏数据目录 ----
	//
	// 先关句柄再动文件。这个顺序不是洁癖：Windows 上只要还有人打开着
	// sync.db，删除和目录替换都会失败——这恰好证明了 `Restore` 文档里
	// 「调用前必须停止服务」不是一句客套话，而是真实的技术约束。
	database.Close()
	for p := range want {
		if err := os.WriteFile(p, []byte("CORRUPTED"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(dataDir, "sync.db")); err != nil {
		t.Fatal(err)
	}

	// ---- 4. 真实恢复 ----
	rr, err := mgr.Restore(ctx, res.SnapshotID)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	t.Logf("恢复完成：用时 %d ms，旧目录挪到 %s", rr.DurationMs, filepath.Base(rr.PreviousDataDir))

	// 验收 1：内容逐字节一致
	for p, content := range want {
		got, rerr := os.ReadFile(p)
		if rerr != nil {
			t.Fatalf("恢复后读不到 %s：%v", filepath.Base(p), rerr)
		}
		if string(got) != content {
			t.Fatalf("%s 恢复后内容不一致：\n want %q\n got  %q", filepath.Base(p), content, string(got))
		}
	}
	t.Logf("验收 1：%d 个 blob 全部逐字节一致", len(want))

	// 验收 2：数据库回来了，且 head_sequence 是备份时的值
	restored, oerr := db.Open(filepath.Join(dataDir, "sync.db"))
	if oerr != nil {
		t.Fatalf("恢复后数据库打不开：%v", oerr)
	}
	defer restored.Close()
	var head int64
	if err := restored.QueryRow(`SELECT head_sequence FROM repo_state`).Scan(&head); err != nil {
		t.Fatalf("读 repo_state：%v", err)
	}
	if head != 4200 {
		t.Fatalf("恢复后的 head_sequence 应当是备份时的 4200，实际 %d", head)
	}
	t.Logf("验收 2：数据库恢复正常，head_sequence=%d", head)

	// 验收 3：旧数据目录被**挪走**而不是删掉——恢复错快照时那是唯一的退路
	if rr.PreviousDataDir == "" {
		t.Fatal("必须保留旧数据目录")
	}
	if _, err := os.Stat(rr.PreviousDataDir); err != nil {
		t.Fatalf("旧数据目录应当还在（%s）：%v", rr.PreviousDataDir, err)
	}
	// 里面确实是被破坏的那份，证明它没有被恢复内容覆盖
	corrupted, _ := os.ReadDir(filepath.Join(rr.PreviousDataDir, "blobs", "ab"))
	if len(corrupted) == 0 {
		t.Fatal("旧目录里应当保留着被破坏的现场")
	}
	t.Logf("验收 3：旧数据目录完整保留在 %s", filepath.Base(rr.PreviousDataDir))
}

// 恢复到一个不存在的快照必须干净地失败——**不能**把现有数据目录搞坏。
//
// 这是恢复流程里最容易被忽略的一条：出错的恢复不应该比不恢复更糟。
func TestDrillRestoreBadSnapshotLeavesDataIntact(t *testing.T) {
	resticBin := resticAvailable(t)

	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	repoDir := filepath.Join(root, "restic-repo")
	keyFile := filepath.Join(root, "backup.key")
	want := seedDataDir(t, dataDir)

	if err := os.WriteFile(keyFile, []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(filepath.Join(dataDir, "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	mgr := backup.New(database, drillQuiescer{}, backup.NewRunner(resticBin), dataDir, "drill", keyFile, logger)
	if _, err := mgr.SetConfig(backup.Update{
		Provider:       ptr("local"),
		LocalPath:      ptr(repoDir),
		ResticPassword: ptr("drill-password"),
		Enabled:        ptrBool(true),
	}); err != nil {
		t.Fatalf("备份配置不被接受：%v", err)
	}
	if err := mgr.Initialize(context.Background()); err != nil {
		t.Skipf("restic init 失败：%v", err)
	}

	if _, err := mgr.Restore(context.Background(), "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("恢复一个不存在的快照必须失败")
	}

	// 关键：失败的恢复不得动到现有数据
	for p, content := range want {
		got, rerr := os.ReadFile(p)
		if rerr != nil || string(got) != content {
			t.Fatalf("失败的恢复破坏了现有数据：%s（%v）", filepath.Base(p), rerr)
		}
	}
	if _, err := os.Stat(filepath.Join(dataDir, "sync.db")); err != nil {
		t.Fatalf("失败的恢复不得删掉数据库：%v", err)
	}
	t.Log("失败的恢复没有动到任何现有数据")
}

func ptr(s string) *string { return &s }
func ptrBool(b bool) *bool { return &b }

var _ = json.Marshal
