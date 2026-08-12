package sync_test

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// v0.13.3 §7.7：日志与诊断隐私。
//
// 这条规则很容易在「加个日志方便排查」时被破坏，而破坏之后没有任何测试会红。
// 所以这里用一个真实仓库跑一遍常见操作，然后逐行检查日志里有没有出现
// 真实路径、Token、密钥材料或用户内容。

// 用一个显眼且绝不会被其他字段偶然包含的路径与内容做标记。
const (
	secretPath    = "私密目录/我的日记-2026.md"
	secretContent = "SENSITIVE-CONTENT-MARKER-9f3a"
	secretToken   = "TOKEN-MARKER-c71e2b"
)

func newLoggingService(t *testing.T) (*syncsvc.Service, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	store, err := storage.New(filepath.Join(dir, "vault"))
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := storage.NewBlobStore(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	shares, err := storage.NewShareStore(filepath.Join(dir, "shares"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	// Debug 级别：把所有日志都收进来，包括平时不输出的
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return syncsvc.New(database, store, blobs, shares, syncsvc.Options{
		HistoryEnabled: true, HistoryDays: 90, HistoryMaxPerFile: 10,
	}, logger), &buf
}

func TestLogsNeverContainUserPathsOrContent(t *testing.T) {
	s, logs := newLoggingService(t)

	content := []byte(secretContent + " 正文正文")
	// 一整轮常见操作：上传、改名、删除、恢复、维护、scrub
	if _, err := s.Upload(syncsvc.UploadParams{
		Path: secretPath, BaseRevision: 0, ClaimedHash: sha256HexT(content),
		DeviceID: "device-" + secretToken, Action: "upsert",
	}, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Delete(syncsvc.DeleteParams{Path: secretPath, BaseRevision: 1, DeviceID: "d1"}); err != nil {
		t.Fatal(err)
	}
	s.RunMaintenance()
	if _, err := s.Scrub(true); err != nil {
		t.Fatal(err)
	}

	out := logs.String()
	for _, forbidden := range []struct {
		what   string
		needle string
	}{
		{"真实路径的目录部分", "私密目录"},
		{"真实路径的文件名", "我的日记"},
		{"用户内容", secretContent},
		{"完整的设备 Token", "device-" + secretToken},
	} {
		if strings.Contains(out, forbidden.needle) {
			t.Fatalf("日志泄露了%s（§7.7 禁止）:\n%s", forbidden.what, out)
		}
	}
}

// 允许出现的字段必须**确实**出现——否则日志就成了没有诊断价值的空壳，
// 运维只能靠猜。§7.7 给的白名单是「必须有这些」，不是「最多有这些」。
func TestLogsKeepDiagnosticFields(t *testing.T) {
	s, logs := newLoggingService(t)
	content := []byte("some content")
	if _, err := s.Upload(syncsvc.UploadParams{
		Path: "note.md", BaseRevision: 0, ClaimedHash: sha256HexT(content),
		DeviceID: "dev-1", Action: "upsert",
	}, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Scrub(false); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	if !strings.Contains(out, "scrub") {
		t.Fatalf("scrub 结果必须留下可检索的日志:\n%s", out)
	}
}

// 截断后的 fileId 可以进日志，但必须是**截断**的：
// 完整 fileId 在 meta 模式下等于服务器可见寻址名，攒够了就能画出仓库结构。
func TestIdentifiersInLogsAreTruncated(t *testing.T) {
	s, logs := newLoggingService(t)
	content := []byte("content for id truncation test")
	res, err := s.Upload(syncsvc.UploadParams{
		Path: "id.md", BaseRevision: 0, ClaimedHash: sha256HexT(content),
		DeviceID: "dev-1", Action: "upsert",
	}, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	// 制造一条一定会打日志的完整性事件
	if _, err := s.Delete(syncsvc.DeleteParams{Path: "id.md", BaseRevision: res.Revision, DeviceID: "dev-1"}); err != nil {
		t.Fatal(err)
	}
	s.RunMaintenance()

	if strings.Contains(logs.String(), res.FileID) {
		t.Fatalf("日志里出现了完整 fileId（§7.7 只允许截断形式）: %s", logs.String())
	}
}
