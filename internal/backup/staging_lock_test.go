package backup

// 0.17.1 回归（线上实测死锁）：buildStaging 必须能在**真实 sync.Service** 上完成。
//
// 0.17.0 的闭包在 WithGlobalLock 持锁期间回调 Service.LatestSequence——它自己
// 也要拿同一把互斥锁（不可重入）→ 线上第一次手动备份就把整台服务器锁死：
// 备份 goroutine 永远不返回、不释放锁，所有需要鉴权/查库的请求全部排队挂死。
// CLI 与本包测试替身的 WithGlobalLock 都是无锁直通，恰好把真实实现全部绕开，
// 这正是它能溜进正式版的原因。本测试用真实 Service 补上这个缺口，
// 并用看门狗把「再次死锁」变成秒级失败而不是挂死整个测试套件。

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

func TestBuildStagingWithRealServiceLock(t *testing.T) {
	dataDir := t.TempDir()
	database, err := db.Open(filepath.Join(dataDir, "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
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
	svc := syncsvc.New(database, store, blobs, shares, syncsvc.Options{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	type result struct {
		staging string
		err     error
	}
	done := make(chan result, 1)
	go func() {
		staging, err := buildStaging(database, svc, dataDir, "test")
		done <- result{staging, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("buildStaging = %v", r.err)
		}
		raw, err := os.ReadFile(filepath.Join(r.staging, "backup-manifest.json"))
		if err != nil {
			t.Fatalf("manifest missing: %v", err)
		}
		var m Manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("manifest parse: %v", err)
		}
		if m.Format != 1 || m.LitesyncVersion != "test" {
			t.Fatalf("manifest = %+v", m)
		}
		if _, err := os.Stat(filepath.Join(r.staging, "sync.db")); err != nil {
			t.Fatalf("db snapshot missing: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("buildStaging 在真实 Service 锁上死锁（0.17.0 的线上事故形态）")
	}
}
