package sync_test

// v9 故障注入/一致性测试（service 层）：
//   - Snapshot 线性一致性：并发写入下，快照文件集必须精确对应快照 sequence
//   - changes 全量裁剪后全局时钟不回退、sequence 不复用
//   - blob 去重命中时的损坏修复
// 对应《一阶段架构审查》P0 1/2 与 P1 12。

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

func newService(t *testing.T, opts syncsvc.Options) *syncsvc.Service {
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
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return syncsvc.New(database, store, blobs, shares, opts, logger)
}

func upload(t *testing.T, s *syncsvc.Service, path string, base int64, content []byte) *syncsvc.UploadResult {
	t.Helper()
	res, err := s.Upload(path, base, sha256HexT(content), bytes.NewReader(content), 0, "test-device", "upsert")
	if err != nil {
		t.Fatalf("upload %s: %v", path, err)
	}
	return res
}

func sha256HexT(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Snapshot 线性一致性：写入方每次上传一个新路径（sequence == 文件数），
// 并发快照读出的 (sequence, files) 必须满足 len(files) == sequence。
// 修复前 ListFiles 与 LatestSequence 分两次查询，会出现 sequence 比文件多 1
// 的快照，使客户端游标跳过一次变更并永久漏同步。
func TestSnapshotLinearizability(t *testing.T) {
	s := newService(t, syncsvc.Options{})
	const total = 120

	done := make(chan struct{})
	var writeErr error
	go func() {
		defer close(done)
		for i := 0; i < total; i++ {
			content := []byte(fmt.Sprintf("content-%d", i))
			if _, err := s.Upload(fmt.Sprintf("f-%04d.md", i), 0, sha256HexT(content),
				bytes.NewReader(content), 0, "w", "upsert"); err != nil {
				writeErr = err
				return
			}
		}
	}()

	for {
		snap, err := s.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(snap.Files)) != snap.Sequence {
			t.Fatalf("snapshot not linearizable: sequence=%d but files=%d", snap.Sequence, len(snap.Files))
		}
		select {
		case <-done:
			if writeErr != nil {
				t.Fatal(writeErr)
			}
			snap, err := s.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if snap.Sequence != total || len(snap.Files) != total {
				t.Fatalf("final snapshot = seq %d files %d, want %d", snap.Sequence, len(snap.Files), total)
			}
			return
		default:
		}
	}
}

// changes 被全量裁剪后：head 不回退、Changes 返回 resync 而不是 latest=0、
// 新写入的 sequence 继续单调递增（绝不复用已发出的 sequence）。
func TestClockSurvivesChangesPrune(t *testing.T) {
	s := newService(t, syncsvc.Options{ChangesMax: 1})
	upload(t, s, "a.md", 0, []byte("a"))
	upload(t, s, "b.md", 0, []byte("b"))
	upload(t, s, "c.md", 0, []byte("c")) // head = 3

	s.RunMaintenance() // ChangesMax=1 → 只留最新一条，水位线推进到 2

	head, err := s.LatestSequence()
	if err != nil || head != 3 {
		t.Fatalf("head after prune = %d (%v), want 3", head, err)
	}

	// 旧游标 → resync，latest 仍是权威 head（修复前这里会回退成 0 造成死循环）
	res, err := s.Changes(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ResyncRequired || res.LatestSequence != 3 || res.MinSequence != 2 {
		t.Fatalf("changes(0) = resync %v latest %d min %d", res.ResyncRequired, res.LatestSequence, res.MinSequence)
	}
	// 新游标正常增量
	res2, err := s.Changes(3, 100)
	if err != nil || res2.ResyncRequired || len(res2.Changes) != 0 {
		t.Fatalf("changes(3) = %+v (%v)", res2, err)
	}

	// 新写入继续 4，不复用 1-3
	out := upload(t, s, "d.md", 0, []byte("d"))
	if out.Sequence != 4 {
		t.Fatalf("sequence after prune = %d, want 4", out.Sequence)
	}

	// 快照 sequence 与 head 一致
	snap, err := s.Snapshot()
	if err != nil || snap.Sequence != 4 {
		t.Fatalf("snapshot sequence = %d (%v), want 4", snap.Sequence, err)
	}
}

// 幂等重传返回的 sequence 不依赖可裁剪的 changes 表。
func TestIdempotentUploadAfterPrune(t *testing.T) {
	s := newService(t, syncsvc.Options{ChangesMax: 1})
	content := []byte("same")
	upload(t, s, "x.md", 0, content)
	upload(t, s, "y.md", 0, []byte("other"))
	s.RunMaintenance() // x.md 的 change 已被裁剪

	out := upload(t, s, "x.md", 0, content) // 幂等：内容一致
	if out.Revision != 1 || out.Sequence == 0 {
		t.Fatalf("idempotent upload = rev %d seq %d; sequence must not be 0", out.Revision, out.Sequence)
	}
}

// blob 去重命中时校验现有文件：被截断的 blob 会被刚校验过的临时文件修复。
func TestBlobDedupRepairsCorruption(t *testing.T) {
	dir := t.TempDir()
	blobs, err := storage.NewBlobStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("blob content for corruption test")
	hash := sha256HexT(content)

	// 正常写入
	tmp, gotHash, _, err := blobs.IngestVerify(bytes.NewReader(content))
	if err != nil || gotHash != hash {
		t.Fatalf("ingest: %v (%s)", err, gotHash)
	}
	if err := blobs.Commit(tmp, hash); err != nil {
		t.Fatal(err)
	}

	// 模拟位腐坏：截断磁盘上的 blob
	p := filepath.Join(dir, hash[:2], hash)
	if err := os.WriteFile(p, content[:5], 0o600); err != nil {
		t.Fatal(err)
	}

	// 再次上传相同内容：去重路径必须发现尺寸不符并用新文件修复
	tmp2, _, _, err := blobs.IngestVerify(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if err := blobs.Commit(tmp2, hash); err != nil {
		t.Fatal(err)
	}
	fixed, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(fixed, content) {
		t.Fatalf("blob not repaired: %d bytes (%v)", len(fixed), err)
	}
}

// tombstone 复活防护（service 层）：base 0 → ConflictError{Deleted, PriorHash}。
func TestTombstoneResurrectionGuard(t *testing.T) {
	s := newService(t, syncsvc.Options{HistoryEnabled: true, HistoryDays: 90, HistoryMaxPerFile: 10})
	old := []byte("sensitive old content")
	upload(t, s, "secret.md", 0, old)
	if _, err := s.Delete("secret.md", 1, "d1"); err != nil {
		t.Fatal(err)
	}

	// 陈旧设备用 base 0 回传旧内容 → 409 + priorHash
	_, err := s.Upload("secret.md", 0, sha256HexT(old), bytes.NewReader(old), 0, "stale-device", "upsert")
	var conflict *syncsvc.ConflictError
	if !asConflict(err, &conflict) || !conflict.Deleted {
		t.Fatalf("base-0 on tombstone = %v, want deleted conflict", err)
	}
	if conflict.PriorHash != sha256HexT(old) {
		t.Fatalf("priorHash = %q, want pre-delete content hash", conflict.PriorHash)
	}

	// 显式基于墓碑 revision 的重建仍然允许（同名新内容）
	newContent := []byte("brand new note")
	res, err := s.Upload("secret.md", conflict.Revision, sha256HexT(newContent), bytes.NewReader(newContent), 0, "d2", "upsert")
	if err != nil || res.Revision != 3 {
		t.Fatalf("explicit recreate = %v rev %v", err, res)
	}
}

func asConflict(err error, target **syncsvc.ConflictError) bool {
	return errors.As(err, target)
}
