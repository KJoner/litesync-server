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
	res, err := s.Upload(syncsvc.UploadParams{
		Path: path, BaseRevision: base, ClaimedHash: sha256HexT(content),
		DeviceID: "test-device", Action: "upsert",
	}, bytes.NewReader(content))
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
			if _, err := s.Upload(syncsvc.UploadParams{
				Path: fmt.Sprintf("f-%04d.md", i), ClaimedHash: sha256HexT(content),
				DeviceID: "w", Action: "upsert",
			}, bytes.NewReader(content)); err != nil {
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
		if int64(len(snap.Objects)) != snap.Sequence {
			t.Fatalf("snapshot not linearizable: sequence=%d but files=%d", snap.Sequence, len(snap.Objects))
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
			if snap.Sequence != total || len(snap.Objects) != total {
				t.Fatalf("final snapshot = seq %d files %d, want %d", snap.Sequence, len(snap.Objects), total)
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
	if _, err := blobs.Commit(tmp, hash, false); err != nil {
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
	res, err := blobs.Commit(tmp2, hash, false)
	if err != nil {
		t.Fatal(err)
	}
	fixed, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(fixed, content) {
		t.Fatalf("blob not repaired: %d bytes (%v)", len(fixed), err)
	}
	// v0.13.3 §7.1：修复必须是「可见的」——调用方要能据此记完整性事件，
	// 而坏副本要进隔离区而不是被悄悄删掉
	if !res.Repaired || res.Reason != "size-mismatch" {
		t.Fatalf("expected a reported repair, got %+v", res)
	}
	if res.QuarantinePath == "" {
		t.Fatal("corrupt copy must be quarantined for forensics, not deleted")
	}
	if _, err := os.Stat(res.QuarantinePath); err != nil {
		t.Fatalf("quarantined copy missing: %v", err)
	}
}

// tombstone 复活防护（service 层）：base 0 → ConflictError{Deleted, PriorHash}。
func TestTombstoneResurrectionGuard(t *testing.T) {
	s := newService(t, syncsvc.Options{HistoryEnabled: true, HistoryDays: 90, HistoryMaxPerFile: 10})
	old := []byte("sensitive old content")
	upload(t, s, "secret.md", 0, old)
	if _, err := s.Delete(syncsvc.DeleteParams{Path: "secret.md", BaseRevision: 1, DeviceID: "d1"}); err != nil {
		t.Fatal(err)
	}

	// 陈旧设备用 base 0 回传旧内容 → 409 + priorHash
	_, err := s.Upload(syncsvc.UploadParams{
		Path: "secret.md", ClaimedHash: sha256HexT(old), DeviceID: "stale-device", Action: "upsert",
	}, bytes.NewReader(old))
	var conflict *syncsvc.ConflictError
	if !asConflict(err, &conflict) || !conflict.Deleted {
		t.Fatalf("base-0 on tombstone = %v, want deleted conflict", err)
	}
	if conflict.PriorHash != sha256HexT(old) {
		t.Fatalf("priorHash = %q, want pre-delete content hash", conflict.PriorHash)
	}

	// v6：带任意 baseRevision 的普通上传都无法穿透墓碑——重建必须走显式 restore
	newContent := []byte("brand new note")
	_, err = s.Upload(syncsvc.UploadParams{
		Path: "secret.md", BaseRevision: conflict.Revision, ClaimedHash: sha256HexT(newContent),
		DeviceID: "d2", Action: "upsert",
	}, bytes.NewReader(newContent))
	if !asConflict(err, &conflict) || !conflict.Deleted {
		t.Fatalf("upsert with tombstone revision = %v, want deleted conflict (restore is required)", err)
	}

	// 显式恢复：revision 连续（2 → 3），身份不变
	rr, err := s.Restore(syncsvc.RestoreParams{
		FileID: conflict.FileID, ExpectedTombstoneRevision: conflict.Revision,
		ContentGeneration: 1, Pseudonym: "secret.md", DeviceID: "d2",
	})
	if err != nil || rr.Revision != 3 {
		t.Fatalf("restore = %v %v", err, rr)
	}
	res, err := s.Upload(syncsvc.UploadParams{
		Path: "secret.md", BaseRevision: rr.Revision, ClaimedHash: sha256HexT(newContent),
		DeviceID: "d2", Action: "upsert",
	}, bytes.NewReader(newContent))
	if err != nil || res.Revision != 4 || res.FileID != conflict.FileID {
		t.Fatalf("write after restore = %v %v", err, res)
	}
}

func asConflict(err error, target **syncsvc.ConflictError) bool {
	return errors.As(err, target)
}

// 完整性 scrub（v9.2）：位腐坏/截断的 HEAD blob 必须被检出并计入 IntegrityIssues。
func TestIntegrityScrubDetectsCorruption(t *testing.T) {
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
	s := syncsvc.New(database, store, blobs, shares, syncsvc.Options{}, logger)

	content := []byte("healthy content for scrub test")
	upload(t, s, "ok.md", 0, content)
	bad := []byte("this blob will be corrupted!")
	upload(t, s, "bad.md", 0, bad)

	// 健康状态：0 issues
	if stats := s.RunMaintenance(); stats.IntegrityIssues != 0 {
		t.Fatalf("healthy scrub issues = %d, want 0", stats.IntegrityIssues)
	}

	// 截断 bad.md 的 blob（尺寸不符必被检出，不依赖抽样）
	hash := sha256HexT(bad)
	blobID, err := s.BlobIDOf(hash)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "blobs", blobID[:2], blobID)
	if err := os.WriteFile(p, bad[:4], 0o600); err != nil {
		t.Fatal(err)
	}
	if stats := s.RunMaintenance(); stats.IntegrityIssues == 0 {
		t.Fatal("truncated HEAD blob must be reported by scrub")
	}

	// 同尺寸位翻转（尺寸校验发现不了）→ 全量 hash 抽查兜底：
	// 文件数 ≤ 8 时全部抽查，必被检出
	flipped := append([]byte{}, bad...)
	flipped[0] ^= 0xff
	if err := os.WriteFile(p, flipped, 0o600); err != nil {
		t.Fatal(err)
	}
	if stats := s.RunMaintenance(); stats.IntegrityIssues == 0 {
		t.Fatal("bit-flipped blob must be caught by hash sampling")
	}
}
