package sync_test

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// newServiceAt 与 newService 相同，但把 blob 目录也返回出来——
// 完整性测试需要直接改写磁盘上的 blob 来模拟位腐坏。
func newServiceAt(t *testing.T, opts syncsvc.Options) (*syncsvc.Service, string) {
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
	blobDir := filepath.Join(dir, "blobs")
	blobs, err := storage.NewBlobStore(blobDir)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := storage.NewShareStore(filepath.Join(dir, "shares"))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return syncsvc.New(database, store, blobs, shares, opts, logger), blobDir
}

// v0.13.3 §7.1 / §7.2：Blob 完整性自愈、隔离与 scrub。

func putBlob(t *testing.T, b *storage.BlobStore, content []byte) string {
	t.Helper()
	tmp, hash, _, err := b.IngestVerify(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if _, err := b.Commit(tmp, hash, false); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return hash
}

// §7.1：位腐坏（尺寸不变、内容变了）只有 strict 模式抓得住。
// 这正是「不得因为同名且同大小就丢弃正确重传」那条要求的核心场景。
func TestStrictVerifyCatchesBitRot(t *testing.T) {
	dir := t.TempDir()
	blobs, err := storage.NewBlobStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("original content of exactly this length")
	hash := putBlob(t, blobs, content)
	p := filepath.Join(dir, hash[:2], hash)

	// 位腐坏：长度不变，内容变了
	rotted := append([]byte(nil), content...)
	rotted[0] ^= 0xff
	if err := os.WriteFile(p, rotted, 0o600); err != nil {
		t.Fatal(err)
	}

	// 非 strict：只比大小 → 看不出问题（这是已知的、有意的性能取舍）
	tmp, _, _, err := blobs.IngestVerify(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	res, err := blobs.Commit(tmp, hash, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Repaired {
		t.Fatal("非 strict 模式不应做全量校验（那会让每次上传都重读一遍文件）")
	}

	// strict：全量重算 hash → 发现损坏、隔离旧副本、用正确内容替换
	tmp2, _, _, err := blobs.IngestVerify(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	res2, err := blobs.Commit(tmp2, hash, true)
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Repaired || res2.Reason != "hash-mismatch" {
		t.Fatalf("strict 模式必须发现位腐坏，got %+v", res2)
	}
	fixed, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(fixed, content) {
		t.Fatalf("blob 未被正确内容修复: %v", err)
	}
	// 坏副本必须留在隔离区（取证），而不是被删掉
	bad, err := os.ReadFile(res2.QuarantinePath)
	if err != nil || !bytes.Equal(bad, rotted) {
		t.Fatalf("隔离区里应当保存着那份坏字节: %v", err)
	}
}

// §7.1：隔离区不参与普通 blob 遍历——否则 GC 会把取证材料当成孤儿 blob 删掉。
func TestQuarantineIsNotWalkedAsBlob(t *testing.T) {
	dir := t.TempDir()
	blobs, err := storage.NewBlobStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("content to be corrupted")
	hash := putBlob(t, blobs, content)
	p := filepath.Join(dir, hash[:2], hash)
	if err := os.WriteFile(p, content[:3], 0o600); err != nil {
		t.Fatal(err)
	}
	tmp, _, _, err := blobs.IngestVerify(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blobs.Commit(tmp, hash, false); err != nil {
		t.Fatal(err)
	}

	seen := map[string]int{}
	if err := blobs.Walk(func(h string, _ os.FileInfo) error {
		seen[h]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if seen[hash] != 1 {
		t.Fatalf("Walk 应当只看到那一份正常 blob，got %d", seen[hash])
	}

	q, err := blobs.ListQuarantine()
	if err != nil || len(q) != 1 || q[0].Hash != hash {
		t.Fatalf("隔离区应当有且只有那份坏副本: %+v (%v)", q, err)
	}
}

// §7.3：隔离区有独立的保留期，不跟随普通 GC。
func TestQuarantinePurgeRespectsRetention(t *testing.T) {
	dir := t.TempDir()
	blobs, err := storage.NewBlobStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("quarantine retention test content")
	hash := putBlob(t, blobs, content)
	if err := os.WriteFile(filepath.Join(dir, hash[:2], hash), content[:2], 0o600); err != nil {
		t.Fatal(err)
	}
	tmp, _, _, err := blobs.IngestVerify(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blobs.Commit(tmp, hash, false); err != nil {
		t.Fatal(err)
	}

	// 保留期未到：一个都不能删
	n, err := blobs.PurgeQuarantine(0)
	if err != nil || n != 0 {
		t.Fatalf("保留期内不得删除隔离副本: n=%d err=%v", n, err)
	}
	// 保留期已过
	n, err = blobs.PurgeQuarantine(1 << 40)
	if err != nil || n != 1 {
		t.Fatalf("过期隔离副本应当被清理: n=%d err=%v", n, err)
	}
}

// §7.2：scrub 发现 HEAD 内容损坏后，该内容必须**不再对外返回**，
// 而且报的错要能和「文件不存在」区分开——客户端绝不能因此跟随删除。
func TestScrubMarksCorruptBlobUnservable(t *testing.T) {
	s, blobDir := newServiceAt(t, syncsvc.Options{HistoryEnabled: true, HistoryDays: 90, HistoryMaxPerFile: 10})
	content := []byte("this content will be corrupted on disk")
	if _, err := s.Upload(syncsvc.UploadParams{
		Path: "note.md", BaseRevision: 0, ClaimedHash: sha256HexT(content),
		DeviceID: "test-device", Action: "upsert",
	}, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}

	// 下载此刻是正常的
	if _, rc, err := s.OpenFile("note.md"); err != nil {
		t.Fatalf("上传后应当可下载: %v", err)
	} else {
		rc.Close()
	}

	// 制造磁盘损坏
	h := sha256HexT(content)
	blobPath := filepath.Join(blobDir, h[:2], h)
	if err := os.WriteFile(blobPath, []byte("corrupted"), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := s.Scrub(true)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Issues == 0 || rep.Unservable == 0 {
		t.Fatalf("scrub 必须发现损坏并停止对外提供: %+v", rep)
	}

	// 核心断言：损坏之后绝不能继续返回内容
	_, rc, err := s.OpenFile("note.md")
	if err == nil {
		rc.Close()
		t.Fatal("发现损坏后仍然返回了内容——这正是 §7.2 明确禁止的")
	}
	if !errors.Is(err, syncsvc.ErrCorrupted) {
		t.Fatalf("必须是 ErrCorrupted 而不是 NotFound（否则客户端会跟随删除）: %v", err)
	}

	events, err := s.IntegrityEvents(true)
	if err != nil || len(events) == 0 {
		t.Fatalf("完整性事件必须入账本: %+v (%v)", events, err)
	}
	if events[0].AffectedRefs == 0 {
		t.Fatal("必须重新检查引用数（§7.1 第 6 步），受影响范围是运维决策依据")
	}
}

// §7.2：干净仓库上 scrub 必须报 clean，且 DB 全量 integrity_check 通过。
func TestScrubCleanRepository(t *testing.T) {
	s, _ := newServiceAt(t, syncsvc.Options{HistoryEnabled: true, HistoryDays: 90, HistoryMaxPerFile: 10})
	for _, body := range []string{"one", "two", "three"} {
		content := []byte(body)
		if _, err := s.Upload(syncsvc.UploadParams{
			Path: body + ".md", BaseRevision: 0, ClaimedHash: sha256HexT(content),
			DeviceID: "test-device", Action: "upsert",
		}, bytes.NewReader(content)); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := s.Scrub(true)
	if err != nil {
		t.Fatal(err)
	}
	if rep.DBCheck != "ok" {
		t.Fatalf("integrity_check: %s", rep.DBCheck)
	}
	if rep.Issues != 0 {
		t.Fatalf("干净仓库不应有问题: %+v", rep)
	}
	if rep.HeadsChecked != 3 {
		t.Fatalf("应当检查 3 个 HEAD，实际 %d", rep.HeadsChecked)
	}
}
