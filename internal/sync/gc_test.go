package sync_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// v0.13.3 §7.3：GC 正确性。
//
// 这一节的每一条都是「宁可少删，不可误删」：被误删的 blob 意味着某个已确认的
// HEAD 或历史版本永久不可读，而用户直到打开那个文件的那天才会发现。

// 造一个够老的孤儿 blob（磁盘上有、DB 无引用）。
// plantOrphan 在磁盘上放一个无引用的 blob。
//
// 位置必须用服务端算出的域化 id（§10.3）：种在裸 contentHash 上的话，
// 后续那次「同内容上传」会落到另一个名字，本测试要验证的
// 「候选被重新引用后必须撤销」就根本触发不到。
func plantOrphan(t *testing.T, s *syncsvc.Service, blobDir string, content []byte) (hash, path string) {
	t.Helper()
	hash = sha256HexT(content)
	id, err := s.BlobIDOf(hash)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(blobDir, id[:2])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, id)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	return hash, path
}

// 第一轮只入册、第二轮才删——而且候选状态是落盘的，重启不会清零。
func TestGCRequiresTwoRounds(t *testing.T) {
	s, blobDir := newServiceAt(t, syncsvc.Options{HistoryEnabled: true})
	_, orphanPath := plantOrphan(t, s, blobDir, []byte("orphan for two-round test"))

	s.RunMaintenance()
	if _, err := os.Stat(orphanPath); err != nil {
		t.Fatal("第一轮不得删除：一次瞬时误判就丢数据是不可接受的")
	}
	s.RunMaintenance()
	if _, err := os.Stat(orphanPath); !os.IsNotExist(err) {
		t.Fatal("连续两轮确认后应当删除")
	}
}

// 候选在两轮之间重新被引用 → 必须撤销候选状态，而不是带着旧计数被删。
func TestGCCandidateClearedWhenReferencedAgain(t *testing.T) {
	s, blobDir := newServiceAt(t, syncsvc.Options{HistoryEnabled: true})
	content := []byte("content that comes back")
	hash, orphanPath := plantOrphan(t, s, blobDir, content)

	// 第一轮：入册为候选
	s.RunMaintenance()
	if _, err := os.Stat(orphanPath); err != nil {
		t.Fatal("第一轮不应删除")
	}

	// 期间这份内容被真正上传（去重命中同一个 blob）
	if _, err := s.Upload(syncsvc.UploadParams{
		Path: "note.md", BaseRevision: 0, ClaimedHash: hash,
		DeviceID: "test-device", Action: "upsert",
	}, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}

	// 第二轮：它现在有引用了，绝不能因为「上一轮记过一次」就被删
	s.RunMaintenance()
	if _, err := os.Stat(orphanPath); err != nil {
		t.Fatal("重新被引用的 blob 被误删了——这会让刚上传的文件永久不可读")
	}

	// 而且候选台账里不能再留着它
	n, err := db.CountGCCandidates(s.DB())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("重新被引用后候选状态必须撤销，仍有 %d 条", n)
	}
}

// scrub / backup 进行中：整轮 GC 跳过。
func TestGCSkippedWhileExclusiveReadInProgress(t *testing.T) {
	s, blobDir := newServiceAt(t, syncsvc.Options{HistoryEnabled: true})
	_, orphanPath := plantOrphan(t, s, blobDir, []byte("orphan during backup"))

	release := s.BeginExclusiveRead()
	s.RunMaintenance()
	s.RunMaintenance()
	if _, err := os.Stat(orphanPath); err != nil {
		t.Fatal("备份/scrub 期间不得 GC：它们读的是某一时刻的全量视图")
	}
	release()

	// 释放之后恢复正常的两轮节奏
	s.RunMaintenance()
	s.RunMaintenance()
	if _, err := os.Stat(orphanPath); !os.IsNotExist(err) {
		t.Fatal("释放后应当恢复 GC")
	}
}

// 元数据迁移进行中：整轮 GC 跳过（寻址与引用关系正在被重写）。
func TestGCSkippedDuringMigration(t *testing.T) {
	s, blobDir := newServiceAt(t, syncsvc.Options{HistoryEnabled: true})
	_, orphanPath := plantOrphan(t, s, blobDir, []byte("orphan during migration"))

	if _, err := s.DB().Exec(`UPDATE repo_state SET meta_state = ?`, db.MetaMigrating); err != nil {
		t.Fatal(err)
	}
	s.RunMaintenance()
	s.RunMaintenance()
	if _, err := os.Stat(orphanPath); err != nil {
		t.Fatal("迁移期间不得 GC：此时的『无引用』判断根本不可信")
	}

	if _, err := s.DB().Exec(`UPDATE repo_state SET meta_state = ?`, db.MetaPlain); err != nil {
		t.Fatal(err)
	}
	s.RunMaintenance()
	s.RunMaintenance()
	if _, err := os.Stat(orphanPath); !os.IsNotExist(err) {
		t.Fatal("迁移结束后应当恢复 GC")
	}
}
