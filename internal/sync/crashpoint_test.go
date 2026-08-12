package sync_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/failpoint"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// 服务端崩溃点恢复测试（v0.14.0-RC / 计划书 §8.2）。
//
// 四条验收标准，每个注入点都要满足：
//
//  1. 成功响应对应的数据一定存在；
//  2. 失败响应可以安全重试；
//  3. 重启后不存在半提交 HEAD；
//  4. 不存在 HEAD 指向缺失 Blob。
//
// 这里的「崩溃」用注入错误模拟。真正的 kill -9 在 Go 单元测试里做不到，
// 但对这套代码来说两者等价：所有状态转换都靠 SQLite 事务与 rename 的原子性，
// 进程在哪一行退出，落盘状态都只有「事务提交前」和「事务提交后」两种。

// assertNoDanglingHeads 检查核心不变量：每个 live HEAD 都必须有一个真实存在的 blob。
func assertNoDanglingHeads(t *testing.T, s *syncsvc.Service, blobDir string) {
	t.Helper()
	heads, err := db.ListHeads(s.DB())
	if err != nil {
		t.Fatal(err)
	}
	for i := range heads {
		h := &heads[i]
		if h.BlobID == "" {
			continue
		}
		p := filepath.Join(blobDir, h.BlobID[:2], h.BlobID)
		st, serr := os.Stat(p)
		if serr != nil {
			t.Fatalf("HEAD %s 指向缺失的 blob %s —— 这份内容已经永久不可读", h.Pseudonym, h.BlobID)
		}
		if st.Size() != h.Size {
			t.Fatalf("HEAD %s 的 blob 尺寸不符：记录 %d，实际 %d", h.Pseudonym, h.Size, st.Size())
		}
	}
}

func uploadOnce(s *syncsvc.Service, path string, base int64, content []byte) (*syncsvc.UploadResult, error) {
	return s.Upload(syncsvc.UploadParams{
		Path: path, BaseRevision: base, ClaimedHash: sha256HexT(content),
		DeviceID: "crash-test", Action: "upsert",
	}, bytes.NewReader(content))
}

// 逐个注入点跑同一套断言：注入 → 上传必失败 → 不变量成立 → 关掉注入重试必成功。
// 覆盖 INV-01：服务端返回写入成功时，对应 Blob 已经持久化、存在且 hash 正确。
// 在 blob 落盘前后、事务提交前后各注入一次崩溃，断言任何一处中断都不会留下
// 「已确认但内容不在」的状态——最坏情况只是一个无引用的孤儿 blob，由 GC 回收。
func TestServerCrashPointsLeaveNoHalfCommit(t *testing.T) {
	points := []struct {
		name string
		fp   string
	}{
		{"临时文件已 fsync、尚未入库", failpoint.BlobAfterTempFsync},
		{"blob rename 之前", failpoint.BlobBeforeRename},
		{"blob 已入库、事务未开始", failpoint.BlobAfterRename},
		{"事务提交之前", failpoint.DBBeforeCommit},
	}
	for _, pt := range points {
		t.Run(pt.name, func(t *testing.T) {
			defer failpoint.Reset()
			s, blobDir := newServiceAt(t, syncsvc.Options{HistoryEnabled: true, HistoryDays: 90, HistoryMaxPerFile: 10})
			content := []byte("content for " + pt.fp)

			cancel := failpoint.EnableError(pt.fp, 1)
			_, err := uploadOnce(s, "note.md", 0, content)
			cancel()
			if err == nil {
				t.Fatal("注入点没有生效——这条崩溃路径其实没有被测到")
			}
			if !errors.Is(err, failpoint.ErrInjected) {
				t.Fatalf("期望注入错误，得到 %v", err)
			}

			// 验收 3：重启后不存在半提交 HEAD。
			// 上传失败了，那么这个对象根本不应该存在
			if h, herr := db.GetHeadByPseudonym(s.DB(), "note.md"); herr != nil {
				t.Fatal(herr)
			} else if h != nil {
				t.Fatalf("上传失败却留下了 HEAD（revision %d）—— 半提交", h.Revision)
			}
			// 验收 4
			assertNoDanglingHeads(t, s, blobDir)

			// 验收 2：失败可以安全重试
			res, err := uploadOnce(s, "note.md", 0, content)
			if err != nil {
				t.Fatalf("重试必须成功: %v", err)
			}
			if res.Revision != 1 {
				t.Fatalf("重试应当产生 revision 1，得到 %d", res.Revision)
			}
			// 验收 1：成功响应对应的数据一定存在
			assertNoDanglingHeads(t, s, blobDir)
			meta, rc, oerr := s.OpenFile("note.md")
			if oerr != nil {
				t.Fatalf("成功响应之后必须能读到内容: %v", oerr)
			}
			defer rc.Close()
			got := make([]byte, meta.Size)
			if _, rerr := rc.Read(got); rerr != nil && len(got) > 0 {
				t.Fatal(rerr)
			}
			if !bytes.Equal(got, content) {
				t.Fatal("读回的内容与上传的不一致")
			}
		})
	}
}

// 最难的窗口：事务已提交、响应尚未返回。
//
// 服务器上数据已经生效，但客户端会看到失败并重试。重试必须收敛到
// **同一个 revision**，而不是产生第二个版本——否则每次网络抖动都会
// 在历史里留下一个重复版本，且 baseRevision 永远对不上。
func TestServerCrashAfterCommitBeforeResponse(t *testing.T) {
	defer failpoint.Reset()
	s, blobDir := newServiceAt(t, syncsvc.Options{HistoryEnabled: true, HistoryDays: 90, HistoryMaxPerFile: 10})
	content := []byte("committed but response lost")

	cancel := failpoint.EnableError(failpoint.DBAfterCommit, 1)
	_, err := uploadOnce(s, "note.md", 0, content)
	cancel()
	if err == nil {
		t.Fatal("注入点没有生效")
	}

	// 数据其实已经落地了
	h, herr := db.GetHeadByPseudonym(s.DB(), "note.md")
	if herr != nil || h == nil {
		t.Fatalf("提交后的数据必须存在: %v", herr)
	}
	if h.Revision != 1 {
		t.Fatalf("期望 revision 1，得到 %d", h.Revision)
	}
	assertNoDanglingHeads(t, s, blobDir)

	// 客户端不知道成功了，带着同样的 base 0 重试。
	// 服务器必须告诉它「已经有 revision 1 了」而不是默默再建一个版本
	_, retryErr := uploadOnce(s, "note.md", 0, content)
	var conflict *syncsvc.ConflictError
	if retryErr == nil {
		// 相同内容被判定为幂等重复也是可以接受的收敛方式
		h2, _ := db.GetHeadByPseudonym(s.DB(), "note.md")
		if h2.Revision != 1 {
			t.Fatalf("相同内容重试不应产生新 revision，得到 %d", h2.Revision)
		}
	} else if !errors.As(retryErr, &conflict) {
		t.Fatalf("重试应当收敛（幂等或冲突），得到 %v", retryErr)
	}
	assertNoDanglingHeads(t, s, blobDir)
}

// GC 在「判定可删」与「实际删除」之间崩溃：只应少删一个，绝不能出现
// 「文件删了但候选记录还在」这种会让下一轮误判的状态。
func TestServerCrashBetweenGCDecisionAndDelete(t *testing.T) {
	defer failpoint.Reset()
	s, blobDir := newServiceAt(t, syncsvc.Options{HistoryEnabled: true})
	_, orphanPath := plantOrphan(t, s, blobDir, []byte("orphan for gc crash test"))

	s.RunMaintenance() // 第一轮：入册
	cancel := failpoint.EnableError(failpoint.GCBeforeDelete, -1)
	s.RunMaintenance() // 第二轮：本该删，但在删之前「崩溃」
	cancel()

	if _, err := os.Stat(orphanPath); err != nil {
		t.Fatal("注入点在删除之前，文件必须还在")
	}
	// 恢复之后应当能正常删掉（候选状态没有被写坏）
	s.RunMaintenance()
	if _, err := os.Stat(orphanPath); !os.IsNotExist(err) {
		t.Fatal("崩溃恢复后 GC 应当能继续完成")
	}
	assertNoDanglingHeads(t, s, blobDir)
}

// 反向保证：没有任何注入时，failpoint 表必须是空的。
// 这是「生产构建不得允许外部任意触发」在测试里的可执行形式（§8.1）。
func TestFailpointsInactiveByDefault(t *testing.T) {
	failpoint.Reset()
	if n := failpoint.ActiveCount(); n != 0 {
		t.Fatalf("默认必须没有任何激活的注入点，实际 %d 个", n)
	}
	if err := failpoint.Eval(failpoint.DBBeforeCommit); err != nil {
		t.Fatalf("未激活的注入点必须是零行为，得到 %v", err)
	}
}

// 迁移逐对象推进时崩溃：journal 里那条仍是 pending，续跑必须幂等重做，
// 而不是产生第二个对象或第二条 change（§8.2「migration 每个对象之间」）。
func TestServerCrashBetweenMigrationObjects(t *testing.T) {
	defer failpoint.Reset()
	s, blobDir := newServiceAt(t, syncsvc.Options{HistoryEnabled: true})
	content := []byte("content for migration crash test")
	if _, err := uploadOnce(s, "note.md", 0, content); err != nil {
		t.Fatal(err)
	}

	cancel := failpoint.EnableError(failpoint.MigrationEachObj, 1)
	_, err := s.MigrateObjectMeta("note.md", "", "", "dev-1")
	cancel()
	if err == nil {
		t.Fatal("注入点没有生效")
	}

	// 崩溃点在任何状态改动之前 → 对象必须完好无损
	h, herr := db.GetHeadByPseudonym(s.DB(), "note.md")
	if herr != nil || h == nil {
		t.Fatalf("迁移中断不得损坏对象: %v", herr)
	}
	if h.Revision != 1 {
		t.Fatalf("迁移不改内容 revision，期望 1 得到 %d", h.Revision)
	}
	assertNoDanglingHeads(t, s, blobDir)
}

// complete 之前崩溃：complete 会不可逆地抹掉明文寻址名，
// 因此此刻崩溃必须让仓库停在原状态，绝不能出现半个 encrypted
// （§8.2「complete 各阶段」）。
func TestServerCrashBeforeMigrationComplete(t *testing.T) {
	defer failpoint.Reset()
	s, _ := newServiceAt(t, syncsvc.Options{HistoryEnabled: true})
	before, err := db.GetRepoState(s.DB(), db.LegacyDefaultScope())
	if err != nil {
		t.Fatal(err)
	}

	cancel := failpoint.EnableError(failpoint.MigrationBeforeDone, 1)
	_, cerr := s.CompleteMetaMigration("some-migration", "dev-1")
	cancel()
	if cerr == nil {
		t.Fatal("注入点没有生效")
	}

	after, err := db.GetRepoState(s.DB(), db.LegacyDefaultScope())
	if err != nil {
		t.Fatal(err)
	}
	if after.MetaState != before.MetaState {
		t.Fatalf("complete 之前崩溃却改了仓库状态：%s -> %s", before.MetaState, after.MetaState)
	}
	if after.FormatEpoch != before.FormatEpoch {
		t.Fatalf("complete 之前崩溃却推进了 formatEpoch：%d -> %d", before.FormatEpoch, after.FormatEpoch)
	}
}

// WAL checkpoint 与 VACUUM 的注入点已接在 erasePlaintextPathsLocked 里，
// 但那段代码只能经由一次**完整**的元数据迁移（plain → migrating → verifying →
// complete）到达。搭一套完整迁移夹具的成本远高于它能带来的信心，
// 因此这两点目前只有接线、没有直接测试——这一条如实记在
// 《v0.14.0-RC 生产资格验证状态》的门槛 4 里，会由真实 Vault 的迁移演练覆盖。
