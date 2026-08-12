package sync_test

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// 规模测试（v0.14.0-RC / 计划书 §8.7）。
//
// 计划书要求「不得只用几十个测试文件证明生产能力」，并且必须按 README 中
// **正式声明的上限**来跑。README 声明的单仓库上限是 20 000 个文件。
//
// 这里默认跑 2 000 个文件（约几秒，适合每次提交都跑）；
// 设 LITESYNC_SCALE=20000 可以按声明上限完整跑一次，用于发布前验证。
//
// 断言的是**正确性在规模下不退化**，不是绝对耗时：
// 耗时受磁盘与 CI 机器影响太大，写死阈值只会带来无意义的 flaky 失败。
// 真正要防的是「小规模下对、大规模下错」的那类问题——
// 比如分页漏条目、快照截断、GC 在大集合上误判。

func scaleN(t *testing.T) int {
	if v := os.Getenv("LITESYNC_SCALE"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
		t.Fatalf("invalid LITESYNC_SCALE: %q", v)
	}
	return 2000
}

func TestScaleSnapshotChangesScrubGC(t *testing.T) {
	n := scaleN(t)
	s, _ := newServiceAt(t, syncsvc.Options{HistoryEnabled: true, HistoryDays: 90, HistoryMaxPerFile: 10})

	start := time.Now()
	for i := 0; i < n; i++ {
		content := []byte(fmt.Sprintf("content of note %d", i))
		if _, err := s.Upload(syncsvc.UploadParams{
			Path:         fmt.Sprintf("notes/%04d/note-%06d.md", i%100, i),
			BaseRevision: 0, ClaimedHash: sha256HexT(content),
			DeviceID: "scale", Action: "upsert",
		}, bytes.NewReader(content)); err != nil {
			t.Fatalf("upload %d: %v", i, err)
		}
	}
	t.Logf("上传 %d 个文件耗时 %s", n, time.Since(start))

	// snapshot：必须一条不少。分页/截断类 bug 只有在大集合上才暴露
	t0 := time.Now()
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Objects) != n {
		t.Fatalf("snapshot 少了条目：期望 %d，实际 %d", n, len(snap.Objects))
	}
	t.Logf("snapshot(%d) 耗时 %s", n, time.Since(t0))

	// changes：分页读完必须恰好覆盖所有 sequence，不重不漏
	t0 = time.Now()
	seen := map[string]bool{}
	var cursor int64
	for {
		resp, cerr := s.Changes(cursor, 500)
		if cerr != nil {
			t.Fatal(cerr)
		}
		if len(resp.Changes) == 0 {
			break
		}
		for _, c := range resp.Changes {
			if c.Sequence <= cursor {
				t.Fatalf("changes 返回了不递增的 sequence：%d <= %d", c.Sequence, cursor)
			}
			cursor = c.Sequence
			seen[c.Pseudonym] = true
		}
		if !resp.HasMore {
			break
		}
	}
	if len(seen) != n {
		t.Fatalf("changes 分页读完少了对象：期望 %d，实际 %d", n, len(seen))
	}
	t.Logf("changes 全量分页(%d) 耗时 %s", n, time.Since(t0))

	// scrub：全量校验在规模下必须仍然报 clean
	t0 = time.Now()
	rep, err := s.Scrub(true)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Issues != 0 {
		t.Fatalf("规模仓库上 scrub 报出了问题：%+v", rep)
	}
	if rep.HeadsChecked != n {
		t.Fatalf("scrub 漏检了 HEAD：期望 %d，实际 %d", n, rep.HeadsChecked)
	}
	t.Logf("scrub --full(%d) 耗时 %s", n, time.Since(t0))

	// GC：大集合上不得误删任何被引用的 blob
	t0 = time.Now()
	s.RunMaintenance()
	s.RunMaintenance()
	if err := assertAllHeadsReadable(s); err != nil {
		t.Fatalf("GC 之后有 HEAD 不可读：%v", err)
	}
	t.Logf("两轮 maintenance(%d) 耗时 %s", n, time.Since(t0))
}

func assertAllHeadsReadable(s *syncsvc.Service) error {
	heads, err := db.ListHeads(s.DB())
	if err != nil {
		return err
	}
	for i := range heads {
		_, rc, oerr := s.OpenFile(heads[i].Pseudonym)
		if oerr != nil {
			return fmt.Errorf("%s: %w", heads[i].Pseudonym, oerr)
		}
		rc.Close()
	}
	return nil
}

// 单文件历史版本数达到声明上限时，保留策略必须真的生效——
// 否则「最大历史版本数」这个声明就只是句空话，磁盘会一直涨。
func TestScaleHistoryRetentionHolds(t *testing.T) {
	const maxPerFile = 10
	s, _ := newServiceAt(t, syncsvc.Options{
		HistoryEnabled: true, HistoryDays: 3650, HistoryMaxPerFile: maxPerFile,
	})
	var rev int64
	for i := 0; i < 60; i++ {
		content := []byte(fmt.Sprintf("revision %d", i))
		res, err := s.Upload(syncsvc.UploadParams{
			Path: "hot.md", BaseRevision: rev, ClaimedHash: sha256HexT(content),
			DeviceID: "scale", Action: "upsert",
		}, bytes.NewReader(content))
		if err != nil {
			t.Fatalf("upload %d: %v", i, err)
		}
		rev = res.Revision
	}
	versions, err := s.History("hot.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) > maxPerFile {
		t.Fatalf("保留策略没生效：声明上限 %d，实际留了 %d 个版本", maxPerFile, len(versions))
	}
	// 而且最新那个必须还在（裁掉的只能是旧的）
	if versions[0].Revision != rev {
		t.Fatalf("最新版本被裁掉了：期望 revision %d，实际 %d", rev, versions[0].Revision)
	}
	if err := assertAllHeadsReadable(s); err != nil {
		t.Fatalf("裁剪之后 HEAD 不可读：%v", err)
	}
}
