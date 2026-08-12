package sync_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// blobID 域化迁移的**演练**（v0.16.0 / §10.3；计划书 §11 第 11 条完成依据）。
//
// 前面 internal/db 的单元测试证明的是「改名与改引用不会互相错位」。
// 这里要证的是更实在的一条：**一个装着真实数据的服务器跑完迁移之后，
// 每一份内容都还读得出来，而且字节完全一样**。
//
// 迁移是不可逆的。「跑通了」不能等于「代码没报错」——必须逐份内容读回来比对。

// 把服务器退回到迁移前的状态：blob 改名回裸 contentHash，引用一并改回。
// 这不是产品功能，只是让演练能从一个真实的「老库」出发。
func demoteToLegacyBlobIDs(t *testing.T, s *syncsvc.Service, blobDir string) {
	t.Helper()
	d := s.DB()
	rows, err := d.Query(`SELECT DISTINCT blob_id, content_hash FROM file_heads WHERE blob_id != ''
		UNION SELECT DISTINCT blob_id, content_hash FROM object_versions WHERE blob_id != ''`)
	if err != nil {
		t.Fatal(err)
	}
	type pair struct{ blobID, hash string }
	var pairs []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.blobID, &p.hash); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		pairs = append(pairs, p)
	}
	rows.Close()

	demoted := 0
	for _, p := range pairs {
		if p.blobID == p.hash {
			continue
		}
		demoted++
		src := filepath.Join(blobDir, p.blobID[:2], p.blobID)
		dstDir := filepath.Join(blobDir, p.hash[:2])
		if err := os.MkdirAll(dstDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(src, filepath.Join(dstDir, p.hash)); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(`UPDATE file_heads SET blob_id = ? WHERE blob_id = ?`, p.hash, p.blobID); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(`UPDATE object_versions SET blob_id = ? WHERE blob_id = ?`, p.hash, p.blobID); err != nil {
			t.Fatal(err)
		}
	}
	if demoted == 0 {
		t.Fatal("没有任何 blob 被退回老格式——后面的迁移会无事可做，整个演练是假的")
	}
	// journal 也要清掉，否则续跑逻辑会以为这些已经做完了
	if _, err := d.Exec(`DELETE FROM migration_journal WHERE migration_id = ?`, db.BlobIDMigrationID); err != nil {
		t.Fatal(err)
	}
}

func TestBlobIDMigrationDrillKeepsEveryFileReadable(t *testing.T) {
	s, blobDir := newServiceAt(t, syncsvc.Options{HistoryEnabled: true})

	// 一份有点分量的仓库：多文件、多版本、跨文件共享内容
	files := map[string][]byte{
		"note.md":        []byte("# 标题\n正文若干"),
		"attach/img.bin": bytes.Repeat([]byte{0x00, 0xff, 0x7f}, 4096),
		"dup-a.md":       []byte("完全相同的内容"),
		"dup-b.md":       []byte("完全相同的内容"), // 与 dup-a 去重到同一个 blob
	}
	for p, c := range files {
		upload(t, s, p, 0, c)
	}
	// note.md 再改两版，制造历史版本引用
	noteV1 := files["note.md"]
	v2 := []byte("# 标题\n改过一次")
	v3 := []byte("# 标题\n又改了一次")
	upload(t, s, "note.md", 1, v2)
	upload(t, s, "note.md", 2, v3)
	files["note.md"] = v3

	// 退回老格式，得到一个「v0.15 时代的库」
	demoteToLegacyBlobIDs(t, s, blobDir)
	if need, err := s.NeedsBlobIDMigration(); err != nil || !need {
		t.Fatalf("退回后应当被识别为待迁移（need=%v err=%v）", need, err)
	}
	// 老库的定义：每一处引用都停在裸 contentHash 上
	var notLegacy int
	if err := s.DB().QueryRow(
		`SELECT COUNT(*) FROM file_heads WHERE blob_id != '' AND blob_id != content_hash`).Scan(&notLegacy); err != nil {
		t.Fatal(err)
	}
	if notLegacy != 0 {
		t.Fatalf("退回不彻底：还有 %d 条引用不是裸 contentHash", notLegacy)
	}
	// 迁移前先确认这个老库本身是好的——否则后面比对的是一个坏基线
	assertAllReadable(t, s, files)

	// dry-run 不得改动任何东西
	dry, err := s.MigrateBlobIDs(false)
	if err != nil {
		t.Fatal(err)
	}
	if dry.Planned == 0 || dry.Renamed != 0 {
		t.Fatalf("dry-run 应当只报计划量：%+v", dry)
	}
	assertAllReadable(t, s, files)

	// 正式迁移
	rep, err := s.MigrateBlobIDs(true)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Renamed == 0 || rep.Failed != 0 {
		t.Fatalf("迁移应当全部成功：%+v", rep)
	}

	// 核心断言：每一份内容仍然读得出来，且字节完全一致
	assertAllReadable(t, s, files)

	// 磁盘上不得再有裸 contentHash 命名的文件——否则隔离性质没真正建立
	for _, c := range files {
		h := sha256HexT(c)
		if _, err := os.Stat(filepath.Join(blobDir, h[:2], h)); err == nil {
			t.Fatalf("迁移后仍存在裸 contentHash 命名的 blob %s", h[:12])
		}
	}

	// 历史版本也要能取回（迁移只改 HEAD 的话这里会失败）
	if _, rc, err := s.OpenVersion("note.md", 1); err != nil {
		t.Fatalf("迁移后历史版本应当仍可取回: %v", err)
	} else {
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, noteV1) {
			t.Fatalf("历史版本内容与迁移前不一致（%d vs %d 字节）", len(got), len(noteV1))
		}
	}

	// 迁移完成后不应再报告待迁移；重跑必须幂等
	if need, err := s.NeedsBlobIDMigration(); err != nil || need {
		t.Fatalf("迁移完成后不应再报告待迁移（need=%v err=%v）", need, err)
	}
	again, err := s.MigrateBlobIDs(true)
	if err != nil {
		t.Fatal(err)
	}
	if again.Renamed != 0 || again.Failed != 0 {
		t.Fatalf("重跑必须幂等：%+v", again)
	}
	assertAllReadable(t, s, files)

	// 迁移后 scrub 必须是干净的：它会拿数据库里的 contentHash
	// 校验域化文件的内容，任何一处对不上都会报出来
	scrub, err := s.Scrub(true)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Issues != 0 {
		t.Fatalf("迁移后 scrub 应当干净：%+v", scrub.Details)
	}

	// 迁移后继续上传：新内容与老内容混在同一套命名下，去重仍然有效
	fresh := []byte("迁移之后写入的新内容")
	upload(t, s, "after.md", 0, fresh)
	upload(t, s, "after-copy.md", 0, fresh)
	files["after.md"] = fresh
	files["after-copy.md"] = fresh
	assertAllReadable(t, s, files)

	id, err := s.BlobIDOf(sha256HexT(fresh))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(blobDir, id[:2]))
	if err != nil {
		t.Fatal(err)
	}
	var same int
	for _, e := range entries {
		if e.Name() == id {
			same++
		}
	}
	if same != 1 {
		t.Fatalf("相同内容应当只存一份，找到 %d 份", same)
	}
}

func assertAllReadable(t *testing.T, s *syncsvc.Service, files map[string][]byte) {
	t.Helper()
	for p, want := range files {
		_, rc, err := s.OpenFile(p)
		if err != nil {
			t.Fatalf("%s 读不出来了: %v", p, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("%s 读取失败: %v", p, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s 内容与迁移前不一致（%d vs %d 字节）", p, len(got), len(want))
		}
	}
}
