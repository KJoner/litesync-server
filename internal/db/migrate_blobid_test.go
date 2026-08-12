package db_test

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
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
)

// blobID 域化迁移（v0.16.0 / §10.3、ADR-010 §8 第 4 步）。
//
// 这次迁移会逐个改名成千上万个文件。它唯一允许的失败模式是
// 「改到一半，journal 记着进度，续跑即可」——**绝不能**是
// 「一半的 HEAD 指向不存在的 blob」。下面每条测试都围绕这一点。

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newBlobEnv(t *testing.T) (*sql.DB, *storage.BlobStore, string) {
	t.Helper()
	dir := t.TempDir()
	d, err := db.Open(filepath.Join(dir, "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	blobDir := filepath.Join(dir, "blobs")
	blobs, err := storage.NewBlobStore(blobDir)
	if err != nil {
		t.Fatal(err)
	}
	return d, blobs, blobDir
}

// 造一个有内容的仓库：blob 落盘 + file_heads 与 object_versions 两处引用。
// 历史版本必须一起造——只改 HEAD 不改历史的话，回滚到旧版本会读不出内容。
func seedBlobs(t *testing.T, d *sql.DB, blobs *storage.BlobStore, n int) (secret []byte, hashes []string) {
	t.Helper()
	secret = []byte("0123456789abcdef0123456789abcdef")
	for i := 0; i < n; i++ {
		content := []byte(fmt.Sprintf("content %d", i))
		sum := sha256.Sum256(content)
		h := hex.EncodeToString(sum[:])
		hashes = append(hashes, h)
		if err := blobs.PutReader(h, bytes.NewReader(content)); err != nil {
			t.Fatal(err)
		}
		fileID := fmt.Sprintf("%032x", i+1)
		if err := db.UpsertObject(d, fileID, db.ObjectLive, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := db.UpsertHead(d, &db.ObjectHead{
			VaultID: db.DefaultVaultID, FileID: fileID, Pseudonym: fileID,
			Revision: 1, BlobID: h, ContentHash: h, Size: int64(len(content)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(
			`INSERT INTO object_versions
			   (vault_id, file_id, revision, blob_id, content_hash, size, mtime, action, created_at)
			 VALUES (?, ?, 1, ?, ?, ?, 0, 'upsert', 0)`,
			db.DefaultVaultID, fileID, h, h, len(content)); err != nil {
			t.Fatal(err)
		}
	}
	return secret, hashes
}

// 失败注入用的 renamer：第 failAt 次改名报错。
type flakyRenamer struct {
	inner  *storage.BlobStore
	calls  int
	failAt int
}

func (f *flakyRenamer) RenameBlob(oldID, newID string) error {
	f.calls++
	if f.failAt > 0 && f.calls == f.failAt {
		return errors.New("injected rename failure")
	}
	return f.inner.RenameBlob(oldID, newID)
}

func (f *flakyRenamer) NewBlobID(secret []byte, h string) string {
	return f.inner.NewBlobID(secret, h)
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// 核心不变量：任何时刻，file_heads 与 object_versions 里每一个 blob 引用
// 都必须在磁盘上存在。这是本次迁移唯一不能破的东西。
func assertNoDanglingRefs(t *testing.T, d *sql.DB, blobDir string) {
	t.Helper()
	for _, table := range []string{"file_heads", "object_versions"} {
		rows, err := d.Query(
			`SELECT file_id, blob_id FROM ` + table + ` WHERE blob_id IS NOT NULL AND blob_id != ''`)
		if err != nil {
			t.Fatal(err)
		}
		var dangling []string
		for rows.Next() {
			var fileID, blobID string
			if err := rows.Scan(&fileID, &blobID); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(blobDir, blobID[:2], blobID)); err != nil {
				dangling = append(dangling, fmt.Sprintf("%s(%s→%s)", table, short(fileID, 8), short(blobID, 12)))
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if len(dangling) > 0 {
			t.Fatalf("存在指向不存在 blob 的引用，这些内容已经读不出来了：%v", dangling)
		}
	}
}

func TestBlobIDMigrationRenamesAndRepoints(t *testing.T) {
	d, blobs, blobDir := newBlobEnv(t)
	secret, hashes := seedBlobs(t, d, blobs, 5)
	scope := db.LegacyDefaultScope()

	// dry-run 不得改动任何东西
	rep, err := db.MigrateBlobIDs(d, scope, secret, blobs, false, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Planned != 5 || rep.Renamed != 0 {
		t.Fatalf("dry-run 应当只报计划量：%+v", rep)
	}
	for _, h := range hashes {
		if _, err := os.Stat(filepath.Join(blobDir, h[:2], h)); err != nil {
			t.Fatal("dry-run 不得改名任何 blob")
		}
	}

	// 正式迁移
	rep, err = db.MigrateBlobIDs(d, scope, secret, blobs, true, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Renamed != 5 || rep.Failed != 0 {
		t.Fatalf("应当改名 5 个：%+v", rep)
	}

	for _, h := range hashes {
		if _, err := os.Stat(filepath.Join(blobDir, h[:2], h)); err == nil {
			t.Fatalf("旧 blobID %s 应当已不存在——留着它等于旧的全局去重路径仍然可达", h[:12])
		}
		newID := storage.BlobIDFor(secret, h)
		if _, err := os.Stat(filepath.Join(blobDir, newID[:2], newID)); err != nil {
			t.Fatalf("新 blobID %s 应当存在", newID[:12])
		}
	}
	// 历史版本的引用也必须跟着改，否则回滚到旧版本会读不出内容
	var oldRefs int
	if err := d.QueryRow(
		`SELECT COUNT(*) FROM object_versions WHERE blob_id = content_hash`).Scan(&oldRefs); err != nil {
		t.Fatal(err)
	}
	if oldRefs != 0 {
		t.Fatalf("还有 %d 条历史版本引用停留在裸 contentHash 上", oldRefs)
	}
	assertNoDanglingRefs(t, d, blobDir)
}

// 中途失败：已完成的那些必须完好，未完成的必须仍指向旧 blob——
// 任何时刻都不能出现「引用指向不存在的 blob」。
func TestBlobIDMigrationSurvivesMidwayFailure(t *testing.T) {
	d, blobs, blobDir := newBlobEnv(t)
	secret, _ := seedBlobs(t, d, blobs, 6)
	scope := db.LegacyDefaultScope()

	flaky := &flakyRenamer{inner: blobs, failAt: 3}
	rep, err := db.MigrateBlobIDs(d, scope, secret, flaky, true, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Failed == 0 {
		t.Fatal("注入的失败没有生效，这条测试什么也没验证到")
	}
	// 关键：即使中途失败，也不能有悬空引用
	assertNoDanglingRefs(t, d, blobDir)

	// 续跑：把剩下的做完，已经做过的落到 skip
	rep2, err := db.MigrateBlobIDs(d, scope, secret, blobs, true, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Failed != 0 {
		t.Fatalf("续跑不应再失败：%+v", rep2)
	}
	if rep2.Renamed+rep2.Skipped != 6 {
		t.Fatalf("续跑后 6 个 blob 应当全部到位：%+v", rep2)
	}
	assertNoDanglingRefs(t, d, blobDir)
}

// 「文件改了名、引用没改成」是最危险的中间态：
// 迁移必须把文件改回去，回到可重试的状态，而不是留下悬空引用。
func TestBlobIDMigrationRollsBackRenameWhenRepointFails(t *testing.T) {
	d, blobs, blobDir := newBlobEnv(t)
	secret, hashes := seedBlobs(t, d, blobs, 2)
	scope := db.LegacyDefaultScope()

	// 注入手法：用触发器让 object_versions 的 UPDATE 必然 ABORT。
	// 这样 repoint 事务在「file_heads 已改、object_versions 未改」处失败，
	// 正好是最危险的那一刻——文件已经改了名，引用却还没跟上。
	if _, err := d.Exec(`
		CREATE TRIGGER block_repoint BEFORE UPDATE OF blob_id ON object_versions
		BEGIN SELECT RAISE(ABORT, 'injected repoint failure'); END`); err != nil {
		t.Fatal(err)
	}

	rep, err := db.MigrateBlobIDs(d, scope, secret, blobs, true, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Failed != 2 {
		t.Fatalf("两条都应当 repoint 失败，否则这条测试没验证到回滚：%+v", rep)
	}

	for _, h := range hashes {
		// 1) 文件必须已经改回旧 id
		if _, err := os.Stat(filepath.Join(blobDir, h[:2], h)); err != nil {
			t.Fatalf("repoint 失败后必须把 blob %s 改回旧 id，否则引用悬空", h[:12])
		}
		// 2) 新 id 不得残留，否则下次续跑会看到两份
		newID := storage.BlobIDFor(secret, h)
		if _, err := os.Stat(filepath.Join(blobDir, newID[:2], newID)); err == nil {
			t.Fatalf("回滚后新 id %s 不应残留", newID[:12])
		}
	}
	// 3) 引用必须整体回到迁移前：事务回滚要把 file_heads 的改动一并撤掉
	var repointed int
	if err := d.QueryRow(
		`SELECT COUNT(*) FROM file_heads WHERE blob_id != content_hash`).Scan(&repointed); err != nil {
		t.Fatal(err)
	}
	if repointed != 0 {
		t.Fatalf("有 %d 条 HEAD 被改到了新 id，但 blob 已经改回旧 id —— 悬空引用", repointed)
	}
	assertNoDanglingRefs(t, d, blobDir)

	// 4) 去掉注入后续跑必须能收敛：失败是可重试的，不是终态
	if _, err := d.Exec(`DROP TRIGGER block_repoint`); err != nil {
		t.Fatal(err)
	}
	rep2, err := db.MigrateBlobIDs(d, scope, secret, blobs, true, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Renamed != 2 || rep2.Failed != 0 {
		t.Fatalf("移除故障后应当全部成功：%+v", rep2)
	}
	assertNoDanglingRefs(t, d, blobDir)
}

// 重复执行必须幂等：已经迁移过的全部落到 Skipped，不再改动任何东西。
// 覆盖 INV-11：重复执行幂等。
func TestBlobIDMigrationIsIdempotent(t *testing.T) {
	d, blobs, blobDir := newBlobEnv(t)
	secret, _ := seedBlobs(t, d, blobs, 4)
	scope := db.LegacyDefaultScope()

	if _, err := db.MigrateBlobIDs(d, scope, secret, blobs, true, quietLogger()); err != nil {
		t.Fatal(err)
	}
	rep, err := db.MigrateBlobIDs(d, scope, secret, blobs, true, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Renamed != 0 || rep.Failed != 0 || rep.Skipped != 4 {
		t.Fatalf("重复执行应当全部 skip：%+v", rep)
	}
	assertNoDanglingRefs(t, d, blobDir)
}

// NeedsBlobIDMigration 必须在迁移完成后转为 false，否则每次启动都会重跑。
func TestNeedsBlobIDMigrationFlips(t *testing.T) {
	d, blobs, _ := newBlobEnv(t)
	secret, _ := seedBlobs(t, d, blobs, 3)

	need, err := db.NeedsBlobIDMigration(d)
	if err != nil {
		t.Fatal(err)
	}
	if !need {
		t.Fatal("存量裸 contentHash 的库必须被识别为待迁移")
	}
	if _, err := db.MigrateBlobIDs(d, db.LegacyDefaultScope(), secret, blobs, true, quietLogger()); err != nil {
		t.Fatal(err)
	}
	need, err = db.NeedsBlobIDMigration(d)
	if err != nil {
		t.Fatal(err)
	}
	if need {
		t.Fatal("迁移完成后不应再报告待迁移")
	}
}

// 零值范围与空 secret 都必须硬失败。
func TestBlobIDMigrationRejectsBadInput(t *testing.T) {
	d, blobs, _ := newBlobEnv(t)
	var zero db.VaultScope
	if _, err := db.MigrateBlobIDs(d, zero, []byte("x"), blobs, true, quietLogger()); !errors.Is(err, db.ErrVaultScopeMissing) {
		t.Fatalf("零值范围必须被拒，得到 %v", err)
	}
	if _, err := db.MigrateBlobIDs(d, db.LegacyDefaultScope(), nil, blobs, true, quietLogger()); err == nil {
		t.Fatal("空 secret 必须被拒——那会让 HMAC 退化成一个固定密钥，存在性泄露就回来了")
	}
}
