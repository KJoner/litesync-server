package backup

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/failpoint"
)

// stagingName 固定不变：restic 按 host+paths 分组快照，
// 路径稳定才能让 forget 的 keep-last/keep-daily 策略正确聚合。
const stagingName = "current"

// Quiescer 由 sync.Service 实现：短暂持有全局写锁，保证快照一致性。
//
// 契约（0.17.1 实测死锁修正）：latestSequence 由实现方**在锁内读好**传给 fn。
// 之前的接口是 fn 里回调 `q.LatestSequence()`——而 sync.Service 的实现自己
// 也要拿同一把锁，Go 互斥锁不可重入 → 线上第一次跑备份就整库死锁
//（CLI 与测试替身的 WithGlobalLock 都是无锁直通，恰好全部绕过了真实实现）。
// 现在闭包拿到的只是一个值，从接口层面消灭「闭包里回调加锁方法」这类错误。
type Quiescer interface {
	WithGlobalLock(fn func(latestSequence int64) error) error
}

// Manifest 写入 staging 根目录，恢复时用于确认备份完整性与版本。
type Manifest struct {
	Format          int    `json:"format"`
	CreatedAt       int64  `json:"createdAt"`
	LitesyncVersion string `json:"litesyncVersion"`
	SchemaVersion   int    `json:"schemaVersion"`
	LatestSequence  int64  `json:"latestSequence"`

	// 批次 G：元数据来自哪种库、快照怎么做的。两种来源产出的 sync.db 格式相同
	//（都是当前 schema 的 SQLite 文件），所以任一来源的备份都能恢复到任一种部署。
	Database string `json:"database,omitempty"` // sqlite | postgres
	DBFormat string `json:"dbFormat,omitempty"` // sqlite-vacuum-into | sqlite-export
	// Blob 水位核对（MG-04「缺失对象明确报告」）：快照里的元数据引用了多少个 blob、
	// 其中有多少在 staging 里找不到。缺失不让备份失败（那会让一个已隔离的坏 blob
	// 挡住全部后续备份），但必须写进 manifest 与日志，恢复时再报告一次。
	ReferencedBlobs int64    `json:"referencedBlobs"`
	MissingBlobs    int64    `json:"missingBlobs"`
	MissingSample   []string `json:"missingBlobSample,omitempty"`
}

// buildStaging 生成一致性备份快照目录：
//
//	/data/.backup-staging/current/
//	├── sync.db              ← SQLite：VACUUM INTO；PostgreSQL：只读快照事务导出（见下）
//	├── blobs/               ← hard link（同一文件系统零拷贝；blob 不可变所以安全）
//	├── shares/              ← hard link
//	├── vaults/              ← hard link（旧版遗留目录，存在才复制）
//	└── backup-manifest.json
//
// 整个构建过程持有 LiteSync 全局写锁（VACUUM INTO + hardlink 都是秒级操作），
// 锁释放后 restic 慢慢读 staging，不再阻塞同步。
//
// PostgreSQL 部署（批次 G）：不能用 VACUUM INTO。改为在同一个全局写锁窗口里，
// 用 REPEATABLE READ READ ONLY 事务把 PG 导出成一个当前 schema 的 SQLite 文件
//（db.ExportToSQLiteFile，导出后逐表摘要校验），再 hard link blob。元数据快照与
// blob 清单取自同一时刻——这个锁窗口就是 blob 保留水位：锁内没有上传提交、没有 GC 删除。
// 选导出而不是 pg_dump：恢复流程与格式和 SQLite 部署完全一致、不依赖与服务端
// 主版本匹配的 pg_dump 二进制、导出自带校验。
func buildStaging(database *sql.DB, q Quiescer, dataDir, version string) (string, error) {
	root := filepath.Join(dataDir, ".backup-staging")
	staging := filepath.Join(root, stagingName)
	// 清理上次崩溃遗留
	if err := os.RemoveAll(staging); err != nil {
		return "", fmt.Errorf("clean staging: %w", err)
	}
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return "", err
	}

	m := Manifest{Format: 1, LitesyncVersion: version, SchemaVersion: 1, Database: "sqlite", DBFormat: "sqlite-vacuum-into"}
	err := q.WithGlobalLock(func(latestSequence int64) error {
		dbCopy := filepath.Join(staging, "sync.db")
		if db.IsPostgres(database) {
			// PG 一致性快照：只读快照事务导出 + 导出后校验
			m.Database, m.DBFormat = "postgres", "sqlite-export"
			if _, err := db.ExportToSQLiteFile(database, dbCopy); err != nil {
				return fmt.Errorf("export postgres snapshot: %w", err)
			}
		} else if _, err := database.Exec(`VACUUM INTO ?`, dbCopy); err != nil {
			// SQLite 一致性快照：VACUUM INTO 产出独立、紧凑的数据库文件
			return fmt.Errorf("vacuum into: %w", err)
		}

		// §8.1 注入点：数据库快照已就位、blob 尚未 link。此刻崩溃留下的是一个
		// 不完整的 staging 目录——下次备份会先清空它重做，绝不能被当成有效备份
		if err := failpoint.Eval(failpoint.BackupStaging); err != nil {
			return err
		}
		for _, dir := range []string{"blobs", "shares", "vaults"} {
			src := filepath.Join(dataDir, dir)
			if _, err := os.Stat(src); err != nil {
				continue // 目录尚不存在（如全新部署没有 shares）
			}
			if err := linkTree(src, filepath.Join(staging, dir)); err != nil {
				return fmt.Errorf("stage %s: %w", dir, err)
			}
		}

		m.CreatedAt = time.Now().Unix()
		m.LatestSequence = latestSequence
		return nil
	})
	if err == nil {
		// staging 在锁释放后不再变化：在锁外核对「快照引用的 blob 是否都在 staging 里」
		var ref int64
		var missing []string
		if ref, missing, err = checkBlobs(filepath.Join(staging, "sync.db"), filepath.Join(staging, "blobs")); err == nil {
			m.ReferencedBlobs, m.MissingBlobs = ref, int64(len(missing))
			m.MissingSample = sampleIDs(missing)
			var raw []byte
			if raw, err = json.MarshalIndent(m, "", "  "); err == nil {
				err = os.WriteFile(filepath.Join(staging, "backup-manifest.json"), raw, 0o600)
			}
		}
	}
	if err != nil {
		os.RemoveAll(staging) //nolint:errcheck
		return "", err
	}
	return staging, nil
}

// checkBlobs 打开一份快照 sync.db（只读），列出它引用的 blob，返回其中在 blobDir 里
// 找不到的（布局与 storage.BlobStore 一致：<id 前两位>/<id>）。
func checkBlobs(snapshot, blobDir string) (referenced int64, missing []string, err error) {
	snap, err := db.OpenSQLiteReadOnly(snapshot)
	if err != nil {
		return 0, nil, fmt.Errorf("open snapshot for blob check: %w", err)
	}
	defer snap.Close()
	ids, err := db.ReferencedBlobIDs(snap)
	if err != nil {
		return 0, nil, fmt.Errorf("list referenced blobs: %w", err)
	}
	for _, id := range ids {
		if len(id) < 3 || strings.ContainsAny(id, `/\.`) {
			missing = append(missing, id) // 非法 id 不可能对应一个文件，按缺失报告
			continue
		}
		if _, serr := os.Stat(filepath.Join(blobDir, id[:2], id)); serr != nil {
			missing = append(missing, id)
		}
	}
	return int64(len(ids)), missing, nil
}

// sampleIDs 只保留前 20 个缺失 id（报告可读；完整清单可由运维命令重算）。
func sampleIDs(ids []string) []string {
	if len(ids) > 20 {
		return append([]string(nil), ids[:20]...)
	}
	return ids
}

func cleanStaging(dataDir string) {
	os.RemoveAll(filepath.Join(dataDir, ".backup-staging")) //nolint:errcheck
}

// linkTree 把 src 目录树复制到 dst：优先 hard link（同一文件系统零拷贝），
// 失败时回退为普通复制。跳过临时文件。
func linkTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if strings.HasPrefix(d.Name(), ".obsync-tmp-") {
			return nil
		}
		if err := os.Link(path, target); err == nil {
			return nil
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
