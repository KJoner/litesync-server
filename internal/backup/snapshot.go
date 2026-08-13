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
}

// buildStaging 生成一致性备份快照目录：
//
//	/data/.backup-staging/current/
//	├── sync.db              ← VACUUM INTO（一致的单文件快照，不碰 -wal/-shm）
//	├── blobs/               ← hard link（同一文件系统零拷贝；blob 不可变所以安全）
//	├── shares/              ← hard link
//	├── vaults/              ← hard link（旧版遗留目录，存在才复制）
//	└── backup-manifest.json
//
// 整个构建过程持有 LiteSync 全局写锁（VACUUM INTO + hardlink 都是秒级操作），
// 锁释放后 restic 慢慢读 staging，不再阻塞同步。
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

	err := q.WithGlobalLock(func(latestSequence int64) error {
		// SQLite 一致性快照：VACUUM INTO 产出独立、紧凑的数据库文件
		dbCopy := filepath.Join(staging, "sync.db")
		if _, err := database.Exec(`VACUUM INTO ?`, dbCopy); err != nil {
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

		m := Manifest{
			Format:          1,
			CreatedAt:       time.Now().Unix(),
			LitesyncVersion: version,
			SchemaVersion:   1,
			LatestSequence:  latestSequence,
		}
		raw, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(staging, "backup-manifest.json"), raw, 0o600)
	})
	if err != nil {
		os.RemoveAll(staging) //nolint:errcheck
		return "", err
	}
	return staging, nil
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
