package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// 备份恢复（v0.13.3 / 计划书 §7.8）。
//
// 恢复是整个系统里最危险的操作：做对了能救回全部数据，做错了会**同时**毁掉
// 服务器上的和客户端上的。因此这里的每一步都偏保守：
//
//   - 恢复前先把现有数据目录整体挪到 `restore-backup-<时间戳>`，而不是原地覆盖。
//     恢复到一半失败时，现场还完整地留着。
//   - 恢复出的内容落到一个临时目录，全部就位之后才换上去。
//   - 恢复完成后**必须**旋转 repoEpoch（由调用方完成）——不旋转的话，
//     客户端会带着旧游标继续增量同步，静默跳过「恢复点之后曾经存在」的那段变更。

// RestoreResult 描述一次恢复的结果。
type RestoreResult struct {
	SnapshotID string
	// PreviousDataDir 是被挪开的旧数据目录；确认恢复无误后由管理员自行删除。
	// 自动删除是不可接受的：万一恢复的是错的快照，那就是唯一的退路。
	PreviousDataDir string
	DurationMs      int64
}

// Restore 从指定快照恢复数据目录。
//
// 调用前必须停止服务：这里会整体替换数据目录，运行中的服务会拿着已经被换掉的
// 文件句柄继续写，结果是两份都坏。
func (m *Manager) Restore(ctx context.Context, snapshotID string) (*RestoreResult, error) {
	if snapshotID == "" {
		return nil, fmt.Errorf("snapshot id is required")
	}
	cfg, err := m.snapshotCfg()
	if err != nil {
		return nil, err
	}
	release, err := m.acquireJob("restore")
	if err != nil {
		return nil, err
	}
	defer release()

	start := time.Now()
	m.log.Info("restore started", "snapshot", snapshotID)

	parent := filepath.Dir(m.dataDir)
	staging, err := os.MkdirTemp(parent, "restore-staging-*")
	if err != nil {
		return nil, fmt.Errorf("create staging dir: %w", err)
	}
	// 失败时清掉临时目录；成功时它已经被 rename 走了，Remove 无害
	defer os.RemoveAll(staging) //nolint:errcheck

	ctx, cancel := context.WithTimeout(ctx, longTimeout)
	defer cancel()
	if _, err := m.runner.Run(ctx,
		[]string{"restore", snapshotID, "--target", staging}, cfg.env(m.dataDir)); err != nil {
		return nil, fmt.Errorf("restic restore: %w", err)
	}

	// restic 会把原路径结构一起还原出来；找到里面的数据目录
	restored, err := locateRestoredDataDir(staging, filepath.Base(m.dataDir))
	if err != nil {
		return nil, err
	}

	// 旧数据目录挪开而不是删除——恢复错快照时这是唯一的退路
	previous := filepath.Join(parent, fmt.Sprintf("restore-backup-%d", start.Unix()))
	if _, err := os.Stat(m.dataDir); err == nil {
		if err := os.Rename(m.dataDir, previous); err != nil {
			return nil, fmt.Errorf("move current data dir aside: %w", err)
		}
	} else {
		previous = ""
	}

	if err := os.Rename(restored, m.dataDir); err != nil {
		// 换上失败 → 立刻把旧目录搬回去，回到调用前的状态
		if previous != "" {
			if rerr := os.Rename(previous, m.dataDir); rerr != nil {
				return nil, fmt.Errorf(
					"install restored data failed (%w) 且未能还原旧目录（旧数据仍在 %s，必须手工处理）", err, previous)
			}
		}
		return nil, fmt.Errorf("install restored data: %w", err)
	}

	res := &RestoreResult{
		SnapshotID:      snapshotID,
		PreviousDataDir: previous,
		DurationMs:      time.Since(start).Milliseconds(),
	}
	m.log.Info("restore completed", "snapshot", snapshotID, "durMs", res.DurationMs,
		"previousDataDir", previous != "")
	return res, nil
}

// locateRestoredDataDir 在 restic 还原出来的目录树里找到数据目录。
//
// restic 保留绝对路径结构（例如 <staging>/data 或 <staging>/srv/litesync/data），
// 所以不能假设它就在第一层。这里按目录名逐层找，找不到就报错——
// 猜一个目录然后把它当数据目录换上去，是不能接受的赌博。
func locateRestoredDataDir(staging, want string) (string, error) {
	var found string
	err := filepath.WalkDir(staging, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() || found != "" {
			return nil //nolint:nilerr
		}
		if d.Name() != want {
			return nil
		}
		// 认准「里面有 sync.db」才算数：同名目录未必是数据目录
		if _, serr := os.Stat(filepath.Join(p, "sync.db")); serr == nil {
			found = p
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("在恢复出的内容里找不到数据目录（期望名为 %q 且含 sync.db）", want)
	}
	return found, nil
}
