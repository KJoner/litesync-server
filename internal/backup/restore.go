package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/KJoner/litesync-server/internal/failpoint"
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

	// 用 `snapshotID:subfolder` 语法只还原数据目录**这一棵子树**，
	// 让它直接落在 staging 根上。
	//
	// 为什么不能用朴素的 `restore <id> --target <staging>`：restic 会把快照里的
	// 完整绝对路径结构一起重建出来。在 Windows 上那意味着先造出
	// `<staging>\C\Users\...` 这一串合成父目录，而 restic 随后要给每一层
	// 设置时间戳——对 `C\Users` 这种目录会得到 Access denied，restic 于是
	// 以 exit 1 结束整个恢复。
	//
	// 这个 bug 是灾备恢复实机演练发现的：用 fake runner 的单元测试永远看不到它，
	// 而它会让 Windows 上的恢复**完全不可用**——偏偏恢复正是最不能出问题的操作。
	// 快照里存的是 staging 目录（<dataDir>/.backup-staging/current），
	// 不是数据目录本身——buildStaging 先把一致的 sync.db 与 blob 硬链接
	// 汇到那里，再交给 restic。因此子树路径要指向 staging。
	snapshotRef := snapshotID + ":" + toSnapshotPath(
		filepath.Join(m.dataDir, ".backup-staging", "current"))
	if _, err := m.runner.Run(ctx,
		[]string{"restore", snapshotRef, "--target", staging}, cfg.env(m.dataDir)); err != nil {
		return nil, fmt.Errorf("restic restore: %w", err)
	}

	// 子树语法下，staging 本身就是还原出来的数据目录
	restored := staging
	if _, err := os.Stat(filepath.Join(restored, "sync.db")); err != nil {
		return nil, fmt.Errorf("恢复出的内容里没有 sync.db（快照 %s 可能不是一份完整的数据目录）", snapshotID)
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

	// §8.1 注入点：数据已换上、repoEpoch 尚未旋转。这是恢复流程里最危险的窗口——
	// 此刻起服务如果被启动，客户端会带着恢复点之前的旧游标继续增量同步，
	// 静默跳过恢复点之后的全部变更。因此调用方必须把「旋转失败」当作硬错误处理
	if err := failpoint.Eval(failpoint.RestoreBeforeEpoch); err != nil {
		return nil, err
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

// toSnapshotPath 把本机的数据目录路径转成 restic 快照里的路径形式。
//
// restic 在快照里统一用正斜杠，并且把 Windows 盘符表示成 `/C/Users/...`
//（去掉冒号）。不做这个转换的话，`snapshotID:subfolder` 会匹配不到任何东西，
// 恢复会以「快照里没有这个子目录」失败。
func toSnapshotPath(dataDir string) string {
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		abs = dataDir
	}
	p := filepath.ToSlash(abs)
	// "C:/Users/x" → "/C/Users/x"
	if len(p) > 1 && p[1] == ':' {
		p = "/" + p[:1] + p[2:]
	}
	return p
}
