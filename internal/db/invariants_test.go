package db_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 不变量标注覆盖检查（计划书 §2 结尾）。
//
// §2 的最后一句是：「所有自动化测试都应标注自己覆盖了哪些 INV 编号。」
// 这句话如果没人检查，标注就会停在最早写的那几个文件里——本次检查正是这么
// 发现 INV-01、02、11、12 在服务端一个标注都没有的，而它们恰好是最核心的四条。
//
// 判据刻意宽松：只要编号出现在某个测试文件里就算。目的不是精确度量覆盖率
//（那做不到），而是让「加了一条不变量却没有任何测试提到它」无法悄悄发生。

// serverOwned 是服务端负责证明的不变量。客户端侧的由 litesync 仓库的
// scripts/check-inv.mjs 检查——两边各查各的，避免一个仓库替另一个背书。
var serverOwned = map[string]string{
	"INV-01": "服务端返回写入成功时，对应 Blob 已经持久化、存在且 hash 正确",
	"INV-02": "同一 repoEpoch 内 headSequence 永不下降；Snapshot 与返回 sequence 对应同一时刻",
	"INV-06": "删除事实必须保留，状态丢失或旧设备不能静默复活已删除内容",
	"INV-07": "加密信封只允许升级，不允许降级",
	"INV-08": "元数据加密完成后，DB / WAL / 日志 / Header / 分享记录 / 当前备份中不得出现真实路径",
	"INV-11": "所有迁移必须可恢复、可重复、幂等；验证失败不得进入 irreversible complete",
	"INV-12": "每个查询、变更、Blob 和 sequence 都必须限定到 vault",
}

func TestInvariantsAreAnnotated(t *testing.T) {
	root := repoRoot(t)

	counts := map[string]int{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil //nolint:nilerr
		}
		// 不数本文件自己：它列出全部编号，会让每一条都「有标注」
		if strings.HasSuffix(path, "invariants_test.go") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil //nolint:nilerr
		}
		text := string(data)
		for inv := range serverOwned {
			counts[inv] += strings.Count(text, inv)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var missing []string
	for inv, desc := range serverOwned {
		if counts[inv] == 0 {
			missing = append(missing, inv+"（"+desc+"）")
		}
	}
	if len(missing) > 0 {
		t.Fatalf("以下不变量没有任何测试标注覆盖：\n  %s\n"+
			"计划书 §2：「所有自动化测试都应标注自己覆盖了哪些 INV 编号。」\n"+
			"没有标注的不变量，等于没人在守它。",
			strings.Join(missing, "\n  "))
	}
}
