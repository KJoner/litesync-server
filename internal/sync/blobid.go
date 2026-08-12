package sync

import (
	"fmt"

	"github.com/KJoner/litesync-server/internal/db"
)

// blobID 域化迁移的服务端入口（v0.16.0 / 计划书 §10.3、ADR-010 §8 第 4 步）。
//
// # 为什么混合状态是安全的
//
// 迁移**不是**启动硬门槛。每一行的 blob_id 都自带「文件在哪」的答案：
// 老行指向裸 contentHash，新上传的行指向域化 id，两者各自都读得到。
// 因此没迁移的服务器照样正确工作，代价只是：
//
//   - 同一份内容可能同时以两个名字各存一份（去重跨越不了这条界）；
//   - 存在性预言机在**老数据**上依然成立。
//
// 第二条才是真正要尽快迁移的理由——§10.3 的隔离性质在迁移完成前不成立。
// 所以启动时会告警，但不会拒绝启动：拒绝启动只会逼运维在没备份的情况下
// 匆忙跑一个不可逆的迁移。

// NeedsBlobIDMigration 报告是否还有停留在裸 contentHash 上的 blob 引用。
func (s *Service) NeedsBlobIDMigration() (bool, error) {
	return db.NeedsBlobIDMigration(s.db)
}

// MigrateBlobIDs 把存量 blob 改名到 Vault 域 id。
//
// confirm=false 只做 dry-run。这一步不可逆（改名之后旧代码按裸 contentHash
// 找不到任何 blob），因此必须显式确认，且执行前应当有一次完整备份。
//
// 全程持 s.mu 并计入 busyOps：迁移在移动 blob，此时跑 GC 或 scrub 会得出
// 「blob 不见了」的错误结论。
func (s *Service) MigrateBlobIDs(confirm bool) (*db.BlobIDMigrationReport, error) {
	secret, err := s.vaultSecret()
	if err != nil {
		return nil, err
	}

	s.busyOps.Add(1)
	defer s.busyOps.Add(-1)
	s.mu.Lock()
	defer s.mu.Unlock()

	rep, err := db.MigrateBlobIDs(s.db, s.scope(), secret, s.blobs, confirm, s.log)
	if err != nil {
		return rep, err
	}
	if confirm && rep.Failed > 0 {
		return rep, fmt.Errorf("%d 个 blob 未能迁移；已完成的部分保持可读，重跑本命令即可续做", rep.Failed)
	}
	return rep, nil
}

// BlobIDOf 回答「这份内容在本 Vault 的磁盘上叫什么名字」。
//
// 给运维工具和测试用：域化之后不能再拿内容哈希拼路径了。
// 它不泄露 secret 本身，但**绝不可以接到任何 HTTP 处理器上**——
// 能问出别的 Vault 的 blobID，就等于把 §10.3 关掉的那个存在性预言机重新打开。
func (s *Service) BlobIDOf(contentHash string) (string, error) {
	return s.blobIDOf(contentHash)
}
