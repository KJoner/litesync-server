package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// Vault 域的 blob 标识（v0.16.0 / 计划书 §10.3、ADR-010 §4）。
//
// # 问题：全局内容寻址去重是一个存在性预言机
//
// 单用户阶段 blobID 就是内容的 sha256，同样的内容全局只存一份。多租户之后
// 这变成一个信息泄露：攻击者上传一份文件，看它是「秒传」还是真的传了，
// 就能判断**别的租户**是否持有同一份内容。
//
// 这不需要读到任何内容，就已经是实质性泄露——想想「你的公司里有没有人
// 存过这份被泄露的文档」这类问题。
//
// # 解法：按 Vault 域分隔
//
//	blobID = HMAC-SHA256(vaultSecret, contentHash)
//
// vaultSecret 每个 Vault 独立、只存服务端、绝不出现在任何响应里。
// 同一份内容在两个 Vault 里得到两个完全无关的 blobID，因此：
//
//   - 跨租户去重不可能发生 → 存在性预言机消失；
//   - Vault **内部**的去重完全保留 → 去重价值的绝大部分来源
//     （同一文件的多个历史版本、同一附件被多处引用）不受影响。
//
// # 为什么这个取舍很划算
//
// E2EE 之下，两个 Vault 用不同的 Vault Key 加密同一份明文，密文完全不同——
// **跨租户去重在加密仓库上本来就命中不了**。也就是说我们放弃的是一个在
// 主要使用场景下已经无效的优化，换来一条干净的隔离边界。

// BlobIDFor 计算某个 Vault 里某份内容的 blob 标识。
//
// contentHash 是内容的 sha256（十六进制）。返回值同样是 64 位十六进制，
// 因此 BlobStore 的路径规则、Walk 的命名校验、隔离区逻辑全都不需要改。
func BlobIDFor(vaultSecret []byte, contentHash string) string {
	mac := hmac.New(sha256.New, vaultSecret)
	// 带上用途前缀：同一个 vaultSecret 将来若被用于别的 HMAC，
	// 两者的输出空间不会互相干扰
	mac.Write([]byte("litesync/v1/blob-id:"))
	mac.Write([]byte(contentHash))
	return hex.EncodeToString(mac.Sum(nil))
}

// VaultSecretLen 是 vaultSecret 的字节长度。
//
// 32 字节即 HMAC-SHA256 的完整安全强度。更长没有收益，更短会削弱
// 「攻击者无法自行计算别的 Vault 的 blobID」这一性质。
const VaultSecretLen = 32

// RenameBlob 把一个 blob 从旧 id 改名到新 id（blobID 域化迁移用）。
//
// **幂等**：新 id 已存在且旧 id 已不在时返回 nil。这是续跑的前提——
// 崩溃恢复后重做同一条不能失败，否则迁移会永远卡在那一条上。
func (b *BlobStore) RenameBlob(oldID, newID string) error {
	src, err := b.path(oldID)
	if err != nil {
		return err
	}
	dst, err := b.path(newID)
	if err != nil {
		return err
	}
	if _, err := os.Stat(src); err != nil {
		// 旧的不在了：如果新的已经在，说明这一条上次已经做完了
		if _, derr := os.Stat(dst); derr == nil {
			return nil
		}
		return fmt.Errorf("blob %s 不存在，且目标 %s 也不存在", oldID[:12], newID[:12])
	}
	if _, err := os.Stat(dst); err == nil {
		// 两边都在：新的已就位，清掉旧的即可（同样是续跑场景）
		return os.Remove(src)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	syncDir(filepath.Dir(dst))
	return nil
}

// NewBlobID 实现 db.BlobRenamer：按 Vault secret 计算域化 id。
func (b *BlobStore) NewBlobID(vaultSecret []byte, contentHash string) string {
	return BlobIDFor(vaultSecret, contentHash)
}
