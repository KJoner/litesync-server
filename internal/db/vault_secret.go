package db

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
)

// Vault secret 的产生与读取（v0.16.0 / 计划书 §10.3、ADR-010 §4）。
//
// secret 是 blobID 域分隔的密钥：blobID = HMAC-SHA256(secret, contentHash)。
// 它只存在于服务端数据库里，绝不出现在任何 API 响应、日志或备份清单中——
// 泄露它等于把「能否自行算出别的 Vault 的 blobID」这条边界拆掉。
//
// # 为什么它不能丢
//
// secret 丢了，磁盘上的 blob 就再也无法与内容哈希对应起来：数据库里的
// blob_id 仍然指得到文件，所以**已有数据不会丢**；但新上传的内容会算出
// 与旧文件不同的 id，去重从此失效。因此 secret 必须与数据库同备份——
// 它就在 sync.db 里，备份数据库即备份 secret。

// EnsureVaultSecret 保证该 Vault 存在且有 secret，返回 secret。
//
// 首次调用时生成 32 字节随机值并落库；之后调用返回已有的那个。
// 这是幂等的：并发或重启都不会换掉一个已经在用的 secret（换掉 = 去重失效）。
func EnsureVaultSecret(d *sql.DB, s VaultScope, ownerID string) ([]byte, error) {
	if !s.Valid() {
		return nil, ErrVaultScopeMissing
	}
	v, err := GetVault(d, s)
	if err != nil {
		return nil, err
	}
	if v != nil && len(v.Secret) > 0 {
		return v.Secret, nil
	}

	secret := make([]byte, VaultSecretLen)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate vault secret: %w", err)
	}
	if v == nil {
		if err := InsertVault(d, &Vault{VaultID: s.ID(), OwnerID: ownerID, Secret: secret}); err != nil {
			return nil, err
		}
	} else {
		// Vault 行在（历史遗留），只是缺 secret：补上，但绝不覆盖已有值
		if _, err := d.Exec(
			`UPDATE vaults SET secret = ? WHERE vault_id = ? AND (secret IS NULL OR length(secret) = 0)`,
			secret, s.ID()); err != nil {
			return nil, err
		}
	}
	// 回读一次：如果另一个进程抢先写入，用它写的那个，不用我们刚生成的
	v, err = GetVault(d, s)
	if err != nil {
		return nil, err
	}
	if v == nil || len(v.Secret) == 0 {
		return nil, errors.New("vault secret 落库后仍读不到")
	}
	return v.Secret, nil
}

// VaultSecretLen 是 secret 的字节长度，与 storage.VaultSecretLen 一致。
// 这里重复定义是为了不让 db 依赖 storage（依赖方向是 storage → db 之外的单向）。
const VaultSecretLen = 32
