package sync

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// v8 新设备接入：
//   - VaultID：这个同步仓库的稳定身份。客户端 Bootstrap 后保存；
//     Server URL 不变但 vaultId 变了（重装/换库）时客户端停止自动同步重新接入。
//   - Pairing：一次性加密配对包。服务器只代存密文（解密密钥在配对链接的
//     #fragment 中，不会出现在任何请求里），短时效 + 消费即删。

const (
	vaultIDMetaKey = "vault-id"

	pairingDefaultTTL = 300 * time.Second // 5 分钟
	pairingMaxTTL     = 900 * time.Second
)

var ErrPairingNotFound = errors.New("pairing not found or expired")

// vaultIdentityLocked 返回该 Vault 的稳定身份（/api/v1/info 的 vaultId）。
// 调用方必须已持有 s.mu。
//
// v0.18 多 Vault 后身份存 vaults.identity。default vault 的值从
// vault_meta['vault-id'] 迁移拷贝——**这一步做错会让所有现有客户端
// 误判「服务器换库」而重新对账**；迁移后仍同步写回 vault_meta，
// 保证回滚到 v0.17 后客户端读到同一个身份。
func (s *Service) vaultIdentityLocked(scope db.VaultScope) (string, error) {
	id, err := db.VaultIdentity(s.db, scope)
	if err != nil {
		return "", err
	}
	if id != "" {
		return id, nil
	}
	isDefault := scope.ID() == db.DefaultVaultID
	if isDefault {
		legacy, ok, gerr := db.GetMeta(s.db, vaultIDMetaKey)
		if gerr != nil {
			return "", gerr
		}
		if ok && legacy != "" {
			return legacy, db.SetVaultIdentity(s.db, scope, legacy)
		}
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	id = hex.EncodeToString(raw)
	if err := db.SetVaultIdentity(s.db, scope, id); err != nil {
		return "", err
	}
	if isDefault {
		if err := db.SetMeta(s.db, vaultIDMetaKey, id, time.Now().Unix()); err != nil {
			return "", err
		}
	}
	return id, nil
}

// CreatePairing 保存一次性配对密文，返回随机 id 与过期时间。
// 归属（vault + 发行者 userID）取自认证上下文，撤销时只认发行者本人（PRE-03）。
func (s *Service) CreatePairing(scope db.VaultScope, userID, ciphertext string, ttl time.Duration) (string, int64, error) {
	if ttl <= 0 || ttl > pairingMaxTTL {
		ttl = pairingDefaultTTL
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", 0, err
	}
	id := hex.EncodeToString(raw)
	now := time.Now()
	expiresAt := now.Add(ttl).Unix()

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := db.InsertPairing(s.db, scope, userID, id, ciphertext, "", now.Unix(), expiresAt); err != nil {
		return "", 0, err
	}
	return id, expiresAt, nil
}

// ConsumePairing 原子地取出并删除配对密文（仅允许消费一次）。
// 不存在 / 已消费 / 已过期一律返回 ErrPairingNotFound。
func (s *Service) ConsumePairing(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ciphertext, ok, err := db.ConsumePairing(s.db, id, time.Now().Unix())
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrPairingNotFound
	}
	return ciphertext, nil
}

// DeletePairing 撤销配对（配对窗口关闭时调用）。
//
// 只有发行者本人（同一 vault、同一 user）能删；不属于调用者的与不存在的
// 一样「成功」返回——插件在关闭窗口时无条件调用它，而区分两种情况的响应
// 本身就是存在性预言机。v2 包连带作废尚未兑换的 grant（ADR-014）。
func (s *Service) DeletePairing(scope db.VaultScope, userID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inTx(func(tx *sql.Tx) error {
		grantID, deleted, err := db.DeletePairingOwned(tx, scope, userID, id)
		if err != nil || !deleted || grantID == "" {
			return err
		}
		return db.RevokeEnrollmentGrant(tx, grantID, time.Now().Unix())
	})
}

// maintainPairings 清理已过期的配对（正常路径消费即删，这里兜底）。
func (s *Service) maintainPairings(now int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.PrunePairings(s.db, now)
}

// inTx 在单个事务里执行 fn（调用方必须已持有 s.mu）。
//
// 注意：sync.db 是单连接池——fn 内部只能用 tx，任何对 s.db 的直接调用都会
// 等待这条连接而永远拿不到（死锁）。
func (s *Service) inTx(fn func(tx *sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback() //nolint:errcheck
		return err
	}
	return tx.Commit()
}
