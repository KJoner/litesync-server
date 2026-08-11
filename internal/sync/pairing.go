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

// VaultID 返回（首次调用时生成）本仓库的稳定标识。
func (s *Service) VaultID() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.vaultIDLocked()
}

// vaultIDLocked：调用方必须已持有 s.mu。
func (s *Service) vaultIDLocked() (string, error) {
	id, ok, err := db.GetMeta(s.db, vaultIDMetaKey)
	if err != nil {
		return "", err
	}
	if ok && id != "" {
		return id, nil
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	id = hex.EncodeToString(raw)
	if err := db.SetMeta(s.db, vaultIDMetaKey, id, time.Now().Unix()); err != nil {
		return "", err
	}
	return id, nil
}

// CreatePairing 保存一次性配对密文，返回随机 id 与过期时间。
func (s *Service) CreatePairing(ciphertext string, ttl time.Duration) (string, int64, error) {
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
	if _, err := s.db.Exec(
		`INSERT INTO pairings (id, ciphertext, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		id, ciphertext, now.Unix(), expiresAt,
	); err != nil {
		return "", 0, err
	}
	return id, expiresAt, nil
}

// ConsumePairing 原子地取出并删除配对密文（仅允许消费一次）。
// 不存在 / 已消费 / 已过期一律返回 ErrPairingNotFound。
func (s *Service) ConsumePairing(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ciphertext string
	err := s.db.QueryRow(
		`DELETE FROM pairings WHERE id = ? AND expires_at > ? RETURNING ciphertext`,
		id, time.Now().Unix(),
	).Scan(&ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrPairingNotFound
	}
	if err != nil {
		return "", err
	}
	return ciphertext, nil
}

// DeletePairing 撤销配对（配对窗口关闭时调用；不存在视为成功）。
func (s *Service) DeletePairing(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM pairings WHERE id = ?`, id)
	return err
}

// maintainPairings 清理已过期的配对（正常路径消费即删，这里兜底）。
func (s *Service) maintainPairings(now int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM pairings WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return n, nil
}
