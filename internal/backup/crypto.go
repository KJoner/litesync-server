// Package backup 实现服务器旁路备份能力（v6）：
// 一致性快照 → Restic → S3 兼容对象存储（Cloudflare R2）。
//
// 安全边界：
//   - R2 凭据与 Restic 密码只存在于「AES-256-GCM 加密后的配置」中（SQLite vault_meta），
//     解密密钥在 /data 之外的 backup-config.key 文件里——单独复制 /data 拿不到凭据；
//   - 凭据只通过子进程环境变量传给 restic，绝不进入命令行参数与日志。
package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var ErrKeyUnavailable = errors.New("backup key file unavailable")

// LoadOrCreateKey 读取（不存在时生成）备份配置加密密钥。
// 文件内容为 64 个十六进制字符（32 字节），权限 0600。
// 生成失败（例如 Docker 只读挂载且宿主机未创建）返回错误，备份功能保持禁用。
func LoadOrCreateKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		key, derr := hex.DecodeString(strings.TrimSpace(string(raw)))
		if derr != nil || len(key) != 32 {
			return nil, fmt.Errorf("%w: %s is not 64 hex chars", ErrKeyUnavailable, path)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %v", ErrKeyUnavailable, err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyUnavailable, err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyUnavailable, err)
	}
	return key, nil
}

// seal 用 AES-256-GCM 加密并编码为 base64(nonce|ciphertext)。
func seal(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

// open 解密 seal 的输出；密钥不符或数据被篡改返回错误。
func open(key []byte, encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
}
