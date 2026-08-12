package storage_test

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"testing"

	"github.com/KJoner/litesync-server/internal/storage"
)

// Vault 域 blobID（v0.16.0 / §10.3、ADR-010 §4）。
//
// 这一组测试要证明的核心性质只有一条：**一个租户无法通过任何可观测的
// 行为，判断另一个租户是否持有某份内容**。

func contentHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// 同一份内容在不同 Vault 里必须得到完全不同的 blobID——
// 这就是存在性预言机被关掉的地方。
func TestBlobIDIsolatesVaults(t *testing.T) {
	secretA := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	secretB := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	h := contentHash("同一份被泄露的文档")

	idA := storage.BlobIDFor(secretA, h)
	idB := storage.BlobIDFor(secretB, h)

	if idA == idB {
		t.Fatal("同一份内容在两个 Vault 里得到了同一个 blobID —— 跨租户存在性泄露")
	}
	// 也不能与裸 contentHash 相同：否则旧的全局去重路径仍然可达
	if idA == h || idB == h {
		t.Fatal("blobID 不得等于裸 contentHash")
	}
}

// Vault 内部的去重必须完整保留——那是去重价值的绝大部分来源。
func TestBlobIDDeduplicatesWithinVault(t *testing.T) {
	secret := []byte("cccccccccccccccccccccccccccccccc")
	h := contentHash("同一个文件的第 7 个历史版本")

	if storage.BlobIDFor(secret, h) != storage.BlobIDFor(secret, h) {
		t.Fatal("同一 Vault 内同一份内容必须得到同一个 blobID（否则历史版本会重复存储）")
	}
}

// 输出必须仍是 64 位十六进制：BlobStore 的路径规则、Walk 的命名校验、
// 隔离区逻辑全都依赖这一点，改变它会牵动一大片。
func TestBlobIDKeepsStorageLayoutCompatible(t *testing.T) {
	hexRe := regexp.MustCompile(`^[0-9a-f]{64}$`)
	secret := []byte("dddddddddddddddddddddddddddddddd")
	for _, c := range []string{"a", "b", "很长的中文内容", ""} {
		id := storage.BlobIDFor(secret, contentHash(c))
		if !hexRe.MatchString(id) {
			t.Fatalf("blobID 必须是 64 位十六进制，得到 %q", id)
		}
	}
}

// 不同内容在同一 Vault 里必须得到不同 blobID（基本正确性）。
func TestBlobIDSeparatesDifferentContent(t *testing.T) {
	secret := []byte("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	if storage.BlobIDFor(secret, contentHash("x")) == storage.BlobIDFor(secret, contentHash("y")) {
		t.Fatal("不同内容必须得到不同 blobID")
	}
}

// secret 只要差一个字节，输出就必须完全不同——
// 否则相邻的 vaultSecret 之间会出现可利用的相关性。
func TestBlobIDIsSensitiveToSecret(t *testing.T) {
	h := contentHash("content")
	s1 := []byte("ffffffffffffffffffffffffffffffff")
	s2 := []byte("fffffffffffffffffffffffffffffffg")
	if storage.BlobIDFor(s1, h) == storage.BlobIDFor(s2, h) {
		t.Fatal("vaultSecret 变化必须导致 blobID 变化")
	}
}
