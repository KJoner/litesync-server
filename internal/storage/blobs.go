package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var ErrInvalidBlobID = errors.New("invalid blob id")

// BlobStore 是内容寻址的不可变 blob 存储：/blobs/<hash[:2]>/<hash>。
// 相同内容只保存一份；写入后不再修改。
type BlobStore struct {
	root string
}

func NewBlobStore(root string) (*BlobStore, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, err
	}
	return &BlobStore{root: abs}, nil
}

func (b *BlobStore) path(hash string) (string, error) {
	if len(hash) != 64 {
		return "", ErrInvalidBlobID
	}
	for _, r := range hash {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", ErrInvalidBlobID
		}
	}
	return filepath.Join(b.root, hash[:2], hash), nil
}

func (b *BlobStore) Has(hash string) bool {
	p, err := b.path(hash)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// PutReader 将内容写入 blob（临时文件 → 校验 hash → 原子改名）。
// blob 已存在时直接成功（内容寻址天然去重）。
func (b *BlobStore) PutReader(hash string, r io.Reader) error {
	p, err := b.path(hash)
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), tmpPrefix+"*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), r); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != hash {
		os.Remove(tmp)
		return ErrHashMismatch
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// IngestVerify 把内容流写入临时文件并计算 SHA-256（不持有任何业务锁，供上传路径使用）。
// 调用方随后在锁内 Commit（原子入库）或 Discard。
func (b *BlobStore) IngestVerify(r io.Reader) (tmpPath, hashHex string, size int64, err error) {
	f, err := os.CreateTemp(b.root, tmpPrefix+"*")
	if err != nil {
		return "", "", 0, err
	}
	tmpPath = f.Name()
	h := sha256.New()
	size, err = io.Copy(io.MultiWriter(f, h), r)
	if err != nil {
		f.Close()
		os.Remove(tmpPath)
		return "", "", 0, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return "", "", 0, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return "", "", 0, err
	}
	return tmpPath, hex.EncodeToString(h.Sum(nil)), size, nil
}

// Commit 把 IngestVerify 的临时文件原子改名为 blob；blob 已存在则丢弃临时文件（去重）。
func (b *BlobStore) Commit(tmpPath, hash string) error {
	p, err := b.path(hash)
	if err != nil {
		os.Remove(tmpPath)
		return err
	}
	if _, err := os.Stat(p); err == nil {
		os.Remove(tmpPath)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, p); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// Discard 丢弃临时文件。
func (b *BlobStore) Discard(tmpPath string) {
	if tmpPath != "" {
		os.Remove(tmpPath)
	}
}

// Walk 遍历所有 blob（孤儿 GC 用），回调收到 hash 与文件信息。
func (b *BlobStore) Walk(fn func(hash string, info os.FileInfo) error) error {
	return filepath.WalkDir(b.root, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // 尽力而为
		}
		name := d.Name()
		if len(name) != 64 || strings.HasPrefix(name, tmpPrefix) {
			return nil
		}
		if _, perr := b.path(name); perr != nil {
			return nil // 非法命名，跳过
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil //nolint:nilerr
		}
		return fn(name, info)
	})
}

func (b *BlobStore) Open(hash string) (*os.File, error) {
	p, err := b.path(hash)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

// Remove 删除 blob（不存在视为成功），并尽力清理空的分片目录。
func (b *BlobStore) Remove(hash string) error {
	p, err := b.path(hash)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	os.Remove(filepath.Dir(p)) // 目录非空时失败，忽略
	return nil
}
