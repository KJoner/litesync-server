// Package storage 负责 Vault 文件在服务器磁盘上的安全读写。
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

var (
	ErrInvalidPath  = errors.New("invalid path")
	ErrHashMismatch = errors.New("content hash mismatch")
)

const tmpPrefix = ".obsync-tmp-"

type Storage struct {
	root string
}

// New 创建以 root 为根目录的存储，root 不存在时自动创建。
func New(root string) (*Storage, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, err
	}
	return &Storage{root: abs}, nil
}

func (s *Storage) Root() string { return s.root }

// ValidatePath 校验客户端提供的 Vault 相对路径。
// 数据安全红线：服务器绝不信任客户端 path，任何逃逸都必须拒绝。
func ValidatePath(p string) error {
	if p == "" || len(p) > 1024 {
		return ErrInvalidPath
	}
	for _, r := range p {
		// 控制字符、反斜杠、冒号（Windows 盘符）一律拒绝
		if r < 0x20 || r == '\\' || r == ':' || r == 0x7f {
			return ErrInvalidPath
		}
	}
	if strings.HasPrefix(p, "/") {
		return ErrInvalidPath
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return ErrInvalidPath
		}
	}
	if !filepath.IsLocal(filepath.FromSlash(p)) {
		return ErrInvalidPath
	}
	return nil
}

// abs 将相对路径转换为根目录内的绝对路径，并再次确认没有逃逸。
func (s *Storage) abs(rel string) (string, error) {
	if err := ValidatePath(rel); err != nil {
		return "", err
	}
	p := filepath.Join(s.root, filepath.FromSlash(rel))
	if !strings.HasPrefix(p, s.root+string(filepath.Separator)) {
		return "", ErrInvalidPath
	}
	return p, nil
}

// WriteTemp 把内容流写入目标目录下的临时文件，返回临时文件路径、SHA-256 和大小。
// 调用方验证 hash 之后再调用 Promote 原子改名，失败则调用 Discard。
func (s *Storage) WriteTemp(rel string, r io.Reader) (tmpPath, hashHex string, size int64, err error) {
	abs, err := s.abs(rel)
	if err != nil {
		return "", "", 0, err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return "", "", 0, err
	}
	f, err := os.CreateTemp(filepath.Dir(abs), tmpPrefix+"*")
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
	// 防止断电导致半文件：先 fsync 再改名
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

// Promote 将临时文件原子地改名为正式文件。
func (s *Storage) Promote(tmpPath, rel string) error {
	abs, err := s.abs(rel)
	if err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, abs); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// Discard 丢弃临时文件。
func (s *Storage) Discard(tmpPath string) {
	if tmpPath != "" {
		os.Remove(tmpPath)
	}
}

// Open 打开正式文件用于读取。
func (s *Storage) Open(rel string) (*os.File, error) {
	abs, err := s.abs(rel)
	if err != nil {
		return nil, err
	}
	return os.Open(abs)
}

// Remove 删除正式文件（不存在视为成功），并清理由此产生的空目录。
func (s *Storage) Remove(rel string) error {
	abs, err := s.abs(rel)
	if err != nil {
		return err
	}
	if err := os.Remove(abs); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// 尽力清理空父目录，失败（非空）即停止
	dir := filepath.Dir(abs)
	for dir != s.root && strings.HasPrefix(dir, s.root+string(filepath.Separator)) {
		if err := os.Remove(dir); err != nil {
			break
		}
		dir = filepath.Dir(dir)
	}
	return nil
}

// CleanTempFiles 清理上次崩溃可能遗留的临时文件（启动时调用）。
func (s *Storage) CleanTempFiles() error {
	return filepath.WalkDir(s.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 尽力而为
		}
		if !d.IsDir() && strings.HasPrefix(d.Name(), tmpPrefix) {
			os.Remove(path)
		}
		return nil
	})
}
