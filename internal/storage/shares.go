package storage

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

var ErrInvalidShareID = errors.New("invalid share id")

// ShareStore 保存分享的密文内容（服务器不持有 Share Key，无法解密）。
type ShareStore struct {
	root string
}

func NewShareStore(root string) (*ShareStore, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, err
	}
	return &ShareStore{root: abs}, nil
}

func validShareID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func (s *ShareStore) path(id string) (string, error) {
	if !validShareID(id) {
		return "", ErrInvalidShareID
	}
	return filepath.Join(s.root, id), nil
}

// Put 原子写入分享内容，返回字节数。
func (s *ShareStore) Put(id string, r io.Reader) (int64, error) {
	p, err := s.path(id)
	if err != nil {
		return 0, err
	}
	f, err := os.CreateTemp(s.root, tmpPrefix+"*")
	if err != nil {
		return 0, err
	}
	tmp := f.Name()
	size, err := io.Copy(f, r)
	if err != nil {
		f.Close()
		os.Remove(tmp)
		return 0, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return 0, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	return size, nil
}

func (s *ShareStore) Open(id string) (*os.File, error) {
	p, err := s.path(id)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

func (s *ShareStore) Remove(id string) error {
	p, err := s.path(id)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
