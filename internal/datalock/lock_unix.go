//go:build unix

package datalock

import (
	"errors"
	"os"
	"syscall"
)

func lockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrHeld
		}
		if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOLCK) {
			return nil, ErrUnsupported
		}
		return nil, err
	}
	return f, nil
}

func unlockFile(f *os.File) error {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:errcheck
	return f.Close()
}
