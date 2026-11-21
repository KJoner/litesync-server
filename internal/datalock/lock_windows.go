//go:build windows

package datalock

import (
	"errors"
	"os"
	"syscall"
)

// Windows：以「只共享读」方式打开锁文件即是独占锁——另一个进程想以写方式再打开会得到
// ERROR_SHARING_VIOLATION（只读打开仍然可以，Holder 读诊断信息用）；句柄随进程退出关闭，锁随之释放。
func lockFile(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		const errSharingViolation syscall.Errno = 32
		const errLockViolation syscall.Errno = 33
		if errors.Is(err, errSharingViolation) || errors.Is(err, errLockViolation) {
			return nil, ErrHeld
		}
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func unlockFile(f *os.File) error { return f.Close() }
