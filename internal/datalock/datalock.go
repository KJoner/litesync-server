// Package datalock 是数据目录的进程级独占锁（v0.20.1 / 复审 SV-03）。
//
// 运行中的 obsync 服务持有 <数据目录>/.obsync-server.lock 的独占锁，进程退出（包括崩溃、被杀）
// 时由操作系统自动释放——不存在「残留锁文件挡住启动」的问题。
//
// 两个用途：
//   - 同一数据目录只能运行一个服务：每 Vault 写锁、迁移租约都在进程内存里，两个进程同时写
//     同一份元数据会绕开它们；
//   - `obsync migrate-to-pg` 的「源库已停写」前置条件变成**机器可检查**的：拿不到锁 = 服务还在
//     运行，迁移直接拒绝；迁移期间持有锁，服务也无法在迁移中途被启动。
//
// 只覆盖同一台机器（同一内核）上的进程：容器共享同一个数据卷时同样有效；网络文件系统上的
// 锁语义取决于实现，平台不支持时返回 ErrUnsupported，调用方要把这件事如实告诉运维。
package datalock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileName 是锁文件名（位于数据目录内）。
const FileName = ".obsync-server.lock"

var (
	// ErrHeld：锁已被另一个进程持有（通常是正在运行的 obsync 服务）。
	ErrHeld = errors.New("data directory is locked by another running obsync process")
	// ErrUnsupported：这个平台 / 文件系统上无法取得独占锁。
	ErrUnsupported = errors.New("exclusive data-directory lock is not supported here")
)

// Lock 是一把已取得的锁。
type Lock struct {
	path string
	f    *os.File
}

// Acquire 取得 dir 的独占锁（不阻塞）：已被占用返回 ErrHeld。
// purpose 写进锁文件（只是给人看的诊断信息：谁、什么时候、为什么拿了锁）。
func Acquire(dir, purpose string) (*Lock, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, FileName)
	f, err := lockFile(path)
	if err != nil {
		return nil, err
	}
	// 诊断信息：截断后重写（持锁者独占，不会与别人交错）
	_ = f.Truncate(0)                                                                                                  //nolint:errcheck
	_, _ = fmt.Fprintf(f, "pid=%d purpose=%s since=%s\n", os.Getpid(), purpose, time.Now().UTC().Format(time.RFC3339)) //nolint:errcheck
	return &Lock{path: path, f: f}, nil
}

// Holder 读出当前锁文件里的诊断信息（拿不到锁时告诉运维是谁持有）。
func Holder(dir string) string {
	raw, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		return ""
	}
	if len(raw) > 200 {
		raw = raw[:200]
	}
	return string(raw)
}

// Release 释放锁（进程退出时操作系统也会释放）。
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := unlockFile(l.f)
	l.f = nil
	return err
}
