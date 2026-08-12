// Package failpoint 提供测试专用的故障注入点（v0.14.0-RC / 计划书 §8.1）。
//
// 为什么需要它：崩溃恢复的正确性无法靠「跑一遍看看」证明。一次上传要经过
// 收流 → 写临时文件 → fsync → rename → 事务开始 → 写 HEAD → 写 change →
// commit → 发响应 这么多步，其中任何一步之后断电，系统都必须落在一个
// 可以安全重试的状态上。这些窗口在真实运行中几乎不可能复现，只能主动注入。
//
// # 生产构建的安全性
//
// 计划书要求「生产构建不得允许外部任意触发」。这里的做法是：
//
//   - 触发表是包级私有变量，只有同进程内的 Go 代码能写；
//   - 没有任何 HTTP / 环境变量 / 配置文件入口能激活 failpoint；
//   - Enable/Disable 只在 _test.go 里被调用（`make lint` 之外，
//     failpoint_prod_test.go 里有一条测试专门断言这一点）。
//
// 也就是说：failpoint 的代码在生产二进制里，但**没有任何外部输入能让它触发**。
// 相比 build tag 方案，这样做的好处是被注入的那条代码路径在生产和测试里
// 完全一致——用 build tag 隔离出来的测试，测的其实是另一份代码。
package failpoint

import (
	"errors"
	"sync"
)

// ErrInjected 是默认注入的错误。测试可以用 errors.Is 判断。
var ErrInjected = errors.New("failpoint: injected failure")

// Action 是一个 failpoint 被触发时执行的动作。
// 返回非 nil 错误时，被注入的代码路径必须按真实错误处理。
type Action func() error

var (
	mu     sync.RWMutex
	active map[string]*entry
)

type entry struct {
	action Action
	// remaining < 0 表示一直触发；> 0 时每次触发递减，归零后自动失效
	remaining int
	hits      int
}

// Eval 在给定 failpoint 处求值。没有激活的注入时返回 nil（零开销路径）。
//
// 调用约定：把它放在**真实故障可能发生的那个位置**，并且像对待真实错误一样
// 处理返回值。写成 `_ = failpoint.Eval(...)` 就失去了全部意义。
func Eval(name string) error {
	mu.RLock()
	e, ok := active[name]
	mu.RUnlock()
	if !ok {
		return nil
	}

	mu.Lock()
	defer mu.Unlock()
	// 双重检查：拿到写锁之前可能已经被别的 goroutine 用完了
	e, ok = active[name]
	if !ok {
		return nil
	}
	e.hits++
	if e.remaining > 0 {
		e.remaining--
		if e.remaining == 0 {
			delete(active, name)
		}
	}
	action := e.action
	if action == nil {
		return ErrInjected
	}
	return action()
}

// Enable 激活一个 failpoint，返回关闭函数。
// times < 0 表示一直生效；times > 0 表示只触发指定次数。
func Enable(name string, times int, action Action) func() {
	mu.Lock()
	if active == nil {
		active = make(map[string]*entry)
	}
	active[name] = &entry{action: action, remaining: times}
	mu.Unlock()
	return func() { Disable(name) }
}

// EnableError 是最常用的形态：在该点返回一个错误。
func EnableError(name string, times int) func() {
	return Enable(name, times, nil)
}

// Disable 取消一个 failpoint。
func Disable(name string) {
	mu.Lock()
	delete(active, name)
	mu.Unlock()
}

// Hits 返回某个 failpoint 至今被求值命中的次数（断言「确实走到了那个点」用）。
func Hits(name string) int {
	mu.RLock()
	defer mu.RUnlock()
	if e, ok := active[name]; ok {
		return e.hits
	}
	return 0
}

// Reset 清空所有注入（测试收尾用）。
func Reset() {
	mu.Lock()
	active = nil
	mu.Unlock()
}

// ActiveCount 返回当前激活的 failpoint 数量。
// 生产二进制里它必须恒为 0——没有任何外部入口能让它变成别的值。
func ActiveCount() int {
	mu.RLock()
	defer mu.RUnlock()
	return len(active)
}

// 计划书 §8.1 列出的服务端注入点。集中定义避免各处拼字符串拼错。
const (
	BlobAfterTempFsync = "blob.after-temp-fsync"
	BlobBeforeRename   = "blob.before-rename"
	BlobAfterRename    = "blob.after-rename"
	DBBeforeCommit     = "db.before-commit"
	DBAfterCommit      = "db.after-commit"
	ResponseBeforeSend = "response.before-send"
	ChangeBeforeHead   = "change.before-head-sequence"
	MigrationEachObj   = "migration.each-object"
	MigrationBeforeDone = "migration.before-complete"
	WALCheckpoint      = "db.wal-checkpoint"
	Vacuum             = "db.vacuum"
	GCBeforeDelete     = "gc.before-delete"
	BackupStaging      = "backup.staging"
	RestoreBeforeEpoch = "restore.before-epoch-rotate"
)
