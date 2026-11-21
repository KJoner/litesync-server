package api

import (
	"net/http"
	"time"
)

// ShiftOIDCClock 把会话复核用的时钟拨快 d（只在测试构建中存在）；返回恢复函数。
func ShiftOIDCClock(d time.Duration) (restore func()) {
	old := oidcNow
	oidcNow = func() time.Time { return old().Add(d) }
	return func() { oidcNow = old }
}

// ForceSessionRevalidation 让所有现存会话在下一次请求时立即向身份服务复核。
func ForceSessionRevalidation(_ http.Handler) {
	oidcNow = func() time.Time { return time.Now().Add(sessionRevalidate + time.Minute) }
}

// ResetOIDCClock 恢复真实时钟。
func ResetOIDCClock() { oidcNow = time.Now }

// ShiftCentralClock 把中心状态检查（ADR-019 §2.5）的时钟拨快 d；返回恢复函数。
func ShiftCentralClock(d time.Duration) (restore func()) {
	old := centralNow
	centralNow = func() time.Time { return old().Add(d) }
	return func() { centralNow = old }
}

// SetCentralCheckTimeout 临时改变中心状态检查的超时；返回恢复函数。
func SetCentralCheckTimeout(d time.Duration) (restore func()) {
	old := centralCheckTimeout
	centralCheckTimeout = d
	return func() { centralCheckTimeout = old }
}
