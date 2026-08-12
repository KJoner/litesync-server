package sync

import (
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
)

// 每 Vault 一把写锁（v0.16.0 / 计划书 §10.2）。
//
// 共用一把锁的话，一个租户的慢速大附件上传会把**所有**租户的写入一起挡住。
// 那不只是慢：外部看来是「别人一忙，我这边就卡住」，
// 一个租户的负载因此变成另一个租户可观测的信号。

func TestVaultLocksAreIndependent(t *testing.T) {
	s := &Service{}

	a := db.LegacyDefaultScope()
	b := db.ScopeFromAuth("tenant-b")

	if s.vaultMu(a) != s.vaultMu(a) {
		t.Fatal("同一个 Vault 必须拿到同一把锁，否则串行化失效")
	}
	if s.vaultMu(a) == s.vaultMu(b) {
		t.Fatal("不同 Vault 必须是不同的锁 —— 共用会让一个租户的负载阻塞另一个")
	}

	// 拿住 A 的锁，B 仍然必须能立刻拿到自己的
	s.vaultMu(a).Lock()
	defer s.vaultMu(a).Unlock()

	done := make(chan struct{})
	go func() {
		s.vaultMu(b).Lock()
		s.vaultMu(b).Unlock()
		close(done)
	}()
	<-done // 共用一把锁的话这里会永远等下去
}

// 零值范围拿到的是一把用完即弃的锁，而不是别人的那把。
func TestZeroScopeDoesNotShareALock(t *testing.T) {
	s := &Service{}
	var zero db.VaultScope

	if s.vaultMu(zero) == s.vaultMu(zero) {
		t.Fatal("零值范围每次都应当拿到全新的锁，不得复用")
	}
	if s.vaultMu(zero) == s.vaultMu(db.LegacyDefaultScope()) {
		t.Fatal("零值范围绝不能拿到默认租户的锁 —— 那会把一个 bug 变成静默的跨租户写入")
	}
}
