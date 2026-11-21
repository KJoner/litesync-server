package db_test

// 跨产品撤销事件 outbox 的领取与终态（v0.20.1 / ADR-019 §2.4「投递任务用租约领取」）。
// 设置了 LITESYNC_TEST_PG_DSN 时同一套断言在 PostgreSQL 上运行。不对应 INV 编号（投递可靠性）。

import (
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
)

func TestRevocationDeliveryLeaseAndTerminalState(t *testing.T) {
	d := openTestDB(t)
	const ev, peer = "00112233445566778899aabbccddeeff", "nexus"
	const now = int64(1_795_244_400)
	if err := db.InsertRevocationDelivery(d, ev, peer, `{"v":1}`, now, now+7*86400); err != nil {
		t.Fatal(err)
	}

	// 领取：到期的 pending 只能被领一次（attempts+1、到期推后到租约结束）
	if ok, err := db.ClaimRevocationDelivery(d, ev, peer, now, now+60); err != nil || !ok {
		t.Fatalf("first claim = %v %v", ok, err)
	}
	if ok, err := db.ClaimRevocationDelivery(d, ev, peer, now+1, now+61); err != nil || ok {
		t.Fatalf("a second worker claimed a leased delivery: %v %v", ok, err)
	}
	if due, err := db.DueRevocationDeliveries(d, now+59, 10); err != nil || len(due) != 0 {
		t.Fatalf("a leased delivery is listed as due: %v %v", due, err)
	}
	// 租约到期（领取者中途中断）：下一个 worker 接续
	if ok, err := db.ClaimRevocationDelivery(d, ev, peer, now+60, now+120); err != nil || !ok {
		t.Fatalf("claim after the lease expired = %v %v", ok, err)
	}
	got, err := db.GetRevocationDelivery(d, ev, peer)
	if err != nil || got == nil || got.Attempts != 2 || got.NextAttemptAt != now+120 {
		t.Fatalf("after two claims: %+v %v", got, err)
	}

	// 写回结果不改 attempts（只由领取递增）
	stale := *got
	stale.Attempts = 0
	stale.State, stale.DeliveredAt, stale.PeerResult, stale.UpdatedAt = db.DeliveryDelivered, now+61, "applied", now+61
	if written, err := db.UpdateRevocationDelivery(d, &stale); err != nil || !written {
		t.Fatalf("record delivered = %v %v", written, err)
	}
	// delivered 是终态：与「重新发送」重叠、较晚结束的那次尝试不得把它改回 pending / failed
	late := *got
	late.State, late.LastError, late.NextAttemptAt, late.UpdatedAt = db.DeliveryPending, "http-503", now+70, now+65
	if written, err := db.UpdateRevocationDelivery(d, &late); err != nil || written {
		t.Fatalf("a late attempt overwrote a delivered record: %v %v", written, err)
	}
	late.State = db.DeliveryFailed
	if written, err := db.UpdateRevocationDelivery(d, &late); err != nil || written {
		t.Fatalf("a late attempt marked a delivered record failed: %v %v", written, err)
	}
	final, _ := db.GetRevocationDelivery(d, ev, peer) //nolint:errcheck
	if final.State != db.DeliveryDelivered || final.PeerResult != "applied" || final.Attempts != 2 {
		t.Fatalf("final = %+v", final)
	}
	// 已送达的既不能再领取，也不会被「重新发送」重置
	if ok, _ := db.ClaimRevocationDelivery(d, ev, peer, now+1000, now+1060); ok { //nolint:errcheck
		t.Fatal("a delivered record was claimed again")
	}
	if n, err := db.ResetRevocationDeliveries(d, ev, now+1000, now+2000); err != nil || n != 0 {
		t.Fatalf("resend reset a delivered record: %d %v", n, err)
	}
}
