package api_test

// 复审 SV-05 的接线：每个会发安全通知的业务操作都在**自己的事务里**写下安全事件——不依赖
// 任何内存队列，也不依赖投递端是否在运行。这里故意不装 Outbox（模拟「业务成功之后、通知落盘之前
// 进程退出」的那种窗口已经不存在）：事件照样在库里；之后装上投递端，全部被处理成邮件。
// 覆盖 INV-12（事件按账号归属）。

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/KJoner/litesync-server/internal/mail"
)

type captureProvider struct{ sent []mail.Message }

func (*captureProvider) Name() string { return "capture" }
func (c *captureProvider) Send(_ context.Context, _, _ string, m mail.Message) (string, error) {
	c.sent = append(c.sent, m)
	return "id-" + m.IdempotencyKey, nil
}

func TestSecurityEventsAreDurableWithBusinessChanges(t *testing.T) {
	e := newRevocationEnv(t, nil, false)
	b, alice := e.loginAs(t, "sam-sub")
	vault := mustVault(t, e, alice, "个人笔记")
	second := mustVault(t, e, alice, "第二个仓库")
	redeemDevice(t, e.testEnv, b.grant(vault), "exch_sam_device_0001", vault) // device-enrolled
	if r, _ := b.do(http.MethodDelete, "/api/v1/vaults/"+second, map[string]any{"confirmName": "第二个仓库"}, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("delete vault = %d", r.StatusCode) // vault-deleted
	}
	if r, _ := b.do(http.MethodPost, "/api/v1/account/token-reset", map[string]any{}, map[string]string{"X-Vault-ID": vault}); r.StatusCode != http.StatusOK {
		t.Fatalf("token reset = %d", r.StatusCode) // token-reset
	}
	if r, _ := b.do(http.MethodPost, "/api/v2/account/logout-devices", nil, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("logout-devices = %d", r.StatusCode) // logout-devices
	}

	rows, err := e.db.Query(`SELECT event, event_state FROM security_events WHERE user_id = ? ORDER BY id`, alice)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var ev, st string
		rows.Scan(&ev, &st) //nolint:errcheck
		if st != "pending" {
			t.Fatalf("no outbox is running, the event must still be pending: %s %s", ev, st)
		}
		got = append(got, ev)
	}
	rows.Close()
	want := []string{"device-enrolled", "vault-deleted", "token-reset", "logout-devices"}
	if len(got) != len(want) {
		t.Fatalf("security events = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("security events = %v, want %v", got, want)
		}
	}

	// 投递端「重启」之后全部处理掉
	cp := &captureProvider{}
	box := mail.NewOutbox(e.db, cp, mail.Config{From: "LiteSync <no-reply@example.invalid>", PublicURL: "https://sync.example.invalid"},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if n, err := box.ProcessEvents(); err != nil || n != len(want) {
		t.Fatalf("processed %d events (%v)", n, err)
	}
	if sent, _, _ := box.RunOnce(context.Background()); sent != len(want) || len(cp.sent) != len(want) {
		t.Fatalf("sent %d mails, want %d", sent, len(want))
	}
	for _, m := range cp.sent {
		if m.To != "sam-sub@example.org" {
			t.Fatalf("mail went to %q", m.To)
		}
	}
}
