package mail

// 复审 SV-05：安全事件与业务变更同一事务落盘，worker 负责渲染与发送；队列满、进程崩溃、
// 投递已被接受但响应丢失都有结果记录。不连接任何真实邮件服务。
//
// 身份邮件（注册验证、找回密码，由 Keycloak 发送）不在这组测试的范围内——这里通过不代表它们
// 具备同样的耐久性与重试语义。

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

func eventRow(t *testing.T, d *sql.DB, userID string) (state, outcome, data string) {
	t.Helper()
	if err := d.QueryRow(`SELECT event_state, outcome, data FROM security_events WHERE user_id = ? ORDER BY id DESC LIMIT 1`, userID).
		Scan(&state, &outcome, &data); err != nil {
		t.Fatal(err)
	}
	return
}

// 业务事务提交之后、worker 处理之前进程退出：事件在库里，重启后的 worker 照常发出。
func TestSecurityEventSurvivesCrashBeforeProcessing(t *testing.T) {
	d := openDB(t)
	u := newUser(t, d, "alice", "alice@example.org", true)
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE users SET display_name = 'business change' WHERE user_id = ?`, u); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordSecurityEvent(tx, u, "device-enrolled", map[string]string{"eventId": "dev-1", "device": "我的手机"}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// ……这里进程退出：没有任何 worker 处理过它。重启：
	fp := &fakeProvider{}
	o, _ := newBox(t, d, fp)
	if n, err := o.ProcessEvents(); err != nil || n != 1 {
		t.Fatalf("restart processed %d events (%v), want 1", n, err)
	}
	if sent, _, _ := o.RunOnce(context.Background()); sent != 1 || !strings.Contains(fp.sent[0].Text, "我的手机") {
		t.Fatalf("restarted worker sent %d (%+v)", sent, fp.sent)
	}
	if st, outcome, data := eventRow(t, d, u); st != "done" || outcome != db.EventOutcomeMailQueued || data != "" {
		t.Fatalf("event after processing: %s / %s / data=%q (display fields must be cleared)", st, outcome, data)
	}
}

// 业务事务回滚：事件随之消失，不会发出一封「新设备已连接」却其实没有接入的通知。
func TestRolledBackBusinessLeavesNoEvent(t *testing.T) {
	d := openDB(t)
	u := newUser(t, d, "bob", "bob@example.org", true)
	tx, _ := d.Begin()
	if err := db.RecordSecurityEvent(tx, u, "device-enrolled", map[string]string{"eventId": "dev-x"}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	tx.Rollback() //nolint:errcheck
	o, _ := newBox(t, d, &fakeProvider{})
	if n, _ := o.ProcessEvents(); n != 0 {
		t.Fatalf("a rolled-back business change produced %d events", n)
	}
}

// 以前 256 条的内存队列满了就丢；现在没有内存队列：600 条事件（含旧入口 Notify）一条不少都处理掉。
func TestNoQueueToOverflow(t *testing.T) {
	d := openDB(t)
	fp := &fakeProvider{}
	o, _ := newBox(t, d, fp)
	const n = 600
	for i := 0; i < n; i++ {
		u := newUser(t, d, fmt.Sprintf("u%d", i), fmt.Sprintf("u%d@example.org", i), true)
		if i%2 == 0 {
			o.Notify(u, "device-enrolled", map[string]string{"eventId": "e"}) // 旧入口：独立事务落盘 + 唤醒
		} else if err := db.RecordSecurityEvent(d, u, "device-enrolled", map[string]string{"eventId": "e"}, time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := o.ProcessEvents(); err != nil || got != n {
		t.Fatalf("processed %d of %d events (%v)", got, n, err)
	}
	var queued int
	d.QueryRow(`SELECT COUNT(*) FROM mail_outbox WHERE status = 'queued'`).Scan(&queued) //nolint:errcheck
	if queued != n {
		t.Fatalf("queued %d mails, want %d (nothing may be dropped)", queued, n)
	}
	st, _ := db.GetSecurityEventStats(d)
	if st.Pending != 0 || st.ByOutcome[db.EventOutcomeMailQueued] != n {
		t.Fatalf("event stats = %+v", st)
	}
}

// 每条事件都有去向：没有已验证邮箱、收件人当日超限、没有模板、收件人被抑制、重复处理。
func TestEveryEventHasARecordedOutcome(t *testing.T) {
	d := openDB(t)
	o, _ := newBox(t, d, &fakeProvider{})
	unverified := newUser(t, d, "mallory", "mallory@example.org", false)
	_ = o.EnqueueNow(unverified, "token-reset", map[string]string{"eventId": "g1"})
	if _, outcome, _ := eventRow(t, d, unverified); outcome != db.EventOutcomeNoAddress {
		t.Fatalf("unverified address outcome = %s", outcome)
	}
	busy := newUser(t, d, "erin", "erin@example.org", true)
	for i := 0; i <= PerRecipientDaily; i++ {
		_ = o.EnqueueNow(busy, "device-enrolled", map[string]string{"eventId": fmt.Sprint(i)})
	}
	if _, outcome, _ := eventRow(t, d, busy); outcome != db.EventOutcomeRecipientLimit {
		t.Fatalf("over the per-recipient limit outcome = %s", outcome)
	}
	odd := newUser(t, d, "odd", "odd@example.org", true)
	_ = o.EnqueueNow(odd, "no-such-template", map[string]string{"eventId": "x"})
	if _, outcome, _ := eventRow(t, d, odd); outcome != db.EventOutcomeUnknownTemplate {
		t.Fatalf("unknown template outcome = %s", outcome)
	}
	bounced := newUser(t, d, "gone", "gone@example.org", true)
	if err := db.SuppressMail(d, "gone@example.org", "hard-bounce", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	_ = o.EnqueueNow(bounced, "vault-deleted", map[string]string{"eventId": "v"})
	if _, outcome, _ := eventRow(t, d, bounced); outcome != db.EventOutcomeSuppressed {
		t.Fatalf("suppressed recipient outcome = %s", outcome)
	}
	// 同一事件记两次：只有一条事件、一封邮件
	twice := newUser(t, d, "twice", "twice@example.org", true)
	_ = db.RecordSecurityEvent(d, twice, "token-reset", map[string]string{"eventId": "same"}, time.Now().Unix())
	_ = db.RecordSecurityEvent(d, twice, "token-reset", map[string]string{"eventId": "same"}, time.Now().Unix())
	if n, _ := o.ProcessEvents(); n != 1 {
		t.Fatalf("a duplicated event was processed %d times", n)
	}
	// 崩溃在「已入队、还没记去向」之间：重处理记为 duplicate，不会多出第二封
	again := newUser(t, d, "again", "again@example.org", true)
	_ = db.RecordSecurityEvent(d, again, "token-reset", map[string]string{"eventId": "g9"}, time.Now().Unix())
	if _, err := db.EnqueueMail(d, "token-reset:"+again+":g9", "token-reset", "again@example.org", "s", "b", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	_, _ = o.ProcessEvents()
	var mails int
	d.QueryRow(`SELECT COUNT(*) FROM mail_outbox WHERE idempotency_key = ?`, "token-reset:"+again+":g9").Scan(&mails) //nolint:errcheck
	if _, outcome, _ := eventRow(t, d, again); outcome != db.EventOutcomeDuplicate || mails != 1 {
		t.Fatalf("re-processing after a crash: outcome %s, mails %d", outcome, mails)
	}
}

// 发送中进程崩溃（已标记 sending、没记结果）：10 分钟后重新领取，用同一个幂等键再发一次。
func TestCrashWhileSendingIsReclaimedWithTheSameKey(t *testing.T) {
	d := openDB(t)
	u := newUser(t, d, "carl", "carl@example.org", true)
	o, c := newBox(t, d, &fakeProvider{})
	_ = o.EnqueueNow(u, "token-reset", map[string]string{"eventId": "g"})
	claimed, err := db.ClaimDueMail(d, c.t.Unix(), c.t.Add(-sendingStaleAfter).Unix(), 10)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim = %d %v", len(claimed), err)
	}
	// ……进程在 Send 之前或之后崩溃。重启后的 worker：
	fp := &fakeProvider{}
	o2, c2 := newBox(t, d, fp)
	c2.t = c.t
	if sent, _, _ := o2.RunOnce(context.Background()); sent != 0 {
		t.Fatal("a mail that is still within its sending window must not be sent twice concurrently")
	}
	c2.t = c2.t.Add(sendingStaleAfter + time.Minute)
	if sent, _, _ := o2.RunOnce(context.Background()); sent != 1 || fp.sent[0].IdempotencyKey != hashKey(claimed[0].IdemKey) {
		t.Fatalf("reclaimed mail: sent %d %+v", sent, fp.sent)
	}
}

// 服务商已经接受、响应丢了：记一次不确定的尝试（可见），同一幂等键退避重试；服务商按键去重，只投递一次。
type dedupProvider struct {
	calls     int
	keys      []string
	delivered map[string]string
	loseFirst bool
}

func (*dedupProvider) Name() string { return "dedup" }
func (p *dedupProvider) Send(_ context.Context, _, _ string, m Message) (string, error) {
	p.calls++
	p.keys = append(p.keys, m.IdempotencyKey)
	if id, ok := p.delivered[m.IdempotencyKey]; ok {
		return id, nil // Resend 的 Idempotency-Key 语义：同一键返回同一封
	}
	p.delivered[m.IdempotencyKey] = fmt.Sprintf("msg-%d", len(p.delivered)+1)
	if p.loseFirst {
		p.loseFirst = false
		return "", fmt.Errorf("%w: response lost", ErrOutcomeUnknown)
	}
	return p.delivered[m.IdempotencyKey], nil
}

func TestAcceptedButResponseLostIsRecorded(t *testing.T) {
	d := openDB(t)
	u := newUser(t, d, "dina", "dina@example.org", true)
	p := &dedupProvider{delivered: map[string]string{}, loseFirst: true}
	o, c := newBox(t, d, p)
	_ = o.EnqueueNow(u, "device-enrolled", map[string]string{"eventId": "d"})
	if _, retried, _ := o.RunOnce(context.Background()); retried != 1 {
		t.Fatal("an unknown outcome must be retried")
	}
	var st, code string
	var attempts, uncertain int
	d.QueryRow(`SELECT status, last_error_code, attempts, uncertain_attempts FROM mail_outbox`).Scan(&st, &code, &attempts, &uncertain) //nolint:errcheck
	if st != "queued" || code != "outcome-unknown" || attempts != 1 || uncertain != 1 {
		t.Fatalf("after a lost response: %s %s attempts=%d uncertain=%d", st, code, attempts, uncertain)
	}
	if s, _ := db.GetMailStats(d); s.Uncertain != 1 {
		t.Fatalf("admin stats must show the uncertain delivery: %+v", s)
	}
	c.t = c.t.Add(2 * time.Minute)
	if sent, _, _ := o.RunOnce(context.Background()); sent != 1 {
		t.Fatal("the retry must complete")
	}
	if p.calls != 2 || len(p.delivered) != 1 || p.keys[0] != p.keys[1] {
		t.Fatalf("retries must reuse the idempotency key: calls=%d delivered=%d keys=%v", p.calls, len(p.delivered), p.keys)
	}
	d.QueryRow(`SELECT status, uncertain_attempts FROM mail_outbox`).Scan(&st, &uncertain) //nolint:errcheck
	if st != "sent" || uncertain != 1 {
		t.Fatalf("final row: %s uncertain=%d (the uncertainty stays on record)", st, uncertain)
	}
}

// SMTP：250 已经拿到，QUIT 失败不算失败（以前会被重试、重复投递）；DATA 结束后没有应答 = 结果未知。
func TestSMTPAcceptedThenQuitFailsIsSuccess(t *testing.T) {
	cert, roots := selfSignedCert(t, "127.0.0.1")
	f := newFakeSMTP(t, cert, true, false)
	f.dropAfterData = true
	if _, err := smtpTo(f, TLSStartTLS, roots).Send(context.Background(), "no-reply@example.invalid", "", testMsg); err != nil {
		t.Fatalf("mail accepted (250) but QUIT failed = %v, want success", err)
	}
	g := newFakeSMTP(t, cert, true, false)
	g.silentAfterData = true
	if _, err := smtpTo(g, TLSStartTLS, roots).Send(context.Background(), "no-reply@example.invalid", "", testMsg); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("no reply after DATA = %v, want ErrOutcomeUnknown", err)
	}
}

// Resend：连接在请求发出之后断开 = 结果未知；连不上（请求没发出）= 普通临时失败。
func TestResendOutcomeUnknownVsNotSent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		conn.Close() // 读完请求就断：服务商可能已经处理
	}))
	defer srv.Close()
	p := &resendProvider{key: "re_test_not_real", url: srv.URL, client: srv.Client()}
	if _, err := p.Send(context.Background(), "a@example.invalid", "", testMsg); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("connection dropped after the request = %v, want ErrOutcomeUnknown", err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // 端口上没有服务：拨号失败
	p2 := &resendProvider{key: "re_test_not_real", url: "http://" + addr, client: &http.Client{Timeout: 2 * time.Second}}
	if _, err := p2.Send(context.Background(), "a@example.invalid", "", testMsg); err == nil || errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("connection refused = %v, want a plain transient error", err)
	}
}
