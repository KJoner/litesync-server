package mail

// 产品通知邮件（ADR-018）：覆盖验收 ID-08 的服务端部分——outbox 幂等、有限退避、
// 硬退信/投诉抑制、配置错误告警不拉黑收件人、日志与存储不留正文（真实投递另需授权的真实邮箱）。

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

type fakeProvider struct {
	errs  []error // 依次返回；用完后成功
	sent  []Message
	calls int
}

func (*fakeProvider) Name() string { return "fake" }
func (f *fakeProvider) Send(_ context.Context, _, _ string, m Message) (string, error) {
	f.calls++
	if len(f.errs) > 0 {
		e := f.errs[0]
		f.errs = f.errs[1:]
		if e != nil {
			return "", e
		}
	}
	f.sent = append(f.sent, m)
	return "msg-" + strconv.Itoa(len(f.sent)), nil
}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func newUser(t *testing.T, d *sql.DB, sub, email string, verified bool) string {
	t.Helper()
	id, _, err := db.CreateOIDCUser(d, "https://idp.example", sub, db.IdentityProfile{Email: email, EmailVerified: verified}, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newBox(t *testing.T, d *sql.DB, p Provider) (*Outbox, *clock) {
	c := &clock{t: time.Unix(1_795_132_800, 0)}
	o := NewOutbox(d, p, Config{From: "LiteSync <no-reply@mail.example.org>", PublicURL: "https://sync.example.org"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	o.now = c.now
	return o, c
}

func status(t *testing.T, d *sql.DB) (st, to, body string, attempts int) {
	t.Helper()
	if err := d.QueryRow(`SELECT status, to_addr, body_text, attempts FROM mail_outbox ORDER BY id DESC LIMIT 1`).Scan(&st, &to, &body, &attempts); err != nil {
		t.Fatal(err)
	}
	return
}

func TestRenderTemplates(t *testing.T) {
	for _, ev := range []string{"device-enrolled", "token-reset", "vault-deleted", "logout-everywhere"} {
		s, b, ok := Render(ev, map[string]string{"device": "我的手机", "vault": "个人笔记"}, "https://sync.example.org", time.Unix(0, 0))
		if !ok || s == "" || !strings.Contains(b, "https://sync.example.org/#/me") {
			t.Fatalf("%s: subject=%q ok=%v body=%q", ev, s, ok, b)
		}
	}
	if _, _, ok := Render("unknown", nil, "", time.Now()); ok {
		t.Fatal("unknown template must not render")
	}
}

func TestOutboxDeliversOnlyToVerifiedEmailAndClearsContent(t *testing.T) {
	d := openDB(t)
	fp := &fakeProvider{}
	o, _ := newBox(t, d, fp)
	verified := newUser(t, d, "alice", "alice@example.org", true)
	unverified := newUser(t, d, "mallory", "mallory@example.org", false)

	if err := o.EnqueueNow(unverified, "device-enrolled", map[string]string{"eventId": "d1"}); err != nil {
		t.Fatal(err)
	}
	var n int
	d.QueryRow(`SELECT COUNT(*) FROM mail_outbox`).Scan(&n) //nolint:errcheck
	if n != 0 {
		t.Fatal("an unverified address must never receive security notifications")
	}
	if err := o.EnqueueNow(verified, "device-enrolled", map[string]string{"eventId": "d1", "device": "我的手机"}); err != nil {
		t.Fatal(err)
	}
	// 同一事件重复入队 → 幂等
	_ = o.EnqueueNow(verified, "device-enrolled", map[string]string{"eventId": "d1", "device": "我的手机"})
	d.QueryRow(`SELECT COUNT(*) FROM mail_outbox`).Scan(&n) //nolint:errcheck
	if n != 1 {
		t.Fatalf("idempotent enqueue produced %d rows", n)
	}
	if sent, _, _ := o.RunOnce(context.Background()); sent != 1 || len(fp.sent) != 1 || fp.sent[0].To != "alice@example.org" {
		t.Fatalf("delivery: sent=%d provider=%v", sent, fp.sent)
	}
	if !strings.Contains(fp.sent[0].Text, "我的手机") || strings.Contains(fp.sent[0].IdempotencyKey, verified) {
		t.Fatalf("rendered mail / opaque idempotency key wrong: %+v", fp.sent[0])
	}
	if st, to, body, _ := status(t, d); st != "sent" || to != "" || body != "" {
		t.Fatalf("after send: status=%s to=%q body=%q (address and body must be cleared)", st, to, body)
	}
}

func TestOutboxRetriesTransientThenGivesUp(t *testing.T) {
	d := openDB(t)
	transient := errors.New("connection reset")
	fp := &fakeProvider{errs: []error{transient, transient, transient, transient, transient, transient}}
	o, c := newBox(t, d, fp)
	u := newUser(t, d, "bob", "bob@example.org", true)
	_ = o.EnqueueNow(u, "token-reset", map[string]string{"eventId": "g2"})
	for i := 1; i < MaxAttempts; i++ {
		if _, retried, _ := o.RunOnce(context.Background()); retried != 1 {
			t.Fatalf("attempt %d should be retried", i)
		}
		if _, retried, _ := o.RunOnce(context.Background()); retried != 0 {
			t.Fatal("must not retry before the backoff elapses")
		}
		c.t = c.t.Add(7 * time.Hour)
	}
	if _, _, failed := o.RunOnce(context.Background()); failed != 1 {
		t.Fatal("after MaxAttempts the mail must be marked failed")
	}
	st, to, _, attempts := status(t, d)
	if st != "failed" || to != "" || attempts != MaxAttempts {
		t.Fatalf("status=%s to=%q attempts=%d", st, to, attempts)
	}
	// 临时失败用尽不拉黑收件人
	_ = o.EnqueueNow(u, "token-reset", map[string]string{"eventId": "g3"})
	if st, _, _, _ := status(t, d); st != "queued" {
		t.Fatalf("a transient give-up must not suppress the recipient, got %s", st)
	}
}

func TestOutboxPermanentSuppressesButConfigErrorDoesNot(t *testing.T) {
	d := openDB(t)
	fp := &fakeProvider{errs: []error{fmt.Errorf("%w: smtp 550", ErrPermanent)}}
	o, _ := newBox(t, d, fp)
	u := newUser(t, d, "carol", "carol@example.org", true)
	_ = o.EnqueueNow(u, "vault-deleted", map[string]string{"eventId": "v1"})
	if _, _, failed := o.RunOnce(context.Background()); failed != 1 {
		t.Fatal("permanent failure must be final")
	}
	_ = o.EnqueueNow(u, "vault-deleted", map[string]string{"eventId": "v2"})
	if st, to, _, _ := status(t, d); st != "suppressed" || to != "" {
		t.Fatalf("after a hard bounce the recipient must be suppressed, got %s to=%q", st, to)
	}
	if fp.calls != 1 {
		t.Fatalf("suppressed mail must not reach the provider (calls=%d)", fp.calls)
	}

	d2 := openDB(t)
	fp2 := &fakeProvider{errs: []error{fmt.Errorf("%w: resend http 401", ErrConfig)}}
	o2, _ := newBox(t, d2, fp2)
	u2 := newUser(t, d2, "dave", "dave@example.org", true)
	_ = o2.EnqueueNow(u2, "vault-deleted", map[string]string{"eventId": "v1"})
	o2.RunOnce(context.Background())
	_ = o2.EnqueueNow(u2, "vault-deleted", map[string]string{"eventId": "v2"})
	if st, _, _, _ := status(t, d2); st != "queued" {
		t.Fatalf("a provider configuration error must not blacklist the recipient, got %s", st)
	}
}

func TestOutboxPerRecipientDailyLimit(t *testing.T) {
	d := openDB(t)
	o, _ := newBox(t, d, &fakeProvider{})
	u := newUser(t, d, "erin", "erin@example.org", true)
	for i := 0; i < PerRecipientDaily+5; i++ {
		_ = o.EnqueueNow(u, "device-enrolled", map[string]string{"eventId": fmt.Sprint(i)})
	}
	var n int
	d.QueryRow(`SELECT COUNT(*) FROM mail_outbox`).Scan(&n) //nolint:errcheck
	if n != PerRecipientDaily {
		t.Fatalf("queued %d mails for one recipient in a day, want cap %d", n, PerRecipientDaily)
	}
}

// 全局日预算（需求 §12 / 验收 ID-08「全局发信限额」）：用尽后不领取、不丢弃，窗口滑过后补发。
func TestOutboxGlobalDailyBudgetDefersInsteadOfDropping(t *testing.T) {
	d := openDB(t)
	fp := &fakeProvider{}
	o, c := newBox(t, d, fp)
	o.cfg.DailyBudget = 2
	for i := 0; i < 5; i++ {
		u := newUser(t, d, fmt.Sprintf("u%d", i), fmt.Sprintf("u%d@example.org", i), true)
		if err := o.EnqueueNow(u, "device-enrolled", map[string]string{"eventId": "e"}); err != nil {
			t.Fatal(err)
		}
	}
	if sent, _, _ := o.RunOnce(context.Background()); sent != 2 {
		t.Fatalf("first run sent %d, want the budget of 2", sent)
	}
	if sent, _, _ := o.RunOnce(context.Background()); sent != 0 {
		t.Fatalf("budget exhausted but sent %d more", sent)
	}
	var queued int
	d.QueryRow(`SELECT COUNT(*) FROM mail_outbox WHERE status = 'queued'`).Scan(&queued) //nolint:errcheck
	if queued != 3 {
		t.Fatalf("over-budget mails must stay queued, not be dropped: queued=%d", queued)
	}
	c.t = c.t.Add(24*time.Hour + time.Minute)
	if sent, _, _ := o.RunOnce(context.Background()); sent != 2 {
		t.Fatalf("next window sent %d, want 2", sent)
	}
	c.t = c.t.Add(24*time.Hour + time.Minute)
	if sent, _, _ := o.RunOnce(context.Background()); sent != 1 || len(fp.sent) != 5 {
		t.Fatalf("last window sent %d (total %d), want everything delivered eventually", sent, len(fp.sent))
	}
}

func svixSign(secret, id, ts string, body []byte) string {
	key, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + ts + "."))
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestResendWebhookSignatureAndSuppression(t *testing.T) {
	d := openDB(t)
	secret := "whsec_" + base64.StdEncoding.EncodeToString([]byte("test-webhook-secret-32-bytes!!!!"))
	now := time.Unix(1_795_132_800, 0)
	h := &ResendWebhook{DB: d, Secret: secret, Now: func() time.Time { return now }}
	srv := httptest.NewServer(h)
	defer srv.Close()
	post := func(body []byte, id, ts, sig string) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
		req.Header.Set("svix-id", id)
		req.Header.Set("svix-timestamp", ts)
		req.Header.Set("svix-signature", sig)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	body := []byte(`{"type":"email.complained","data":{"to":["frank@example.org"]}}`)
	ts := strconv.FormatInt(now.Unix(), 10)
	if c := post(body, "msg_1", ts, "v1,"+base64.StdEncoding.EncodeToString([]byte("forged"))); c != http.StatusUnauthorized {
		t.Fatalf("forged signature = %d, want 401", c)
	}
	old := strconv.FormatInt(now.Add(-time.Hour).Unix(), 10)
	if c := post(body, "msg_1", old, svixSign(secret, "msg_1", old, body)); c != http.StatusUnauthorized {
		t.Fatalf("stale timestamp = %d, want 401", c)
	}
	if c := post(body, "msg_1", ts, "v0,abc "+svixSign(secret, "msg_1", ts, body)); c != http.StatusNoContent {
		t.Fatalf("valid signature = %d, want 204", c)
	}
	var reason string
	if err := d.QueryRow(`SELECT reason FROM mail_suppressions WHERE addr_hash = ?`, db.MailAddrHash("Frank@Example.org ")).Scan(&reason); err != nil || reason != "complaint" {
		t.Fatalf("complaint must suppress the (normalized) address: %v %q", err, reason)
	}
	soft := []byte(`{"type":"email.bounced","data":{"to":["gina@example.org"],"bounce":{"type":"Transient"}}}`)
	post(soft, "msg_2", ts, svixSign(secret, "msg_2", ts, soft))
	if err := d.QueryRow(`SELECT reason FROM mail_suppressions WHERE addr_hash = ?`, db.MailAddrHash("gina@example.org")).Scan(&reason); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("a soft bounce must not suppress the address")
	}
	// 未配置密钥 → 端点关闭
	closed := httptest.NewServer(&ResendWebhook{DB: d})
	defer closed.Close()
	if res, _ := http.Post(closed.URL, "application/json", bytes.NewReader(body)); res.StatusCode != http.StatusNotFound {
		t.Fatalf("webhook without secret = %d, want 404", res.StatusCode)
	}
}
