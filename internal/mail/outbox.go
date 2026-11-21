package mail

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// 退避：第 n 次失败后等待 backoff[n-1]；超过 MaxAttempts 记为失败并告警。
var backoff = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour}

const (
	// MaxAttempts：临时失败的最大尝试次数。
	MaxAttempts = 6
	// PerRecipientDaily：单个收件人 24 小时内最多入队的通知数（防止被刷成邮件炸弹）。
	PerRecipientDaily = 20
	sendingStaleAfter = 10 * time.Minute
)

// Outbox 负责把已落盘的安全事件变成邮件并在后台投递（v0.20.1 / 复审 SV-05）。
//
// 业务操作在**自己的事务里**写一条最小的安全事件（db.RecordSecurityEvent），提交之后调用 Wake；
// 这里的 worker 查收件地址、渲染、入队、发送。没有内存队列：Wake 只是「尽快来看一眼」的信号，
// 丢了也没关系（每 15 秒都会扫一次）；进程在任何时刻退出，未处理的事件都还在库里。
type Outbox struct {
	db       *sql.DB
	provider Provider
	cfg      Config
	log      *slog.Logger
	now      func() time.Time
	wake     chan struct{}
	// lastBudgetWarn：日预算用尽的告警节流（每小时一条）
	lastBudgetWarn time.Time
}

// NewOutbox 构造 outbox；provider 为 nil 时用 log 渠道。
func NewOutbox(d *sql.DB, p Provider, cfg Config, logger *slog.Logger) *Outbox {
	if p == nil {
		p = logProvider{logger: logger}
	}
	return &Outbox{db: d, provider: p, cfg: cfg, log: logger, now: time.Now, wake: make(chan struct{}, 1)}
}

// Wake 实现 sync.Notifier：业务事务已经提交（事件已落盘），请 worker 尽快处理。非阻塞。
func (o *Outbox) Wake() {
	select {
	case o.wake <- struct{}{}:
	default: // 已经有一个待处理的唤醒；事件本身在库里，不会丢
	}
}

// Notify 是事务之外的旧入口：事件以独立事务落盘再唤醒 worker。业务代码应在自己的事务里
// 调用 db.RecordSecurityEvent（与业务变更同生共死），这里只给拿不到事务的调用方兜底。
func (o *Outbox) Notify(userID, event string, data map[string]string) {
	if err := db.RecordSecurityEvent(o.db, userID, event, data, o.now().Unix()); err != nil {
		o.log.Warn("record security event failed", "event", event, "error", err)
	}
	o.Wake()
}

// Start 启动后台循环（处理事件 + 投递），直到 ctx 结束。
func (o *Outbox) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			case <-o.wake:
			}
			if _, err := o.ProcessEvents(); err != nil {
				o.log.Warn("security event processing failed; will retry", "error", err)
			}
			o.RunOnce(ctx)
		}
	}()
}

// EnqueueNow 同步记录并处理一条事件（测试与 CLI 用）。
func (o *Outbox) EnqueueNow(userID, event string, data map[string]string) error {
	if err := db.RecordSecurityEvent(o.db, userID, event, data, o.now().Unix()); err != nil {
		return err
	}
	_, err := o.ProcessEvents()
	return err
}

// ProcessEvents 处理全部未处理的安全事件：每条事件在一个事务里「渲染 + 入队 + 记下去向」。
// 返回处理的条数。中途出错就停（下一轮重试；已处理的不会重复——邮件幂等键就是事件键）。
func (o *Outbox) ProcessEvents() (int, error) {
	total := 0
	for {
		batch, err := db.PendingSecurityEvents(o.db, 50)
		if err != nil || len(batch) == 0 {
			return total, err
		}
		for _, ev := range batch {
			outcome, err := o.processEvent(ev)
			if err != nil {
				return total, err
			}
			total++
			if outcome != db.EventOutcomeMailQueued && outcome != db.EventOutcomeDuplicate {
				o.log.Info("security event recorded without mail", "event", ev.Event, "outcome", outcome)
			}
		}
	}
}

func (o *Outbox) processEvent(ev db.SecurityEvent) (string, error) {
	tx, err := o.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck
	outcome, mailID, err := o.render(tx, ev)
	if err != nil {
		return "", err
	}
	if err := db.CompleteSecurityEvent(tx, ev.ID, outcome, mailID, o.now().Unix()); err != nil {
		return "", err
	}
	return outcome, tx.Commit()
}

// render 决定一条事件的去向（调用方的事务里）：没有已验证邮箱、收件人当日超限、没有模板都是
// 「记下结果、不发」；否则渲染并入队（幂等键 = 事件键，重处理不会重复入队）。
func (o *Outbox) render(tx *sql.Tx, ev db.SecurityEvent) (string, int64, error) {
	addr, err := db.UserNotifyAddress(tx, ev.UserID)
	if err != nil {
		return "", 0, err
	}
	if addr == "" {
		return db.EventOutcomeNoAddress, 0, nil // 例如只用 API Token 的旧管理员
	}
	if id, status, err := db.MailByKey(tx, ev.Key); err != nil {
		return "", 0, err
	} else if id != 0 {
		if status == "suppressed" {
			return db.EventOutcomeSuppressed, id, nil
		}
		return db.EventOutcomeDuplicate, id, nil
	}
	now := o.now()
	if n, err := db.CountRecentMailTo(tx, addr, now.Add(-24*time.Hour).Unix()); err != nil {
		return "", 0, err
	} else if n >= PerRecipientDaily {
		o.log.Warn("mail per-recipient daily limit reached; notification not sent", "event", ev.Event)
		return db.EventOutcomeRecipientLimit, 0, nil
	}
	subject, body, ok := Render(ev.Event, ev.Data, o.cfg.PublicURL, time.Unix(ev.CreatedAt, 0))
	if !ok {
		o.log.Error("security event has no mail template", "event", ev.Event)
		return db.EventOutcomeUnknownTemplate, 0, nil
	}
	if _, err := db.EnqueueMail(tx, ev.Key, ev.Event, addr, subject, body, now.Unix()); err != nil {
		return "", 0, err
	}
	id, status, err := db.MailByKey(tx, ev.Key)
	if err != nil {
		return "", 0, err
	}
	if status == "suppressed" {
		return db.EventOutcomeSuppressed, id, nil
	}
	return db.EventOutcomeMailQueued, id, nil
}

// RunOnce 投递一批到期邮件；返回 (成功, 重试, 失败) 数。
func (o *Outbox) RunOnce(ctx context.Context) (sent, retried, failed int) {
	now := o.now()
	limit := 20
	// 全局日预算：滚动 24 小时窗口。用尽时不领取任何邮件——它们留在队列里，窗口滑过后自然发出
	if o.cfg.DailyBudget > 0 {
		n, err := db.CountMailSentSince(o.db, now.Add(-24*time.Hour).Unix())
		if err != nil {
			o.log.Warn("mail budget check failed", "error", err)
			return
		}
		if n >= o.cfg.DailyBudget {
			if now.Sub(o.lastBudgetWarn) >= time.Hour {
				o.lastBudgetWarn = now
				o.log.Warn("mail daily budget exhausted; notifications are deferred (not dropped)", "budget", o.cfg.DailyBudget)
			}
			return
		}
		limit = min(limit, o.cfg.DailyBudget-n)
	}
	batch, err := db.ClaimDueMail(o.db, now.Unix(), now.Add(-sendingStaleAfter).Unix(), limit)
	if err != nil {
		o.log.Warn("mail claim failed", "error", err)
		return
	}
	for _, m := range batch {
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		id, err := o.provider.Send(sctx, o.cfg.From, o.cfg.ReplyTo, Message{To: m.To, Subject: m.Subject, Text: m.BodyText, IdempotencyKey: hashKey(m.IdemKey)})
		cancel()
		ts := o.now().Unix()
		switch {
		case err == nil:
			_ = db.MarkMailSent(o.db, m.ID, id, ts) //nolint:errcheck
			sent++
			o.log.Info("mail sent", "template", m.Template, "provider", o.provider.Name())
		case errors.Is(err, ErrPermanent):
			_ = db.MarkMailFailed(o.db, m.ID, m.ToHash, codeOf(err), true, ts) //nolint:errcheck
			failed++
			o.log.Warn("mail permanently rejected; recipient suppressed", "template", m.Template, "code", codeOf(err))
		case errors.Is(err, ErrConfig):
			_ = db.MarkMailFailed(o.db, m.ID, m.ToHash, codeOf(err), false, ts) //nolint:errcheck
			failed++
			// 管理员告警：配置问题会让**所有**通知都发不出去
			o.log.Error("mail provider configuration error; check OBSYNC_MAIL_* settings", "provider", o.provider.Name(), "code", codeOf(err))
		case errors.Is(err, ErrOutcomeUnknown) && m.Attempts+1 < MaxAttempts:
			// 请求已发出、没拿到结果（服务商可能已接受）：记一次不确定的尝试，用同一幂等键退避重试（SV-05）
			wait := backoff[min(m.Attempts, len(backoff)-1)]
			_ = db.MarkMailUncertain(o.db, m.ID, ts+int64(wait.Seconds()), ts) //nolint:errcheck
			retried++
			o.log.Warn("mail delivery outcome unknown; retrying with the same idempotency key",
				"template", m.Template, "provider", o.provider.Name())
		case m.Attempts+1 >= MaxAttempts:
			_ = db.MarkMailFailed(o.db, m.ID, m.ToHash, "max-attempts", false, ts) //nolint:errcheck
			failed++
			o.log.Error("mail delivery gave up after retries", "template", m.Template, "provider", o.provider.Name())
		default:
			wait := backoff[min(m.Attempts, len(backoff)-1)]
			_ = db.MarkMailRetry(o.db, m.ID, "transient", ts+int64(wait.Seconds()), ts) //nolint:errcheck
			retried++
		}
	}
	return
}

// hashKey 把内部幂等键（含 userID）变成发给服务商的不透明值。
func hashKey(k string) string {
	sum := sha256.Sum256([]byte(k))
	return fmt.Sprintf("ls-%x", sum[:16])
}

func codeOf(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// ---------------------------------------------------------------- 模板

// Render 生成通知邮件（纯文本、中文）。正文不含任何秘密、不含笔记内容。
func Render(event string, d map[string]string, publicURL string, now time.Time) (subject, body string, ok bool) {
	when := now.UTC().Format("2006-01-02 15:04 UTC")
	if d["time"] != "" {
		when = d["time"]
	}
	var lines []string
	switch event {
	case "device-enrolled":
		subject = "新设备已连接到你的 LiteSync 仓库"
		lines = []string{
			fmt.Sprintf("设备「%s」（%s）已于 %s 连接到仓库「%s」。", or(d["device"], "未命名设备"), or(d["platform"], "未知平台"), when, or(d["vault"], "—")),
			"如果这不是你本人的操作，请立即在「账号与设备」中撤销这台设备，并检查账号安全。",
		}
	case "token-reset":
		subject = "你的 LiteSync API Token 已重置"
		lines = []string{
			fmt.Sprintf("你的 API Token 已于 %s 重置，名下 %s 台设备的授权已被撤销，需要重新连接。", when, or(d["revokedDevices"], "全部")),
			"如果这不是你本人的操作，说明有人掌握了你的旧 Token 和仓库密码，请立即检查账号安全。",
		}
	case "vault-deleted":
		subject = "LiteSync 仓库已删除"
		lines = []string{
			fmt.Sprintf("仓库「%s」已于 %s 从服务器上删除。设备上已下载的本地文件不受影响。", or(d["vault"], "—"), when),
			"已删除的仓库无法通过网页恢复；服务器备份按运营方公布的保留期自然过期。",
		}
	case "logout-everywhere":
		subject = "已退出所有产品与设备"
		lines = []string{
			fmt.Sprintf("你的账号已于 %s 执行「退出所有产品与设备」：LiteSync 的 %s 台设备授权已被撤销，", when, or(d["revokedDevices"], "全部")) +
				"身份中心所有浏览器里的登录已结束，另一个产品也已收到撤销通知（结果可在「账号与设备 → 最近的撤销」查看）。",
			"每台 Obsidian 需要重新连接后才能继续同步。",
		}
	case "logout-devices":
		subject = "已退出 LiteSync 的全部设备"
		lines = []string{
			fmt.Sprintf("你的账号已于 %s 执行「退出 LiteSync 的全部设备」，%s 台设备的授权与尚未使用的连接链接已被撤销。", when, or(d["revokedDevices"], "全部")),
			"每台 Obsidian 需要重新连接后才能继续同步。身份中心的登录与其他产品不受影响。",
		}
	default:
		return "", "", false
	}
	lines = append(lines, "")
	if publicURL != "" {
		lines = append(lines, "管理设备与账号："+strings.TrimRight(publicURL, "/")+"/#/me")
	}
	lines = append(lines, "这是一封自动发送的账号安全通知，请勿直接回复。")
	return subject, strings.Join(lines, "\n"), true
}

func or(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// ---------------------------------------------------------------- 服务商回执（退信 / 投诉）

// ResendWebhook 处理 Resend 的事件回调（Svix 签名）：硬退信与投诉进抑制表。
// secret 为空时整个端点不可用（404）。
type ResendWebhook struct {
	DB     *sql.DB
	Secret string // whsec_...
	Log    *slog.Logger
	Now    func() time.Time
}

func (h *ResendWebhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Secret == "" {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 256<<10))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}
	if !VerifySvix(h.Secret, r.Header.Get("svix-id"), r.Header.Get("svix-timestamp"), r.Header.Get("svix-signature"), body, now()) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	var ev struct {
		Type string `json:"type"`
		Data struct {
			To     json.RawMessage `json:"to"`
			Bounce struct {
				Type string `json:"type"`
			} `json:"bounce"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var to []string
	if err := json.Unmarshal(ev.Data.To, &to); err != nil {
		var one string
		if json.Unmarshal(ev.Data.To, &one) == nil && one != "" {
			to = []string{one}
		}
	}
	reason := ""
	switch ev.Type {
	case "email.complained":
		reason = "complaint"
	case "email.bounced":
		// 软退信（Transient / soft）只是暂时问题，不拉黑
		if t := strings.ToLower(ev.Data.Bounce.Type); t != "transient" && t != "soft" {
			reason = "hard-bounce"
		}
	}
	if reason != "" {
		for _, addr := range to {
			_ = db.SuppressMail(h.DB, addr, reason, now().Unix()) //nolint:errcheck
		}
		if h.Log != nil {
			h.Log.Warn("mail recipient suppressed by provider event", "reason", reason, "count", len(to))
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// VerifySvix 校验 Svix 签名：HMAC-SHA256(base64decode(secret 去掉 whsec_ 前缀),
// "{id}.{timestamp}.{body}")，签名头可含多个空格分隔的 "v1,<base64>"；时间戳±5 分钟。
func VerifySvix(secret, id, ts, sigHeader string, body []byte, now time.Time) bool {
	if id == "" || ts == "" || sigHeader == "" {
		return false
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	if d := now.Sub(time.Unix(sec, 0)); d > 5*time.Minute || d < -5*time.Minute {
		return false
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil || len(key) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + ts + "."))
	mac.Write(body)
	want := mac.Sum(nil)
	for _, part := range strings.Fields(sigHeader) {
		v, sig, ok := strings.Cut(part, ",")
		if !ok || v != "v1" {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(sig)
		if err == nil && hmac.Equal(got, want) {
			return true
		}
	}
	return false
}
