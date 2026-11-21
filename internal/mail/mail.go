// Package mail 是产品通知邮件的可替换适配层（v0.20 公开化 / ADR-018）。
//
// 分工：身份邮件（注册验证、重发、找回密码、换邮箱）由身份服务（Keycloak）用它自己的
// SMTP 配置发送——业务层不伪造验证链接。这里只发产品安全通知：新设备接入、Token 重置、
// 仓库删除、退出所有设备。
//
// 投递语义：outbox 持久化 → 后台 worker 至少一次投递（幂等键去重）→ 临时失败指数退避 →
// 永久失败（硬退信、地址无效）进抑制表不再重试 → 服务商回执（退信/投诉）同样进抑制表。
// 「发送成功」只表示服务商接受了这封邮件，不代表一定进收件箱。
package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Message 是一封已渲染的邮件（纯文本；产品通知不需要 HTML，也就不需要清洗）。
type Message struct {
	To             string
	Subject        string
	Text           string
	IdempotencyKey string
}

// ErrPermanent 包装**收件人级**的永久失败（地址无效、硬退信）：重试不会成功，
// 地址进抑制表。
var ErrPermanent = errors.New("permanent mail failure")

// ErrConfig 包装**配置级**失败（API Key 无效、发件域未验证、SMTP 认证/发件人被拒）：
// 不是收件人的错，**不**进抑制表；邮件记为失败并告警管理员。
var ErrConfig = errors.New("mail provider configuration error")

// Provider 是一个发信渠道。
type Provider interface {
	Name() string
	// Send 返回服务商的消息 ID；永久失败用 fmt.Errorf("%w: …", ErrPermanent) 包装。
	Send(ctx context.Context, from, replyTo string, m Message) (string, error)
}

// Config 来自服务端环境变量；任何密钥都不进前端、插件或仓库。
type Config struct {
	Provider string // log | smtp | resend
	From     string // 例如 "LiteSync <no-reply@mail.example.com>"
	ReplyTo  string
	// SMTP
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	SMTPTLS      string // starttls（默认）| implicit | none（仅限本机回环中继）；见 ParseTLSMode
	// Resend（HTTPS API）
	ResendAPIKey string
	ResendURL    string // 默认 https://api.resend.com/emails（测试可覆盖）
	// PublicURL：邮件里「账号与设备」链接的基址
	PublicURL string
	// DailyBudget：全局每 24 小时最多发出的邮件数（需求 §12 / 验收 ID-08）；0 = 不限。
	// 超出的留在队列里延后发送（不丢弃），并记 WARN 提醒管理员。
	DailyBudget int
}

// SMTP TLS 模式（复审 SV-04）。只有这三个值；ParseTLSMode 是唯一的解析入口。
const (
	TLSStartTLS = "starttls" // 默认：明文连接后必须升级为 TLS；服务器不支持 STARTTLS 直接失败，绝不降级
	TLSImplicit = "implicit" // 连接即 TLS（常见于 465 端口）
	TLSNone     = "none"     // 不加密：只允许回环地址上的本机中继
)

// ParseTLSMode 规范化并校验 TLS 模式：去掉首尾空白、大小写不敏感（"STARTTLS" 与 " starttls " 等价）；
// 空值 = starttls。其他任何值（包括 "startls" 这类拼写错误）一律报错——以前未知值会悄悄走进
// 普通 TCP 分支，把邮件明文发出去。
func ParseTLSMode(v string) (string, error) {
	switch m := strings.ToLower(strings.TrimSpace(v)); m {
	case "", TLSStartTLS:
		return TLSStartTLS, nil
	case TLSImplicit, TLSNone:
		return m, nil
	default:
		return "", fmt.Errorf("mail: unknown SMTP TLS mode %q (use starttls / implicit / none)", v)
	}
}

// IsLoopbackHost 报告 host 是否是本机回环（none 模式只允许它）。
func IsLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && ip.IsLoopback()
}

// NewProvider 按配置构造渠道；未配置时返回只记日志的 log 渠道（开发/自托管默认）。
func NewProvider(c Config, logger *slog.Logger) (Provider, error) {
	switch strings.ToLower(c.Provider) {
	case "", "log":
		return logProvider{logger: logger}, nil
	case "smtp":
		if c.SMTPHost == "" || c.From == "" {
			return nil, errors.New("mail: smtp provider needs SMTP host and From")
		}
		mode, err := ParseTLSMode(c.SMTPTLS)
		if err != nil {
			return nil, err
		}
		if mode == TLSNone && !IsLoopbackHost(c.SMTPHost) {
			return nil, errors.New("mail: SMTP TLS mode none is only allowed for a loopback relay")
		}
		c.SMTPTLS = mode
		if c.SMTPPort == 0 {
			c.SMTPPort = 587
		}
		return &smtpProvider{c: c}, nil
	case "resend":
		if c.ResendAPIKey == "" || c.From == "" {
			return nil, errors.New("mail: resend provider needs API key and From")
		}
		url := c.ResendURL
		if url == "" {
			url = "https://api.resend.com/emails"
		}
		return &resendProvider{key: c.ResendAPIKey, url: url, client: &http.Client{Timeout: 15 * time.Second}}, nil
	default:
		return nil, fmt.Errorf("mail: unknown provider %q (use log/smtp/resend)", c.Provider)
	}
}

// ---------------------------------------------------------------- log

type logProvider struct{ logger *slog.Logger }

func (logProvider) Name() string { return "log" }

// Send 只记录「有一封邮件」——不记地址、主题与正文（日志隐私）。
func (p logProvider) Send(_ context.Context, _, _ string, m Message) (string, error) {
	p.logger.Info("mail (log provider, not delivered)", "idempotencyKey", m.IdempotencyKey, "bytes", len(m.Text))
	return "log-" + m.IdempotencyKey, nil
}

// ---------------------------------------------------------------- smtp

type smtpProvider struct {
	c Config
	// roots：测试注入的信任根（nil = 系统信任库）
	roots *x509.CertPool
}

func (p *smtpProvider) tlsConfig() *tls.Config {
	return &tls.Config{ServerName: p.c.SMTPHost, MinVersion: tls.VersionTLS12, RootCAs: p.roots}
}

// classifyTLS：证书校验失败（不受信任、主机名不符、已过期……）是配置 / 基础设施问题——重试不会自己好，
// 记为配置错误并告警，不拉黑收件人；其余 TLS 握手错误按临时错误处理。
func classifyTLS(err error) error {
	var verr *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &verr) || errors.As(err, &unknown) || errors.As(err, &host) || errors.As(err, &invalid) {
		return fmt.Errorf("%w: smtp tls certificate rejected", ErrConfig)
	}
	return err
}

func (*smtpProvider) Name() string { return "smtp" }

func encodeHeader(s string) string { return mime.QEncoding.Encode("utf-8", s) }

func buildRFC822(from, replyTo string, m Message) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", m.To)
	if replyTo != "" {
		fmt.Fprintf(&b, "Reply-To: %s\r\n", replyTo)
	}
	fmt.Fprintf(&b, "Subject: %s\r\n", encodeHeader(m.Subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@litesync>\r\n", m.IdempotencyKey)
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n")
	// 身份/安全邮件不做点击跟踪（需求 §11.3）：纯文本、没有改写链接的环节
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(m.Text, "\n", "\r\n"))
	return b.Bytes()
}

func (p *smtpProvider) Send(ctx context.Context, from, replyTo string, m Message) (string, error) {
	addr := net.JoinHostPort(p.c.SMTPHost, strconv.Itoa(p.c.SMTPPort))
	d := net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	switch p.c.SMTPTLS {
	case TLSImplicit:
		conn, err = (&tls.Dialer{NetDialer: &d, Config: p.tlsConfig()}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return "", classifyTLS(err)
		}
	case TLSStartTLS, TLSNone:
		conn, err = d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return "", err
		}
	default:
		// NewProvider 已经校验过；这里是第二道：未知模式绝不走明文
		return "", fmt.Errorf("%w: invalid SMTP TLS mode %q", ErrConfig, p.c.SMTPTLS)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second)) //nolint:errcheck
	c, err := smtp.NewClient(conn, p.c.SMTPHost)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if p.c.SMTPTLS == TLSStartTLS {
		// 不降级：服务器不提供 STARTTLS 就不发（以前这里依赖 StartTLS 的报错，现在显式检查并给出原因）
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return "", fmt.Errorf("%w: smtp server does not offer STARTTLS; refusing to send in plaintext", ErrConfig)
		}
		if err := c.StartTLS(p.tlsConfig()); err != nil {
			return "", classifyTLS(err)
		}
	}
	if p.c.SMTPUser != "" {
		if err := c.Auth(smtp.PlainAuth("", p.c.SMTPUser, p.c.SMTPPassword, p.c.SMTPHost)); err != nil {
			return "", fmt.Errorf("%w: smtp auth", ErrConfig)
		}
	}
	if err := c.Mail(envelopeAddr(from)); err != nil {
		return "", classifySMTP(err, false)
	}
	if err := c.Rcpt(envelopeAddr(m.To)); err != nil {
		return "", classifySMTP(err, true)
	}
	w, err := c.Data()
	if err != nil {
		return "", classifySMTP(err, false)
	}
	if _, err := w.Write(buildRFC822(from, replyTo, m)); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", classifySMTP(err, false)
	}
	return m.IdempotencyKey, c.Quit()
}

// envelopeAddr 从 "名字 <addr>" 里取出 addr。
func envelopeAddr(s string) string {
	if i := strings.LastIndex(s, "<"); i >= 0 {
		if j := strings.LastIndex(s, ">"); j > i {
			return s[i+1 : j]
		}
	}
	return strings.TrimSpace(s)
}

// classifySMTP：收件人阶段（RCPT）的 5xx 是收件人级永久失败（进抑制表）；其他阶段的
// 5xx 是配置问题（发件人/内容被拒）；4xx 与网络错误可重试。
func classifySMTP(err error, recipientStage bool) error {
	msg := err.Error()
	if len(msg) >= 3 && msg[0] == '5' {
		if recipientStage {
			return fmt.Errorf("%w: smtp %s", ErrPermanent, msg[:3])
		}
		return fmt.Errorf("%w: smtp %s", ErrConfig, msg[:3])
	}
	return err
}

// ---------------------------------------------------------------- resend

type resendProvider struct {
	key    string
	url    string
	client *http.Client
}

func (*resendProvider) Name() string { return "resend" }

func (p *resendProvider) Send(ctx context.Context, from, replyTo string, m Message) (string, error) {
	body := map[string]any{"from": from, "to": []string{m.To}, "subject": m.Subject, "text": m.Text}
	if replyTo != "" {
		body["reply_to"] = replyTo
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+p.key)
	req.Header.Set("Content-Type", "application/json")
	// 服务商侧幂等：同一封邮件重试不会被发两次
	req.Header.Set("Idempotency-Key", m.IdempotencyKey)
	res, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
		var ok struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(data, &ok) //nolint:errcheck
		return ok.ID, nil
	case res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500:
		return "", fmt.Errorf("resend: http %d", res.StatusCode)
	default:
		// 422：收件人/内容校验失败（收件人级）；401/403/400：Key 无效、发件域未验证等（配置级）
		if res.StatusCode == http.StatusUnprocessableEntity {
			return "", fmt.Errorf("%w: resend http %d", ErrPermanent, res.StatusCode)
		}
		return "", fmt.Errorf("%w: resend http %d", ErrConfig, res.StatusCode)
	}
}
