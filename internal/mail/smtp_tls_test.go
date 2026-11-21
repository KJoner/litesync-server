package mail

// 复审 SV-04：SMTP TLS 模式只接受合法枚举，未知值失败；默认 starttls 不降级。
// 全部用本机 127.0.0.1 上的测试监听（一个最小的 SMTP 服务器 + 测试时生成的自签名证书），
// 不连接任何真实邮件服务、不发送任何真实邮件。

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	gosync "sync"
	"testing"
	"time"
)

func TestParseTLSModeIsStrict(t *testing.T) {
	for in, want := range map[string]string{
		"": "starttls", "   ": "starttls", "starttls": "starttls", "STARTTLS": "starttls", " StartTLS ": "starttls",
		"implicit": "implicit", "IMPLICIT": "implicit", "none": "none", "None": "none",
	} {
		got, err := ParseTLSMode(in)
		if err != nil || got != want {
			t.Fatalf("ParseTLSMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"startls", "start-tls", "ssl", "tls", "starttls1", "on", "off", "false", "smtps"} {
		if got, err := ParseTLSMode(bad); err == nil {
			t.Fatalf("ParseTLSMode(%q) = %q, want an error (a typo must never fall back to plaintext)", bad, got)
		}
	}
}

func TestNewProviderRejectsUnknownOrUnsafeTLS(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	base := Config{Provider: "smtp", From: "LiteSync <no-reply@example.invalid>", SMTPHost: "smtp.example.invalid"}
	for _, bad := range []string{"startls", "ssl"} {
		c := base
		c.SMTPTLS = bad
		if _, err := NewProvider(c, logger); err == nil {
			t.Fatalf("NewProvider with SMTPTLS=%q must fail", bad)
		}
	}
	c := base
	c.SMTPTLS = "none"
	if _, err := NewProvider(c, logger); err == nil {
		t.Fatal("TLS mode none with a non-loopback relay must fail")
	}
	c.SMTPHost = "127.0.0.1"
	if _, err := NewProvider(c, logger); err != nil {
		t.Fatalf("TLS mode none with a loopback relay = %v", err)
	}
	c = base
	c.SMTPTLS = ""
	p, err := NewProvider(c, logger)
	if err != nil || p.(*smtpProvider).c.SMTPTLS != TLSStartTLS {
		t.Fatalf("empty TLS mode must default to starttls: %v", err)
	}
	c.SMTPTLS = "IMPLICIT"
	if p, err := NewProvider(c, logger); err != nil || p.(*smtpProvider).c.SMTPTLS != TLSImplicit {
		t.Fatalf("upper-case implicit must be normalized: %v", err)
	}
	// 绕过 NewProvider 直接构造的未知模式：Send 也绝不走明文
	sp := &smtpProvider{c: Config{SMTPHost: "127.0.0.1", SMTPPort: 1, SMTPTLS: "startls-typo"}}
	if _, err := sp.Send(context.Background(), "a@example.invalid", "", Message{To: "b@example.invalid"}); !errors.Is(err, ErrConfig) {
		t.Fatalf("an unknown mode at send time = %v, want ErrConfig", err)
	}
}

// ---------------------------------------------------------------- 本机测试监听

type fakeSMTP struct {
	ln       net.Listener
	cert     tls.Certificate
	starttls bool // EHLO 是否宣告 STARTTLS
	implicit bool // 连接即 TLS
	mu       gosync.Mutex
	mailSeen []bool // 每次 MAIL FROM 时连接是否已加密（false = 明文泄露）
	dataSeen int
	// dropAfterData：DATA 回 250 之后直接断开（QUIT 拿不到应答）；silentAfterData：收完 DATA 不应答就断开
	dropAfterData   bool
	silentAfterData bool
}

func selfSignedCert(t *testing.T, hosts ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "smtp-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func newFakeSMTP(t *testing.T, cert tls.Certificate, starttls, implicit bool) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") // 本机临时端口（与 httptest 相同），不对外
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, cert: cert, starttls: starttls, implicit: implicit}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	encrypted := false
	if f.implicit {
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{f.cert}})
		if err := tc.Handshake(); err != nil {
			return
		}
		c, encrypted = tc, true
	}
	r := bufio.NewReader(c)
	write := func(s string) { io.WriteString(c, s+"\r\n") } //nolint:errcheck
	write("220 smtp-test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			if f.starttls && !encrypted {
				write("250-smtp-test")
				write("250 STARTTLS")
			} else {
				write("250 smtp-test")
			}
		case cmd == "STARTTLS":
			if !f.starttls || encrypted {
				write("502 not supported")
				continue
			}
			write("220 go ahead")
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{f.cert}})
			if err := tc.Handshake(); err != nil {
				return
			}
			c, encrypted, r = tc, true, bufio.NewReader(tc)
			write = func(s string) { io.WriteString(c, s+"\r\n") } //nolint:errcheck
		case strings.HasPrefix(cmd, "MAIL FROM"):
			f.mu.Lock()
			f.mailSeen = append(f.mailSeen, encrypted)
			f.mu.Unlock()
			write("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO"):
			write("250 ok")
		case cmd == "DATA":
			write("354 go")
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
			}
			f.mu.Lock()
			f.dataSeen++
			f.mu.Unlock()
			if f.silentAfterData {
				return
			}
			write("250 queued")
			if f.dropAfterData {
				return
			}
		case cmd == "QUIT":
			write("221 bye")
			return
		default:
			write("500 unknown")
		}
	}
}

func (f *fakeSMTP) seen() (mail []bool, data int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]bool(nil), f.mailSeen...), f.dataSeen
}

func smtpTo(f *fakeSMTP, mode string, roots *x509.CertPool) *smtpProvider {
	return &smtpProvider{c: Config{SMTPHost: "127.0.0.1", SMTPPort: f.port(), SMTPTLS: mode}, roots: roots}
}

var testMsg = Message{To: "someone@example.invalid", Subject: "测试", Text: "合成内容", IdempotencyKey: "ls-test"}

func TestSMTPStartTLSUpgradesBeforeAnyEnvelope(t *testing.T) {
	cert, roots := selfSignedCert(t, "127.0.0.1")
	f := newFakeSMTP(t, cert, true, false)
	if _, err := smtpTo(f, TLSStartTLS, roots).Send(context.Background(), "no-reply@example.invalid", "", testMsg); err != nil {
		t.Fatalf("starttls send = %v", err)
	}
	if mail, data := f.seen(); len(mail) != 1 || !mail[0] || data != 1 {
		t.Fatalf("MAIL FROM must only happen after the TLS upgrade: mail=%v data=%d", mail, data)
	}
}

// 服务器不提供 STARTTLS：拒绝发送（配置错误），绝不降级为明文——服务器一条信封命令都收不到。
func TestSMTPStartTLSNotOfferedNeverDowngrades(t *testing.T) {
	cert, roots := selfSignedCert(t, "127.0.0.1")
	f := newFakeSMTP(t, cert, false, false)
	_, err := smtpTo(f, TLSStartTLS, roots).Send(context.Background(), "no-reply@example.invalid", "", testMsg)
	if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("no STARTTLS offered = %v, want a configuration error", err)
	}
	if mail, data := f.seen(); len(mail) != 0 || data != 0 {
		t.Fatalf("plaintext envelope leaked: mail=%v data=%d", mail, data)
	}
}

// 证书不受信任 / 主机名不符：配置错误，不发送。
func TestSMTPCertificateErrorsAreConfigErrors(t *testing.T) {
	cert, _ := selfSignedCert(t, "127.0.0.1")
	f := newFakeSMTP(t, cert, true, false)
	_, err := smtpTo(f, TLSStartTLS, nil).Send(context.Background(), "no-reply@example.invalid", "", testMsg) // 系统信任库：不认这张自签名证书
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("untrusted certificate = %v, want ErrConfig", err)
	}
	wrongHost, roots := selfSignedCert(t, "mail.example.invalid") // 证书是给别的主机名的
	g := newFakeSMTP(t, wrongHost, true, false)
	if _, err := smtpTo(g, TLSStartTLS, roots).Send(context.Background(), "no-reply@example.invalid", "", testMsg); !errors.Is(err, ErrConfig) {
		t.Fatalf("hostname mismatch = %v, want ErrConfig", err)
	}
	for _, s := range []*fakeSMTP{f, g} {
		if mail, data := s.seen(); len(mail) != 0 || data != 0 {
			t.Fatalf("envelope sent despite a certificate error: mail=%v data=%d", mail, data)
		}
	}
}

func TestSMTPImplicitTLS(t *testing.T) {
	cert, roots := selfSignedCert(t, "127.0.0.1")
	f := newFakeSMTP(t, cert, false, true)
	if _, err := smtpTo(f, TLSImplicit, roots).Send(context.Background(), "no-reply@example.invalid", "", testMsg); err != nil {
		t.Fatalf("implicit TLS send = %v", err)
	}
	if mail, _ := f.seen(); len(mail) != 1 || !mail[0] {
		t.Fatalf("implicit TLS must encrypt from the first byte: %v", mail)
	}
	if _, err := smtpTo(f, TLSImplicit, nil).Send(context.Background(), "no-reply@example.invalid", "", testMsg); !errors.Is(err, ErrConfig) {
		t.Fatalf("implicit TLS with an untrusted certificate = %v, want ErrConfig", err)
	}
}

// none 只给本机回环中继：明文发送（这一种情况下是被允许的）。
func TestSMTPNoneOnLoopbackSendsPlaintext(t *testing.T) {
	cert, _ := selfSignedCert(t, "127.0.0.1")
	f := newFakeSMTP(t, cert, false, false)
	if _, err := smtpTo(f, TLSNone, nil).Send(context.Background(), "no-reply@example.invalid", "", testMsg); err != nil {
		t.Fatalf("none on loopback = %v", err)
	}
	if mail, data := f.seen(); len(mail) != 1 || mail[0] || data != 1 {
		t.Fatalf("none mode on loopback: mail=%v data=%d", mail, data)
	}
}
