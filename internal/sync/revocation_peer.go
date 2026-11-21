package sync

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// 产品之间的撤销事件（v0.20.1 / ADR-019 §2.4，含 2026-11-21 定稿的「签名与编码细则」「发送方对返回码
// 的处理」「迟到的事件」，与 Nexus 逐字一致）。
//
//	POST {对方产品内部地址}/api/internal/v1/account-revocations
//	Content-Type: application/json
//	X-Revocation-Timestamp: <Unix 秒>
//	X-Revocation-Signature: v1=<小写 hex(HMAC-SHA256(密钥原样 UTF-8 字节, 时间戳 + "." + 原始请求体字节))>
//
//	{"v":1,"eventId":"<32 位小写 hex>","issuer":"<ID Token 的 iss>","subject":"<sub>",
//	 "scope":"all-products-all-devices","reason":"user-request","origin":"litesync",
//	 "occurredAt":"<RFC 3339，秒精度，以 Z 结尾>"}
//
// 以 (issuer, subject) 定位对方的本地账号，任何一方都不使用另一方的本地 user_id。事件只能撤销，
// 不能授予任何权限；接收方不转发（避免环路）。重试时请求体字节不变，时间戳与签名每次重算。

// PeerRevocationPath 是接收端的固定路径。
const PeerRevocationPath = "/api/internal/v1/account-revocations"

// 签名与时间窗。
const (
	peerSignatureVersion = "v1="
	peerClockSkew        = 300 * time.Second
	// PeerRevocationMinSecret：共享密钥的最短长度（字节）
	PeerRevocationMinSecret = 32
	peerDeliveryLifetime    = 7 * 24 * time.Hour
	peerCallTimeout         = 5 * time.Second
	// peerLease：领取一条投递时把下次到期推后这么久——两个 worker 不会同时发同一条；
	// 发送途中进程中断，60 秒后由下一个 worker 接续
	peerLease = 60 * time.Second
	// peerOccurredAtLayout：occurredAt 的格式（秒精度、UTC、以 Z 结尾）
	peerOccurredAtLayout = "2006-01-02T15:04:05Z"
)

// peerBackoff：第 n 次失败后的等待（ADR-019 §2.3：5 s、15 s、30 s、30 s…）。
var peerBackoff = []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second}

// errRedirectRefused：对方返回重定向。不跟随（ADR-019 §2.4），按网络类错误退避重试。
var errRedirectRefused = errors.New("peer revocation endpoint answered with a redirect; not following")

// PeerRevocationConfig 配置跨产品撤销。URL 与 Secret 都非空才启用（config 层拒绝半套配置）。
type PeerRevocationConfig struct {
	// URL：对方产品的内部地址（例如 compose 网络里的 http://nexus:8787）；接口路径自动补上
	URL    string
	Secret string
	// Product：对方产品名（账户中心展示用；默认 nexus）
	Product string
	Client  *http.Client
}

type peerState struct {
	cfg      PeerRevocationConfig
	endpoint string
}

// SetPeerRevocation 安装跨产品撤销配置（启动时调用一次）。
func (s *Service) SetPeerRevocation(cfg PeerRevocationConfig) {
	if cfg.URL == "" || cfg.Secret == "" {
		s.peer = nil
		return
	}
	if cfg.Product == "" {
		cfg.Product = "nexus"
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: peerCallTimeout}
	}
	// 不跟随重定向：复制一份客户端，只改重定向策略（不动调用方传进来的那个）
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return errRedirectRefused }
	cfg.Client = &c
	endpoint := strings.TrimRight(cfg.URL, "/")
	if !strings.HasSuffix(endpoint, PeerRevocationPath) {
		endpoint += PeerRevocationPath
	}
	s.peer = &peerState{cfg: cfg, endpoint: endpoint}
}

// PeerRevocationConfigured 报告是否配置了跨产品撤销（发出与接收共用同一把密钥）。
func (s *Service) PeerRevocationConfigured() bool { return s.peer != nil }

// PeerEvent 是撤销事件的线上格式（字段顺序与 ADR-019 §2.4 一致：序列化顺序即签名覆盖的字节顺序）。
type PeerEvent struct {
	V          int    `json:"v"`
	EventID    string `json:"eventId"`
	Issuer     string `json:"issuer"`
	Subject    string `json:"subject"`
	Scope      string `json:"scope"`
	Reason     string `json:"reason"`
	Origin     string `json:"origin"`
	OccurredAt string `json:"occurredAt"`
}

var (
	eventIDRe = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	peerTSRe  = regexp.MustCompile(`^[0-9]{1,12}$`)
	peerSigRe = regexp.MustCompile(`^v1=([0-9a-fA-F]{64})$`)
)

// SignPeerRevocation 计算签名头的值：v1=<小写 hex(HMAC-SHA256(secret 的 UTF-8 字节, ts + "." + body))>。
// 固定测试向量见 revocation_peer_internal_test.go（与 Nexus 的 peer-revocation.test.ts 同一组）。
func SignPeerRevocation(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	return peerSignatureVersion + hex.EncodeToString(mac.Sum(nil))
}

// 接收端的错误（api 层据此决定 400 / 401）。
var (
	ErrPeerSignature  = errors.New("revocation event signature or timestamp rejected")
	ErrPeerMalformed  = errors.New("revocation event is malformed")
	ErrPeerNotEnabled = errors.New("peer revocation is not configured")
)

// VerifyPeerRevocation 按 ADR-019 §2.4 的顺序校验：先常数时间验签，再查 ±300 秒时间窗。
// 头格式不对、签名不符、时间戳超窗一律 ErrPeerSignature（401）。
func (s *Service) VerifyPeerRevocation(tsHeader, sigHeader string, body []byte, now time.Time) error {
	if s.peer == nil {
		return ErrPeerNotEnabled
	}
	ts := strings.TrimSpace(tsHeader)
	m := peerSigRe.FindStringSubmatch(strings.TrimSpace(sigHeader))
	if !peerTSRe.MatchString(ts) || m == nil {
		return ErrPeerSignature
	}
	given, err := hex.DecodeString(strings.ToLower(m[1]))
	if err != nil {
		return ErrPeerSignature
	}
	want, _ := hex.DecodeString(strings.TrimPrefix(SignPeerRevocation(s.peer.cfg.Secret, ts, body), peerSignatureVersion)) //nolint:errcheck
	if !hmac.Equal(given, want) {
		return ErrPeerSignature
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return ErrPeerSignature
	}
	if d := now.Sub(time.Unix(sec, 0)); d > peerClockSkew || d < -peerClockSkew {
		return ErrPeerSignature
	}
	return nil
}

// ParsePeerEvent 校验事件格式（签名通过之后再调用）：v=1、eventId 32 位 hex（统一转小写）、
// scope 只接受 all-products-all-devices、各字段非空且不超长、occurredAt 可解析。
func ParsePeerEvent(body []byte) (*PeerEvent, error) {
	var ev PeerEvent
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&ev); err != nil {
		return nil, ErrPeerMalformed
	}
	nonEmpty := func(v string, max int) bool { return v != "" && len(v) <= max }
	switch {
	case ev.V != 1, !eventIDRe.MatchString(ev.EventID),
		!nonEmpty(ev.Issuer, 512), !nonEmpty(ev.Subject, 255), !nonEmpty(ev.Reason, 64),
		!nonEmpty(ev.Origin, 32), !nonEmpty(ev.OccurredAt, 40),
		ev.Scope != db.RevocationScopeAllProducts,
		ev.Origin == "litesync": // 自己发出的事件绕回来了：配置成环，拒绝而不是再撤销一次
		return nil, ErrPeerMalformed
	}
	if _, err := time.Parse(time.RFC3339, ev.OccurredAt); err != nil {
		return nil, ErrPeerMalformed
	}
	ev.EventID = strings.ToLower(ev.EventID)
	return &ev, nil
}

// 接收结果（返回给发送方，也记入收件箱）。
const (
	PeerResultApplied         = "applied"
	PeerResultUnknownIdentity = "unknown-identity"
)

// lookupPeerIdentity 按 (issuer, subject) 找本地账号；issuer 容忍末尾斜杠差异（ADR-019 §2.4）。
func lookupPeerIdentity(q db.Queryer, issuer, subject string) (*db.ExternalIdentity, error) {
	trimmed := strings.TrimRight(issuer, "/")
	for _, cand := range []string{issuer, trimmed, trimmed + "/"} {
		ident, err := db.GetIdentity(q, cand, subject)
		if err != nil || ident != nil {
			return ident, err
		}
	}
	return nil, nil
}

// ApplyPeerRevocation 执行收到的撤销事件：按 eventId 去重（重复投递返回同样的结果）；
// 按 (issuer, subject) 找到本地账号就执行 B（reason 记入审计），找不到记为 unknown-identity。
// 收件箱记录与 B 在同一事务里：要么都发生，要么都没发生（发送方会重试）。
//
// 迟到的事件（ADR-019 §2.4）：B 在**应用时**执行，撤销此刻之前签发的全部凭据——包括用户在 C 之后、
// 事件送达之前重新登录得到的凭据；不按 occurredAt 截断。
func (s *Service) ApplyPeerRevocation(ev *PeerEvent) (string, error) {
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	if result, _, found, err := db.GetRevocationInbox(s.db, ev.EventID); err != nil {
		return "", err
	} else if found {
		return result, nil
	}
	ident, err := lookupPeerIdentity(s.db, ev.Issuer, ev.Subject)
	if err != nil {
		return "", err
	}
	if ident == nil {
		if err := db.InsertRevocationInbox(s.db, ev.EventID, ev.Origin, PeerResultUnknownIdentity, "", now); err != nil {
			if db.IsUniqueViolation(err) {
				return PeerResultUnknownIdentity, nil
			}
			return "", err
		}
		s.log.Info("peer revocation: unknown identity", "event", ev.EventID, "origin", ev.Origin)
		return PeerResultUnknownIdentity, nil
	}
	reason := "peer:" + ev.Origin + ":" + ev.Reason
	err = s.inTx(func(tx *sql.Tx) error {
		out, err := db.RevokeAccountTx(tx, db.RevokeParams{
			UserID: ident.UserID, EventID: ev.EventID, Scope: db.RevocationScopeAllProducts,
			Reason: reason, Origin: ev.Origin, Now: now,
		})
		if err != nil {
			return err
		}
		if err := db.InsertRevocationInbox(tx, ev.EventID, ev.Origin, PeerResultApplied, ident.UserID, now); err != nil {
			return err
		}
		return db.AuditUserEvent(tx, ident.UserID, "account-revoked",
			fmt.Sprintf("event=%s scope=%s reason=%s devices=%d grants=%d authEpoch=%d",
				ev.EventID, db.RevocationScopeAllProducts, reason, out.RevokedDevices, out.RevokedGrants, out.AuthEpoch))
	})
	if err != nil {
		return "", err
	}
	s.log.Warn("account revoked by peer event", "user", ident.UserID, "event", ev.EventID, "origin", ev.Origin)
	return PeerResultApplied, nil
}

// ---------------------------------------------------------------- 发出

// peerPayload 生成一个事件的线上载荷（同一事件的每次重试发送完全相同的字节）。
func peerPayload(eventID, issuer, subject, reason string, at time.Time) (string, error) {
	raw, err := json.Marshal(PeerEvent{
		V: 1, EventID: eventID, Issuer: issuer, Subject: subject, Scope: db.RevocationScopeAllProducts,
		Reason: reason, Origin: "litesync", OccurredAt: at.UTC().Format(peerOccurredAtLayout),
	})
	return string(raw), err
}

// DeliverRevocationNow 在请求返回前同步投递一次（动作 C 第 3 步）；失败的留给后台重试。
func (s *Service) DeliverRevocationNow(ctx context.Context, eventID string) {
	if s.peer == nil {
		return
	}
	s.mu.Lock()
	list, err := db.DeliveriesOfEvent(s.db, eventID)
	s.mu.Unlock()
	if err != nil {
		s.log.Warn("load revocation deliveries failed", "event", eventID, "error", err)
		return
	}
	for i := range list {
		if list[i].State == db.DeliveryPending {
			s.deliverPeer(ctx, list[i].EventID, list[i].Peer)
		}
	}
}

// RetryRevocation 「重新发送」：把该事件尚未送达的投递重置为立即到期并同步投递一次。
func (s *Service) RetryRevocation(ctx context.Context, eventID string) error {
	if s.peer == nil {
		return ErrPeerNotEnabled
	}
	now := time.Now()
	s.mu.Lock()
	_, err := db.ResetRevocationDeliveries(s.db, eventID, now.Unix(), now.Add(peerDeliveryLifetime).Unix())
	s.mu.Unlock()
	if err != nil {
		return err
	}
	s.DeliverRevocationNow(ctx, eventID)
	return nil
}

// RunRevocationDeliveries 投递一批到期的事件（后台 worker 每 5 秒调用一次；测试直接调用）。
// 返回本轮尝试的条数（领取不到租约的不算）。
func (s *Service) RunRevocationDeliveries(ctx context.Context) int {
	if s.peer == nil {
		return 0
	}
	s.mu.Lock()
	due, err := db.DueRevocationDeliveries(s.db, time.Now().Unix(), 20)
	s.mu.Unlock()
	if err != nil {
		s.log.Warn("load due revocation deliveries failed", "error", err)
		return 0
	}
	n := 0
	for i := range due {
		if ctx.Err() != nil {
			break
		}
		if s.deliverPeer(ctx, due[i].EventID, due[i].Peer) {
			n++
		}
	}
	return n
}

// StartRevocationWorker 启动后台重试（直到 ctx 结束）。
func (s *Service) StartRevocationWorker(ctx context.Context) {
	if s.peer == nil {
		return
	}
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.RunRevocationDeliveries(ctx)
			}
		}
	}()
}

// deliverPeer 领取租约后尝试投递一次并写回真实结果（ADR-019 §2.4 / §5 撤销事件状态机）：
//
//	2xx → delivered（记录对方的 applied / unknown-identity）
//	401 → failed（签名被拒，不重试，需运维修正密钥后手动重发）
//	400 与其他 4xx（408、429 除外）→ failed
//	408、429、5xx、网络错误、5 秒超时、重定向（不跟随）→ pending，按 5 s、15 s、30 s… 退避；7 天后 failed
//
// 领取不到租约（别的 worker 正在发、或还没到期）返回 false。
func (s *Service) deliverPeer(ctx context.Context, eventID, peer string) bool {
	if s.peer == nil {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	ok, err := db.ClaimRevocationDelivery(s.db, eventID, peer, now.Unix(), now.Add(peerLease).Unix())
	var d *db.RevocationDelivery
	if err == nil && ok {
		d, err = db.GetRevocationDelivery(s.db, eventID, peer)
	}
	s.mu.Unlock()
	if err != nil {
		s.log.Warn("claim revocation delivery failed", "event", eventID, "error", err)
		return false
	}
	if !ok || d == nil {
		return false
	}

	state, errClass, result := s.postPeer(ctx, d.Payload)
	done := time.Now()
	d.UpdatedAt = done.Unix()
	switch state {
	case db.DeliveryDelivered:
		d.State, d.DeliveredAt, d.PeerResult, d.LastError = db.DeliveryDelivered, done.Unix(), result, ""
	case db.DeliveryFailed:
		d.State, d.LastError = db.DeliveryFailed, errClass
	default:
		d.LastError = errClass
		if done.Unix() >= d.ExpiresAt {
			d.State, d.LastError = db.DeliveryFailed, "expired:"+errClass
		} else {
			wait := peerBackoff[min(max(d.Attempts, 1), len(peerBackoff))-1]
			d.State, d.NextAttemptAt = db.DeliveryPending, done.Add(wait).Unix()
		}
	}
	s.mu.Lock()
	written, err := db.UpdateRevocationDelivery(s.db, d)
	s.mu.Unlock()
	if err != nil {
		s.log.Error("record revocation delivery failed", "event", d.EventID, "error", err)
		return true
	}
	if !written {
		// 与「重新发送」重叠的另一次尝试已经送达：已送达是终态，这次的结果不再写回
		s.log.Info("revocation event already delivered by an overlapping attempt", "event", d.EventID, "peer", d.Peer)
		return true
	}
	switch d.State {
	case db.DeliveryDelivered:
		s.log.Info("revocation event delivered", "event", d.EventID, "peer", d.Peer, "result", d.PeerResult, "attempts", d.Attempts)
	case db.DeliveryFailed:
		s.log.Error("revocation event delivery failed; fix the peer configuration and resend from the account center",
			"event", d.EventID, "peer", d.Peer, "error", d.LastError, "attempts", d.Attempts)
	default:
		s.log.Warn("revocation event delivery will be retried", "event", d.EventID, "peer", d.Peer,
			"error", d.LastError, "attempts", d.Attempts)
	}
	return true
}

// postPeer 发送一次（时间戳与签名现算，请求体字节不变）。返回 (状态, 错误类别, 对方结果)。
func (s *Service) postPeer(ctx context.Context, payload string) (state, errClass, result string) {
	p := s.peer
	if p == nil {
		return db.DeliveryPending, "not-configured", ""
	}
	cctx, cancel := context.WithTimeout(ctx, peerCallTimeout)
	defer cancel()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, p.endpoint, strings.NewReader(payload))
	if err != nil {
		return db.DeliveryFailed, "bad-url", ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Revocation-Timestamp", ts)
	req.Header.Set("X-Revocation-Signature", SignPeerRevocation(p.cfg.Secret, ts, []byte(payload)))
	resp, err := p.cfg.Client.Do(req)
	if err != nil {
		switch {
		case errors.Is(err, errRedirectRefused):
			return db.DeliveryPending, "redirect-refused", ""
		case errors.Is(err, context.DeadlineExceeded) || errors.Is(cctx.Err(), context.DeadlineExceeded):
			return db.DeliveryPending, "timeout", ""
		default:
			return db.DeliveryPending, "network", ""
		}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	code := resp.StatusCode
	switch {
	case code >= 200 && code < 300:
		var body struct {
			Applied *bool  `json:"applied"`
			Reason  string `json:"reason"`
		}
		_ = json.Unmarshal(raw, &body) //nolint:errcheck
		switch {
		case body.Applied != nil && *body.Applied:
			return db.DeliveryDelivered, "", PeerResultApplied
		case body.Reason == PeerResultUnknownIdentity:
			return db.DeliveryDelivered, "", PeerResultUnknownIdentity
		default:
			return db.DeliveryDelivered, "", "accepted"
		}
	case code == http.StatusUnauthorized:
		return db.DeliveryFailed, "signature-rejected", ""
	case code == http.StatusRequestTimeout || code == http.StatusTooManyRequests:
		return db.DeliveryPending, fmt.Sprintf("http-%d", code), ""
	case code >= 500:
		return db.DeliveryPending, fmt.Sprintf("http-%d", code), ""
	case code >= 400:
		return db.DeliveryFailed, fmt.Sprintf("rejected:http-%d", code), ""
	default:
		// 1xx / 3xx（重定向不跟随时 Client 已经报错，这里只剩少见的其他情况）：当作临时错误重试
		return db.DeliveryPending, fmt.Sprintf("http-%d", code), ""
	}
}

// RevocationStats 返回跨产品投递计数（管理员页；不含任何身份信息）。
func (s *Service) RevocationStats() (db.RevocationStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.GetRevocationStats(s.db)
}
