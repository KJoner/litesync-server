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
	gosync "sync"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// 产品之间的撤销事件（v0.20.1 / ADR-019 §2.4）。
//
//	POST {对方产品内部地址}/api/internal/v1/account-revocations
//	Content-Type: application/json
//	X-Revocation-Timestamp: <Unix 秒>
//	X-Revocation-Signature: v1=<hex(HMAC-SHA256(共享密钥, 时间戳 + "." + 原始请求体))>
//
//	{"v":1,"eventId":"<128 位随机，hex>","issuer":"<OIDC issuer>","subject":"<sub>",
//	 "scope":"all-products-all-devices","reason":"user-request","origin":"litesync",
//	 "occurredAt":"<RFC 3339>"}
//
// 共享密钥按**配置字符串的原始字节**作 HMAC 密钥（不做 hex / base64 解码），两个产品必须相同，
// 至少 32 字节。以 (issuer, subject) 定位对方的本地账号，任何一方都不使用另一方的本地 user_id。
// 事件只能撤销，不能授予任何权限；接收方不转发（避免环路）。

// PeerRevocationPath 是接收端的固定路径。
const PeerRevocationPath = "/api/internal/v1/account-revocations"

// 签名与时间窗。
const (
	peerSignatureVersion = "v1="
	peerClockSkew        = 5 * time.Minute
	// PeerRevocationMinSecret：共享密钥的最短长度（字节）
	PeerRevocationMinSecret = 32
	peerDeliveryLifetime    = 7 * 24 * time.Hour
	peerCallTimeout         = 5 * time.Second
)

// peerBackoff：第 n 次失败后的等待（ADR-019 §2.3：5 s、15 s、30 s、30 s…）。
var peerBackoff = []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second}

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
	inflight gosync.Map // eventID+peer → struct{}：同一条投递同一时刻只发一次
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
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: peerCallTimeout}
	}
	endpoint := strings.TrimRight(cfg.URL, "/")
	if !strings.HasSuffix(endpoint, PeerRevocationPath) {
		endpoint += PeerRevocationPath
	}
	s.peer = &peerState{cfg: cfg, endpoint: endpoint}
}

// PeerRevocationConfigured 报告是否配置了跨产品撤销（发出与接收共用同一把密钥）。
func (s *Service) PeerRevocationConfigured() bool { return s.peer != nil }

// PeerEvent 是撤销事件的线上格式（字段顺序与 ADR-019 §2.4 一致）。
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

var eventIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// SignPeerRevocation 计算签名头的值：v1=<hex(HMAC-SHA256(secret, ts + "." + body))>。
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

// VerifyPeerRevocation 校验签名与时间戳（常数时间比较；时间戳与本机相差超过 5 分钟拒绝）。
func (s *Service) VerifyPeerRevocation(tsHeader, sigHeader string, body []byte, now time.Time) error {
	if s.peer == nil {
		return ErrPeerNotEnabled
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(tsHeader), 10, 64)
	if err != nil {
		return ErrPeerSignature
	}
	if d := now.Sub(time.Unix(sec, 0)); d > peerClockSkew || d < -peerClockSkew {
		return ErrPeerSignature
	}
	got := strings.TrimSpace(sigHeader)
	if !strings.HasPrefix(got, peerSignatureVersion) {
		return ErrPeerSignature
	}
	gotMAC, err := hex.DecodeString(strings.TrimPrefix(got, peerSignatureVersion))
	if err != nil {
		return ErrPeerSignature
	}
	want, _ := hex.DecodeString(strings.TrimPrefix(SignPeerRevocation(s.peer.cfg.Secret, strings.TrimSpace(tsHeader), body), peerSignatureVersion)) //nolint:errcheck
	if !hmac.Equal(gotMAC, want) {
		return ErrPeerSignature
	}
	return nil
}

// ParsePeerEvent 校验事件格式（签名通过之后再调用）。
func ParsePeerEvent(body []byte) (*PeerEvent, error) {
	var ev PeerEvent
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&ev); err != nil {
		return nil, ErrPeerMalformed
	}
	switch {
	case ev.V != 1, !eventIDRe.MatchString(ev.EventID), ev.Issuer == "", len(ev.Issuer) > 512,
		ev.Subject == "", len(ev.Subject) > 255, ev.Scope != db.RevocationScopeAllProducts,
		ev.Origin == "", len(ev.Origin) > 32, ev.Origin == "litesync", len(ev.Reason) > 64:
		return nil, ErrPeerMalformed
	}
	if _, err := time.Parse(time.RFC3339, ev.OccurredAt); err != nil {
		return nil, ErrPeerMalformed
	}
	return &ev, nil
}

// 接收结果（返回给发送方，也记入收件箱）。
const (
	PeerResultApplied         = "applied"
	PeerResultUnknownIdentity = "unknown-identity"
)

// ApplyPeerRevocation 执行收到的撤销事件：按 eventId 去重（重复投递返回同样的结果）；
// 按 (issuer, subject) 找到本地账号就执行 B（reason 记入审计），找不到记为 unknown-identity。
// 收件箱记录与 B 在同一事务里：要么都发生，要么都没发生（发送方会重试）。
func (s *Service) ApplyPeerRevocation(ev *PeerEvent) (string, error) {
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	if result, _, found, err := db.GetRevocationInbox(s.db, ev.EventID); err != nil {
		return "", err
	} else if found {
		return result, nil
	}
	ident, err := db.GetIdentity(s.db, ev.Issuer, ev.Subject)
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
		Reason: reason, Origin: "litesync", OccurredAt: at.UTC().Format(time.RFC3339),
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
			s.deliverPeer(ctx, list[i])
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
// 返回本轮尝试的条数。
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
	for i := range due {
		if ctx.Err() != nil {
			break
		}
		s.deliverPeer(ctx, due[i])
	}
	return len(due)
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

// deliverPeer 尝试投递一次并写回真实结果（ADR-019 §5 撤销事件状态机）：
//
//	200 → delivered（对方 applied / unknown-identity）
//	400 / 401 → failed（格式错误、签名或时间戳不符：重试也不会成功，需要运维修正，可手动重发）
//	其他（5xx、404、429、网络错误、超时）→ pending，按 5 s、15 s、30 s… 退避；7 天后 failed
func (s *Service) deliverPeer(ctx context.Context, d db.RevocationDelivery) {
	p := s.peer
	if p == nil {
		return
	}
	key := d.EventID + "\x00" + d.Peer
	if _, busy := p.inflight.LoadOrStore(key, struct{}{}); busy {
		return
	}
	defer p.inflight.Delete(key)

	now := time.Now()
	d.Attempts++
	state, errClass, result := s.postPeer(ctx, d.Payload)
	d.UpdatedAt = now.Unix()
	switch state {
	case db.DeliveryDelivered:
		d.State, d.DeliveredAt, d.PeerResult, d.LastError = db.DeliveryDelivered, now.Unix(), result, ""
	case db.DeliveryFailed:
		d.State, d.LastError = db.DeliveryFailed, errClass
	default:
		d.LastError = errClass
		if now.Unix() >= d.ExpiresAt {
			d.State, d.LastError = db.DeliveryFailed, "expired:"+errClass
		} else {
			wait := peerBackoff[min(d.Attempts, len(peerBackoff))-1]
			d.State, d.NextAttemptAt = db.DeliveryPending, now.Add(wait).Unix()
		}
	}
	s.mu.Lock()
	err := db.UpdateRevocationDelivery(s.db, &d)
	s.mu.Unlock()
	if err != nil {
		s.log.Error("record revocation delivery failed", "event", d.EventID, "error", err)
		return
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
}

// postPeer 发送一次。返回 (状态, 错误类别, 对方结果)。
func (s *Service) postPeer(ctx context.Context, payload string) (state, errClass, result string) {
	p := s.peer
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
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(cctx.Err(), context.DeadlineExceeded) {
			return db.DeliveryPending, "timeout", ""
		}
		return db.DeliveryPending, "network", ""
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	switch {
	case resp.StatusCode == http.StatusOK:
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
	case resp.StatusCode == http.StatusBadRequest:
		return db.DeliveryFailed, "bad-request", ""
	case resp.StatusCode == http.StatusUnauthorized:
		return db.DeliveryFailed, "signature-rejected", ""
	default:
		return db.DeliveryPending, fmt.Sprintf("http-%d", resp.StatusCode), ""
	}
}

// RevocationStats 返回跨产品投递计数（管理员页；不含任何身份信息）。
func (s *Service) RevocationStats() (db.RevocationStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.GetRevocationStats(s.db)
}
