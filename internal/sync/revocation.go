package sync

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// 账号撤销的三种范围（v0.20.1 / ADR-019）的服务层。
//
//	A 退出此会话            api 层（/auth/logout、back-channel logout）：只动网页会话，**从不**撤销设备（R-3）
//	B 退出本产品的全部设备   RevokeAccount(scope=product-devices)
//	C 退出所有产品与设备     RevokeAccount(scope=all-products-all-devices) + api 层的身份中心一步 + 跨产品事件
//	D 中心停用 / 删除        api 层发现后 RevokeAccount(reason=central-disabled|account-deleted)
//
// 管理员停用（SetUserDisabled）与 Token 重置（ResetUserToken）也是 B，在各自的事务里调用
// db.RevokeAccountTx。

// 撤销原因（记入撤销事件与审计；不含任何令牌）。
const (
	RevokeReasonUserRequest     = "user-request"
	RevokeReasonCentralDisabled = "central-disabled"
	RevokeReasonAccountDeleted  = "account-deleted"
)

// statusTokenTTL：动作 C 之后浏览器查看进度、「重新发送」用的一次性凭证有效期。
// 这时本产品的全部网页会话（包括发起 C 的这一个）都已经失效，没有它就看不到 pending / failed。
const statusTokenTTL = 30 * time.Minute

// RevokeRequest 是一次账号级撤销请求。
type RevokeRequest struct {
	UserID string
	// AllProducts：动作 C——本产品部分照常执行，身份中心一步由 api 层随后补上结果，
	// 并签发一个只能查看 / 重发这一事件的状态凭证
	AllProducts bool
	// PeerIssuer / PeerSubject：动作 C 且账号绑定了统一账号时，用它们在另一个产品里定位账号
	//（ADR-019 R-6：只用 (issuer, subject) 关联）。为空 = 没有可通知的对方，身份中心一步记 not-applicable
	PeerIssuer  string
	PeerSubject string
	Reason      string
	// Origin：发起方产品；本产品发起为 litesync
	Origin string
}

// RevokeResult 是本产品部分的结果。
type RevokeResult struct {
	EventID        string
	AuthEpoch      int64
	RevokedDevices int
	RevokedGrants  int
	// StatusToken：动作 C 的进度查看凭证（明文只在这里出现一次；库里只存哈希）
	StatusToken string
}

// RevokeAccount 执行动作 B（或动作 C 的本产品部分）：一个事务里授权代次 +1、
// 设备与待领取授权标记撤销、删除待领取配对包、记下撤销事件与审计。
// 返回时本产品内该账号此前签发的一切凭据与授权都已失效（R-4）。
func (s *Service) RevokeAccount(req RevokeRequest) (*RevokeResult, error) {
	if req.UserID == "" {
		return nil, errors.New("revoke: user is required")
	}
	if req.Reason == "" {
		req.Reason = RevokeReasonUserRequest
	}
	if req.Origin == "" {
		req.Origin = "litesync"
	}
	eventID, err := db.NewEventID()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	p := db.RevokeParams{
		UserID: req.UserID, EventID: eventID, Scope: db.RevocationScopeProduct,
		Reason: req.Reason, Origin: req.Origin, Now: now.Unix(),
	}
	res := &RevokeResult{EventID: eventID}
	linked := req.PeerIssuer != "" && req.PeerSubject != ""
	var payload string
	if req.AllProducts {
		p.Scope = db.RevocationScopeAllProducts
		p.IdentityState = "not-applicable"
		if linked {
			p.IdentityState = "pending"
		}
		if res.StatusToken, err = randomHex(32); err != nil {
			return nil, err
		}
		p.StatusTokenHash = statusTokenHash(res.StatusToken)
		p.StatusTokenExpires = now.Add(statusTokenTTL).Unix()
		if linked && s.peer != nil {
			if payload, err = peerPayload(eventID, req.PeerIssuer, req.PeerSubject, req.Reason, now); err != nil {
				return nil, err
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var out *db.RevokeOutcome
	err = s.inTx(func(tx *sql.Tx) error {
		var err error
		if out, err = db.RevokeAccountTx(tx, p); err != nil {
			return err
		}
		if payload != "" {
			// 跨产品事件与本产品的撤销同一事务落盘（outbox）：进程在这之后任何时刻退出，
			// 后台都会把它送出去。立即到期：请求内的同步投递先领租约（60 秒），后台不会同时再发
			if err := db.InsertRevocationDelivery(tx, eventID, s.peer.cfg.Product, payload,
				now.Unix(), now.Add(peerDeliveryLifetime).Unix()); err != nil {
				return err
			}
		}
		if req.Reason == RevokeReasonUserRequest {
			// 安全事件与撤销同一事务落盘（复审 SV-05）
			template := "logout-devices"
			if req.AllProducts {
				template = "logout-everywhere"
			}
			if err := s.recordEvent(tx, req.UserID, template, map[string]string{
				"revokedDevices": fmt.Sprint(out.RevokedDevices), "eventId": eventID,
			}); err != nil {
				return err
			}
		}
		return db.AuditUserEvent(tx, req.UserID, "account-revoked",
			fmt.Sprintf("event=%s scope=%s reason=%s devices=%d grants=%d authEpoch=%d",
				eventID, p.Scope, p.Reason, out.RevokedDevices, out.RevokedGrants, out.AuthEpoch))
	})
	if err != nil {
		return nil, err
	}
	res.AuthEpoch, res.RevokedDevices, res.RevokedGrants = out.AuthEpoch, out.RevokedDevices, out.RevokedGrants
	s.log.Warn("account revoked", "user", req.UserID, "event", eventID, "scope", p.Scope, "reason", p.Reason,
		"revokedDevices", out.RevokedDevices, "revokedGrants", out.RevokedGrants)
	s.wake()
	return res, nil
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func statusTokenHash(token string) string {
	sum := sha256.Sum256([]byte("litesync/v1/revocation-status:" + token))
	return hex.EncodeToString(sum[:])
}

// SetRevocationIdentityResult 写入动作 C 第 2 步（身份中心）的真实结果。
func (s *Service) SetRevocationIdentityResult(eventID, state, errClass string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.SetRevocationIdentityResult(s.db, eventID, state, errClass)
}

// ListRevocations 返回某账号最近的撤销事件（账户中心「最近的撤销」）。
func (s *Service) ListRevocations(userID string, limit int) ([]db.RevocationRecord, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.ListRevocationsOfUser(s.db, userID, limit)
}

// RevocationForUser 返回属于 userID 的一个撤销事件；不是他的与不存在的一样返回 nil。
func (s *Service) RevocationForUser(eventID, userID string) (*db.RevocationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := db.GetRevocation(s.db, eventID)
	if err != nil || r == nil || r.UserID != userID {
		return nil, err
	}
	return r, nil
}

// RevocationByStatusToken 用动作 C 签发的状态凭证取回那一个事件（过期、不匹配一律 nil）。
func (s *Service) RevocationByStatusToken(eventID, token string) (*db.RevocationRecord, error) {
	if token == "" || eventID == "" {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := db.GetRevocation(s.db, eventID)
	if err != nil || r == nil {
		return nil, err
	}
	if r.StatusTokenHash == "" || !constantTimeEqual(r.StatusTokenHash, statusTokenHash(token)) ||
		time.Now().Unix() > r.StatusTokenExpires {
		return nil, nil
	}
	return r, nil
}

// MarkCentralChecked 记录「身份中心确认这个账号仍然启用」的时刻（中心状态检查成功、
// 统一登录成功、会话刷新成功）。只前进，不回退。
func (s *Service) MarkCentralChecked(userID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.SetCentralCheckedAt(s.db, userID, at.Unix())
}
