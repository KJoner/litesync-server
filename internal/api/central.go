package api

// 中心停用的发现（v0.20.1 / ADR-019 §2.5，动作 D）。
//
// 产品用**只读**服务账号（client credentials；realm-management 的 view-users）按需查询
// 用户状态：GET {admin}/users/{sub} → enabled；404 = 已删除。
//
//   - 任一已认证请求（网页会话、设备凭据、短期票、API Token）到达时，该账号上一次成功检查
//     已超过 60 秒就先同步检查；同一账号并发请求只查一次（单飞），超时 3 秒。
//   - 停用 / 删除：立即执行 B（reason=central-disabled / account-deleted），本次请求按撤销返回。
//   - 不可达（含 401/403 这类配置错误——它们**不是**「用户被停用」）：上一次成功检查在
//     15 分钟宽限内放行，60 秒后再试；超过宽限后，设备请求返回 503 IDENTITY_UNAVAILABLE
//    （可重试，客户端保留本地待发内容），网页会话按 ADR-011 的复核宽限处理（放行）。
//   - 统一登录成功、会话刷新成功也算一次「确认启用」（身份中心刚刚认证过这个人）。
//
// 未配置服务账号（OBSYNC_OIDC_STATUS_CLIENT_ID/SECRET）时 central 为 nil，不做这项检查：
// 中心停用只经 refresh 复核结束网页会话，设备要在产品里撤销。启动日志与账户中心如实写明。

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	gosync "sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// CodeIdentityUnavailable：身份中心暂时无法确认账号状态且已超过宽限（设备请求，可重试）。
const CodeIdentityUnavailable = "IDENTITY_UNAVAILABLE"

const (
	centralCheckEvery = 60 * time.Second // 两次检查的最小间隔（R-7：停用后最迟 60 秒 + 一次检查耗时被拒）
	centralRetryAfter = 60 * time.Second // 不可达时下一次再试
	centralGrace      = 15 * time.Minute // 不可达时的宽限
	centralNoLinkTTL  = 60 * time.Second // 「没有绑定统一账号」的缓存时间（之后可能被认领绑定）
)

// 可在测试中替换（export_test.go）。
var (
	centralNow          = time.Now
	centralCheckTimeout = 3 * time.Second
)

type centralVerdict int

const (
	centralAllow centralVerdict = iota
	centralRevoked
	centralUnavailable
)

type centralUser struct {
	subject     string
	linkSeen    time.Time // 上次查询绑定关系的时间（subject 为空时用于缓存）
	lastOK      time.Time
	retryAt     time.Time
	inflight    chan struct{}
	lastVerdict centralVerdict
}

type centralChecker struct {
	rp           *oidcRP
	svc          *syncsvc.Service
	log          *slog.Logger
	clientID     string
	clientSecret string
	adminBase    string // …/admin/realms/{realm}

	mu    gosync.Mutex
	users map[string]*centralUser

	tokMu  gosync.Mutex
	tok    *oauth2.Token
	warnMu gosync.Mutex
	warnAt time.Time
}

// DeriveAdminAPIBase 从 issuer 推导 Keycloak 管理接口基址：
// https://host/realms/{realm} → https://host/admin/realms/{realm}（保留可能的上下文路径，如 /auth）。
func DeriveAdminAPIBase(issuer string) (string, error) {
	u, err := url.Parse(strings.TrimRight(issuer, "/"))
	if err != nil || u.Host == "" {
		return "", errors.New("invalid issuer")
	}
	i := strings.LastIndex(u.Path, "/realms/")
	if i < 0 || strings.Count(u.Path[i+len("/realms/"):], "/") != 0 || len(u.Path) <= i+len("/realms/") {
		return "", errors.New("issuer is not of the form https://host[/ctx]/realms/{realm}")
	}
	u.Path = u.Path[:i] + "/admin" + u.Path[i:]
	return u.String(), nil
}

func newCentralChecker(rp *oidcRP, svc *syncsvc.Service, log *slog.Logger) *centralChecker {
	if rp == nil || rp.opts.StatusClientID == "" || rp.opts.StatusClientSecret == "" {
		return nil
	}
	base := strings.TrimRight(rp.opts.AdminAPIURL, "/")
	if base == "" {
		b, err := DeriveAdminAPIBase(rp.opts.Issuer)
		if err != nil {
			log.Error("central status check disabled: cannot derive the admin API URL from the issuer; set OBSYNC_OIDC_ADMIN_API_URL", "error", err)
			return nil
		}
		base = b
	}
	return &centralChecker{rp: rp, svc: svc, log: log, clientID: rp.opts.StatusClientID,
		clientSecret: rp.opts.StatusClientSecret, adminBase: base, users: map[string]*centralUser{}}
}

// markOK：身份中心刚刚确认过这个账号（登录、刷新成功）。
func (c *centralChecker) markOK(userID string, at time.Time) {
	if c == nil || userID == "" {
		return
	}
	c.mu.Lock()
	st := c.users[userID]
	if st != nil && st.lastOK.Before(at) {
		st.lastOK = at
		st.retryAt = time.Time{}
	}
	c.mu.Unlock()
	if err := c.svc.MarkCentralChecked(userID, at); err != nil {
		c.log.Warn("record central check failed", "user", userID, "error", err)
	}
}

// loadLocked 取（必要时建立）账号的检查状态。调用方持有 c.mu；会短暂释放去查库。
func (c *centralChecker) state(userID string, now time.Time) *centralUser {
	c.mu.Lock()
	st := c.users[userID]
	if st != nil && (st.subject != "" || now.Sub(st.linkSeen) < centralNoLinkTTL) {
		c.mu.Unlock()
		return st
	}
	c.mu.Unlock()
	// 查绑定关系与上次确认时间（锁外：不在 c.mu 里做数据库调用）
	_, subject, linked := c.rp.linkedSubjectFor(c.svc, userID)
	var lastOK time.Time
	if u, err := c.svc.UserByID(userID); err == nil && u != nil && u.CentralCheckedAt > 0 {
		lastOK = time.Unix(u.CentralCheckedAt, 0)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st = c.users[userID]
	if st == nil {
		st = &centralUser{}
		if len(c.users) > 100000 { // 防止被大量账号撑爆内存：清掉没有在途检查的条目
			for k, v := range c.users {
				if v.inflight == nil {
					delete(c.users, k)
				}
			}
		}
		c.users[userID] = st
	}
	st.linkSeen = now
	if linked {
		st.subject = subject
	}
	if lastOK.After(st.lastOK) {
		st.lastOK = lastOK
	}
	return st
}

// check 返回本次请求的裁决（ADR-019 §2.5）。
func (c *centralChecker) check(ctx context.Context, userID string) centralVerdict {
	now := centralNow()
	st := c.state(userID, now)
	c.mu.Lock()
	if st.subject == "" {
		c.mu.Unlock()
		return centralAllow // 没有绑定统一账号：身份中心里没有这个人可查
	}
	if now.Sub(st.lastOK) < centralCheckEvery {
		c.mu.Unlock()
		return centralAllow
	}
	if now.Before(st.retryAt) {
		v := c.graceLocked(st, now)
		c.mu.Unlock()
		return v
	}
	if st.inflight != nil {
		wait := st.inflight
		c.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return centralUnavailable
		}
		c.mu.Lock()
		v := st.lastVerdict
		c.mu.Unlock()
		return v
	}
	done := make(chan struct{})
	st.inflight = done
	subject := st.subject
	c.mu.Unlock()

	status := c.lookup(ctx, subject)

	c.mu.Lock()
	var v centralVerdict
	switch status {
	case lookupEnabled:
		st.lastOK, st.retryAt = now, time.Time{}
		v = centralAllow
	case lookupDisabled, lookupDeleted:
		v = centralRevoked
	default:
		st.retryAt = now.Add(centralRetryAfter)
		v = c.graceLocked(st, now)
	}
	st.lastVerdict = v
	st.inflight = nil
	close(done)
	c.mu.Unlock()

	switch status {
	case lookupEnabled:
		if err := c.svc.MarkCentralChecked(userID, now); err != nil {
			c.log.Warn("record central check failed", "user", userID, "error", err)
		}
	case lookupDisabled, lookupDeleted:
		reason := syncsvc.RevokeReasonCentralDisabled
		if status == lookupDeleted {
			reason = syncsvc.RevokeReasonAccountDeleted
		}
		if _, err := c.svc.RevokeAccount(syncsvc.RevokeRequest{UserID: userID, Reason: reason}); err != nil {
			c.log.Error("central disable: revoking the account failed", "user", userID, "error", err)
		} else {
			c.log.Warn("account disabled or deleted in the identity center; all product credentials revoked",
				"user", userID, "reason", reason)
		}
	}
	return v
}

func (c *centralChecker) graceLocked(st *centralUser, now time.Time) centralVerdict {
	if !st.lastOK.IsZero() && now.Sub(st.lastOK) <= centralGrace {
		return centralAllow
	}
	return centralUnavailable
}

type lookupStatus int

const (
	lookupEnabled lookupStatus = iota
	lookupDisabled
	lookupDeleted
	lookupUnavailable
)

// lookup 查询身份中心里这个主体的状态（总时限 3 秒，含换服务账号令牌）。
func (c *centralChecker) lookup(ctx context.Context, subject string) lookupStatus {
	cctx, cancel := context.WithTimeout(c.rp.ctx(ctx), centralCheckTimeout)
	defer cancel()
	tok, err := c.serviceToken(cctx)
	if err != nil {
		c.warnConfig("central status check: cannot obtain the service-account token", err)
		return lookupUnavailable
	}
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, c.adminBase+"/users/"+url.PathEscape(subject), nil)
	if err != nil {
		return lookupUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	resp, err := c.rp.opts.HTTPClient.Do(req)
	if err != nil {
		return lookupUnavailable
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10)) //nolint:errcheck
	switch resp.StatusCode {
	case http.StatusOK:
		var u struct {
			Enabled *bool `json:"enabled"`
		}
		if json.Unmarshal(raw, &u) != nil || u.Enabled == nil {
			return lookupUnavailable
		}
		if *u.Enabled {
			return lookupEnabled
		}
		return lookupDisabled
	case http.StatusNotFound:
		return lookupDeleted
	case http.StatusUnauthorized:
		c.dropToken()
		c.warnConfig("central status check: the identity center rejected the service-account token (401)", nil)
		return lookupUnavailable
	case http.StatusForbidden:
		// 403 = 服务账号缺少 view-users（或 client 的作用域映射里没有它）：这是配置问题，不是用户被停用
		c.warnConfig("central status check: forbidden (403) — grant realm-management/view-users to the service account "+
			"AND add it to the client's scope mappings (fullScopeAllowed=false)", nil)
		return lookupUnavailable
	default:
		return lookupUnavailable
	}
}

func (c *centralChecker) serviceToken(ctx context.Context) (string, error) {
	c.tokMu.Lock()
	defer c.tokMu.Unlock()
	if c.tok != nil && c.tok.Valid() && time.Until(c.tok.Expiry) > 30*time.Second {
		return c.tok.AccessToken, nil
	}
	if err := c.rp.ensure(ctx); err != nil {
		return "", err
	}
	cfg := clientcredentials.Config{ClientID: c.clientID, ClientSecret: c.clientSecret, TokenURL: c.rp.provider.Endpoint().TokenURL}
	tok, err := cfg.Token(ctx)
	if err != nil {
		return "", err
	}
	if tok.Expiry.IsZero() {
		tok.Expiry = time.Now().Add(time.Minute)
	}
	c.tok = tok
	return tok.AccessToken, nil
}

func (c *centralChecker) dropToken() {
	c.tokMu.Lock()
	c.tok = nil
	c.tokMu.Unlock()
}

// warnConfig 配置类问题每 10 分钟记一条 ERROR（管理员告警），不刷屏。
func (c *centralChecker) warnConfig(msg string, err error) {
	c.warnMu.Lock()
	defer c.warnMu.Unlock()
	if time.Since(c.warnAt) < 10*time.Minute {
		return
	}
	c.warnAt = time.Now()
	if err != nil {
		c.log.Error(msg, "error", exchangeErrCode(err))
		return
	}
	c.log.Error(msg)
}

// linkedSubjectFor 返回账号在本实例身份中心下的 subject。
func (rp *oidcRP) linkedSubjectFor(svc *syncsvc.Service, userID string) (issuer, subject string, ok bool) {
	ids, err := svc.IdentitiesOf(userID)
	if err != nil {
		return "", "", false
	}
	for _, id := range ids {
		if id.Issuer == rp.opts.Issuer {
			return id.Issuer, id.Subject, true
		}
	}
	return "", "", false
}

// centralGate 在凭据校验通过之后、处理器之前执行动作 D 的检查；返回 false 时响应已写好。
// session=true 表示网页会话（不可达时按 ADR-011 的会话复核宽限放行）。
func (h *handlers) centralGate(w http.ResponseWriter, r *http.Request, id *authIdentity, session bool) bool {
	if h.central == nil || id == nil || id.OwnerUserID == "" {
		return true
	}
	switch h.central.check(r.Context(), id.OwnerUserID) {
	case centralRevoked:
		if session {
			writeCoded(w, http.StatusUnauthorized, CodeAuthRequired,
				"这个账号已在身份中心被停用或删除，本产品的全部登录与设备授权已撤销。", false)
		} else {
			writeCoded(w, http.StatusUnauthorized, CodeTokenRevoked,
				"这个账号已在身份中心被停用或删除，设备授权已撤销。本地还没同步的内容会保留在设备上。", false)
		}
		return false
	case centralUnavailable:
		if session {
			return true
		}
		w.Header().Set("Retry-After", "60")
		writeCoded(w, http.StatusServiceUnavailable, CodeIdentityUnavailable,
			"暂时无法向身份中心确认账号状态，请稍后重试；本地还没同步的内容会保留在设备上，不需要重新连接。", true)
		return false
	}
	return true
}
