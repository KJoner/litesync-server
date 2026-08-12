package sync

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// 短期 access token（v0.16.0 / 计划书 §10.5、ADR-010 §7）。
//
// # 为什么长期凭据不够
//
// 设备 token 是长期有效的。它会出现在配置文件、日志、抓包、备份里，
// 而这些地方的生命周期远长于任何一次使用。一旦泄露，在有人想起来撤销之前
// 它一直有效——而「有人想起来」通常发生在事故之后。
//
// 所以引入两层：
//
//	长期 device credential（可单独撤销、只用来换票）
//	  → 分钟级 access token（绑定 device+vault+scope+expiry，被动泄露后自动过期）
//
// # 为什么是无状态签名而不是存表
//
// 分钟级的票会被频繁签发，存表意味着持续的写入与清理。这里改用服务端密钥
// 签名的自包含票据：
//
//	lst1.<base64url(payload)>.<base64url(HMAC-SHA256(serverSecret, payload))>
//
// 但**撤销**不能因此变弱。所以校验时除了验签与过期，还要回查设备是否仍然
// 有效——撤销一台设备立刻让它所有在途的票失效，而不是等几分钟。
// 这一次查询换来的是「撤销即时生效」，值得。
//
// # scope 只能收窄
//
// 换票时可以要求比设备本身更小的 scope 集合（例如一次只读同步就只要 sync），
// 但绝不能要到设备没有的权限。收窄是有价值的：一张只带 sync 的票即使泄露，
// 也改不了 vault-key、创建不了分享。

const (
	// accessTokenPrefix 让 token 一眼可辨（日志里发现它就知道该当秘密处理）。
	accessTokenPrefix = "lst1"
	// accessTokenMaxTTL 是签发时允许的最长有效期。
	// 「短期」如果可以要到几天，这套机制就退化成了第二种长期凭据。
	accessTokenMaxTTL = 15 * time.Minute
	// accessTokenDefaultTTL 是不指定时的默认有效期。
	accessTokenDefaultTTL = 5 * time.Minute
	// tokenSigningSecretID 是签名密钥在 server_secrets 里的标识。
	tokenSigningSecretID = "access-token-signing"
)

var (
	// ErrAccessTokenInvalid：格式错误、签名不对，或者压根不是一张票。
	// 所有「不是有效票」的情况都返回同一个错误——区分它们等于给攻击者反馈。
	ErrAccessTokenInvalid = errors.New("access token is invalid")
	// ErrAccessTokenExpired：签名有效但已过期。
	ErrAccessTokenExpired = errors.New("access token has expired")
	// ErrScopeEscalation：要的权限比设备本身还大。
	ErrScopeEscalation = errors.New("requested scopes exceed the device's own scopes")
)

// AccessClaims 是一张票携带的全部信息。
type AccessClaims struct {
	DeviceID  string `json:"d"`
	VaultID   string `json:"v"`
	Scopes    string `json:"s"` // 逗号分隔
	IssuedAt  int64  `json:"i"`
	ExpiresAt int64  `json:"e"`
}

// HasScope 报告这张票是否带某个权限。
func (c *AccessClaims) HasScope(scope string) bool {
	for _, s := range strings.Split(c.Scopes, ",") {
		if strings.TrimSpace(s) == scope {
			return true
		}
	}
	return false
}

// IssueAccessToken 用长期设备凭据换一张短期票。
//
// requested 为空表示「沿用设备自己的全部 scope」；否则必须是设备 scope 的子集。
func (s *Service) IssueAccessToken(deviceID string, requested []string, ttl time.Duration) (string, *AccessClaims, error) {
	dev, err := db.GetDeviceByID(s.db, deviceID)
	if err != nil {
		return "", nil, err
	}
	if dev == nil || dev.Revoked {
		// 已撤销的设备换不到票。这是撤销生效的第一道闸
		return "", nil, ErrAccessTokenInvalid
	}

	granted := dev.Scopes
	if len(requested) > 0 {
		narrowed, nerr := narrowScopes(dev.Scopes, requested)
		if nerr != nil {
			return "", nil, nerr
		}
		granted = narrowed
	}
	// backup-admin 永远不经由设备票发放（§10.5 最后一条）。
	// 它只属于根 Token 与 admin 会话——一台普通同步设备被攻破，
	// 不应该顺带把「能读取整个仓库的备份」也交出去。
	granted = stripScope(granted, ScopeBackupAdmin)

	if ttl <= 0 {
		ttl = accessTokenDefaultTTL
	}
	if ttl > accessTokenMaxTTL {
		ttl = accessTokenMaxTTL
	}
	now := time.Now()
	vaultID := dev.VaultID
	if vaultID == "" {
		vaultID = db.DefaultVaultID
	}
	claims := &AccessClaims{
		DeviceID:  deviceID,
		VaultID:   vaultID,
		Scopes:    granted,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}

	secret, err := s.tokenSigningSecret()
	if err != nil {
		return "", nil, err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", nil, err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	mac := signAccessToken(secret, body)
	return accessTokenPrefix + "." + body + "." + mac, claims, nil
}

// VerifyAccessToken 校验一张票：签名、有效期、以及设备是否仍然有效。
//
// 三项缺一不可。只验签名的话，撤销一台设备要等票自然过期；
// 只查设备的话，任何人都能自己编一张票。
func (s *Service) VerifyAccessToken(token string) (*AccessClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != accessTokenPrefix {
		return nil, ErrAccessTokenInvalid
	}
	secret, err := s.tokenSigningSecret()
	if err != nil {
		return nil, err
	}
	// 先验签名再解析：不验签就解析等于让攻击者控制我们的解析器输入
	want := signAccessToken(secret, parts[1])
	if subtle.ConstantTimeCompare([]byte(want), []byte(parts[2])) != 1 {
		return nil, ErrAccessTokenInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrAccessTokenInvalid
	}
	claims := &AccessClaims{}
	if err := json.Unmarshal(raw, claims); err != nil {
		return nil, ErrAccessTokenInvalid
	}
	if claims.DeviceID == "" || claims.VaultID == "" {
		return nil, ErrAccessTokenInvalid
	}
	if time.Now().Unix() >= claims.ExpiresAt {
		return nil, ErrAccessTokenExpired
	}

	// 撤销即时生效：设备没了/被撤销，在途的票立刻作废
	dev, err := db.GetDeviceByID(s.db, claims.DeviceID)
	if err != nil {
		return nil, err
	}
	if dev == nil || dev.Revoked {
		return nil, ErrAccessTokenInvalid
	}
	// 设备 scope 事后被收窄的话，票也跟着收窄——票不能比签发它的凭据更大
	claims.Scopes = intersectScopes(claims.Scopes, dev.Scopes)
	return claims, nil
}

// tokenSigningSecret 惰性加载并缓存签名密钥。
//
// 它与 blobID 的 vaultSecret 是**两个**密钥。共用一个会让「轮换签名密钥」
// 这种日常运维动作顺带把所有 blob 的名字算错。
func (s *Service) tokenSigningSecret() ([]byte, error) {
	s.tokenSecretOnce.Do(func() {
		s.tokenSecret, s.tokenSecretErr = db.EnsureServerSecret(s.db, tokenSigningSecretID)
	})
	return s.tokenSecret, s.tokenSecretErr
}

func signAccessToken(secret []byte, body string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("litesync/v1/access-token:"))
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// narrowScopes 校验 requested ⊆ have，返回归一化后的 scope 串。
func narrowScopes(have string, requested []string) (string, error) {
	owned := map[string]bool{}
	for _, s := range strings.Split(have, ",") {
		if s = strings.TrimSpace(s); s != "" {
			owned[s] = true
		}
	}
	var out []string
	for _, r := range requested {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if !owned[r] {
			return "", fmt.Errorf("%w: %s", ErrScopeEscalation, r)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return "", fmt.Errorf("%w: 请求的 scope 集合为空", ErrScopeEscalation)
	}
	return strings.Join(out, ","), nil
}

func intersectScopes(a, b string) string {
	inB := map[string]bool{}
	for _, s := range strings.Split(b, ",") {
		if s = strings.TrimSpace(s); s != "" {
			inB[s] = true
		}
	}
	var out []string
	for _, s := range strings.Split(a, ",") {
		if s = strings.TrimSpace(s); s != "" && inB[s] {
			out = append(out, s)
		}
	}
	return strings.Join(out, ",")
}

func stripScope(scopes, drop string) string {
	var out []string
	for _, s := range strings.Split(scopes, ",") {
		if s = strings.TrimSpace(s); s != "" && s != drop {
			out = append(out, s)
		}
	}
	return strings.Join(out, ",")
}

// randomSecret 生成一个服务端密钥。
func randomSecret(n int) ([]byte, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return raw, nil
}
