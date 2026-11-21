package sync

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// 配对 v2：Web/插件发行 + 显式、原子、可恢复的兑换（v0.20 / ADR-014，接口约定 §5）。
//
//	grant（= enrollments 行）：发行时由认证上下文定死 (vault, user, scopes)，5 分钟
//	pairing（= pairings 行）：浏览器/插件本地加密的配置包，绑定 grant，读取不消费
//	redeem：同一事务内消费 grant、建设备、暂存加密的结果（10 分钟可重放）

const (
	pairingGrantTTL  = 5 * time.Minute
	redeemReplayTTL  = 10 * time.Minute
	redeemReplayInfo = "litesync/v2/redeem-replay"
)

var (
	ErrPairingUsed    = errors.New("pairing already used")
	ErrPairingExpired = errors.New("pairing expired")
	ErrPairingRevoked = errors.New("pairing revoked")
	ErrVaultMismatch  = errors.New("pairing is bound to a different vault")
	// ErrGrantNotFound：配对包要绑定的 grant 不存在或不属于调用者。
	ErrGrantNotFound = errors.New("pairing grant not found")
)

var exchangeIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

// ValidExchangeID 校验客户端生成的兑换 ID（随机、足够长、无特殊字符）。
func ValidExchangeID(id string) bool { return exchangeIDRe.MatchString(id) }

// PairingGrant 是发行结果（enrollmentSecret 明文只在这里出现一次）。
type PairingGrant struct {
	GrantID          string
	EnrollmentSecret string
	ExpiresAt        int64
	VaultIdentity    string
	VaultName        string
	RepoEpoch        string
	HeadSequence     int64
}

// CreatePairingGrant 为调用者的仓库发行一次性设备 grant。
// 仓库必须已完成加密初始化；新设备的归属 = (该仓库, 发行者本人)。
func (s *Service) CreatePairingGrant(scope db.VaultScope, userID, actorDeviceID string) (*PairingGrant, error) {
	if ready, err := s.VaultReady(scope); err != nil {
		return nil, err
	} else if !ready {
		return nil, ErrVaultNotReady
	}
	id, secret, expiresAt, err := s.CreateEnrollment(pairingGrantTTL, scope.ID(), userID, actorDeviceID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	identity, err := s.vaultIdentityLocked(scope)
	if err != nil {
		return nil, err
	}
	v, err := db.GetVault(s.db, scope)
	if err != nil {
		return nil, err
	}
	rs, err := db.GetRepoState(s.db, scope)
	if err != nil {
		return nil, err
	}
	g := &PairingGrant{GrantID: id, EnrollmentSecret: secret, ExpiresAt: expiresAt,
		VaultIdentity: identity, RepoEpoch: rs.RepoEpoch, HeadSequence: rs.HeadSequence}
	if v != nil {
		g.VaultName = v.Name
	}
	return g, nil
}

// CreatePairingV2 保存绑定 grant 的配对包密文；grant 必须属于调用者的同一仓库且仍有效。
// 配对包的有效期与 grant 相同（撤销/兑换/过期时一并删除）。
func (s *Service) CreatePairingV2(scope db.VaultScope, userID, grantID, ciphertext string) (string, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, err := db.GetEnrollmentByID(s.db, grantID)
	if err != nil {
		return "", 0, err
	}
	now := time.Now().Unix()
	if g == nil || g.VaultID != scope.ID() || g.UserID != userID || g.ConsumedAt != 0 || g.Revoked || g.ExpiresAt <= now {
		return "", 0, ErrGrantNotFound
	}
	pairID, err := randomHex(16)
	if err != nil {
		return "", 0, err
	}
	if err := db.InsertPairing(s.db, scope, userID, pairID, ciphertext, grantID, now, g.ExpiresAt); err != nil {
		return "", 0, err
	}
	return pairID, g.ExpiresAt, nil
}

// PairingEnvelope 读取配对包（**不消费**）。grant 已兑换/撤销/过期时同样返回
// ErrPairingNotFound——没有 secret 的调用者不应分辨这些状态。
func (s *Service) PairingEnvelope(pairID string) (string, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	ct, grantID, expiresAt, ok, err := db.PairingEnvelope(s.db, pairID, now)
	if err != nil {
		return "", 0, err
	}
	if !ok {
		return "", 0, ErrPairingNotFound
	}
	if grantID != "" {
		g, err := db.GetEnrollmentByID(s.db, grantID)
		if err != nil {
			return "", 0, err
		}
		if g == nil || g.ConsumedAt != 0 || g.Revoked || g.ExpiresAt <= now {
			return "", 0, ErrPairingNotFound
		}
	}
	return ct, expiresAt, nil
}

// RedeemParams 是一次兑换请求。
type RedeemParams struct {
	Secret          string
	ExchangeID      string
	ExpectedVaultID string
	DeviceName      string
	Platform        string
}

// RedeemResult 是兑换结果（Token 明文只在响应里出现）。
type RedeemResult struct {
	DeviceID           string   `json:"deviceId"`
	VaultID            string   `json:"vaultId"`
	VaultIdentity      string   `json:"vaultIdentity"`
	Scopes             []string `json:"scopes"`
	DeviceCredential   string   `json:"deviceCredential"`
	EnrollmentStatus   string   `json:"enrollmentStatus"`
	RequiresVaultUnlock bool    `json:"requiresVaultUnlock"`
	Replayed           bool     `json:"replayed"`
}

func replayKey(secret string) ([]byte, error) {
	return hkdf.Key(sha256.New, []byte(secret), nil, redeemReplayInfo, 32)
}

func sealReplay(secret, exchangeID, grantID string, plain []byte) (string, error) {
	key, err := replayKey(secret)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	aad := []byte(redeemReplayInfo + ":" + exchangeID + ":" + grantID)
	return base64.StdEncoding.EncodeToString(append(nonce, gcm.Seal(nil, nonce, plain, aad)...)), nil
}

func openReplay(secret, exchangeID, grantID, sealed string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, err
	}
	key, err := replayKey(secret)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("replay blob truncated")
	}
	aad := []byte(redeemReplayInfo + ":" + exchangeID + ":" + grantID)
	return gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], aad)
}

// EnrollmentVault 返回 secret 对应 grant 绑定的仓库（任何状态）。
//
// 兑换端点公开、secret 即认证：api 层用这里查到的仓库构造 VaultScope（「范围只能
// 来自认证结果」——这里的认证结果就是 grant 本身），再调 RedeemEnrollment，
// 后者在锁内复核两者一致。业务包不自造 scope（tenancy_guard_test）。
func (s *Service) EnrollmentVault(secret string) (string, error) {
	if secret == "" {
		return "", ErrEnrollmentInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	row, err := db.GetEnrollmentBySecretHash(s.db, sha256Hex([]byte(secret)))
	if err != nil {
		return "", err
	}
	if row == nil {
		return "", ErrEnrollmentInvalid
	}
	return row.VaultID, nil
}

// RedeemEnrollment 显式兑换（ADR-014 §5.3）。scope 必须来自 EnrollmentVault。
func (s *Service) RedeemEnrollment(scope db.VaultScope, p RedeemParams) (*RedeemResult, error) {
	if p.Secret == "" || !ValidExchangeID(p.ExchangeID) || !scope.Valid() {
		return nil, ErrEnrollmentInvalid
	}
	name := strings.TrimSpace(p.DeviceName)
	if name == "" {
		name = "New device"
	}
	if len(name) > 128 {
		name = name[:128]
	}
	hash := sha256Hex([]byte(p.Secret))
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	row, err := db.GetEnrollmentBySecretHash(s.db, hash)
	if err != nil {
		return nil, err
	}
	if row == nil || row.VaultID != scope.ID() {
		return nil, ErrEnrollmentInvalid
	}
	if row.ConsumedAt != 0 {
		// 响应丢失后的重试：同 secret + 同 exchangeId + 窗口内 → 原样返回
		if row.ExchangeID != "" && row.ExchangeID == p.ExchangeID &&
			row.ReplayCiphertext != "" && row.ReplayExpiresAt > now.Unix() {
			plain, err := openReplay(p.Secret, p.ExchangeID, row.ID, row.ReplayCiphertext)
			if err != nil {
				return nil, ErrPairingUsed
			}
			var res RedeemResult
			if err := json.Unmarshal(plain, &res); err != nil {
				return nil, err
			}
			res.Replayed = true
			return &res, nil
		}
		return nil, ErrPairingUsed
	}
	switch {
	case row.Revoked:
		return nil, ErrPairingRevoked
	case row.ExpiresAt <= now.Unix():
		return nil, ErrPairingExpired
	case p.ExpectedVaultID != "" && p.ExpectedVaultID != row.VaultID:
		return nil, ErrVaultMismatch // 不消费：用户可以回到正确的链接
	}
	if ok, err := db.VaultIsReady(s.db, scope); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrVaultNotReady
	}
	if u, err := db.GetUser(s.db, row.UserID); err != nil {
		return nil, err
	} else if u == nil || u.Disabled {
		return nil, ErrPairingRevoked
	}
	identity, err := s.vaultIdentityLocked(scope)
	if err != nil {
		return nil, err
	}
	rs, err := db.GetRepoState(s.db, scope)
	if err != nil {
		return nil, err
	}

	var res *RedeemResult
	err = s.inTx(func(tx *sql.Tx) error {
		g, err := db.ConsumeEnrollmentV2(tx, hash, p.ExchangeID, now.Unix())
		if err != nil {
			return err
		}
		if g == nil {
			return ErrPairingUsed // 并发：另一个兑换刚抢先成功
		}
		deviceID, err := randomHex(8)
		if err != nil {
			return err
		}
		token, err := randomHex(32)
		if err != nil {
			return err
		}
		if err := db.InsertDeviceTx(tx, &db.Device{
			DeviceID: deviceID, Name: name, TokenHash: sha256Hex([]byte(token)),
			Scopes: g.Scopes, CreatedAt: now.Unix(), LastSeenAt: now.Unix(),
			VaultID: g.VaultID, UserID: g.UserID, Platform: p.Platform,
		}); err != nil {
			return err
		}
		res = &RedeemResult{
			DeviceID: deviceID, VaultID: g.VaultID, VaultIdentity: identity,
			Scopes: strings.Split(g.Scopes, ","), DeviceCredential: token,
			EnrollmentStatus: "consumed", RequiresVaultUnlock: rs.EncryptionState == db.EncryptionEncrypted,
		}
		plain, err := json.Marshal(res)
		if err != nil {
			return err
		}
		sealed, err := sealReplay(p.Secret, p.ExchangeID, row.ID, plain)
		if err != nil {
			return err
		}
		if err := db.StoreEnrollmentReplay(tx, hash, sealed, now.Add(redeemReplayTTL).Unix()); err != nil {
			return err
		}
		if err := db.DeletePairingsOfGrant(tx, row.ID); err != nil {
			return err
		}
		return db.AppendAudit(tx, scope, deviceID, "device-enrolled", fmt.Sprintf("via=redeem-v2 grant=%s", row.ID))
	})
	if err != nil {
		return nil, err
	}
	s.log.Info("device enrolled", "deviceId", res.DeviceID, "vault", res.VaultID, "via", "redeem-v2")
	return res, nil
}
