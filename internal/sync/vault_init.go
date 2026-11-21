package sync

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// 仓库加密初始化（v0.20 公开化 / ADR-012）的业务层。
//
// 浏览器在本地生成 VMK 与 salt、用仓库密码包装成与插件逐字段一致的 keyDoc；
// 这里只校验文档的**形状与参数下限**（服务端不理解也不需要理解密文），然后
// 原子提交。服务端从不接收仓库密码、KEK 或明文 VMK。

var (
	ErrInitInProgress      = db.ErrInitInProgress
	ErrInitVersionMismatch = db.ErrInitVersionMismatch
	ErrInitAlreadyReady    = db.ErrInitAlreadyReady
	ErrInitLeaseMissing    = db.ErrInitLeaseMissing
	ErrIdempotencyReused   = db.ErrIdempotencyReused
	ErrVaultNotEmpty       = db.ErrVaultNotEmpty
	// ErrVaultNotReady：仓库未完成加密初始化，拒绝内容写入。
	ErrVaultNotReady = errors.New("vault is not ready (encryption initialization incomplete)")
	// ErrInvalidKeyDoc：keyDoc 不符合当前加密 profile（拒绝弱参数与畸形文档）。
	ErrInvalidKeyDoc = errors.New("key document does not match the crypto profile")
)

// MinKDFIterations / MaxKDFIterations：PBKDF2 参数的可接受区间。下限是插件当前
// 常量（600k，OWASP 2023 建议值）；上限防止有人存一份让所有设备解锁时卡死的文档。
const (
	MinKDFIterations = 600_000
	MaxKDFIterations = 10_000_000
)

// CryptoProfile 是一次初始化协商的加密能力（接口约定 §2.3）。
type CryptoProfile struct {
	ProtocolVersion int    `json:"protocolVersion"`
	KeyDocVersion   int    `json:"keyDocVersion"`
	WriteEnvelope   string `json:"writeEnvelope"`
}

// CurrentCryptoProfile 是服务端推荐给新仓库的 profile。
func CurrentCryptoProfile() CryptoProfile {
	return CryptoProfile{ProtocolVersion: ProtocolVersion, KeyDocVersion: 1, WriteEnvelope: "LSE3"}
}

// ValidateKeyDoc 校验浏览器提交的 keyDoc 与 profile（只看形状与参数下限）。
func ValidateKeyDoc(raw string, profile CryptoProfile) error {
	if profile.ProtocolVersion != ProtocolVersion || profile.KeyDocVersion != 1 ||
		(profile.WriteEnvelope != "LSE3" && profile.WriteEnvelope != "LSE4") {
		return fmt.Errorf("%w: unsupported profile", ErrInvalidKeyDoc)
	}
	var doc struct {
		Version    *int    `json:"version"`
		KDF        string  `json:"kdf"`
		Iterations *int64  `json:"iterations"`
		Salt       string  `json:"salt"`
		IV         string  `json:"iv"`
		WrappedKey string  `json:"wrappedKey"`
		Enabled    *bool   `json:"enabled"`
		CreatedAt  *float64 `json:"createdAt"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return fmt.Errorf("%w: not a JSON object", ErrInvalidKeyDoc)
	}
	b64len := func(s string) int {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return -1
		}
		return len(b)
	}
	switch {
	case doc.Version == nil || *doc.Version != 1:
		return fmt.Errorf("%w: version must be 1", ErrInvalidKeyDoc)
	case doc.KDF != "pbkdf2-sha256":
		return fmt.Errorf("%w: kdf must be pbkdf2-sha256", ErrInvalidKeyDoc)
	case doc.Iterations == nil || *doc.Iterations < MinKDFIterations || *doc.Iterations > MaxKDFIterations:
		return fmt.Errorf("%w: iterations out of range", ErrInvalidKeyDoc)
	case b64len(doc.Salt) < 16:
		return fmt.Errorf("%w: salt too short", ErrInvalidKeyDoc)
	case b64len(doc.IV) != 12:
		return fmt.Errorf("%w: iv must be 12 bytes", ErrInvalidKeyDoc)
	case b64len(doc.WrappedKey) != 48:
		return fmt.Errorf("%w: wrappedKey must wrap a 32-byte key", ErrInvalidKeyDoc)
	case doc.Enabled == nil || !*doc.Enabled:
		return fmt.Errorf("%w: enabled must be true", ErrInvalidKeyDoc)
	case doc.CreatedAt == nil:
		return fmt.Errorf("%w: createdAt missing", ErrInvalidKeyDoc)
	}
	return nil
}

// CreateVaultV2 新建仓库（v2）：同一用户同一 clientRequestID 幂等。
// requireE2EE=true 时仓库从 pending_encryption 开始，完成初始化前拒绝内容写入。
func (s *Service) CreateVaultV2(userID, name, clientRequestID string, requireE2EE bool) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, created, err := db.CreateUserVaultV2(s.db, userID, name, clientRequestID, requireE2EE, db.MaxVaultsPerUser)
	if err == nil && created {
		s.log.Info("vault created", "user", userID, "vault", id, "pendingEncryption", requireE2EE)
	}
	return id, created, err
}

// VaultInitStatus 返回初始化状态与 keyDoc 是否已存在（不含任何秘密）。
func (s *Service) VaultInitStatus(scope db.VaultScope) (*db.VaultInit, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vi, err := db.GetVaultInit(s.db, scope)
	if err != nil || vi == nil {
		return vi, false, err
	}
	_, present, err := db.GetMeta(s.db, vaultKeyMetaKeyFor(scope))
	return vi, present, err
}

// VaultReady 报告仓库是否接受内容写入（写入闸门）。
func (s *Service) VaultReady(scope db.VaultScope) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.VaultIsReady(s.db, scope)
}

// vaultReadyLocked 是写路径内部的二道闸门（调用方已持有 s.mu）。
func (s *Service) vaultReadyLocked(scope db.VaultScope) error {
	ok, err := db.VaultIsReady(s.db, scope)
	if err != nil {
		return err
	}
	if !ok {
		return ErrVaultNotReady
	}
	return nil
}

// ClaimVaultInit 认领初始化（租约 10 分钟）。
func (s *Service) ClaimVaultInit(scope db.VaultScope, opID string) (*db.VaultInit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.ClaimVaultInit(s.db, scope, opID, time.Now().Unix())
}

// CommitVaultInit 原子提交初始化。resetAuth 是浏览器从 VMK 派生的重置凭证
//（hex，可空）；服务端只存它的哈希。返回 (结果, 是否重放)。
func (s *Service) CommitVaultInit(scope db.VaultScope, opID string, expectedVersion int64,
	keyDoc string, profile CryptoProfile, resetAuth string) (map[string]any, bool, error) {
	if err := ValidateKeyDoc(keyDoc, profile); err != nil {
		return nil, false, err
	}
	resetHash := ""
	if resetAuth != "" {
		raw, err := hex.DecodeString(resetAuth)
		if err != nil || len(raw) != 32 {
			return nil, false, fmt.Errorf("%w: resetAuth must be 32 bytes hex", ErrInvalidKeyDoc)
		}
		resetHash = db.HashToken(resetAuth) // 与 RegisterVaultResetAuth 的存储形式一致
	}
	reqSum := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s|%s", expectedVersion, keyDoc, resetAuth, profile.WriteEnvelope)))
	s.mu.Lock()
	defer s.mu.Unlock()
	identity, err := s.vaultIdentityLocked(scope)
	if err != nil {
		return nil, false, err
	}
	result := map[string]any{
		"vaultId": scope.ID(), "vaultIdentity": identity, "initState": db.InitReady,
		"initVersion": expectedVersion + 1, "cryptoProfile": profile,
	}
	resultJSON, _ := json.Marshal(result)
	saved, replay, err := db.CommitVaultInit(s.db, scope, db.InitCommit{
		OpID: opID, ExpectedVersion: expectedVersion,
		KeyDocMetaKey: vaultKeyMetaKeyFor(scope), KeyDoc: keyDoc,
		ResetAuthHash: resetHash, RequestHash: hex.EncodeToString(reqSum[:]),
		ResultJSON: string(resultJSON),
	}, time.Now().Unix())
	if err != nil {
		return nil, false, err
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(saved), &out); err != nil {
		return nil, false, err
	}
	if !replay {
		s.log.Info("vault initialized", "vault", scope.ID())
	}
	return out, replay, nil
}

// PendingVaults 列出未完成初始化的仓库（运维）。
func (s *Service) PendingVaults() ([]db.VaultInit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.ListPendingVaults(s.db)
}

// guardWriteReady 是内容写路径的统一闸门：仓库必须已完成加密初始化（ADR-012 I-1），
// 然后才是原有的协议/世代/迁移冻结检查。调用方已持有 s.mu。
func (s *Service) guardWriteReady(scope db.VaultScope, rs *db.RepoState, c ClientContext, deviceID, pseudonym string) error {
	if err := s.vaultReadyLocked(scope); err != nil {
		return err
	}
	return s.guardWrite(rs, c, deviceID, pseudonym)
}

// RoleIn 返回 userID 在仓库里的角色（ok=false 表示不是成员）。
func (s *Service) RoleIn(scope db.VaultScope, userID string) (db.Role, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.RoleOf(s.db, scope, userID)
}
