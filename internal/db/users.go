package db

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// 用户账号与 API Token（v0.18.0 / v11 设计 §4）。
//
// Token 体系从「唯一根 Token（环境变量，进程期不可变）」升级为「按用户落库」：
//
//   - users.token_hash 只存 SHA-256(token)。Token 是 ≥32 字节 CSPRNG 输出，
//     高熵值用快哈希即可（慢哈希是给低熵密码准备的）；数据库泄露或任何
//     常规查看都拿不回明文——包括管理员（v11 设计 §3.2 的承诺）。
//   - OBSYNC_TOKEN 降级为「首次初始化的种子」：库里已有不同的哈希时以库为准
//     （说明网页端轮换过），环境变量失效。
//   - token_generation 是会话世代：每次轮换 +1，网页会话记住创建时的世代，
//     不一致即拒。这让 CLI 兜底重置（另一个进程）也能立即踢掉服务进程
//     内存里的全部会话，无需重启。

// TokenPrefix 是服务端生成的 API Token 的固定前缀。
// 认证不校验前缀（旧的无前缀环境变量 Token 继续有效）；
// 加前缀是为了让日志扫描与泄露检测工具能识别这类凭据。
const TokenPrefix = "lsk_"

// AdminUserID 是内置管理员账号的 user_id。
// 与 vaults.owner_id 的既有取值保持一致（EnsureVaultSecret 写死 "default"）。
const AdminUserID = "default"

// HashToken 返回 Token 的存储哈希（SHA-256 hex）。
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

const userColumns = `user_id, name, created_at,
	COALESCE(token_hash, ''), token_generation, is_admin, disabled, COALESCE(last_seen_at, 0)`

func scanUser(row *sql.Row) (*User, error) {
	u := &User{}
	var isAdmin, disabled int
	err := row.Scan(&u.UserID, &u.Name, &u.CreatedAt,
		&u.TokenHash, &u.TokenGeneration, &isAdmin, &disabled, &u.LastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.IsAdmin = isAdmin != 0
	u.Disabled = disabled != 0
	return u, nil
}

// GetUserByTokenHash 按 Token 哈希查用户。查不到返回 (nil, nil)。
//
// 按哈希做索引查找不构成计时侧信道：SHA-256 输出均匀且不可逆，
// 命中与否的时间差异不携带任何关于其他 Token 的信息。
func GetUserByTokenHash(q dbtx, tokenHash string) (*User, error) {
	if tokenHash == "" {
		return nil, nil
	}
	return scanUser(q.QueryRow(`SELECT `+userColumns+` FROM users WHERE token_hash = ?`, tokenHash))
}

// GetUser 按 user_id 查用户。查不到返回 (nil, nil)。
func GetUser(q dbtx, userID string) (*User, error) {
	return scanUser(q.QueryRow(`SELECT `+userColumns+` FROM users WHERE user_id = ?`, userID))
}

// GetUserByName 按用户名查用户。查不到返回 (nil, nil)。
func GetUserByName(q dbtx, name string) (*User, error) {
	return scanUser(q.QueryRow(`SELECT `+userColumns+` FROM users WHERE name = ?`, name))
}

// SetUserToken 写入新的 Token 哈希并把会话世代 +1。
//
// 世代 +1 的效果：所有按旧世代建立的网页会话在下一次校验时被拒。
// 轮换与会话作废因此是同一个原子写，不存在「Token 换了、旧会话还活着」的窗口。
func SetUserToken(q dbtx, userID, tokenHash string) (generation int64, err error) {
	res, err := q.Exec(`UPDATE users SET token_hash = ?, token_generation = token_generation + 1
		WHERE user_id = ?`, tokenHash, userID)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 { //nolint:errcheck
		return 0, fmt.Errorf("user %s not found", userID)
	}
	err = q.QueryRow(`SELECT token_generation FROM users WHERE user_id = ?`, userID).Scan(&generation)
	return generation, err
}

// TouchUser 更新最近活动时间（调用方自行节流）。
func TouchUser(q dbtx, userID string, now int64) error {
	_, err := q.Exec(`UPDATE users SET last_seen_at = ? WHERE user_id = ?`, now, userID)
	return err
}

// UserTokenGeneration 返回用户当前的会话世代；用户不存在返回 (0, nil)。
func UserTokenGeneration(q dbtx, userID string) (int64, error) {
	var gen int64
	err := q.QueryRow(`SELECT token_generation FROM users WHERE user_id = ?`, userID).Scan(&gen)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return gen, err
}

// SetUserDisabled 设置禁用位。禁用即时生效：Token 认证与会话世代校验都会拒绝。
func SetUserDisabled(q dbtx, userID string, disabled bool) error {
	v := 0
	if disabled {
		v = 1
	}
	_, err := q.Exec(`UPDATE users SET disabled = ? WHERE user_id = ?`, v, userID)
	return err
}

// OwnerVaultOf 返回用户作为 owner 的 Vault（一人一 Vault 约定，v11 设计 §5.1）。
// 没有则返回空串。
func OwnerVaultOf(q dbtx, userID string) (string, error) {
	var vaultID string
	err := q.QueryRow(`SELECT vault_id FROM memberships WHERE user_id = ? AND role = 'owner'
		ORDER BY created_at ASC LIMIT 1`, userID).Scan(&vaultID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return vaultID, err
}

// AdminTokenReconcile 是启动对账的结果。
type AdminTokenReconcile int

const (
	// AdminTokenCreated：首次启动，管理员账号按 OBSYNC_TOKEN 建立。
	AdminTokenCreated AdminTokenReconcile = iota
	// AdminTokenAdopted：已有账号但尚无 Token（v0.16 基座建的空壳行），补上环境变量的哈希。
	AdminTokenAdopted
	// AdminTokenUnchanged：库里的哈希与环境变量一致。
	AdminTokenUnchanged
	// AdminTokenSuperseded：库里的哈希与环境变量**不同**——网页端轮换过，
	// 以库为准，环境变量当前无效。调用方必须把这件事清楚地写进启动日志。
	AdminTokenSuperseded
)

// EnsureAdminUser 启动对账（幂等）：保证内置管理员账号存在并持有可用的 Token 哈希。
//
// 三分支规则见 v11 设计 §4.1。envTokenHash 为空表示环境变量缺失——
// 只在库里已有可用哈希时合法（config 层已强制 OBSYNC_TOKEN 必填，这里只兜底）。
func EnsureAdminUser(q dbtx, envTokenHash string) (AdminTokenReconcile, error) {
	u, err := GetUser(q, AdminUserID)
	if err != nil {
		return AdminTokenUnchanged, err
	}
	if u == nil {
		if envTokenHash == "" {
			return AdminTokenUnchanged, errors.New("no admin account and no OBSYNC_TOKEN to seed it from")
		}
		_, err := q.Exec(`INSERT INTO users (user_id, name, created_at, token_hash, token_generation, is_admin, disabled)
			VALUES (?, 'admin', ?, ?, 1, 1, 0)`, AdminUserID, time.Now().Unix(), envTokenHash)
		return AdminTokenCreated, err
	}
	// 旧库可能有 v0.16 基座留下的行：确保管理位在（幂等）
	if !u.IsAdmin {
		if _, err := q.Exec(`UPDATE users SET is_admin = 1 WHERE user_id = ?`, AdminUserID); err != nil {
			return AdminTokenUnchanged, err
		}
	}
	switch {
	case u.TokenHash == "":
		if envTokenHash == "" {
			return AdminTokenUnchanged, errors.New("admin account has no token and OBSYNC_TOKEN is empty")
		}
		_, err := q.Exec(`UPDATE users SET token_hash = ? WHERE user_id = ?`, envTokenHash, AdminUserID)
		return AdminTokenAdopted, err
	case subtle.ConstantTimeCompare([]byte(u.TokenHash), []byte(envTokenHash)) == 1:
		return AdminTokenUnchanged, nil
	default:
		return AdminTokenSuperseded, nil
	}
}

// ---------- 重置凭证（v11 设计 §3.1） ----------
//
// reset_auth_hash 存 SHA-256(resetKey)，resetKey = HKDF(VMK, "litesync/v1/token-reset-auth")。
// 它把「知道 E2EE 密码」从前端关卡升级为重置端点的服务端硬关卡：
// 只持有 API Token 的攻击者派生不出 resetKey，抢不走重置权。

// ErrResetAuthMismatch：提交的重置凭证与已登记的不符。
var ErrResetAuthMismatch = errors.New("reset credential does not match the registered one")

// GetVaultResetAuth 返回该 Vault 已登记的重置凭证哈希；未登记返回空串。
func GetVaultResetAuth(q dbtx, s VaultScope) (string, error) {
	if !s.Valid() {
		return "", ErrVaultScopeMissing
	}
	var h string
	err := q.QueryRow(`SELECT COALESCE(reset_auth_hash, '') FROM vaults WHERE vault_id = ?`, s.ID()).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return h, err
}

// RegisterVaultResetAuth 登记（或更新）重置凭证。
//
//   - 尚未登记 → 直接写入；
//   - 已登记且提交值与现值一致 → 幂等成功（同一 VMK 派生出的值恒定）；
//   - 已登记且 previous 匹配现值 → 允许更新（改密码的流程）；
//   - 其他 → ErrResetAuthMismatch。已登记的凭证**不可**被仅持会话者覆盖，
//     否则拿到 Token 的攻击者可以先换掉凭证再重置。
func RegisterVaultResetAuth(q dbtx, s VaultScope, resetAuth, previous string) error {
	if !s.Valid() {
		return ErrVaultScopeMissing
	}
	if resetAuth == "" {
		return errors.New("reset credential is required")
	}
	newHash := HashToken(resetAuth)
	cur, err := GetVaultResetAuth(q, s)
	if err != nil {
		return err
	}
	switch {
	case cur == "", subtle.ConstantTimeCompare([]byte(cur), []byte(newHash)) == 1:
		// 首次登记或幂等重放
	case previous != "" && subtle.ConstantTimeCompare([]byte(cur), []byte(HashToken(previous))) == 1:
		// 持旧凭证更新
	default:
		return ErrResetAuthMismatch
	}
	_, err = q.Exec(`UPDATE vaults SET reset_auth_hash = ? WHERE vault_id = ?`, newHash, s.ID())
	return err
}

// VerifyVaultResetAuth 校验重置凭证。
// enforced=false 表示该 Vault 尚未登记凭证（未启用 E2EE，或所有端都还没升级）——
// 此时放行，但调用方必须把「本次重置未经 E2EE 密码确认」如实告知（v11 设计 §3.1 披露）。
func VerifyVaultResetAuth(q dbtx, s VaultScope, submitted string) (enforced, ok bool, err error) {
	cur, err := GetVaultResetAuth(q, s)
	if err != nil {
		return false, false, err
	}
	if cur == "" {
		return false, true, nil
	}
	return true, subtle.ConstantTimeCompare([]byte(cur), []byte(HashToken(submitted))) == 1, nil
}
