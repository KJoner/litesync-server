package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// 邀请与用户注册（v0.18 / v11 设计 §5.5）。
//
// 邀请链接 = https://server/join/<secret>。secret 是 32 字节 CSPRNG，
// 库里只存 SHA-256——邀请表泄露也不能凭它注册。
// 一次性：注册成功即标记 used；注册**失败**（重名等）不消耗。
// 无效 / 过期 / 已用 / 已撤销对外一律 404，不区分原因（区分即存在性预言机）。

const invitesSchema = `
CREATE TABLE IF NOT EXISTS invites (
	id          TEXT PRIMARY KEY,
	secret_hash TEXT NOT NULL UNIQUE,
	server_url  TEXT NOT NULL DEFAULT '',
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL,
	used_at     INTEGER NOT NULL DEFAULT 0,
	used_by     TEXT NOT NULL DEFAULT '',
	revoked     INTEGER NOT NULL DEFAULT 0
);
`

// Invite 是一条邀请记录（secret 本身不落库）。
type Invite struct {
	ID        string
	ServerURL string
	CreatedAt int64
	ExpiresAt int64
	UsedAt    int64
	UsedBy    string // 注册产生的用户名（管理列表展示用）
	Revoked   bool
}

// CreateInvite 生成一条邀请，返回 (id, secret)。secret 明文只在这里出现一次。
func CreateInvite(q dbtx, serverURL string, ttl time.Duration) (id, secret string, expiresAt int64, err error) {
	rawID := make([]byte, 4)
	rawSecret := make([]byte, 32)
	if _, err = rand.Read(rawID); err != nil {
		return "", "", 0, err
	}
	if _, err = rand.Read(rawSecret); err != nil {
		return "", "", 0, err
	}
	id = hex.EncodeToString(rawID)
	secret = hex.EncodeToString(rawSecret)
	now := time.Now()
	expiresAt = now.Add(ttl).Unix()
	_, err = q.Exec(`INSERT INTO invites (id, secret_hash, server_url, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)`, id, HashToken(secret), serverURL, now.Unix(), expiresAt)
	return id, secret, expiresAt, err
}

// GetInviteBySecret 返回**当前可用**的邀请；无效/过期/已用/已撤销一律 (nil, nil)。
func GetInviteBySecret(q dbtx, secret string, now int64) (*Invite, error) {
	inv := &Invite{}
	var revoked int64
	err := q.QueryRow(`SELECT id, server_url, created_at, expires_at, used_at, used_by, revoked
		FROM invites WHERE secret_hash = ? AND used_at = 0 AND revoked = 0 AND expires_at > ?`,
		HashToken(secret), now).
		Scan(&inv.ID, &inv.ServerURL, &inv.CreatedAt, &inv.ExpiresAt, &inv.UsedAt, &inv.UsedBy, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return inv, nil
}

// ListInvites 返回全部邀请（管理列表，最新在前）。
func ListInvites(q dbtx) ([]Invite, error) {
	rows, err := q.Query(`SELECT id, server_url, created_at, expires_at, used_at, used_by, revoked
		FROM invites ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		var inv Invite
		var revoked int64
		if err := rows.Scan(&inv.ID, &inv.ServerURL, &inv.CreatedAt, &inv.ExpiresAt,
			&inv.UsedAt, &inv.UsedBy, &revoked); err != nil {
			return nil, err
		}
		inv.Revoked = revoked != 0
		out = append(out, inv)
	}
	return out, rows.Err()
}

// RevokeInvite 撤销一条未使用的邀请；不存在或已用返回 false。
func RevokeInvite(q dbtx, id string) (bool, error) {
	res, err := q.Exec(`UPDATE invites SET revoked = 1 WHERE id = ? AND used_at = 0`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return n > 0, nil
}

// markInviteUsed 原子消费邀请（注册事务内调用）。返回 false = 已被并发注册抢先。
func markInviteUsed(q dbtx, id, usedBy string, now int64) (bool, error) {
	res, err := q.Exec(`UPDATE invites SET used_at = ?, used_by = ? WHERE id = ? AND used_at = 0 AND revoked = 0`,
		now, usedBy, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return n > 0, nil
}

// PruneInvites 清理过期超过 30 天的邀请（维护任务）。
func PruneInvites(q dbtx, now int64) (int64, error) {
	res, err := q.Exec(`DELETE FROM invites WHERE expires_at < ?`, now-30*86400)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return n, nil
}

// ErrNameTaken：用户名已被占用（注册失败，不消耗邀请）。
var ErrNameTaken = errors.New("user name already taken")

// ErrInviteGone：邀请无效、过期、已用或已撤销。
var ErrInviteGone = errors.New("invite invalid, expired, or already used")

// NewUserRegistration 是注册事务的产物。
type NewUserRegistration struct {
	UserID  string
	Name    string
	VaultID string
	Token   string // 明文只在此出现一次
}

// RegisterInvitedUser 消费邀请并建立完整的用户与专属 Vault（单事务，v11 设计 §5.5）：
// user（token_hash）→ vault（identity + blobID secret）→ owner membership →
// 标记邀请已用 → 审计。repo_state 行由调用方在事务提交后 initRepoState（幂等）。
func RegisterInvitedUser(d *sql.DB, inviteSecret, name string, now int64) (*NewUserRegistration, error) {
	inv, err := GetInviteBySecret(d, inviteSecret, now)
	if err != nil {
		return nil, err
	}
	if inv == nil {
		return nil, ErrInviteGone
	}
	if existing, err := GetUserByName(d, name); err != nil {
		return nil, err
	} else if existing != nil {
		return nil, ErrNameTaken
	}

	rawUser := make([]byte, 4)
	rawToken := make([]byte, 32)
	for _, b := range [][]byte{rawUser, rawToken} {
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
	}
	reg := &NewUserRegistration{
		UserID: "u-" + hex.EncodeToString(rawUser),
		Name:   name,
		Token:  TokenPrefix + hex.EncodeToString(rawToken),
	}

	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec(`INSERT INTO users (user_id, name, created_at, token_hash, token_generation, is_admin, disabled)
		VALUES (?, ?, ?, ?, 1, 0, 0)`, reg.UserID, name, now, HashToken(reg.Token)); err != nil {
		return nil, err
	}
	// 仓库全套与 v0.19 的「新建仓库」共用同一实现（createVaultTx）
	reg.VaultID, err = createVaultTx(tx, reg.UserID, name, now)
	if err != nil {
		return nil, err
	}
	ok, err := markInviteUsed(tx, inv.ID, name, now)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInviteGone // 并发注册抢先消费了同一条邀请
	}
	scope := VaultScope{vaultID: reg.VaultID}
	if err := AppendAudit(tx, scope, reg.UserID, "user-registered",
		fmt.Sprintf("invite=%s name=%s", inv.ID, name)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	// repo_state 行（幂等）：注册返回时这个 Vault 已可接受首次同步。
	// 放在事务提交后——initRepoState 自己管理读写，与上面的事务互不嵌套。
	if err := initRepoState(d, scope); err != nil {
		return nil, fmt.Errorf("init repo state for new vault: %w", err)
	}
	return reg, nil
}

// SetUserDisabledCascade 禁用/解禁用户（v11 设计 §5.7；v0.20.1 起停用 = 动作 B，ADR-019 §2.1）。
//
// 停用在同一事务里完成：置禁用位 + 授权代次 +1（全部网页会话、设备凭据、待领取授权与
// API Token 一起失效，记一条 reason=admin-disable 的撤销事件）。数据全部保留。
// 重新启用**只**清禁用位：代次只增不减，任何旧凭据都不会复活（R-2）——用户重新登录、
// 重新连接设备；只用 API Token 的旧账号需要 `obsync token reset --user <名>` 换发新 Token。
// 返回撤销的设备数。
func SetUserDisabledCascade(d *sql.DB, userID string, disabled bool, actor string) (int, error) {
	u, err := GetUser(d, userID)
	if err != nil {
		return 0, err
	}
	if u == nil {
		return 0, errors.New("user not found")
	}
	if u.IsAdmin {
		return 0, errors.New("cannot disable an admin account")
	}
	vaultID, err := OwnerVaultOf(d, userID)
	if err != nil {
		return 0, err
	}
	tx, err := d.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := SetUserDisabled(tx, userID, disabled); err != nil {
		return 0, err
	}
	revoked := 0
	if disabled {
		eventID, err := NewEventID()
		if err != nil {
			return 0, err
		}
		out, err := RevokeAccountTx(tx, RevokeParams{
			UserID: userID, EventID: eventID, Scope: RevocationScopeProduct,
			Reason: "admin-disable", Origin: "litesync", Now: time.Now().Unix(),
		})
		if err != nil {
			return 0, err
		}
		revoked = out.RevokedDevices
		if vaultID != "" {
			if err := AppendAudit(tx, VaultScope{vaultID: vaultID}, actor, "user-disabled",
				fmt.Sprintf("user=%s devices=%d grants=%d authEpoch=%d", userID, revoked, out.RevokedGrants, out.AuthEpoch)); err != nil {
				return 0, err
			}
		}
	} else if vaultID != "" {
		if err := AppendAudit(tx, VaultScope{vaultID: vaultID}, actor, "user-enabled",
			fmt.Sprintf("user=%s (old credentials stay revoked)", userID)); err != nil {
			return 0, err
		}
	}
	return revoked, tx.Commit()
}
