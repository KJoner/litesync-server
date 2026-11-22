package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
)

// 统一身份映射（v0.20 公开化 / ADR-011）。
//
// 账号权威是外部 OIDC 身份服务；本地只记 (issuer, subject) → user_id。
//   - 主键是 (issuer, subject)：subject 在同一 issuer 下稳定且不复用；
//   - 邮箱、显示名只是**资料快照**，每次登录刷新，永远不参与匹配——
//     「同邮箱自动合并」会把资源关联给后来注册同一地址（或回收再注册）的另一个人；
//   - (issuer, user_id) 唯一：一个本地用户在同一身份服务下只绑一个主体，
//     认领冲突一律拒绝而不是覆盖。

const identitySchema = `
CREATE TABLE IF NOT EXISTS external_identities (
	issuer         TEXT NOT NULL,
	subject        TEXT NOT NULL,
	user_id        TEXT NOT NULL,
	email          TEXT NOT NULL DEFAULT '',
	email_verified INTEGER NOT NULL DEFAULT 0,
	display_name   TEXT NOT NULL DEFAULT '',
	created_at     INTEGER NOT NULL,
	last_login_at  INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (issuer, subject)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_external_identities_user ON external_identities(issuer, user_id);
`

var (
	// ErrIdentityTaken：这个外部主体已绑定到另一个本地用户（认领冲突，ADR-011 I-3）。
	ErrIdentityTaken = errors.New("external identity already linked to another user")
	// ErrUserAlreadyLinked：这个本地用户在该 issuer 下已经绑定了另一个主体。
	ErrUserAlreadyLinked = errors.New("user already linked to a different external identity")
	// ErrRegistrationClosed：注册关闭（或邀请无效）时首次出现的外部主体不建本地用户。
	ErrRegistrationClosed = errors.New("registration is closed")
)

// ExternalIdentity 是一条映射。
type ExternalIdentity struct {
	Issuer        string
	Subject       string
	UserID        string
	Email         string
	EmailVerified bool
	DisplayName   string
	// Username 是身份服务里的登录用户名（preferred_username）快照，只用于账号页展示。
	// 旧账号的用户名本身就是邮箱；它和昵称、邮箱一样永远不参与匹配。
	Username    string
	CreatedAt   int64
	LastLoginAt int64
}

// IdentityProfile 是一次登录时从 ID Token 取到的资料快照（不参与匹配）。
type IdentityProfile struct {
	Email         string
	EmailVerified bool
	// DisplayName：昵称 → 旧的 name → 不像邮箱的 preferred_username，见 api.idClaims.profile。
	DisplayName string
	// Username：preferred_username 原样（去首尾空白），账号页的「登录用户名」只认它，不从昵称推断。
	Username string
}

func scanIdentity(sc interface{ Scan(...any) error }) (*ExternalIdentity, error) {
	e := &ExternalIdentity{}
	var verified int
	if err := sc.Scan(&e.Issuer, &e.Subject, &e.UserID, &e.Email, &verified,
		&e.DisplayName, &e.Username, &e.CreatedAt, &e.LastLoginAt); err != nil {
		return nil, err
	}
	e.EmailVerified = verified != 0
	return e, nil
}

const identityColumns = `issuer, subject, user_id, email, email_verified, display_name, username, created_at, last_login_at`

// GetIdentity 按 (issuer, subject) 查映射；查不到返回 (nil, nil)。
func GetIdentity(q dbtx, issuer, subject string) (*ExternalIdentity, error) {
	e, err := scanIdentity(q.QueryRow(`SELECT `+identityColumns+` FROM external_identities
		WHERE issuer = ? AND subject = ?`, issuer, subject))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return e, err
}

// IdentitiesOfUser 返回本地用户的全部外部身份（账户页展示「已绑定」）。
func IdentitiesOfUser(q dbtx, userID string) ([]ExternalIdentity, error) {
	rows, err := q.Query(`SELECT `+identityColumns+` FROM external_identities
		WHERE user_id = ? ORDER BY created_at ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExternalIdentity
	for rows.Next() {
		e, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

// TouchIdentity 刷新资料快照与最近登录时间（不改变映射本身）。
func TouchIdentity(q dbtx, issuer, subject string, p IdentityProfile, now int64) error {
	_, err := q.Exec(`UPDATE external_identities
		SET email = ?, email_verified = ?, display_name = ?, username = ?, last_login_at = ?
		WHERE issuer = ? AND subject = ?`,
		truncate(p.Email, 254), boolInt(p.EmailVerified), truncate(p.DisplayName, 128),
		truncate(p.Username, 255), now, issuer, subject)
	return err
}

// LinkIdentity 把外部主体绑定到**已存在**的本地用户（旧账号认领，ADR-011 §1.7）。
//
// 幂等：同一 (issuer, subject) 已绑定到同一用户时直接成功。冲突一律拒绝：
// 主体已属于别人 → ErrIdentityTaken；该用户已在此 issuer 下绑定了别的主体 →
// ErrUserAlreadyLinked。从不覆盖已有映射。
func LinkIdentity(q dbtx, issuer, subject, userID string, p IdentityProfile, now int64) error {
	if issuer == "" || subject == "" || userID == "" {
		return fmt.Errorf("link identity: empty issuer/subject/user")
	}
	existing, err := GetIdentity(q, issuer, subject)
	if err != nil {
		return err
	}
	if existing != nil {
		if existing.UserID != userID {
			return ErrIdentityTaken
		}
		return TouchIdentity(q, issuer, subject, p, now)
	}
	var other string
	err = q.QueryRow(`SELECT subject FROM external_identities WHERE issuer = ? AND user_id = ?`,
		issuer, userID).Scan(&other)
	if err == nil {
		return ErrUserAlreadyLinked
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = q.Exec(`INSERT INTO external_identities
		(issuer, subject, user_id, email, email_verified, display_name, username, created_at, last_login_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		issuer, subject, userID, truncate(p.Email, 254), boolInt(p.EmailVerified),
		truncate(p.DisplayName, 128), truncate(p.Username, 255), now, now)
	if err != nil && IsUniqueViolation(err) {
		// 并发：另一个请求刚抢先建立了映射——按冲突处理，绝不覆盖
		return ErrIdentityTaken
	}
	return err
}

// CreateOIDCUser 为首次出现的外部主体建立本地用户与映射（开放注册，无邀请）。
func CreateOIDCUser(d *sql.DB, issuer, subject string, p IdentityProfile, now int64) (userID string, created bool, err error) {
	return CreateOIDCUserWithInvite(d, issuer, subject, p, "", now)
}

// CreateOIDCUserWithInvite 为首次出现的外部主体建立本地用户与映射（单事务）。
//
// 本地用户**没有** API Token（token_hash 为 NULL）、不是管理员、**没有仓库**——
// 零仓库账号是公开版的正常状态（需求 §3.1、§4.1）：LiteSync 首次进入时引导
// 创建仓库，Nexus 用户可以永远不创建。
//
// inviteID 非空时（邀请模式）在同一事务里消费该邀请；邀请已被并发消费则整个
// 建号回滚并返回 ErrRegistrationClosed。
//
// 并发安全：两个回调同时为同一主体建号时，后到者在 INSERT 映射时撞唯一约束，
// 整个事务回滚，然后按已有映射登录（返回 created=false）。
func CreateOIDCUserWithInvite(d *sql.DB, issuer, subject string, p IdentityProfile, inviteID string, now int64) (userID string, created bool, err error) {
	if existing, gerr := GetIdentity(d, issuer, subject); gerr != nil {
		return "", false, gerr
	} else if existing != nil {
		return existing.UserID, false, TouchIdentity(d, issuer, subject, p, now)
	}
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		return "", false, err
	}
	userID = "u-" + hex.EncodeToString(raw)

	tx, err := d.Begin()
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`INSERT INTO users (user_id, name, created_at, token_hash, token_generation, is_admin, disabled, email, display_name, created_via)
		VALUES (?, '', ?, NULL, 1, 0, 0, ?, ?, 'oidc')`,
		userID, now, truncate(p.Email, 254), truncate(p.DisplayName, 128)); err != nil {
		return "", false, err
	}
	if _, err := tx.Exec(`INSERT INTO external_identities
		(issuer, subject, user_id, email, email_verified, display_name, username, created_at, last_login_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		issuer, subject, userID, truncate(p.Email, 254), boolInt(p.EmailVerified),
		truncate(p.DisplayName, 128), truncate(p.Username, 255), now, now); err != nil {
		if IsUniqueViolation(err) {
			tx.Rollback() //nolint:errcheck
			existing, gerr := GetIdentity(d, issuer, subject)
			if gerr != nil || existing == nil {
				return "", false, fmt.Errorf("identity race: %v", gerr)
			}
			return existing.UserID, false, nil
		}
		return "", false, err
	}
	if inviteID != "" {
		ok, merr := markInviteUsed(tx, inviteID, "oidc:"+userID, now)
		if merr != nil {
			return "", false, merr
		}
		if !ok {
			return "", false, ErrRegistrationClosed
		}
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	return userID, true, nil
}

// AuditUserEvent 把一条账号级事件记到该用户的默认仓库审计链上；
// 零仓库用户没有可挂的仓库，静默跳过（调用方另记日志）。
func AuditUserEvent(q dbtx, userID, action, detail string) error {
	vaultID, err := OwnerVaultOf(q, userID)
	if err != nil || vaultID == "" {
		return err
	}
	return AppendAudit(q, VaultScope{vaultID: vaultID}, userID, action, detail)
}

// SetUserProfileSnapshot 刷新 users 表上的资料快照（管理员列表展示用）。
func SetUserProfileSnapshot(q dbtx, userID string, p IdentityProfile) error {
	_, err := q.Exec(`UPDATE users SET email = ?, display_name = ? WHERE user_id = ?`,
		truncate(p.Email, 254), truncate(p.DisplayName, 128), userID)
	return err
}

// BumpSessionGeneration 让该用户的全部网页会话失效（「退出所有设备」、
// 外部身份服务通知的全局退出）。API Token 本身不变。
func BumpSessionGeneration(q dbtx, userID string) (int64, error) {
	var gen int64
	err := q.QueryRow(`UPDATE users SET token_generation = token_generation + 1
		WHERE user_id = ? RETURNING token_generation`, userID).Scan(&gen)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return gen, err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// truncate 按字节截断到 max 以内且不切断 UTF-8 字符（资料快照字段的长度兜底）。
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}
