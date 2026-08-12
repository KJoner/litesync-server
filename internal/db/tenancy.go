package db

import (
	"database/sql"
	"errors"
	"time"
)

// 多租户模型（v0.16.0 / 计划书 §10、ADR-010）。
//
// # VaultScope：把「必须记得带 vault 范围」变成「想漏都漏不掉」
//
// 多租户里最常见也最致命的一类漏洞是：某一处查询忘了带 vault 条件，
// 或者从**请求体**里取了 vaultId。只要有一处，整套隔离就形同虚设。
//
// 光靠代码审查是保不住的——审查能发现已经写出来的错误，拦不住下一个
// 新写的。因此这里用类型层强制：所有按租户划分的查询都要求一个
// VaultScope，而 VaultScope 的唯一构造入口在认证层。
//
// 这与 §6.11 的强类型 FileState 转换是同一个思路。

// VaultScope 是一次请求被授权访问的 Vault 范围。
//
// 它的字段不可导出，因此**只能**通过 ScopeFromAuth 构造；业务代码拿到的
// 是一个已经被认证过的范围，没法凭空造一个指向别人 Vault 的出来。
type VaultScope struct {
	vaultID string
}

// ID 返回 vault 标识（拼 SQL 用）。
func (v VaultScope) ID() string { return v.vaultID }

// Valid 报告这个范围是否可用。零值 VaultScope 无效——
// 那意味着某处忘了从认证上下文取范围。
func (v VaultScope) Valid() bool { return v.vaultID != "" }

// ScopeFromAuth 由**认证层**在校验完凭据之后调用，把认证结果转成 VaultScope。
//
// 这是唯一的构造入口。它故意起了一个「一看就知道该在哪调用」的名字：
// 出现在业务代码里的 db.ScopeFromAuth 调用一眼就是可疑的，
// 而 internal/api/tenancy_guard_test.go 会把这条约束变成会失败的测试。
func ScopeFromAuth(vaultID string) VaultScope {
	return VaultScope{vaultID: vaultID}
}

// LegacyDefaultScope 是单用户阶段的隐式租户。
//
// 存量部署的数据全都挂在 DefaultVaultID 下；多租户上线后它成为一个普通
// 租户，不再有任何特殊待遇。保留这个函数只是为了让迁移路径与旧测试可读——
// 新代码不应该调用它。
func LegacyDefaultScope() VaultScope { return VaultScope{vaultID: DefaultVaultID} }

// ErrVaultScopeMissing：拿到了零值 VaultScope。
//
// 这一定是编程错误（某处忘了从认证上下文取范围），因此是硬失败而不是
// 「退化为默认租户」——后者会把一个漏洞变成静默的跨租户访问。
var ErrVaultScopeMissing = errors.New("vault scope is missing; it must come from the authenticated context")

// Role 是成员在某个 Vault 里的角色（§10.4）。
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleEditor Role = "editor"
	RoleReader Role = "reader"
)

// CanWrite 报告该角色是否可以写入内容。
func (r Role) CanWrite() bool { return r == RoleOwner || r == RoleAdmin || r == RoleEditor }

// CanAdmin 报告该角色是否可以管理成员与密钥。
func (r Role) CanAdmin() bool { return r == RoleOwner || r == RoleAdmin }

// User 是一个账号。
type User struct {
	UserID    string
	Name      string
	CreatedAt int64
}

// Vault 是一个独立的同步仓库。
//
// Secret 是该 Vault 的 blobID 域分隔密钥（ADR-010 §4）：
// blobID = HMAC(Secret, contentHash)。它只存在服务端，绝不出现在任何响应里——
// 泄露它等于把跨租户去重的存在性预言机还给攻击者。
type Vault struct {
	VaultID   string
	OwnerID   string
	Name      string
	Secret    []byte
	CreatedAt int64
}

// Membership 是「某个用户在某个 Vault 里的角色」。
type Membership struct {
	UserID    string
	VaultID   string
	Role      Role
	CreatedAt int64
}

// KeyEpochRecord 记录一次密钥世代推进及其原因（成员移除、手工轮换等）。
type KeyEpochRecord struct {
	VaultID   string
	Epoch     int64
	Reason    string
	CreatedAt int64
}

// AuditEvent 是一条审计记录。
//
// 只记「谁在哪个 Vault 做了什么」，不记路径与内容——审计日志同样受
// §7.7 的日志隐私约束。
type AuditEvent struct {
	VaultID string
	Actor   string // deviceId 或 userId
	Action  string
	Detail  string
	At      int64
}

const tenancySchema = `
CREATE TABLE IF NOT EXISTS users (
	user_id    TEXT PRIMARY KEY,
	name       TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vaults (
	vault_id   TEXT PRIMARY KEY,
	owner_id   TEXT NOT NULL,
	name       TEXT NOT NULL DEFAULT '',
	-- blobID 的域分隔密钥（ADR-010 §4）。绝不出现在任何 API 响应里
	secret     BLOB NOT NULL,
	created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS memberships (
	user_id    TEXT NOT NULL,
	vault_id   TEXT NOT NULL,
	role       TEXT NOT NULL CHECK (role IN ('owner','admin','editor','reader')),
	created_at INTEGER NOT NULL,
	PRIMARY KEY (user_id, vault_id)
);
CREATE INDEX IF NOT EXISTS idx_memberships_vault ON memberships(vault_id);

CREATE TABLE IF NOT EXISTS key_epochs (
	vault_id   TEXT NOT NULL,
	epoch      INTEGER NOT NULL,
	reason     TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	PRIMARY KEY (vault_id, epoch)
);

CREATE TABLE IF NOT EXISTS audit_events (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	vault_id TEXT NOT NULL,
	actor    TEXT NOT NULL,
	action   TEXT NOT NULL,
	detail   TEXT NOT NULL DEFAULT '',
	at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_vault_at ON audit_events(vault_id, at DESC);
`

// ---------- 用户与 Vault ----------

func InsertUser(q dbtx, u *User) error {
	if u.CreatedAt == 0 {
		u.CreatedAt = time.Now().Unix()
	}
	_, err := q.Exec(`INSERT INTO users (user_id, name, created_at) VALUES (?, ?, ?)
		ON CONFLICT(user_id) DO NOTHING`, u.UserID, u.Name, u.CreatedAt)
	return err
}

func InsertVault(q dbtx, v *Vault) error {
	if v.CreatedAt == 0 {
		v.CreatedAt = time.Now().Unix()
	}
	if len(v.Secret) == 0 {
		return errors.New("vault secret is required (blob id domain separation)")
	}
	_, err := q.Exec(`INSERT INTO vaults (vault_id, owner_id, name, secret, created_at)
		VALUES (?, ?, ?, ?, ?) ON CONFLICT(vault_id) DO NOTHING`,
		v.VaultID, v.OwnerID, v.Name, v.Secret, v.CreatedAt)
	return err
}

// GetVault 按范围取 Vault。注意参数是 VaultScope 而不是裸 string——
// 调用方拿不到一个没被认证过的范围。
func GetVault(q dbtx, s VaultScope) (*Vault, error) {
	if !s.Valid() {
		return nil, ErrVaultScopeMissing
	}
	v := &Vault{}
	err := q.QueryRow(`SELECT vault_id, owner_id, name, secret, created_at FROM vaults WHERE vault_id = ?`,
		s.ID()).Scan(&v.VaultID, &v.OwnerID, &v.Name, &v.Secret, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

// ---------- 成员 ----------

func UpsertMembership(q dbtx, m *Membership) error {
	if m.CreatedAt == 0 {
		m.CreatedAt = time.Now().Unix()
	}
	_, err := q.Exec(`INSERT INTO memberships (user_id, vault_id, role, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(user_id, vault_id) DO UPDATE SET role = excluded.role`,
		m.UserID, m.VaultID, string(m.Role), m.CreatedAt)
	return err
}

// RoleOf 返回用户在该 Vault 里的角色；不是成员返回 ("", false)。
//
// 这是授权判断的**唯一**依据：请求里带的任何角色声明都不作数。
func RoleOf(q dbtx, s VaultScope, userID string) (Role, bool, error) {
	if !s.Valid() {
		return "", false, ErrVaultScopeMissing
	}
	var role string
	err := q.QueryRow(`SELECT role FROM memberships WHERE vault_id = ? AND user_id = ?`,
		s.ID(), userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return Role(role), true, nil
}

// RemoveMembership 移除成员。调用方随后**必须**推进 keyEpoch（§10.4）——
// 只删 membership 不换密钥，被移除者仍能解开后续内容。
func RemoveMembership(q dbtx, s VaultScope, userID string) error {
	if !s.Valid() {
		return ErrVaultScopeMissing
	}
	_, err := q.Exec(`DELETE FROM memberships WHERE vault_id = ? AND user_id = ?`, s.ID(), userID)
	return err
}

// ListMembers 列出某 Vault 的全部成员。
func ListMembers(q dbtx, s VaultScope) ([]Membership, error) {
	if !s.Valid() {
		return nil, ErrVaultScopeMissing
	}
	rows, err := q.Query(`SELECT user_id, vault_id, role, created_at FROM memberships
		WHERE vault_id = ? ORDER BY created_at ASC`, s.ID())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Membership
	for rows.Next() {
		var m Membership
		var role string
		if err := rows.Scan(&m.UserID, &m.VaultID, &role, &m.CreatedAt); err != nil {
			return nil, err
		}
		m.Role = Role(role)
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---------- 密钥世代与审计 ----------

// RecordKeyEpoch 登记一次密钥世代推进。
func RecordKeyEpoch(q dbtx, s VaultScope, epoch int64, reason string) error {
	if !s.Valid() {
		return ErrVaultScopeMissing
	}
	_, err := q.Exec(`INSERT INTO key_epochs (vault_id, epoch, reason, created_at)
		VALUES (?, ?, ?, ?) ON CONFLICT(vault_id, epoch) DO NOTHING`,
		s.ID(), epoch, reason, time.Now().Unix())
	return err
}

// AppendAudit 追加一条审计记录（只记身份与动作，不记路径与内容）。
func AppendAudit(q dbtx, s VaultScope, actor, action, detail string) error {
	if !s.Valid() {
		return ErrVaultScopeMissing
	}
	_, err := q.Exec(`INSERT INTO audit_events (vault_id, actor, action, detail, at)
		VALUES (?, ?, ?, ?, ?)`, s.ID(), actor, action, detail, time.Now().Unix())
	return err
}

// ListAudit 读取审计记录（按范围，最新在前）。
func ListAudit(q dbtx, s VaultScope, limit int) ([]AuditEvent, error) {
	if !s.Valid() {
		return nil, ErrVaultScopeMissing
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := q.Query(`SELECT vault_id, actor, action, detail, at FROM audit_events
		WHERE vault_id = ? ORDER BY at DESC, id DESC LIMIT ?`, s.ID(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.VaultID, &e.Actor, &e.Action, &e.Detail, &e.At); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------- 迁移校验查询（v0.16 从 sync 包收回，ADR-010 T-1） ----------
//
// 这几个查询原先散在 internal/sync/meta.go 里，各自手写 `vault_id = ?` 并
// 硬编码 DefaultVaultID。单用户下没问题，多租户下就是「按错误的范围校验」——
// 而校验器给出错误答案，比没有校验器更危险：它会让人以为已经检查过了。
//
// 收回 db 包并要求 VaultScope 之后，范围只能来自认证上下文。

// MaxContentGeneration 返回某对象历史里最大的 contentGeneration。
func MaxContentGeneration(q dbtx, s VaultScope, fileID string) (int64, error) {
	if !s.Valid() {
		return 0, ErrVaultScopeMissing
	}
	var maxGen int64
	err := q.QueryRow(
		`SELECT COALESCE(MAX(content_generation), 0) FROM object_versions WHERE vault_id = ? AND file_id = ?`,
		s.ID(), fileID).Scan(&maxGen)
	return maxGen, err
}

// CountDuplicateRevisions 统计 (file_id, revision) 重复的历史行。
func CountDuplicateRevisions(q dbtx, s VaultScope) (int64, error) {
	if !s.Valid() {
		return 0, ErrVaultScopeMissing
	}
	var n int64
	err := q.QueryRow(
		`SELECT COUNT(*) FROM (SELECT file_id, revision FROM object_versions
		 WHERE vault_id = ? GROUP BY file_id, revision HAVING COUNT(*) > 1)`, s.ID()).Scan(&n)
	return n, err
}

// CountOrphanHistory 统计归属不到任何已知对象的历史行。
func CountOrphanHistory(q dbtx, s VaultScope) (int64, error) {
	if !s.Valid() {
		return 0, ErrVaultScopeMissing
	}
	var n int64
	err := q.QueryRow(
		`SELECT COUNT(*) FROM object_versions v WHERE v.vault_id = ?
		   AND NOT EXISTS (SELECT 1 FROM file_objects o WHERE o.vault_id = v.vault_id AND o.file_id = v.file_id)`,
		s.ID()).Scan(&n)
	return n, err
}

// CountPlaintextAddressedChangesAfter 统计 cutoff 之后仍以明文寻址名发布的变更。
func CountPlaintextAddressedChangesAfter(q dbtx, s VaultScope, cutoff int64) (int64, error) {
	if !s.Valid() {
		return 0, ErrVaultScopeMissing
	}
	var n int64
	err := q.QueryRow(
		`SELECT COUNT(*) FROM object_changes
		  WHERE vault_id = ? AND sequence > ? AND pseudonym != file_id`, s.ID(), cutoff).Scan(&n)
	return n, err
}

// DeleteAllChanges 清空某租户的 changes（complete 的全量裁剪）。
func DeleteAllChanges(q dbtx, s VaultScope) error {
	if !s.Valid() {
		return ErrVaultScopeMissing
	}
	_, err := q.Exec(`DELETE FROM object_changes WHERE vault_id = ?`, s.ID())
	return err
}
