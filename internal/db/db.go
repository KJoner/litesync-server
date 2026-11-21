// Package db 负责 SQLite 的打开、初始化和元数据读写。
package db

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Open 打开（必要时创建）SQLite 数据库并初始化 Schema。
// 默认 synchronous=FULL（v9）：WAL 下 NORMAL 不保证掉电后已确认事务的持久性，
// 与「已确认就绝不能丢」的红线冲突；确有性能需要时用 OpenWithSync(path, false)。
// 单用户场景：固定单连接即可，天然避免 SQLITE_BUSY。
//
// 注意：v5 → v6 的**数据**迁移不在这里执行——它需要读取 blob 信封头才能推断
// contentGeneration 与信封版本，因此由 cmd/obsync 在 storage 就绪后调用
// MigrateToV6。Open 只保证「表结构与列齐备」。
func Open(path string) (*sql.DB, error) {
	return OpenWithSync(path, true)
}

// OpenWithSync 打开数据库；syncFull=false 时使用 synchronous=NORMAL（牺牲掉电持久性）。
func OpenWithSync(path string, syncFull bool) (*sql.DB, error) {
	d, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(1)
	d.SetConnMaxLifetime(0)
	d.SetConnMaxIdleTime(0)

	synchronous := "PRAGMA synchronous=FULL"
	if !syncFull {
		synchronous = "PRAGMA synchronous=NORMAL"
	}
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		synchronous,
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := d.Exec(pragma); err != nil {
			d.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}

	if _, err := d.Exec(schema + integritySchema + gcSchema + checkpointSchema + tenancySchema + serverSecretsSchema + vaultRetentionSchema + invitesSchema + identitySchema + vaultInitSchema + mailSchema); err != nil {
		d.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	if err := migrateColumns(d); err != nil {
		d.Close()
		return nil, fmt.Errorf("migrate columns: %w", err)
	}
	if err := migrateJournalKindCheck(d); err != nil {
		d.Close()
		return nil, fmt.Errorf("migrate journal kind: %w", err)
	}
	// §10.2：repo_state 从单行实例级表改为按 Vault 划分。
	// 必须在 initRepoState 之前——后者要按 vault_id 查询。
	if err := migrateRepoStatePerVault(d); err != nil {
		d.Close()
		return nil, fmt.Errorf("migrate repo state: %w", err)
	}
	if err := initRepoState(d, LegacyDefaultScope()); err != nil {
		d.Close()
		return nil, fmt.Errorf("init repo state: %w", err)
	}
	return d, nil
}

// columnMigration 描述一次「缺列则补」的迁移。
type columnMigration struct {
	table, column, ddl string
	// legacyOnly：只对升级上来的旧库有意义（表不存在时跳过）
	legacyOnly bool
}

// migrateColumns 为旧库补齐新增列（CREATE TABLE IF NOT EXISTS 不会加列）。
//
// 分两类：
//   - v5 遗留表（files / changes / file_versions）：补齐 v5 末期的列，
//     好让 v5 → v6 迁移能完整读出它们；这些表在新库里不存在，直接跳过
//   - v6 表（repo_state / devices）：补齐 v6 新增的列
func migrateColumns(d *sql.DB) error {
	migrations := []columnMigration{
		// --- v5 遗留表（仅升级路径） ---
		{"files", "canonical_key", `ALTER TABLE files ADD COLUMN canonical_key TEXT NOT NULL DEFAULT ''`, true},
		{"files", "file_id", `ALTER TABLE files ADD COLUMN file_id TEXT NOT NULL DEFAULT ''`, true},
		{"files", "meta_enc", `ALTER TABLE files ADD COLUMN meta_enc TEXT NOT NULL DEFAULT ''`, true},
		{"files", "meta_generation", `ALTER TABLE files ADD COLUMN meta_generation INTEGER NOT NULL DEFAULT 0`, true},
		{"file_versions", "file_id", `ALTER TABLE file_versions ADD COLUMN file_id TEXT NOT NULL DEFAULT ''`, true},
		{"changes", "meta_generation", `ALTER TABLE changes ADD COLUMN meta_generation INTEGER NOT NULL DEFAULT 0`, true},

		// --- v6 新增列（ADR-003 / ADR-006） ---
		{"repo_state", "meta_state", `ALTER TABLE repo_state ADD COLUMN meta_state TEXT NOT NULL DEFAULT 'plain'`, false},
		{"repo_state", "schema_version", `ALTER TABLE repo_state ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 5`, false},
		{"repo_state", "format_epoch", `ALTER TABLE repo_state ADD COLUMN format_epoch INTEGER NOT NULL DEFAULT 1`, false},
		{"repo_state", "minimum_envelope_version", `ALTER TABLE repo_state ADD COLUMN minimum_envelope_version INTEGER NOT NULL DEFAULT 0`, false},
		{"repo_state", "meta_schema_version", `ALTER TABLE repo_state ADD COLUMN meta_schema_version INTEGER NOT NULL DEFAULT 1`, false},
		{"repo_state", "migration_id", `ALTER TABLE repo_state ADD COLUMN migration_id TEXT NOT NULL DEFAULT ''`, false},
		{"repo_state", "migration_owner_device_id", `ALTER TABLE repo_state ADD COLUMN migration_owner_device_id TEXT NOT NULL DEFAULT ''`, false},
		{"repo_state", "migration_lease_expires_at", `ALTER TABLE repo_state ADD COLUMN migration_lease_expires_at INTEGER NOT NULL DEFAULT 0`, false},
		{"repo_state", "migration_cutoff_sequence", `ALTER TABLE repo_state ADD COLUMN migration_cutoff_sequence INTEGER NOT NULL DEFAULT 0`, false},
		{"repo_state", "migration_target_format_epoch", `ALTER TABLE repo_state ADD COLUMN migration_target_format_epoch INTEGER NOT NULL DEFAULT 0`, false},
		{"repo_state", "migration_key_epoch", `ALTER TABLE repo_state ADD COLUMN migration_key_epoch INTEGER NOT NULL DEFAULT 0`, false},
		{"devices", "last_acked_sequence", `ALTER TABLE devices ADD COLUMN last_acked_sequence INTEGER NOT NULL DEFAULT 0`, false},

		// --- v0.15 新增列（§9.2 设备签名密钥） ---
		{"devices", "signing_public_key", `ALTER TABLE devices ADD COLUMN signing_public_key TEXT NOT NULL DEFAULT ''`, false},

		// --- v0.16 新增列（§10.4 成员权限与密钥轮换） ---
		// 设备必须知道自己属于哪个 (vault, user)，否则「移除成员时撤销他的设备」
		// 无从谈起。存量设备默认落在 default vault 的 owner 名下。
		{"devices", "vault_id", `ALTER TABLE devices ADD COLUMN vault_id TEXT NOT NULL DEFAULT 'default'`, false},
		{"devices", "user_id", `ALTER TABLE devices ADD COLUMN user_id TEXT NOT NULL DEFAULT ''`, false},
		// 移除成员后 Vault Key 必须由管理员设备重新封装；在那之前这里记着待办的 epoch
		{"vaults", "pending_rewrap_epoch", `ALTER TABLE vaults ADD COLUMN pending_rewrap_epoch INTEGER NOT NULL DEFAULT 0`, false},

		// --- v0.17 新增列（§15 第 3 步：迁移前必须能确认没有旧客户端） ---
		// 没有这一列，「检查设备列表，无旧客户端」这一步根本无法执行——
		// 而它是不可逆迁移的前置条件。
		{"devices", "client_version", `ALTER TABLE devices ADD COLUMN client_version TEXT NOT NULL DEFAULT ''`, false},
		{"devices", "client_protocol", `ALTER TABLE devices ADD COLUMN client_protocol INTEGER NOT NULL DEFAULT 0`, false},

		// --- v0.17 运维页增强：设备平台与最近来源 IP ---
		// 丢设备的那天，「哪台是那部手机、它最后从哪个网络连上来」必须一眼可答；
		// 只有设备名的列表回答不了这两个问题。
		{"devices", "platform", `ALTER TABLE devices ADD COLUMN platform TEXT NOT NULL DEFAULT ''`, false},
		{"devices", "last_ip", `ALTER TABLE devices ADD COLUMN last_ip TEXT NOT NULL DEFAULT ''`, false},

		// --- v0.18 用户 API Token 落库与多用户（v11 设计 §4.1、§5.2） ---
		// token_hash 只存 SHA-256；token_generation 是会话世代（轮换 +1，旧会话即拒）
		{"users", "token_hash", `ALTER TABLE users ADD COLUMN token_hash TEXT`, false},
		{"users", "token_generation", `ALTER TABLE users ADD COLUMN token_generation INTEGER NOT NULL DEFAULT 1`, false},
		{"users", "is_admin", `ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0`, false},
		{"users", "disabled", `ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0`, false},
		{"users", "last_seen_at", `ALTER TABLE users ADD COLUMN last_seen_at INTEGER`, false},
		// identity：/api/v1/info 返回的仓库稳定身份，多 Vault 后按 Vault 独立；
		// default vault 的值由 migrateVaultIdentity 从 vault_meta 拷贝，保证升级
		// 不会让现有客户端误判「服务器换库」而重新对账。
		{"vaults", "identity", `ALTER TABLE vaults ADD COLUMN identity TEXT NOT NULL DEFAULT ''`, false},
		// reset_auth_hash：重置凭证（E2EE 密码知识证明）的哈希，见 users.go
		{"vaults", "reset_auth_hash", `ALTER TABLE vaults ADD COLUMN reset_auth_hash TEXT`, false},
		// enrollments 的归属（v11 设计 §5.4）：一次性注册凭据在**创建时**就定死
		// 新设备将落到哪个 (vault, user)——消费方无法声称自己属于别的租户
		{"enrollments", "vault_id", `ALTER TABLE enrollments ADD COLUMN vault_id TEXT NOT NULL DEFAULT 'default'`, false},
		{"enrollments", "user_id", `ALTER TABLE enrollments ADD COLUMN user_id TEXT NOT NULL DEFAULT ''`, false},
		// shares / pairings 的归属（v11 设计 §5.4）：创建/列表/撤销按 Vault 隔离；
		// 公开读取路径（分享链接、配对落地页）仍按不可猜测的 id 寻址，行为不变
		{"shares", "vault_id", `ALTER TABLE shares ADD COLUMN vault_id TEXT NOT NULL DEFAULT 'default'`, false},
		{"pairings", "vault_id", `ALTER TABLE pairings ADD COLUMN vault_id TEXT NOT NULL DEFAULT 'default'`, false},
		// --- v0.20 公开化（基线 PRE-03 / ADR-014） ---
		// 配对包的发行者与 v2 grant 绑定：撤销只认发行者本人；v2 包的密文随
		// grant 的兑换/撤销/过期一并删除，读取 envelope 不消费
		{"pairings", "user_id", `ALTER TABLE pairings ADD COLUMN user_id TEXT NOT NULL DEFAULT ''`, false},
		{"pairings", "grant_id", `ALTER TABLE pairings ADD COLUMN grant_id TEXT NOT NULL DEFAULT ''`, false},
		// enrollment grant（ADR-014）：可被发行者撤销；v2 兑换记录 exchange_id，
		// 并把签发结果用 secret 派生的密钥加密暂存一个短窗口，供「响应丢失后同
		// exchangeId 重试」原样取回（只知道 exchangeId 的人拿不到任何东西）
		{"enrollments", "revoked", `ALTER TABLE enrollments ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0`, false},
		{"enrollments", "exchange_id", `ALTER TABLE enrollments ADD COLUMN exchange_id TEXT NOT NULL DEFAULT ''`, false},
		{"enrollments", "replay_ciphertext", `ALTER TABLE enrollments ADD COLUMN replay_ciphertext TEXT NOT NULL DEFAULT ''`, false},
		{"enrollments", "replay_expires_at", `ALTER TABLE enrollments ADD COLUMN replay_expires_at INTEGER NOT NULL DEFAULT 0`, false},
		// 统一身份（ADR-011）：users 上的资料快照只用于管理员列表展示，从不参与匹配；
		// created_via 区分 token（旧管理员/邀请）与 oidc（公开注册）账号
		{"users", "email", `ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''`, false},
		{"users", "display_name", `ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''`, false},
		{"users", "created_via", `ALTER TABLE users ADD COLUMN created_via TEXT NOT NULL DEFAULT ''`, false},
		// 仓库加密初始化状态机（ADR-012）：既有仓库一律 ready（含旧明文仓库，其
		// encryption_state 不变）；v2 新建仓库从 pending_encryption 开始
		{"vaults", "init_state", `ALTER TABLE vaults ADD COLUMN init_state TEXT NOT NULL DEFAULT 'ready'`, false},
		{"vaults", "init_version", `ALTER TABLE vaults ADD COLUMN init_version INTEGER NOT NULL DEFAULT 1`, false},
		{"vaults", "client_request_id", `ALTER TABLE vaults ADD COLUMN client_request_id TEXT NOT NULL DEFAULT ''`, false},
		{"vaults", "init_lease_op", `ALTER TABLE vaults ADD COLUMN init_lease_op TEXT NOT NULL DEFAULT ''`, false},
		{"vaults", "init_lease_expires", `ALTER TABLE vaults ADD COLUMN init_lease_expires INTEGER NOT NULL DEFAULT 0`, false},
		// 用户级配额覆盖值（需求 §12）：0 = 跟随服务器默认，-1 = 不限，>0 = 指定值
		{"users", "quota_bytes", `ALTER TABLE users ADD COLUMN quota_bytes INTEGER NOT NULL DEFAULT 0`, false},
		{"users", "quota_vaults", `ALTER TABLE users ADD COLUMN quota_vaults INTEGER NOT NULL DEFAULT 0`, false},
	}

	for _, m := range migrations {
		exists, err := TableExists(d, m.table)
		if err != nil {
			return err
		}
		if !exists {
			if m.legacyOnly {
				continue
			}
			return fmt.Errorf("table %s missing", m.table)
		}
		has, err := columnExists(d, m.table, m.column)
		if err != nil {
			return err
		}
		if !has {
			if _, err := d.Exec(m.ddl); err != nil {
				return err
			}
		}
	}

	// v0.18：Token 哈希查找与用户名唯一性。
	// name 的唯一性只约束非空名（v0.16 基座的测试用户 name 为空，不应互相冲突）。
	for _, ddl := range []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_token_hash ON users(token_hash) WHERE token_hash IS NOT NULL`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_name ON users(name) WHERE name != ''`,
		// v2 建库幂等（ADR-012）：同一用户同一 clientRequestId 只能建出一个仓库
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_vaults_client_request ON vaults(owner_id, client_request_id) WHERE client_request_id != ''`,
		// 存量设备归属回填（幂等）：v0.16 加列时的默认值是 ''，而单用户阶段的
		// 全部设备事实上属于管理员。InsertDevice 已强制归属兜底，此后不会再有空值行。
		`UPDATE devices SET user_id = 'default' WHERE user_id = ''`,
	} {
		if _, err := d.Exec(ddl); err != nil {
			return err
		}
	}

	// v5 遗留表的索引与 file_id 回填（迁移读取时需要 file_id 尽量完整）
	if exists, err := TableExists(d, "files"); err != nil {
		return err
	} else if exists {
		if err := backfillLegacyFileIDs(d); err != nil {
			return err
		}
		if _, err := d.Exec(`CREATE INDEX IF NOT EXISTS idx_files_canonical ON files(canonical_key)`); err != nil {
			return err
		}
	}
	return nil
}

// backfillLegacyFileIDs 为 v5 旧行生成随机 file_id（幂等）。
func backfillLegacyFileIDs(d *sql.DB) error {
	rows, err := d.Query(`SELECT path FROM files WHERE COALESCE(file_id, '') = ''`)
	if err != nil {
		return err
	}
	var paths []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return err
		}
		paths = append(paths, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, p := range paths {
		id, err := NewFileID()
		if err != nil {
			return err
		}
		if _, err := d.Exec(`UPDATE files SET file_id = ? WHERE path = ?`, id, p); err != nil {
			return err
		}
	}
	return nil
}

func columnExists(d *sql.DB, table, column string) (bool, error) {
	rows, err := d.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}
