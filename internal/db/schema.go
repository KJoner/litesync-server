package db

// 协议 v6 schema（ADR-001 / ADR-002 / ADR-003 / ADR-006）。
//
// v5 用 path 做主键，导致迁移重置 revision、历史撞唯一键、删除丢身份、
// 改名断历史。v6 把身份（file_id）与展示名（pseudonym）彻底分开：
//   - 所有主键都是 file_id；path 只是一个可变属性
//   - revision 属于对象，跨改名 / 迁移 / 删除恢复连续
//   - 删除进入独立的 tombstones 台账，绝不删行
//
// v5 的 files / changes / file_versions 不再出现在这里：它们只存在于升级上来的
// 旧库中，由 migrateToV6 迁移后重命名为 v5_*（只读保留，供回滚与核对）。
const schema = `
CREATE TABLE IF NOT EXISTS vault_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS shares (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    size INTEGER NOT NULL,
    expires_at INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

-- 一次性加密配对包（v8 新设备接入）：只存客户端加密后的密文，
-- 解密密钥只在配对链接的 #fragment 中，服务器永远看不到配置明文
CREATE TABLE IF NOT EXISTS pairings (
    id TEXT PRIMARY KEY,
    ciphertext TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- v9.2 设备级凭据：每台设备独立 token（只存 hash）+ 最小权限 scopes，可单独撤销。
-- 根 Token（.env）保留全权限，仅用于首台设备注册、设备管理与灾难恢复。
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL UNIQUE,
    scopes TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    -- v6：该设备已确认（ACK）到的 sequence。tombstone 清理必须确认所有
    -- 未撤销设备都越过了删除点，绝不只按时间清理（ADR-002 §3.4）
    last_acked_sequence INTEGER NOT NULL DEFAULT 0,
    -- v0.15：该设备的 checkpoint 签名公钥（base64 SPKI，ECDSA P-256）。
    -- 服务器只存不用——它没有任何私钥，也不验证签名；验证在客户端做，
    -- 因为「服务器说这个签名是对的」本身就毫无价值（§9.2）
    signing_public_key TEXT NOT NULL DEFAULT ''
);

-- 一次性注册凭据（配对包 v2 携带的是它，不再是根 Token）：
-- 消费即作废，过期自动清理；秘密只存 hash
CREATE TABLE IF NOT EXISTS enrollments (
    id TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL UNIQUE,
    scopes TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER NOT NULL DEFAULT 0
);

-- 仓库权威状态（单行）。head_sequence 是唯一的全局时钟，在每次变更事务内递增，
-- 永不回退；changes 只是可裁剪日志。
--   repo_epoch                sequence 空间的世代，从备份恢复后旋转
--   format_epoch              寻址格式世代（ADR-006）：元数据加密完成时 +1
--   minimum_envelope_version  仓库级信封下限（ADR-006）：单调不减，落库前校验
--   schema_version            数据模型版本（6 = 本 schema）
CREATE TABLE IF NOT EXISTS repo_state (
    -- v0.16 §10.2：每个 Vault 一行。v0.16 之前这里是 id INTEGER CHECK (id = 1)，
    -- 也就是实例级的单行表；升级由 migrateRepoStatePerVault 整表重建完成。
    vault_id TEXT PRIMARY KEY DEFAULT 'default',
    repo_epoch TEXT NOT NULL,
    head_sequence INTEGER NOT NULL,
    min_retained_sequence INTEGER NOT NULL DEFAULT 0,
    encryption_state TEXT NOT NULL DEFAULT 'plaintext'
        CHECK (encryption_state IN ('plaintext','migrating','encrypted')),
    key_epoch INTEGER NOT NULL DEFAULT 0,
    meta_state TEXT NOT NULL DEFAULT 'plain'
        CHECK (meta_state IN ('plain','migrating','verifying','encrypted')),
    schema_version INTEGER NOT NULL DEFAULT 6,
    format_epoch INTEGER NOT NULL DEFAULT 1,
    minimum_envelope_version INTEGER NOT NULL DEFAULT 0,
    meta_schema_version INTEGER NOT NULL DEFAULT 1,
    migration_id TEXT NOT NULL DEFAULT '',
    migration_owner_device_id TEXT NOT NULL DEFAULT '',
    migration_lease_expires_at INTEGER NOT NULL DEFAULT 0,
    migration_cutoff_sequence INTEGER NOT NULL DEFAULT 0,
    migration_target_format_epoch INTEGER NOT NULL DEFAULT 0,
    migration_key_epoch INTEGER NOT NULL DEFAULT 0
);

-- ---------- v6 对象模型（ADR-001） ----------

-- 对象台账：一个 file_id 的一生（含删除后）
CREATE TABLE IF NOT EXISTS file_objects (
    vault_id TEXT NOT NULL DEFAULT 'default',
    file_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    deleted_at INTEGER NOT NULL DEFAULT 0,
    object_state TEXT NOT NULL DEFAULT 'live'
        CHECK (object_state IN ('live','deleted')),
    PRIMARY KEY (vault_id, file_id)
);

-- 当前 HEAD：只保存 live 对象，删除后整行移入 tombstones
CREATE TABLE IF NOT EXISTS file_heads (
    vault_id TEXT NOT NULL DEFAULT 'default',
    file_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    content_generation INTEGER NOT NULL DEFAULT 0,
    blob_id TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime INTEGER NOT NULL,
    meta_generation INTEGER NOT NULL DEFAULT 0,
    pseudonym TEXT NOT NULL,
    encrypted_metadata TEXT NOT NULL DEFAULT '',
    canonical_path_hmac TEXT NOT NULL DEFAULT '',
    key_epoch INTEGER NOT NULL DEFAULT 0,
    envelope_version INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (vault_id, file_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_heads_pseudonym ON file_heads(vault_id, pseudonym);
CREATE UNIQUE INDEX IF NOT EXISTS idx_heads_canonical
    ON file_heads(vault_id, canonical_path_hmac) WHERE canonical_path_hmac != '';

-- 隐私 tombstone 台账（ADR-002）：删除事实、防复活锚点与恢复所需身份。
-- 元数据迁移只做**格式转换**（last_pseudonym → file_id，canonical → HMAC），
-- 绝不删除——删掉等于让旧设备复活已删内容（INV-06）。
CREATE TABLE IF NOT EXISTS tombstones (
    vault_id TEXT NOT NULL DEFAULT 'default',
    file_id TEXT NOT NULL,
    last_pseudonym TEXT NOT NULL,
    canonical_path_hmac TEXT NOT NULL DEFAULT '',
    deletion_revision INTEGER NOT NULL,
    content_generation INTEGER NOT NULL DEFAULT 0,
    meta_generation INTEGER NOT NULL DEFAULT 0,
    key_epoch INTEGER NOT NULL DEFAULT 0,
    prior_content_hash TEXT NOT NULL DEFAULT '',
    deleted_at INTEGER NOT NULL,
    deletion_sequence INTEGER NOT NULL DEFAULT 0,
    retain_until INTEGER NOT NULL DEFAULT 0,
    delete_proof TEXT NOT NULL DEFAULT '',
    needs_review INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (vault_id, file_id)
);

CREATE INDEX IF NOT EXISTS idx_tombstones_pseudonym ON tombstones(vault_id, last_pseudonym);
CREATE INDEX IF NOT EXISTS idx_tombstones_canonical ON tombstones(vault_id, canonical_path_hmac);

-- 历史：按对象身份唯一，绝不再用 (path, revision)
CREATE TABLE IF NOT EXISTS object_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id TEXT NOT NULL DEFAULT 'default',
    file_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    content_generation INTEGER NOT NULL DEFAULT 0,
    blob_id TEXT,
    content_hash TEXT,
    size INTEGER NOT NULL,
    mtime INTEGER NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('upsert','delete','restore','merge')),
    device_id TEXT,
    key_epoch INTEGER NOT NULL DEFAULT 0,
    operation_id TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    UNIQUE (vault_id, file_id, revision)
);

CREATE INDEX IF NOT EXISTS idx_object_versions_blob ON object_versions(blob_id);

-- 变更日志：可裁剪，携带身份而不是路径
CREATE TABLE IF NOT EXISTS object_changes (
    sequence INTEGER NOT NULL,
    vault_id TEXT NOT NULL DEFAULT 'default',
    file_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('upsert','delete','restore')),
    revision INTEGER NOT NULL,
    content_generation INTEGER NOT NULL DEFAULT 0,
    meta_generation INTEGER NOT NULL DEFAULT 0,
    pseudonym TEXT NOT NULL,
    content_hash TEXT NOT NULL DEFAULT '',
    operation_id TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    PRIMARY KEY (vault_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_object_changes_file ON object_changes(vault_id, file_id);

-- 迁移逐对象台账（ADR-003 §3.3）：进度必须落库，绝不依赖内存中的遍历位置。
-- schema 迁移（migration_id='schema-v6'）与元数据加密迁移共用同一张表。
CREATE TABLE IF NOT EXISTS migration_journal (
    migration_id TEXT NOT NULL,
    vault_id TEXT NOT NULL DEFAULT 'default',
    file_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('object','tombstone','version','blob')),
    source_format TEXT NOT NULL DEFAULT '',
    target_format TEXT NOT NULL DEFAULT '',
    stage TEXT NOT NULL DEFAULT 'pending'
        CHECK (stage IN ('pending','done','failed','skipped')),
    last_error TEXT NOT NULL DEFAULT '',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (migration_id, vault_id, file_id, kind)
);

CREATE INDEX IF NOT EXISTS idx_journal_stage ON migration_journal(migration_id, stage);
`

// DefaultVaultID：单用户阶段的常量 vault 域。
// 所有表与索引都已带 vault_id（ADR-001 §3.2），v0.16 多租户时无需再次重写。
const DefaultVaultID = "default"

// SchemaVersion 当前数据模型版本。
const SchemaVersion = 6
