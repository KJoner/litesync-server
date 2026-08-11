package db

const schema = `
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL UNIQUE,
    content_hash TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS changes (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    revision INTEGER NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('upsert','delete')),
    content_hash TEXT,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_changes_path ON changes(path);

CREATE TABLE IF NOT EXISTS file_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    revision INTEGER NOT NULL,
    blob_id TEXT,
    content_hash TEXT,
    size INTEGER NOT NULL,
    mtime INTEGER NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('upsert','delete','restore','merge')),
    device_id TEXT,
    created_at INTEGER NOT NULL,
    UNIQUE(path, revision)
);

CREATE INDEX IF NOT EXISTS idx_versions_blob ON file_versions(blob_id);

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

-- v9 仓库权威状态（单行）：head_sequence 是唯一的全局时钟，在每次变更事务内递增，
-- 永不回退；changes 只是可裁剪日志，不再兼任时钟。repo_epoch 标识 sequence 空间的
-- 世代：从备份恢复后必须旋转（obsync rotate-epoch），客户端据此进入灾备合并而不是
-- 沿用旧游标静默漏掉变更。
CREATE TABLE IF NOT EXISTS repo_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    repo_epoch TEXT NOT NULL,
    head_sequence INTEGER NOT NULL,
    min_retained_sequence INTEGER NOT NULL DEFAULT 0,
    encryption_state TEXT NOT NULL DEFAULT 'plaintext'
        CHECK (encryption_state IN ('plaintext','migrating','encrypted')),
    key_epoch INTEGER NOT NULL DEFAULT 0
);
`
