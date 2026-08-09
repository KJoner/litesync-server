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
`
