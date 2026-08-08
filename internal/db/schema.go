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
`
