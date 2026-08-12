package db

import (
	"database/sql"
	"time"
)

// 签名 checkpoint 存储（v0.15.0 / 计划书 §9）。
//
// 服务器在这里扮演的角色是**转发者**，不是权威：
//
//   - 它存不了假的：checkpoint 由设备私钥签名，服务器没有任何私钥；
//   - 它改不了：任何一个字节的改动都会让签名失效；
//   - 它能做的只有「不转发」或者「转发旧的」——前者用户看得见（同步停了），
//     后者由客户端的信任锚与链接检查挡住。
//
// 表是**只追加**的：删除或修改历史 checkpoint 会破坏链的可验证性，
// 因此这里既不提供 UPDATE 也不提供按 hash 的 DELETE。

// Checkpoint 是一份已签名的仓库状态快照。
type Checkpoint struct {
	Hash            string
	VaultID         string
	RepoEpoch       string
	HeadSequence    int64
	PreviousHash    string
	SigningDeviceID string
	// Body 是 canonical 序列化后的原文；服务器不解析它，原样转发
	Body      string
	Signature string
	CreatedAt int64
}

const checkpointSchema = `
CREATE TABLE IF NOT EXISTS checkpoints (
	hash              TEXT PRIMARY KEY,
	vault_id          TEXT NOT NULL,
	repo_epoch        TEXT NOT NULL,
	head_sequence     INTEGER NOT NULL,
	previous_hash     TEXT NOT NULL DEFAULT '',
	signing_device_id TEXT NOT NULL,
	body              TEXT NOT NULL,
	signature         TEXT NOT NULL,
	created_at        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_checkpoints_head
	ON checkpoints(vault_id, repo_epoch, head_sequence DESC);
`

// InsertCheckpoint 追加一个 checkpoint。
//
// hash 冲突视为幂等重复（同一份东西被重复提交）——注意这里**不**做
// "ON CONFLICT DO UPDATE"：checkpoint 一旦发布就不可变。
func InsertCheckpoint(q dbtx, c *Checkpoint) error {
	if c.CreatedAt == 0 {
		c.CreatedAt = time.Now().Unix()
	}
	_, err := q.Exec(`
		INSERT INTO checkpoints
			(hash, vault_id, repo_epoch, head_sequence, previous_hash, signing_device_id, body, signature, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(hash) DO NOTHING`,
		c.Hash, c.VaultID, c.RepoEpoch, c.HeadSequence, c.PreviousHash,
		c.SigningDeviceID, c.Body, c.Signature, c.CreatedAt)
	return err
}

// LatestCheckpoint 返回当前 epoch 下 headSequence 最大的那个。
func LatestCheckpoint(q dbtx, vaultID, repoEpoch string) (*Checkpoint, error) {
	row := q.QueryRow(`
		SELECT hash, vault_id, repo_epoch, head_sequence, previous_hash, signing_device_id, body, signature, created_at
		FROM checkpoints WHERE vault_id = ? AND repo_epoch = ?
		ORDER BY head_sequence DESC, created_at DESC LIMIT 1`, vaultID, repoEpoch)
	return scanCheckpoint(row)
}

// CheckpointsSince 返回 headSequence 大于 since 的 checkpoint（升序）。
// 客户端用它把本地的链续上，而不是只拿最新那一个——只拿最新的话，
// 中间断了一截就永远接不回去。
func CheckpointsSince(q dbtx, vaultID, repoEpoch string, since int64, limit int) ([]Checkpoint, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	rows, err := q.Query(`
		SELECT hash, vault_id, repo_epoch, head_sequence, previous_hash, signing_device_id, body, signature, created_at
		FROM checkpoints WHERE vault_id = ? AND repo_epoch = ? AND head_sequence > ?
		ORDER BY head_sequence ASC LIMIT ?`, vaultID, repoEpoch, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Checkpoint
	for rows.Next() {
		var c Checkpoint
		if err := rows.Scan(&c.Hash, &c.VaultID, &c.RepoEpoch, &c.HeadSequence, &c.PreviousHash,
			&c.SigningDeviceID, &c.Body, &c.Signature, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CheckpointsAtSequence 返回同一个 headSequence 上的所有 checkpoint。
//
// 正常情况下只会有一个。出现多个说明有两台设备在同一位置各自发布了不同的
// 状态快照——这本身就是分叉证据，服务器把它们**都**留着，让客户端看到全貌。
// 悄悄丢掉其中一个才是最糟的做法：那会让分叉变得不可见。
func CheckpointsAtSequence(q dbtx, vaultID, repoEpoch string, seq int64) ([]Checkpoint, error) {
	rows, err := q.Query(`
		SELECT hash, vault_id, repo_epoch, head_sequence, previous_hash, signing_device_id, body, signature, created_at
		FROM checkpoints WHERE vault_id = ? AND repo_epoch = ? AND head_sequence = ?
		ORDER BY created_at ASC`, vaultID, repoEpoch, seq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Checkpoint
	for rows.Next() {
		var c Checkpoint
		if err := rows.Scan(&c.Hash, &c.VaultID, &c.RepoEpoch, &c.HeadSequence, &c.PreviousHash,
			&c.SigningDeviceID, &c.Body, &c.Signature, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func scanCheckpoint(row *sql.Row) (*Checkpoint, error) {
	var c Checkpoint
	err := row.Scan(&c.Hash, &c.VaultID, &c.RepoEpoch, &c.HeadSequence, &c.PreviousHash,
		&c.SigningDeviceID, &c.Body, &c.Signature, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}
