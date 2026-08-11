package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
)

// 加密状态机（v9）：plaintext → migrating → encrypted。
// migrating/encrypted 状态下服务器拒绝非 LSE1 密文上传（明文写冻结）。
const (
	EncryptionPlaintext = "plaintext"
	EncryptionMigrating = "migrating"
	EncryptionEncrypted = "encrypted"
)

// 元数据加密状态机（v9.3 三期）：plain → migrating → encrypted。
// encrypted 态下服务器可见 path 只是伪名（=file_id），真实路径在 meta_enc 里。
const (
	MetaPlain     = "plain"
	MetaMigrating = "migrating"
	MetaEncrypted = "encrypted"
)

// RepoState 对应 repo_state 单行（id=1）。
type RepoState struct {
	RepoEpoch           string
	HeadSequence        int64
	MinRetainedSequence int64
	EncryptionState     string
	KeyEpoch            int64
	MetaState           string
}

func randomEpoch() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// initRepoState 初始化 repo_state（幂等，db.Open 时调用）。
// 旧库迁移：head 取 MAX(changes.sequence)、sqlite_sequence、旧水位线三者最大值，
// 保证升级后 head 绝不小于任何客户端已见过的 sequence。
func initRepoState(d *sql.DB) error {
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM repo_state`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}

	var maxChanges, sqliteSeq, watermark int64
	if err := d.QueryRow(`SELECT COALESCE(MAX(sequence), 0) FROM changes`).Scan(&maxChanges); err != nil {
		return err
	}
	// AUTOINCREMENT 的历史最大值（changes 被整表裁剪后仍然保留）
	err := d.QueryRow(`SELECT seq FROM sqlite_sequence WHERE name = 'changes'`).Scan(&sqliteSeq)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if v, ok, err := GetMeta(d, "changes-watermark"); err != nil {
		return err
	} else if ok {
		fmt.Sscanf(v, "%d", &watermark) //nolint:errcheck
	}

	head := max(maxChanges, sqliteSeq, watermark)
	epoch, err := randomEpoch()
	if err != nil {
		return err
	}
	_, err = d.Exec(
		`INSERT INTO repo_state (id, repo_epoch, head_sequence, min_retained_sequence, encryption_state, key_epoch)
		 VALUES (1, ?, ?, ?, ?, 0)`,
		epoch, head, watermark, EncryptionPlaintext,
	)
	return err
}

// GetRepoState 读取仓库权威状态。
func GetRepoState(q dbtx) (*RepoState, error) {
	rs := &RepoState{}
	err := q.QueryRow(
		`SELECT repo_epoch, head_sequence, min_retained_sequence, encryption_state, key_epoch, COALESCE(meta_state, 'plain')
		 FROM repo_state WHERE id = 1`,
	).Scan(&rs.RepoEpoch, &rs.HeadSequence, &rs.MinRetainedSequence, &rs.EncryptionState, &rs.KeyEpoch, &rs.MetaState)
	if err != nil {
		return nil, err
	}
	return rs, nil
}

// SetMetaState 更新元数据加密状态机。
func SetMetaState(q dbtx, state string) error {
	_, err := q.Exec(`UPDATE repo_state SET meta_state = ? WHERE id = 1`, state)
	return err
}

// NextSequence 在变更事务内分配下一个 sequence（head_sequence += 1）。
// 必须与 HEAD 更新、version、change 写入在同一事务中提交，保证：
// 任何已返回给客户端的 sequence 都精确对应一次已持久化的状态变更。
func NextSequence(q dbtx) (int64, error) {
	rs, err := GetRepoState(q)
	if err != nil {
		return 0, err
	}
	seq := rs.HeadSequence + 1
	if _, err := q.Exec(`UPDATE repo_state SET head_sequence = ? WHERE id = 1`, seq); err != nil {
		return 0, err
	}
	return seq, nil
}

// SetMinRetainedSequence 推进裁剪水位线（只增不减，事务内调用）。
func SetMinRetainedSequence(q dbtx, seq int64) error {
	_, err := q.Exec(
		`UPDATE repo_state SET min_retained_sequence = ? WHERE id = 1 AND min_retained_sequence < ?`,
		seq, seq,
	)
	return err
}

// SetEncryptionState 更新加密状态机；keyEpoch 只在进入 migrating 时递增。
func SetEncryptionState(q dbtx, state string, bumpKeyEpoch bool) error {
	if bumpKeyEpoch {
		_, err := q.Exec(
			`UPDATE repo_state SET encryption_state = ?, key_epoch = key_epoch + 1 WHERE id = 1`, state)
		return err
	}
	_, err := q.Exec(`UPDATE repo_state SET encryption_state = ? WHERE id = 1`, state)
	return err
}

// RotateEpoch 旋转 repo_epoch（灾备恢复后由 obsync rotate-epoch 命令执行）。
// 客户端发现 epoch 变化后停止普通增量同步，进入恢复合并流程。
func RotateEpoch(q dbtx) (string, error) {
	epoch, err := randomEpoch()
	if err != nil {
		return "", err
	}
	if _, err := q.Exec(`UPDATE repo_state SET repo_epoch = ? WHERE id = 1`, epoch); err != nil {
		return "", err
	}
	return epoch, nil
}
