package db

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
)

// 服务端密钥（v0.16.0 / 计划书 §10.5、ADR-010 §7）。
//
// 目前只有一把：access token 的签名密钥。刻意做成一张按 id 取的表，
// 而不是往 repo_state 上再加一列——将来还会有别的服务端密钥，
// 每加一把就改一次 repo_state 的表结构是没必要的。
//
// 这些密钥只存在服务端，不出现在任何响应、日志或备份清单里。
// 它们**在**数据库里，因此备份数据库即备份密钥；反过来说，
// 谁能读到数据库文件谁就能签票——这与「谁能读数据库谁就能改任何一行」
// 是同一级别的信任假设，不引入新的攻击面。

const serverSecretsSchema = `
CREATE TABLE IF NOT EXISTS server_secrets (
	id         TEXT PRIMARY KEY,
	secret     BLOB NOT NULL,
	created_at INTEGER NOT NULL
);
`

// ServerSecretLen 是服务端密钥的字节长度（HMAC-SHA256 的完整强度）。
const ServerSecretLen = 32

// EnsureServerSecret 取出（必要时生成）某个服务端密钥。
//
// 幂等：并发或重启都不会换掉一把已经在用的密钥——换掉签名密钥会让
// 所有在途的 access token 立刻失效，那是一次运维事件，不该由启动顺序触发。
func EnsureServerSecret(d *sql.DB, id string) ([]byte, error) {
	if id == "" {
		return nil, errors.New("server secret id is required")
	}
	var secret []byte
	err := d.QueryRow(`SELECT secret FROM server_secrets WHERE id = ?`, id).Scan(&secret)
	if err == nil && len(secret) > 0 {
		return secret, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	fresh := make([]byte, ServerSecretLen)
	if _, err := rand.Read(fresh); err != nil {
		return nil, fmt.Errorf("generate server secret: %w", err)
	}
	if _, err := d.Exec(
		`INSERT INTO server_secrets (id, secret, created_at) VALUES (?, ?, strftime('%s','now'))
		 ON CONFLICT(id) DO NOTHING`, id, fresh); err != nil {
		return nil, err
	}
	// 回读：另一个进程抢先写入时用它写的那把，别用我们刚生成的
	if err := d.QueryRow(`SELECT secret FROM server_secrets WHERE id = ?`, id).Scan(&secret); err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, errors.New("server secret 落库后仍读不到")
	}
	return secret, nil
}

// RotateServerSecret 换掉一把服务端密钥。
//
// 对 access token 签名密钥来说，这会让**所有**在途的票立刻失效，
// 客户端需要用长期设备凭据重新换票。这是「怀疑签名密钥泄露」时的处置手段，
// 不是日常动作，因此必须显式调用，不会被启动流程顺手触发。
func RotateServerSecret(d *sql.DB, id string) error {
	fresh := make([]byte, ServerSecretLen)
	if _, err := rand.Read(fresh); err != nil {
		return err
	}
	_, err := d.Exec(
		`INSERT INTO server_secrets (id, secret, created_at) VALUES (?, ?, strftime('%s','now'))
		 ON CONFLICT(id) DO UPDATE SET secret = excluded.secret, created_at = excluded.created_at`,
		id, fresh)
	return err
}
