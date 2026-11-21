package db

import (
	"database/sql"
	"errors"
)

// 配对包（v8 新设备接入）的数据访问。
//
// v0.20（公开化基线 PRE-03）：配对包记录发行者的 (vault, user)。
// 此前 INSERT 根本不写 vault_id（列存在但永远是默认值），撤销也只按 id——
// 任何持 pairing scope 的凭据都能删掉别人的配对包，删除仓库时也清不掉
// 非默认仓库发行的配对包。
//
// 消费路径（POST /pair/{id}/consume）仍然公开、按不可猜测的 id 寻址：
// 新设备此刻还没有任何凭据，密文本身由链接 #fragment 里的密钥保护。

// InsertPairing 保存一个配对包密文，归属取自认证上下文。
func InsertPairing(q dbtx, s VaultScope, userID, id, ciphertext, grantID string, createdAt, expiresAt int64) error {
	if !s.Valid() {
		return ErrVaultScopeMissing
	}
	_, err := q.Exec(
		`INSERT INTO pairings (id, ciphertext, created_at, expires_at, vault_id, user_id, grant_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, ciphertext, createdAt, expiresAt, s.ID(), userID, grantID)
	return err
}

// ConsumePairing 原子地取出并删除未过期的配对密文（一次性；0.19 插件的旧流程）。
// 不存在 / 已消费 / 已过期返回 ("", false, nil)。
//
// v2（grant 绑定）的包同样允许旧流程消费：0.19 插件不认识新字段，但包里的
// enrollment 在服务端早已绑定了用户与仓库，旧流程拿到的仍是正确仓库的设备
// 凭据——缺的只是「导入前核对仓库」这一步体验（版本兼容表 §2）。
func ConsumePairing(q dbtx, id string, now int64) (string, bool, error) {
	var ciphertext string
	err := q.QueryRow(
		`DELETE FROM pairings WHERE id = ? AND expires_at > ? RETURNING ciphertext`,
		id, now,
	).Scan(&ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return ciphertext, true, nil
}

// PairingEnvelope 读取（**不消费**）v2 配对包：返回密文、过期时间与绑定的 grant。
// 不存在或已过期返回 ok=false。
func PairingEnvelope(q dbtx, id string, now int64) (ciphertext, grantID string, expiresAt int64, ok bool, err error) {
	err = q.QueryRow(
		`SELECT ciphertext, grant_id, expires_at FROM pairings WHERE id = ? AND expires_at > ?`,
		id, now,
	).Scan(&ciphertext, &grantID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", 0, false, nil
	}
	if err != nil {
		return "", "", 0, false, err
	}
	return ciphertext, grantID, expiresAt, true, nil
}

// DeletePairingOwned 只删除属于 (vault, user) 的配对包；返回被删除包绑定的 grant
//（v2 撤销要连带作废 grant）。不属于调用者的与不存在的同样返回 ("", false)。
func DeletePairingOwned(q dbtx, s VaultScope, userID, id string) (grantID string, deleted bool, err error) {
	if !s.Valid() {
		return "", false, ErrVaultScopeMissing
	}
	err = q.QueryRow(
		`DELETE FROM pairings WHERE id = ? AND vault_id = ? AND user_id = ? RETURNING grant_id`,
		id, s.ID(), userID,
	).Scan(&grantID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return grantID, true, nil
}

// DeletePairingsOfGrant 删除绑定某 grant 的配对包（grant 被兑换、撤销或过期时）。
func DeletePairingsOfGrant(q dbtx, grantID string) error {
	if grantID == "" {
		return nil
	}
	_, err := q.Exec(`DELETE FROM pairings WHERE grant_id = ?`, grantID)
	return err
}

// PrunePairings 清理已过期的配对包（维护任务兜底）。
func PrunePairings(q dbtx, now int64) (int64, error) {
	res, err := q.Exec(`DELETE FROM pairings WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected() //nolint:errcheck
	return n, nil
}
