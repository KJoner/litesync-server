package db

import (
	"database/sql"
	"errors"
)

// 每 Vault 的保留策略覆盖（v0.16.0 / 计划书 §10.2）。
//
// 保留多久是**每个租户自己的数据治理决定**：一个团队要保留一年备查，
// 另一个团队被要求 30 天后必须消失。服务器替他们统一是越权的，
// 而且在合规场景下是错的。
//
// 用 -1 表示「未设置，沿用实例默认」——0 在这套语义里是「不限」，
// 是一个有意义的值，不能拿来当哨兵。

const vaultRetentionSchema = `
CREATE TABLE IF NOT EXISTS vault_retention (
	vault_id            TEXT PRIMARY KEY,
	history_days        INTEGER NOT NULL DEFAULT -1,
	history_max_per_file INTEGER NOT NULL DEFAULT -1,
	attachment_days     INTEGER NOT NULL DEFAULT -1,
	attachment_max      INTEGER NOT NULL DEFAULT -1,
	updated_at          INTEGER NOT NULL DEFAULT 0
);
`

// VaultRetention 是一个 Vault 的保留策略覆盖；-1 表示沿用实例默认。
type VaultRetention struct {
	HistoryDays       int
	HistoryMaxPerFile int
	AttachmentDays    int
	AttachmentMax     int
}

// GetVaultRetention 读取覆盖；没有设过返回 (nil, nil)。
func GetVaultRetention(q dbtx, s VaultScope) (*VaultRetention, error) {
	if !s.Valid() {
		return nil, ErrVaultScopeMissing
	}
	r := &VaultRetention{}
	err := q.QueryRow(
		`SELECT history_days, history_max_per_file, attachment_days, attachment_max
		 FROM vault_retention WHERE vault_id = ?`, s.ID()).
		Scan(&r.HistoryDays, &r.HistoryMaxPerFile, &r.AttachmentDays, &r.AttachmentMax)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// SetVaultRetention 写入覆盖（-1 = 沿用实例默认）。
func SetVaultRetention(q dbtx, s VaultScope, r VaultRetention) error {
	if !s.Valid() {
		return ErrVaultScopeMissing
	}
	for _, v := range []int{r.HistoryDays, r.HistoryMaxPerFile, r.AttachmentDays, r.AttachmentMax} {
		if v < -1 {
			return errors.New("retention 值只能是 -1（沿用默认）、0（不限）或正数")
		}
	}
	_, err := q.Exec(
		`INSERT INTO vault_retention
		   (vault_id, history_days, history_max_per_file, attachment_days, attachment_max, updated_at)
		 VALUES (?, ?, ?, ?, ?, strftime('%s','now'))
		 ON CONFLICT(vault_id) DO UPDATE SET
		   history_days = excluded.history_days,
		   history_max_per_file = excluded.history_max_per_file,
		   attachment_days = excluded.attachment_days,
		   attachment_max = excluded.attachment_max,
		   updated_at = excluded.updated_at`,
		s.ID(), r.HistoryDays, r.HistoryMaxPerFile, r.AttachmentDays, r.AttachmentMax)
	return err
}
