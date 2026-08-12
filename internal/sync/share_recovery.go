package sync

import (
	"errors"
	"fmt"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// 分享恢复（v0.17 / 计划书 §11.3）。
//
// # 「恢复」到底能恢复什么
//
// 分享的密钥从不上传——链接里的 fragment 才是密钥，服务器只有密文。
// 因此密文一旦被过期回收清掉，服务器手上**没有任何**能重建它的材料。
// 那不是「删除了但还能找回」，是真的没了。
//
// 能恢复的只有一种情况：分享还在盘上，只是有效期设短了。这种把有效期
// 往后延就行。把这两种情况混为一谈是危险的——用户会以为「反正管理员能恢复」，
// 于是不去重新分享，而对方一直打不开。

var (
	// ErrShareGone：密文已被回收，无法恢复。
	ErrShareGone = errors.New("share ciphertext has been reclaimed and cannot be recovered")
	// ErrShareRevoked：主动撤销的分享不通过延长有效期恢复。
	// 撤销是一个明确的意图表达，不该被一个「恢复」按钮悄悄推翻。
	ErrShareRevoked = errors.New("share was explicitly revoked")
)

// ShareCiphertextExists 报告某个分享的密文是否还在盘上。
func (s *Service) ShareCiphertextExists(id string) bool {
	return s.shares.Has(id)
}

// ExtendShare 把分享的有效期延长到 expiresAt。
func (s *Service) ExtendShare(id string, expiresAt int64) error {
	if expiresAt <= time.Now().Unix() {
		return errors.New("expiresAt must be in the future")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	sh, err := db.GetShare(s.db, id)
	if err != nil {
		return err
	}
	if sh == nil {
		return ErrShareGone
	}
	if sh.Revoked {
		return ErrShareRevoked
	}
	// 顺序很重要：先确认密文还在，再改数据库。反过来的话，
	// 一个「已延长」的分享可能指向一份已经不存在的密文——
	// 用户点开链接得到的是一个说不清的错误，而不是「已过期，请重新分享」
	if !s.shares.Has(id) {
		return ErrShareGone
	}
	if err := db.UpdateShareExpiry(s.db, id, expiresAt); err != nil {
		return err
	}
	if err := db.AppendAudit(s.db, s.scope(), "admin", "share-extended",
		"share="+truncateID(id)); err != nil {
		s.log.Warn("share extend: audit failed", "error", err)
	}
	s.log.Info("share expiry extended", "share", truncateID(id), "expiresAt", expiresAt)
	return nil
}

// Logf 让 api 层在非致命路径上记一笔日志，而不必持有 logger。
func (s *Service) Logf(format string, args ...any) {
	s.log.Warn(fmt.Sprintf(format, args...))
}
