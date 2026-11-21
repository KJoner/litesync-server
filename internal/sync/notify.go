package sync

import "github.com/KJoner/litesync-server/internal/db"

// Notifier 接收账号安全事件（v0.20 公开化 / ADR-018），由 internal/mail 的 Outbox 实现。
//
// 约定：只在业务操作**提交之后**调用；实现必须是非阻塞的（Outbox 异步入队），
// 且绝不能回调 Service——否则持有 s.mu 时会自锁。未设置时所有事件静默丢弃。
type Notifier interface {
	Notify(userID, event string, data map[string]string)
}

// SetNotifier 安装通知器（启动时调用一次）。
func (s *Service) SetNotifier(n Notifier) { s.notifier = n }

func (s *Service) notify(userID, event string, data map[string]string) {
	if s.notifier != nil && userID != "" {
		s.notifier.Notify(userID, event, data)
	}
}

// MailStats 返回通知 outbox 的计数（管理员告警页用；不含任何地址）。
func (s *Service) MailStats() (db.MailStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.GetMailStats(s.db)
}
