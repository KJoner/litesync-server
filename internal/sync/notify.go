package sync

import (
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// Notifier 是账号安全通知的投递端（v0.20 / ADR-018），由 internal/mail 的 Outbox 实现。
//
// v0.20.1（复审 SV-05）起它只负责「唤醒」：业务操作在**自己的事务里**用 recordEvent 记下一条最小的
// 安全事件（与业务变更同生共死），提交之后调用 wake；投递端在后台查地址、渲染、入队、发送，
// 每条事件的去向都记成结果。以前是提交之后才把通知塞进容量 256 的内存队列，满了丢弃，
// 业务成功到落盘之间进程退出也会丢。
//
// 约定：Wake 必须非阻塞，且绝不能回调 Service——否则持有 s.mu 时会自锁。未设置时事件照常落盘，
// 只是暂时没有人处理（不影响业务；之后装上投递端会补发）。
type Notifier interface {
	Wake()
}

// SetNotifier 安装通知器（启动时调用一次）。
func (s *Service) SetNotifier(n Notifier) { s.notifier = n }

// wake 在业务事务提交之后调用：请投递端尽快处理刚落盘的事件。
func (s *Service) wake() {
	if s.notifier != nil {
		s.notifier.Wake()
	}
}

// recordEvent 在调用方的事务里记下一条安全事件（q 必须是业务操作自己的事务）。
// data 只放模板需要的最少字段；不得含任何秘密。
func (s *Service) recordEvent(q db.Queryer, userID, event string, data map[string]string) error {
	if userID == "" {
		return nil
	}
	return db.RecordSecurityEvent(q, userID, event, data, time.Now().Unix())
}

// MailStats 返回通知 outbox 的计数（管理员告警页用；不含任何地址）。
func (s *Service) MailStats() (db.MailStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return db.GetMailStats(s.db)
}
