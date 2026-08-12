package sync_test

import (
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
	"github.com/KJoner/litesync-server/internal/storage"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// 成员移除与密钥轮换（v0.16.0 / 计划书 §10.4、ADR-010 §6）。
//
// 这一组测试盯的是「移除成员」这个动作的**完整后果**。它很容易被做成
// 「删一行 memberships 就完事」——那样被移除的人手里的设备凭据仍然有效，
// 新内容仍然用他持有的那把密钥加密，等于什么都没发生。

func newTenantEnv(t *testing.T) *syncsvc.Service {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	store, _ := storage.New(filepath.Join(dir, "vault"))
	blobs, _ := storage.NewBlobStore(filepath.Join(dir, "blobs"))
	shares, _ := storage.NewShareStore(filepath.Join(dir, "shares"))
	return syncsvc.New(database, store, blobs, shares, syncsvc.Options{HistoryEnabled: true},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// seedTenant 造一个有 owner + 若干成员、每人一台设备的 Vault。
func seedTenant(t *testing.T, s *syncsvc.Service, members map[string]db.Role) map[string]string {
	t.Helper()
	scope := db.LegacyDefaultScope()
	d := s.DB()
	devices := map[string]string{}
	for userID, role := range members {
		if err := db.InsertUser(d, &db.User{UserID: userID, Name: userID}); err != nil {
			t.Fatal(err)
		}
		if err := db.UpsertMembership(d, &db.Membership{
			UserID: userID, VaultID: db.DefaultVaultID, Role: role,
		}); err != nil {
			t.Fatal(err)
		}
		cred, err := s.CreateDevice(userID + "-laptop")
		if err != nil {
			t.Fatal(err)
		}
		if err := db.BindDeviceToTenant(d, scope, cred.DeviceID, userID); err != nil {
			t.Fatal(err)
		}
		devices[userID] = cred.DeviceID
	}
	return devices
}

func TestRemoveMemberRevokesDevicesAndRotatesKey(t *testing.T) {
	s := newTenantEnv(t)
	devices := seedTenant(t, s, map[string]db.Role{
		"alice": db.RoleOwner,
		"bob":   db.RoleEditor,
	})
	before, err := db.CurrentKeyEpoch(s.DB())
	if err != nil {
		t.Fatal(err)
	}

	rep, err := s.RemoveMember(syncsvc.Actor{DeviceID: devices["alice"]}, "bob")
	if err != nil {
		t.Fatal(err)
	}

	// 1) 成员关系没了
	if _, ok, _ := db.RoleOf(s.DB(), db.LegacyDefaultScope(), "bob"); ok {
		t.Fatal("成员关系应当已删除")
	}
	// 2) 他的设备立刻作废——这是「拿不到新内容」的实际执行手段
	if rep.RevokedDevices != 1 {
		t.Fatalf("应当撤销 1 台设备，实际 %d", rep.RevokedDevices)
	}
	dev, err := db.GetDeviceByID(s.DB(), devices["bob"])
	if err != nil {
		t.Fatal(err)
	}
	if dev == nil || !dev.Revoked {
		t.Fatal("被移除成员的设备必须已撤销")
	}
	// 3) keyEpoch 推进：此后的新内容用新密钥
	if rep.NewKeyEpoch != before+1 {
		t.Fatalf("keyEpoch 应当 %d → %d，实际 %d", before, before+1, rep.NewKeyEpoch)
	}
	// 4) 待重新封装：服务器拿不到 Vault Key，只能记下待办
	pending, err := s.PendingRewrapEpoch()
	if err != nil {
		t.Fatal(err)
	}
	if pending != rep.NewKeyEpoch {
		t.Fatalf("应当标记 epoch %d 待重新封装，实际 %d", rep.NewKeyEpoch, pending)
	}
	// 5) 关于本地明文的说明必须原样带出来，不能被悄悄省掉
	if !strings.Contains(rep.LocalPlaintext, "无法远程删除") {
		t.Fatalf("必须明确说明已下载的本地明文收不回来，得到：%q", rep.LocalPlaintext)
	}

	// 6) 审计留痕：事后要能回答「这次轮换是因为谁被移除了」
	events, err := s.AuditTrail(10)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range events {
		if e.Action == "member-removed" && strings.Contains(e.Detail, "bob") {
			found = true
			if strings.Contains(e.Detail, "/") || strings.Contains(e.Detail, ".md") {
				t.Fatalf("审计记录里不得出现路径：%q", e.Detail)
			}
		}
	}
	if !found {
		t.Fatal("缺少 member-removed 审计记录")
	}
}

// 只有 owner/admin 能移除成员；editor 不行。
func TestRemoveMemberRequiresAdminRole(t *testing.T) {
	s := newTenantEnv(t)
	devices := seedTenant(t, s, map[string]db.Role{
		"alice": db.RoleOwner,
		"bob":   db.RoleEditor,
		"carol": db.RoleReader,
	})

	if _, err := s.RemoveMember(syncsvc.Actor{DeviceID: devices["bob"]}, "carol"); err != syncsvc.ErrNotAuthorized {
		t.Fatalf("editor 移除成员应当被拒，得到 %v", err)
	}
	// carol 仍在，且没有发生任何轮换——被拒的操作不该有副作用
	if _, ok, _ := db.RoleOf(s.DB(), db.LegacyDefaultScope(), "carol"); !ok {
		t.Fatal("被拒的移除不该真的删掉成员")
	}
	if pending, _ := s.PendingRewrapEpoch(); pending != 0 {
		t.Fatal("被拒的移除不该触发密钥轮换")
	}

	// 未绑定任何用户的设备（存量单用户设备）同样没有管理权
	cred, err := s.CreateDevice("unbound")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoveMember(syncsvc.Actor{DeviceID: cred.DeviceID}, "carol"); err != syncsvc.ErrNotAuthorized {
		t.Fatalf("未绑定用户的设备应当被拒，得到 %v", err)
	}
}

// 不能移除最后一个 owner：那会造出一个谁也管不了的 Vault。
func TestCannotRemoveLastOwner(t *testing.T) {
	s := newTenantEnv(t)
	seedTenant(t, s, map[string]db.Role{"alice": db.RoleOwner})

	if _, err := s.RemoveMember(syncsvc.Actor{Root: true}, "alice"); err != db.ErrLastOwner {
		t.Fatalf("移除最后一个 owner 应当被拒，得到 %v", err)
	}
	// 有第二个 owner 时就可以了
	seedTenant(t, s, map[string]db.Role{"dave": db.RoleOwner})
	if _, err := s.RemoveMember(syncsvc.Actor{Root: true}, "alice"); err != nil {
		t.Fatalf("还有其他 owner 时应当允许移除，得到 %v", err)
	}
}

// 不是成员的用户不能被「移除」——静默成功会掩盖调用方的 bug。
func TestRemoveNonMemberFails(t *testing.T) {
	s := newTenantEnv(t)
	seedTenant(t, s, map[string]db.Role{"alice": db.RoleOwner})
	if _, err := s.RemoveMember(syncsvc.Actor{Root: true}, "nobody"); err != db.ErrNotAMember {
		t.Fatalf("移除非成员应当报错，得到 %v", err)
	}
	if pending, _ := s.PendingRewrapEpoch(); pending != 0 {
		t.Fatal("失败的移除不该触发密钥轮换")
	}
}

// 重新封装必须对准新 epoch：上传一份仍属于旧 epoch 的文档不算完成轮换。
func TestClearPendingRewrapRequiresMatchingEpoch(t *testing.T) {
	s := newTenantEnv(t)
	devices := seedTenant(t, s, map[string]db.Role{
		"alice": db.RoleOwner,
		"bob":   db.RoleEditor,
	})
	rep, err := s.RemoveMember(syncsvc.Actor{DeviceID: devices["alice"]}, "bob")
	if err != nil {
		t.Fatal(err)
	}

	if err := s.ClearPendingRewrap(rep.NewKeyEpoch - 1); err == nil {
		t.Fatal("旧 epoch 的文档不该算作完成轮换")
	}
	if pending, _ := s.PendingRewrapEpoch(); pending != rep.NewKeyEpoch {
		t.Fatal("失败的清除不该改变待办状态")
	}

	if err := s.ClearPendingRewrap(rep.NewKeyEpoch); err != nil {
		t.Fatal(err)
	}
	if pending, _ := s.PendingRewrapEpoch(); pending != 0 {
		t.Fatal("对准 epoch 之后待办应当清除")
	}
}
