package sync_test

import (
	"strings"
	"testing"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// 迁移前置检查（v0.17 / 计划书 §15 第 3、6、7 步）。
//
// 这个检查存在的唯一理由是挡住「我以为都升级了」。因此它必须在该挡的时候
// **真的挡住**——一个永远返回通过的前置检查比没有更糟，它会让人放心地
// 按下不可逆的那一步。

func TestPreflightPassesOnCleanRepo(t *testing.T) {
	s := newTenantEnv(t)
	rep, err := s.MigrationPreflight("")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Blocked() {
		t.Fatalf("空仓库不该被挡：%+v", rep.Issues)
	}
}

// §15 第 3 步的核心：从未上报过版本的设备必须**阻塞**迁移。
//
// 让它通过等于把检查变成安慰剂：那台设备可能正是那台没升级的。
func TestPreflightBlocksOnUnknownClientVersion(t *testing.T) {
	s := newTenantEnv(t)
	if _, err := s.CreateDevice("从未上报版本的设备"); err != nil {
		t.Fatal(err)
	}

	rep, err := s.MigrationPreflight("")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Blocked() {
		t.Fatal("有设备从未上报版本时必须阻塞——这一步的全部意义就是排除旧客户端")
	}
	if rep.UnknownVersion != 1 {
		t.Fatalf("应当报告 1 台未知版本设备，得到 %d", rep.UnknownVersion)
	}
	var found bool
	for _, is := range rep.Issues {
		if is.Code == "UNKNOWN_CLIENT_VERSION" && is.Blocking {
			found = true
		}
	}
	if !found {
		t.Fatalf("缺少 UNKNOWN_CLIENT_VERSION 阻塞项：%+v", rep.Issues)
	}
}

// 上报了版本但版本不对 → 阻塞，并且要指名道姓说是哪一台。
func TestPreflightBlocksOnOutdatedClient(t *testing.T) {
	s := newTenantEnv(t)
	cred, err := s.CreateDevice("旧笔记本")
	if err != nil {
		t.Fatal(err)
	}
	// 模拟这台设备连过一次，上报了老版本
	if _, err := s.AuthDeviceWithClient(cred.Token, "0.13.2", 6); err != nil {
		t.Fatal(err)
	}

	rep, err := s.MigrationPreflight("0.17.0")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Blocked() {
		t.Fatal("版本不符必须阻塞")
	}
	if rep.OutdatedClient != 1 {
		t.Fatalf("应当报告 1 台旧客户端，得到 %d", rep.OutdatedClient)
	}
	var detail string
	for _, is := range rep.Issues {
		if is.Code == "OUTDATED_CLIENT" {
			detail = is.Detail
		}
	}
	// 只说「有旧客户端」没用，运维需要知道去关哪一台
	if detail == "" || !strings.Contains(detail, "旧笔记本") || !strings.Contains(detail, "0.13.2") {
		t.Fatalf("必须指出是哪一台设备、什么版本：%q", detail)
	}
}

// 版本相符 → 放行。没有这条对照，上面两条可能只是「永远阻塞」。
func TestPreflightPassesWhenAllClientsCurrent(t *testing.T) {
	s := newTenantEnv(t)
	cred, err := s.CreateDevice("已升级的设备")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthDeviceWithClient(cred.Token, "0.17.0", 6); err != nil {
		t.Fatal(err)
	}
	rep, err := s.MigrationPreflight("0.17.0")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Blocked() {
		t.Fatalf("全部升级到位时应当放行：%+v", rep.Issues)
	}
}

// 已撤销的设备不参与判断：一台被撤销的旧设备不该永远挡着迁移。
func TestPreflightIgnoresRevokedDevices(t *testing.T) {
	s := newTenantEnv(t)
	cred, err := s.CreateDevice("已撤销的旧设备")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeDevice(cred.DeviceID); err != nil {
		t.Fatal(err)
	}
	rep, err := s.MigrationPreflight("0.17.0")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Blocked() {
		t.Fatalf("已撤销的设备不该阻塞迁移：%+v", rep.Issues)
	}
	if rep.ActiveDevices != 0 {
		t.Fatalf("已撤销设备不该计入在用数：%d", rep.ActiveDevices)
	}
}

// 陈旧设备是**警告**不是阻塞：它可能永远不回来，也可能明天就回来。
// 阻塞会让一台早就不用的旧手机永久卡住迁移。
func TestPreflightWarnsButDoesNotBlockOnStaleDevices(t *testing.T) {
	s := newTenantEnv(t)
	cred, err := s.CreateDevice("半年没开机的设备")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthDeviceWithClient(cred.Token, "0.17.0", 6); err != nil {
		t.Fatal(err)
	}
	long := time.Now().AddDate(0, 0, -200).Unix()
	if _, err := s.DB().Exec(`UPDATE devices SET last_seen_at = ? WHERE id = ?`, long, cred.DeviceID); err != nil {
		t.Fatal(err)
	}

	rep, err := s.MigrationPreflight("0.17.0")
	if err != nil {
		t.Fatal(err)
	}
	if rep.StaleDevices != 1 {
		t.Fatalf("应当报告 1 台陈旧设备，得到 %d", rep.StaleDevices)
	}
	if rep.Blocked() {
		t.Fatal("陈旧设备只应告警，不应阻塞——否则一台早就不用的旧手机会永久卡住迁移")
	}
}

// 已有迁移在进行中时必须阻塞：并发迁移是 ADR-003 租约要防的事。
func TestPreflightBlocksWhenMigrationInProgress(t *testing.T) {
	s := newTenantEnv(t)
	if err := db.BeginMigrationRecord(s.DB(), db.LegacyDefaultScope(),
		"mig-1", "dev-1", time.Now().Add(time.Hour).Unix(), 100, 2, 1); err != nil {
		t.Fatal(err)
	}
	rep, err := s.MigrationPreflight("")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Blocked() {
		t.Fatal("已有迁移在进行时必须阻塞")
	}
}
