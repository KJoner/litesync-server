package db_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
	_ "modernc.org/sqlite"
)

// 每 Vault 独立状态（v0.16.0 / 计划书 §10.2）。
//
// v0.16 之前 repo_state 是一张单行表（id=1），也就是实例级的。
// 多租户下这不成立，而且不成立的方式是**安静的**：
//
//   - 一个租户旋转 repoEpoch → 所有租户的游标一起作废；
//   - 一个租户写入推高 head_sequence → 别人的客户端追一个追不上的游标，
//     同时从这个数字读出「别人今天写了多少」；
//   - 一个租户开始元数据迁移 → 所有租户的写入一起被冻结。
//
// 这些都不报错。所以必须在结构上根治，并且用测试钉住。

func twoVaults(t *testing.T) (*sql.DB, db.VaultScope, db.VaultScope) {
	t.Helper()
	d := openTestDB(t)
	a := db.LegacyDefaultScope()
	b := db.ScopeFromAuth("tenant-b")
	if err := db.InitVaultState(d, b); err != nil {
		t.Fatal(err)
	}
	return d, a, b
}

func TestRepoEpochIsPerVault(t *testing.T) {
	d, a, b := twoVaults(t)

	beforeB, err := db.GetRepoState(d, b)
	if err != nil {
		t.Fatal(err)
	}
	// A 从备份恢复并旋转 epoch
	newA, err := db.RotateEpoch(d, a)
	if err != nil {
		t.Fatal(err)
	}
	afterB, err := db.GetRepoState(d, b)
	if err != nil {
		t.Fatal(err)
	}
	if afterB.RepoEpoch != beforeB.RepoEpoch {
		t.Fatal("A 的灾备恢复不该让 B 的 repoEpoch 变化 —— B 的所有客户端会被无故踢进恢复流程")
	}
	stA, err := db.GetRepoState(d, a)
	if err != nil {
		t.Fatal(err)
	}
	if stA.RepoEpoch != newA {
		t.Fatal("A 自己的 epoch 应当已经旋转")
	}
	// 两个 Vault 初始 epoch 本来就该不同：继承会让灾备恢复互相干扰
	if beforeB.RepoEpoch == "" || beforeB.RepoEpoch == stA.RepoEpoch {
		t.Fatal("新 Vault 必须有自己独立的 repoEpoch")
	}
}

func TestHeadSequenceIsPerVault(t *testing.T) {
	d, a, b := twoVaults(t)

	for i := 0; i < 5; i++ {
		if _, err := db.NextSequence(d, a); err != nil {
			t.Fatal(err)
		}
	}
	seqB, err := db.NextSequence(d, b)
	if err != nil {
		t.Fatal(err)
	}
	if seqB != 1 {
		t.Fatalf("B 的第一个 sequence 应当是 1，得到 %d —— "+
			"A 的写入推高了 B 的游标，既让 B 追不上，也泄露了 A 写了多少", seqB)
	}
	stA, _ := db.GetRepoState(d, a)
	if stA.HeadSequence != 5 {
		t.Fatalf("A 的 head 应当是 5，得到 %d", stA.HeadSequence)
	}
}

func TestMigrationStateIsPerVault(t *testing.T) {
	d, a, b := twoVaults(t)

	if err := db.SetMetaState(d, a, db.MetaMigrating); err != nil {
		t.Fatal(err)
	}
	stB, err := db.GetRepoState(d, b)
	if err != nil {
		t.Fatal(err)
	}
	if stB.MetaState != db.MetaPlain {
		t.Fatalf("A 开始迁移不该冻结 B 的写入（B 的 metaState = %q）", stB.MetaState)
	}
}

func TestFormatAndKeyEpochArePerVault(t *testing.T) {
	d, a, b := twoVaults(t)

	if err := db.SetFormatEpoch(d, a, 5); err != nil {
		t.Fatal(err)
	}
	if err := db.SetEncryptionState(d, a, db.EncryptionMigrating, true); err != nil {
		t.Fatal(err)
	}
	if err := db.RaiseMinimumEnvelopeVersion(d, a, 3); err != nil {
		t.Fatal(err)
	}
	if err := db.SetMinRetainedSequence(d, a, 99); err != nil {
		t.Fatal(err)
	}

	stB, err := db.GetRepoState(d, b)
	if err != nil {
		t.Fatal(err)
	}
	if stB.FormatEpoch != 1 || stB.KeyEpoch != 0 ||
		stB.MinimumEnvelopeVersion != 0 || stB.MinRetainedSequence != 0 {
		t.Fatalf("A 的世代/下限/水位线泄漏到了 B：%+v", stB)
	}
	stA, _ := db.GetRepoState(d, a)
	if stA.FormatEpoch != 5 || stA.KeyEpoch != 1 ||
		stA.MinimumEnvelopeVersion != 3 || stA.MinRetainedSequence != 99 {
		t.Fatalf("A 自己的值没写进去：%+v", stA)
	}
}

// 零值范围必须硬失败，而不是退化成默认租户——
// 后者会把一个漏洞变成静默的跨租户读写。
func TestRepoStateRejectsZeroScope(t *testing.T) {
	d := openTestDB(t)
	var zero db.VaultScope
	if _, err := db.GetRepoState(d, zero); err != db.ErrVaultScopeMissing {
		t.Fatalf("零值范围必须被拒，得到 %v", err)
	}
	if _, err := db.NextSequence(d, zero); err != db.ErrVaultScopeMissing {
		t.Fatalf("NextSequence 零值范围必须被拒，得到 %v", err)
	}
	if _, err := db.CurrentKeyEpoch(d, zero); err != db.ErrVaultScopeMissing {
		t.Fatalf("CurrentKeyEpoch 零值范围必须被拒，得到 %v", err)
	}
}

// 保留策略按 Vault 覆盖（§10.2 最后一项）。
func TestRetentionIsPerVault(t *testing.T) {
	d, a, b := twoVaults(t)

	if ov, err := db.GetVaultRetention(d, a); err != nil || ov != nil {
		t.Fatalf("没设过覆盖时应当返回 nil，得到 %v %v", ov, err)
	}
	// -1 = 沿用实例默认；0 = 不限（一个有意义的值，不能当哨兵）
	if err := db.SetVaultRetention(d, a, db.VaultRetention{
		HistoryDays: 30, HistoryMaxPerFile: -1, AttachmentDays: 0, AttachmentMax: -1,
	}); err != nil {
		t.Fatal(err)
	}
	ov, err := db.GetVaultRetention(d, a)
	if err != nil || ov == nil {
		t.Fatalf("应当读回覆盖：%v %v", ov, err)
	}
	if ov.HistoryDays != 30 || ov.HistoryMaxPerFile != -1 || ov.AttachmentDays != 0 {
		t.Fatalf("覆盖值不对：%+v", *ov)
	}
	// B 不受影响：一个团队要求 30 天后必须消失，不该让另一个团队的历史也被裁掉
	if ovB, err := db.GetVaultRetention(d, b); err != nil || ovB != nil {
		t.Fatal("A 的保留策略不该影响 B")
	}
	if err := db.SetVaultRetention(d, a, db.VaultRetention{HistoryDays: -2}); err == nil {
		t.Fatal("非法值应当被拒")
	}
}

// 从 v0.16 之前的单行表升级：数据必须原样落到默认租户，一个字段都不能丢。
func TestUpgradeFromSingleRowRepoState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// v0.15 时代的 repo_state：单行、id=1、没有 vault_id
	if _, err := raw.Exec(`
		CREATE TABLE repo_state (
		    id INTEGER PRIMARY KEY CHECK (id = 1),
		    repo_epoch TEXT NOT NULL,
		    head_sequence INTEGER NOT NULL,
		    min_retained_sequence INTEGER NOT NULL DEFAULT 0,
		    encryption_state TEXT NOT NULL DEFAULT 'plaintext',
		    key_epoch INTEGER NOT NULL DEFAULT 0,
		    meta_state TEXT NOT NULL DEFAULT 'plain',
		    schema_version INTEGER NOT NULL DEFAULT 6,
		    format_epoch INTEGER NOT NULL DEFAULT 1,
		    minimum_envelope_version INTEGER NOT NULL DEFAULT 0,
		    meta_schema_version INTEGER NOT NULL DEFAULT 1,
		    migration_id TEXT NOT NULL DEFAULT '',
		    migration_owner_device_id TEXT NOT NULL DEFAULT '',
		    migration_lease_expires_at INTEGER NOT NULL DEFAULT 0,
		    migration_cutoff_sequence INTEGER NOT NULL DEFAULT 0,
		    migration_target_format_epoch INTEGER NOT NULL DEFAULT 0,
		    migration_key_epoch INTEGER NOT NULL DEFAULT 0
		);
		INSERT INTO repo_state (id, repo_epoch, head_sequence, min_retained_sequence,
			encryption_state, key_epoch, meta_state, format_epoch, minimum_envelope_version)
		VALUES (1, 'legacy-epoch-value', 4242, 100, 'encrypted', 7, 'encrypted', 3, 3);`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	// 升级
	d, err := db.Open(path)
	if err != nil {
		t.Fatalf("升级失败：%v", err)
	}
	defer d.Close()

	st, err := db.GetRepoState(d, db.LegacyDefaultScope())
	if err != nil {
		t.Fatal(err)
	}
	// 每一个字段都必须原样保留。丢掉 repoEpoch = 所有客户端被踢进恢复流程；
	// 丢掉 head = 已发出的 sequence 被重新分配，客户端静默跳过一整段历史
	if st.RepoEpoch != "legacy-epoch-value" {
		t.Fatalf("repoEpoch 丢了：%q", st.RepoEpoch)
	}
	if st.HeadSequence != 4242 {
		t.Fatalf("headSequence 丢了：%d", st.HeadSequence)
	}
	if st.MinRetainedSequence != 100 || st.KeyEpoch != 7 || st.FormatEpoch != 3 ||
		st.MinimumEnvelopeVersion != 3 || st.EncryptionState != "encrypted" ||
		st.MetaState != "encrypted" {
		t.Fatalf("升级后字段错位：%+v", *st)
	}
	// 重复打开必须幂等
	d.Close()
	d2, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	st2, err := db.GetRepoState(d2, db.LegacyDefaultScope())
	if err != nil {
		t.Fatal(err)
	}
	if st2.HeadSequence != 4242 || st2.RepoEpoch != "legacy-epoch-value" {
		t.Fatalf("重复升级不幂等：%+v", *st2)
	}
}
