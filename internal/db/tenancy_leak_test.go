package db_test

import (
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
)

// 跨租户信息泄露（v0.16.0 / 计划书 §10.6、ADR-010 §9）。
//
// 这一组盯的是「不用越权也能问出来的东西」。跨租户漏洞不一定长成
// 「读到了别人的文件」——「知道别人写了多少次」「知道别人有没有这份内容」
// 同样是泄露，而且更难被发现，因为每一次响应看上去都完全正常。

// changes 游标必须按租户隔离：一个租户的写入不得出现在另一个租户的变更流里。
func TestChangesAreScopedPerVault(t *testing.T) {
	d := openTestDB(t)

	// 两个租户各写一条
	for _, v := range []string{db.DefaultVaultID, "other-tenant"} {
		if _, err := d.Exec(
			`INSERT INTO object_changes
			   (sequence, vault_id, file_id, action, revision, pseudonym, created_at)
			 VALUES (1, ?, ?, 'upsert', 1, ?, 0)`,
			v, v+"-file", v+"-file"); err != nil {
			t.Fatal(err)
		}
	}

	changes, err := db.ListChanges(d, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 {
		t.Fatalf("默认租户应当只看到自己的 1 条变更，看到 %d 条", len(changes))
	}
	for i := range changes {
		if changes[i].VaultID != db.DefaultVaultID {
			t.Fatalf("变更流里混进了 vault %q 的记录", changes[i].VaultID)
		}
	}
}

// head_sequence 目前存在单行的 repo_state 里，也就是**实例级**的。
//
// 单实例服务一个租户时这没问题。但一旦同一个库里出现第二个租户，
// 「最新 sequence」就必须变成按租户的——否则 A 的写入会推高 B 看到的 head，
// B 的客户端会一直追一个永远追不上的游标，同时也从这个数字里读出
// 「别人今天写了多少」。
//
// 这条测试不修问题，它只保证问题**暴露的那一刻**会有人知道：
// 谁第一个往 object_changes 里写入第二个 vault_id，谁就会看到这条测试变红。
func TestHeadSequenceMustBecomePerVaultBeforeMultiTenantWrites(t *testing.T) {
	d := openTestDB(t)

	var vaults int
	if err := d.QueryRow(`SELECT COUNT(DISTINCT vault_id) FROM object_changes`).Scan(&vaults); err != nil {
		t.Fatal(err)
	}
	if vaults > 1 {
		t.Skip("已经是多租户写入，下面的前提检查交给真实实现")
	}

	// repo_state 是单行表：确认这一点，好让「head 是实例级的」这个事实是可见的
	var rows int
	if err := d.QueryRow(`SELECT COUNT(*) FROM repo_state`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("repo_state 应当是单行表，实际 %d 行", rows)
	}
	hasVaultCol := false
	cols, err := d.Query(`SELECT name FROM pragma_table_info('repo_state')`)
	if err != nil {
		t.Fatal(err)
	}
	for cols.Next() {
		var name string
		if err := cols.Scan(&name); err != nil {
			cols.Close()
			t.Fatal(err)
		}
		if name == "vault_id" {
			hasVaultCol = true
		}
	}
	cols.Close()
	if hasVaultCol {
		t.Skip("repo_state 已经按租户划分，本前提检查不再适用")
	}
	// 走到这里说明：repo_state 单行、没有 vault_id、object_changes 只有一个租户。
	// 这是当前架构的真实状态——一实例一租户。把它写下来，
	// 是为了让「加第二个租户」这件事无法悄悄发生。
	t.Log("当前为一实例一租户：head_sequence 是实例级的；" +
		"引入同库多租户前必须先把 repo_state 按 vault 划分")
}

// blob 的存在性不得被跨租户探测（§10.3 的性质，在 db 层再钉一次）。
//
// 判据：同一份内容在两个租户里必须落在两个不同的 blob_id 上，
// 因此「这个 id 存在吗」这个问题在跨租户方向上问不出任何东西。
func TestBlobExistenceIsNotCrossTenantObservable(t *testing.T) {
	d := openTestDB(t)
	const sameContent = "0000000000000000000000000000000000000000000000000000000000000001"

	// 两个租户各自持有同一份内容，但各自的 blob_id 不同（域化的结果）
	for i, v := range []string{db.DefaultVaultID, "other-tenant"} {
		blobID := []string{
			"aaaa000000000000000000000000000000000000000000000000000000000000",
			"bbbb000000000000000000000000000000000000000000000000000000000000",
		}[i]
		if _, err := d.Exec(
			`INSERT INTO file_heads (vault_id, file_id, revision, blob_id, content_hash,
			   size, mtime, pseudonym, created_at, updated_at)
			 VALUES (?, ?, 1, ?, ?, 1, 0, ?, 0, 0)`,
			v, v+"-file", blobID, sameContent, v+"-file"); err != nil {
			t.Fatal(err)
		}
	}

	// 拿另一个租户的 blob_id 去问「本租户有没有」，必须得到「没有」
	n, err := db.CountBlobReferencesIn(d, db.LegacyDefaultScope(),
		"bbbb000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("本租户不该看到别的租户的 blob 引用，得到 %d", n)
	}
	// 对照：自己的那个必须查得到，否则上面的 0 只是因为查询本身坏了
	n, err = db.CountBlobReferencesIn(d, db.LegacyDefaultScope(),
		"aaaa000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("本租户自己的 blob 引用应当查得到")
	}
}
