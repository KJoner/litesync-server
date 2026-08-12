package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/KJoner/litesync-server/internal/db"
)

// 端到端演练（v0.14.0-RC / 计划书 §8.8 门槛 5、6、9）。
//
// 这些是「必须实际跑一次」而不是「有单元测试就算数」的项目。它们跑在
// **真实的 HTTP 服务 + 真实的 SQLite + 真实的 blob 目录**上，走的是和生产
// 完全相同的代码路径——唯一的差别是监听在测试端口而不是公网。
//
// 仍然做不到、必须由人在真实设备上完成的部分（诚实列出）：
//   - Obsidian 客户端参与的双设备实机流程（本文件只驱动服务端 API）；
//   - 真实 restic 仓库上的 backup restore（本机没有 restic）；
//   - 移动端的原子替换探测。

// 门槛 5：空服务器实际恢复。
//
// 场景：一台已有内容的客户端接入一个**全新的空服务器**。
// 必须结果是「本地内容一条不少地上到服务器」，而不是「服务器的空状态
// 把本地清空」——后者是这一条门槛真正要防的事故。
func TestDrillEmptyServerOnboarding(t *testing.T) {
	e := newTestEnv(t, 1<<20)

	// 全新服务器：snapshot 必须是空的
	_, snap0 := e.doJSON(t, http.MethodGet, "/api/v1/snapshot", testToken, nil)
	files0, _ := snap0["files"].([]any)
	if len(files0) != 0 {
		t.Fatalf("全新服务器的快照应当为空，得到 %d 条", len(files0))
	}

	// 客户端把本地的 30 个文件推上去（模拟 local-init 之后的首轮同步）
	const n = 30
	want := map[string]string{}
	for i := 0; i < n; i++ {
		path := fmt.Sprintf("notes/%02d/note-%03d.md", i%5, i)
		content := fmt.Sprintf("# note %d\n本地已有内容", i)
		want[path] = content
		if r, _ := e.upload(t, path, 0, []byte(content)); r.StatusCode != http.StatusOK {
			t.Fatalf("upload %s = %d", path, r.StatusCode)
		}
	}

	// 验收 1：服务器上一条不少
	_, snap1 := e.doJSON(t, http.MethodGet, "/api/v1/snapshot", testToken, nil)
	files1, _ := snap1["files"].([]any)
	if len(files1) != n {
		t.Fatalf("接入后服务器应有 %d 个对象，实际 %d", n, len(files1))
	}

	// 验收 2：每一个都能原样读回（内容没被改、没被截断）
	for path, content := range want {
		resp, got := e.download(t, path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("download %s = %d", path, resp.StatusCode)
		}
		if !bytes.Equal(got, []byte(content)) {
			t.Fatalf("%s 读回的内容与上传的不一致", path)
		}
	}

	// 验收 3：第二台设备从 0 拉 changes 能看到全部对象
	seen := map[string]bool{}
	var cursor int64
	for {
		resp, body := e.changes(t, fmt.Sprintf("?since=%d&limit=100", cursor))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("changes = %d", resp.StatusCode)
		}
		list, _ := body["changes"].([]any)
		if len(list) == 0 {
			break
		}
		for _, raw := range list {
			c := raw.(map[string]any)
			seen[c["path"].(string)] = true
			cursor = int64(c["sequence"].(float64))
		}
		if hasMore, _ := body["hasMore"].(bool); !hasMore {
			break
		}
	}
	if len(seen) != n {
		t.Fatalf("第二台设备应当能看到全部 %d 个对象，实际 %d", n, len(seen))
	}
}

// 门槛 9：所有 live HEAD 的 Blob 均存在且 hash 正确。
//
// 这一条的「实际跑一次」形态就是对一个有真实内容的仓库跑
// `integrity scan --full` 并留存输出。
func TestDrillIntegrityScanOnRealRepository(t *testing.T) {
	e := newTestEnv(t, 1<<20)

	// 造一个有历史、有删除、有恢复的仓库——比「上传几个文件」更接近真实
	for i := 0; i < 20; i++ {
		path := fmt.Sprintf("doc-%02d.md", i)
		if r, _ := e.upload(t, path, 0, []byte(fmt.Sprintf("v1 of %d", i))); r.StatusCode != http.StatusOK {
			t.Fatalf("upload = %d", r.StatusCode)
		}
		// 一半的文件再改两次，产生历史版本
		if i%2 == 0 {
			for rev := int64(1); rev <= 2; rev++ {
				if r, _ := e.upload(t, path, rev, []byte(fmt.Sprintf("v%d of %d", rev+1, i))); r.StatusCode != http.StatusOK {
					t.Fatalf("upload rev %d = %d", rev, r.StatusCode)
				}
			}
		}
	}
	// 删掉几个，留下 tombstone
	for i := 0; i < 4; i++ {
		path := fmt.Sprintf("doc-%02d.md", i)
		rev := int64(1)
		if i%2 == 0 {
			rev = 3
		}
		if r, _ := e.delete(t, path, rev); r.StatusCode != http.StatusOK {
			t.Fatalf("delete %s = %d", path, r.StatusCode)
		}
	}

	// 跑全量扫描
	resp, body := e.doJSON(t, http.MethodGet, "/api/v1/admin/integrity/scan?full=1", testToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("integrity scan = %d", resp.StatusCode)
	}
	report, _ := json.MarshalIndent(body, "", "  ")
	t.Logf("integrity scan --full 输出：\n%s", report)

	if body["dbCheck"] != "ok" {
		t.Fatalf("SQLite integrity_check 未通过：%v", body["dbCheck"])
	}
	if issues, _ := body["issues"].(float64); issues != 0 {
		t.Fatalf("干净仓库不应报出完整性问题：%v", body)
	}
	if heads, _ := body["headsChecked"].(float64); heads != 16 {
		t.Fatalf("应当检查 16 个 live HEAD（20 - 4 删除），实际 %v", body["headsChecked"])
	}
	if versions, _ := body["versionsChecked"].(float64); versions == 0 {
		t.Fatal("历史版本必须也被扫描到")
	}

	// 门槛 9 的核心断言：每个 live HEAD 都能真正读出内容
	_, snap := e.doJSON(t, http.MethodGet, "/api/v1/snapshot", testToken, nil)
	for _, raw := range snap["files"].([]any) {
		f := raw.(map[string]any)
		path := f["path"].(string)
		if r, _ := e.download(t, path); r.StatusCode != http.StatusOK {
			t.Fatalf("live HEAD %s 无法读出（%d）", path, r.StatusCode)
		}
	}
}

// 门槛 6：metadata migration 演练。
//
// 走完整的状态机：plain → E2EE → migrating（逐对象 + tombstone）→ verify →
// complete，并在**每一个阶段之后**检查仓库仍然自洽。
//
// 这是「实际跑一次」而不是「单元测试覆盖到了」——区别在于它跑的是完整链路：
// 真实的 HTTP 层、真实的状态机守卫、真实的 journal、真实的完整性扫描。
func TestDrillMetadataMigration(t *testing.T) {
	e := newTestEnv(t, 1<<20)

	// 准备一个有历史、有删除的仓库
	const n = 10
	for i := 0; i < n; i++ {
		path := fmt.Sprintf("笔记/doc-%02d.md", i)
		if r, _ := e.upload(t, path, 0, lse3Payload(1, 1, fmt.Sprint(i))); r.StatusCode != http.StatusOK {
			t.Fatalf("upload = %d", r.StatusCode)
		}
		if i%3 == 0 {
			if r, _ := e.upload(t, path, 1, lse3Payload(1, 2, fmt.Sprint(i)+"b")); r.StatusCode != http.StatusOK {
				t.Fatalf("upload rev2 = %d", r.StatusCode)
			}
		}
	}
	// 一条真实删除：删除屏障必须活到迁移完成之后（INV-06）
	if r, _ := e.upload(t, "笔记/已删除.md", 0, lse3Payload(1, 1, "gone")); r.StatusCode != http.StatusOK {
		t.Fatalf("upload = %d", r.StatusCode)
	}
	_, delBody := e.delete(t, "笔记/已删除.md", 1)
	deletedID, _ := delBody["fileId"].(string)
	if deletedID == "" {
		t.Fatal("删除应当返回 fileId")
	}

	assertClean := func(stage string) {
		t.Helper()
		r, scan := e.doJSON(t, http.MethodGet, "/api/v1/admin/integrity/scan?full=1", testToken, nil)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("[%s] scan = %d", stage, r.StatusCode)
		}
		if scan["dbCheck"] != "ok" {
			t.Fatalf("[%s] DB 校验失败：%v", stage, scan["dbCheck"])
		}
		if issues, _ := scan["issues"].(float64); issues != 0 {
			t.Fatalf("[%s] 出现完整性问题：%v", stage, scan)
		}
		t.Logf("[%s] scan clean：heads=%v versions=%v", stage, scan["headsChecked"], scan["versionsChecked"])
	}
	assertClean("迁移前")

	// 阶段 1：启用 E2EE 并抬高信封下限
	e.enterEncryptedRepo(t)
	assertClean("启用 E2EE 后")

	// 阶段 2：begin
	if r, body := e.postMeta(t, "begin", nil); r.StatusCode != http.StatusOK || body["metaState"] != "migrating" {
		t.Fatalf("meta begin = %d %v", r.StatusCode, body)
	}
	st := e.metaStatus(t)
	journal := st["journal"].(map[string]any)
	pending, _ := journal["pending"].(float64)
	if int(pending) != n+1 {
		t.Fatalf("journal 应当含 %d 个对象 + 1 条 tombstone，实际 %v", n, journal)
	}
	t.Logf("begin：metaState=%v journal=%v", st["metaState"], journal)

	// 阶段 3：逐对象迁移。身份与 revision 必须原样保留（INV-05）
	before := e.snapshotFiles(t)
	migrated := 0
	for path, meta := range before {
		idBefore := meta["fileId"].(string)
		revBefore := meta["revision"].(float64)
		genBefore := meta["contentGeneration"].(float64)

		canon := fmt.Sprintf("%064x", migrated+1)
		r, out := e.migrateObject(t, path, metaEncA, canon)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("migrate %s = %d %v", path, r.StatusCode, out)
		}
		// 迁移之后寻址名变成伪名（= fileId），但身份本身不变
		if out["toPath"] != idBefore {
			t.Fatalf("%s 迁移后的伪名应当等于 fileId：want %s got %v", path, idBefore, out["toPath"])
		}
		migrated++

		after := e.snapshotFiles(t)
		cur, ok := after[idBefore]
		if !ok {
			t.Fatalf("%s 迁移后在快照里找不到（伪名 %s）", path, idBefore)
		}
		if cur["revision"].(float64) != revBefore {
			t.Fatalf("%s 迁移改变了 revision：%v → %v", path, revBefore, cur["revision"])
		}
		if cur["contentGeneration"].(float64) != genBefore {
			t.Fatalf("%s 迁移改变了 contentGeneration：%v → %v", path, genBefore, cur["contentGeneration"])
		}
	}
	t.Logf("逐对象迁移完成：%d 个", migrated)
	assertClean("逐对象迁移后")

	// 阶段 4：tombstone 转换。删除屏障必须被保留（转换而不是丢弃，ADR-002）
	r, tombs := e.doJSON(t, http.MethodGet, "/api/v1/meta/tombstones", testToken, nil)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("list tombstones = %d", r.StatusCode)
	}
	list, _ := tombs["tombstones"].([]any)
	if len(list) != 1 {
		t.Fatalf("应当有 1 条待转换的明文 tombstone，实际 %v", tombs)
	}
	for _, raw := range list {
		tb := raw.(map[string]any)
		if r, out := e.doJSON(t, http.MethodPost, "/api/v1/meta/migrate-tombstone", testToken, map[string]any{
			"fileId": tb["fileId"], "canonicalHash": fmt.Sprintf("%064x", 999),
		}); r.StatusCode != http.StatusOK {
			t.Fatalf("migrate tombstone = %d %v", r.StatusCode, out)
		}
	}
	t.Logf("tombstone 转换完成：%d 条", len(list))

	// 阶段 5：verify + validate。complete 之前的最后一道闸门
	if r, out := e.postMeta(t, "verify", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("verify = %d %v", r.StatusCode, out)
	}
	r, val := e.doJSON(t, http.MethodGet, "/api/v1/meta/validate", testToken, nil)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("validate = %d %v", r.StatusCode, val)
	}
	t.Logf("validate：%v", val)

	// 阶段 6：complete —— 这一步不可逆地抹掉明文寻址名。
	//
	// 服务器要求显式的 confirmErase:true（LS-121-C01）。这不是形式主义：
	// 少打一个参数就抹掉全部明文寻址名，是不可接受的默认行为。
	// 先验证不带确认时确实被拒
	if r, out := e.postMeta(t, "complete", nil); r.StatusCode == http.StatusOK {
		t.Fatalf("complete 必须要求显式确认，却直接通过了：%v", out)
	}
	if r, out := e.postMeta(t, "complete", map[string]any{"confirmErase": true}); r.StatusCode != http.StatusOK {
		t.Fatalf("complete = %d %v", r.StatusCode, out)
	}
	st = e.metaStatus(t)
	if st["metaState"] != "encrypted" {
		t.Fatalf("complete 之后应当是 encrypted，实际 %v", st["metaState"])
	}
	t.Logf("complete：metaState=%v formatEpoch=%v", st["metaState"], st["formatEpoch"])

	assertClean("complete 后")

	// 验收 1：删除屏障还在——否则那个已删除的文件会在其他设备上复活
	if r, _ := e.upload(t, deletedID, 0, lse3Payload(1, 1, "resurrect")); r.StatusCode == http.StatusOK {
		t.Fatal("已删除对象的 tombstone 在迁移后消失了——该文件会在其他设备上复活")
	}

	// 验收 2：所有内容仍然可读（迁移只改寻址，不动内容）
	final := e.snapshotFiles(t)
	if len(final) != n {
		t.Fatalf("迁移后应当仍有 %d 个 live 对象，实际 %d", n, len(final))
	}
	for pseudonym := range final {
		if r, _ := e.download(t, pseudonym); r.StatusCode != http.StatusOK {
			t.Fatalf("迁移后 %s 无法读出（%d）", pseudonym, r.StatusCode)
		}
	}

	// 验收 3：明文路径确实被抹除了——快照里不应再出现任何真实路径片段
	for pseudonym := range final {
		if strings.Contains(pseudonym, "笔记") || strings.Contains(pseudonym, ".md") {
			t.Fatalf("迁移后快照里仍有明文路径：%s", pseudonym)
		}
	}
	t.Log("迁移演练全部通过：身份保留、删除屏障保留、内容可读、明文路径已抹除")
}

// 门槛 7 的服务端一半：repoEpoch 旋转之后，带旧 epoch 的写请求必须被拒。
//
// 真实 restic 恢复本机跑不了（没装 restic），但「恢复之后客户端会怎样」
// 这一半可以完整验证——而那正是数据安全的关键环节。
func TestDrillEpochRotationBlocksStaleClients(t *testing.T) {
	e := newTestEnv(t, 1<<20)
	if r, _ := e.upload(t, "before.md", 0, []byte("恢复点之前的内容")); r.StatusCode != http.StatusOK {
		t.Fatalf("upload = %d", r.StatusCode)
	}
	_, info := e.doJSON(t, http.MethodGet, "/api/v1/info", testToken, nil)
	oldEpoch := info["repoEpoch"].(string)

	// 模拟恢复后的 epoch 旋转
	if _, err := db.RotateEpoch(e.svc.DB(), db.LegacyDefaultScope()); err != nil {
		t.Fatalf("rotate epoch: %v", err)
	}
	_, info2 := e.doJSON(t, http.MethodGet, "/api/v1/info", testToken, nil)
	newEpoch := info2["repoEpoch"].(string)
	if newEpoch == oldEpoch {
		t.Fatal("旋转之后 repoEpoch 必须变化")
	}
	t.Logf("repoEpoch %s → %s", oldEpoch[:8], newEpoch[:8])

	// 带**旧** epoch 的写请求必须被拒绝——否则那台客户端会带着作废的游标
	// 继续增量同步，静默跳过恢复点之后的全部变更
	content := []byte("stale client write")
	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytes.NewReader(content))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-File-Path", url.PathEscape("stale.md"))
	req.Header.Set("X-Base-Revision", "0")
	req.Header.Set("X-Content-Hash", sha256Hex(content))
	req.Header.Set("X-File-Mtime", "1700000000000")
	// 唯一「不对」的地方就是这个旧 epoch——其余一切都是合法请求，
	// 这样被拒才能证明确实是 epoch 守卫在起作用
	req.Header.Set("X-Repo-Epoch", oldEpoch)
	resp, body := e.do(t, req)
	if resp.StatusCode == http.StatusOK {
		t.Fatal("带旧 repoEpoch 的写请求必须被拒绝，否则会静默跳过恢复点之后的变更")
	}
	t.Logf("旧 epoch 写请求被拒：HTTP %d %v", resp.StatusCode, body)
	// 必须因为**正确的原因**被拒。因为路径非法之类的偶然原因被拒，
	// 等于这道防线其实没生效——换个请求就穿过去了
	if body["code"] != "REPO_EPOCH_MISMATCH" {
		t.Fatalf("必须以 REPO_EPOCH_MISMATCH 拒绝，实际 %v", body["code"])
	}

	// 对照组：带**新** epoch 的同一个请求必须通过。
	// 没有这一步的话，上面的断言可能只是「所有写都被拒」而不是「epoch 守卫生效」
	req2, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/api/v1/file", bytes.NewReader(content))
	req2.Header.Set("Authorization", "Bearer "+testToken)
	req2.Header.Set("X-File-Path", url.PathEscape("fresh.md"))
	req2.Header.Set("X-Base-Revision", "0")
	req2.Header.Set("X-Content-Hash", sha256Hex(content))
	req2.Header.Set("X-File-Mtime", "1700000000000")
	req2.Header.Set("X-Repo-Epoch", newEpoch)
	if r2, b2 := e.do(t, req2); r2.StatusCode != http.StatusOK {
		t.Fatalf("带新 epoch 的写请求必须通过，得到 %d %v", r2.StatusCode, b2)
	}

	// 恢复点之前的内容仍然完好
	if r, got := e.download(t, "before.md"); r.StatusCode != http.StatusOK ||
		!bytes.Equal(got, []byte("恢复点之前的内容")) {
		t.Fatal("旋转 epoch 不得影响已有内容")
	}
}
