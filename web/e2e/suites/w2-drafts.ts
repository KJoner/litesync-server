// W2（RC-1）：加密草稿的生命周期。旧上传的成功响应不能删掉更新的草稿；两次草稿写入逆序完成时
// 较早的不能覆盖较晚的；多个标签页同时改同一篇各有各的草稿；上传进行中锁定 / 刷新 / 切库 / 换号 /
// 强制结束（渲染进程崩溃）之后，全部输入都能从已验证的加密草稿里恢复。真实 Chromium，合成数据。
import { api, E2E, sleep, Suite, until } from "../lib/harness";
import { PluginDevice, snapshotPaths } from "../lib/plugin";
import { createVault, draftRecords, editorText, enterVault, hold, offline, openNote, openVaultCard, tokenLogin, unlock, waitState } from "../lib/ui";

const PASSWORD = "W2 草稿测试密码 · 2026-11-21";
const PASSWORD2 = "W2 第二个仓库 · 2026-11-21";

/* eslint-disable @typescript-eslint/no-explicit-any */
async function appendLine(page: any, text: string): Promise<void> {
	await page.locator(".cm-content").click();
	await page.keyboard.press("Control+End");
	await page.keyboard.press("Enter");
	await page.keyboard.insertText(text);
}
async function replaceLine(page: any, n: number, text: string): Promise<void> {
	await page.locator(".cm-content").click();
	await page.keyboard.press("Control+Home");
	for (let i = 1; i < n; i++) await page.keyboard.press("ArrowDown");
	await page.keyboard.press("Home");
	await page.keyboard.press("Shift+End");
	await page.keyboard.insertText(text);
}
/** 强制结束：让渲染进程崩溃（不跑 beforeunload / pagehide，等同于被系统杀掉）。 */
async function crash(ctx: any, page: any): Promise<void> {
	const cdp = await ctx.newCDPSession(page);
	// Page.crash 让目标进程直接退出，这个调用本身可能永远等不到回应：限时
	await Promise.race([cdp.send("Page.crash").catch(() => undefined), sleep(1500)]);
	await sleep(300);
	await Promise.race([page.close().catch(() => undefined), sleep(3000)]);
}
/** 打开笔记并恢复本机草稿；返回是否出现了恢复提示。 */
/** 输入是否保存在：编辑器（当前文档）、服务器上的这篇，或它的冲突副本里。 */
async function preserved(page: any, dev: PluginDevice, vaultId: string, path: string, needles: string[]): Promise<{ ok: boolean; where: string }> {
	const has = (t: string) => needles.every((n) => t.includes(n));
	if (has(await editorText(page).catch(() => ""))) return { ok: true, where: "编辑器" };
	dev.forget(path);
	if (has((await dev.read(path).catch(() => ({ text: "" }))).text)) return { ok: true, where: "服务器上的这篇" };
	const stem = path.replace(/.md$/, "");
	for (const f of await snapshotPaths(vaultId)) {
		if (f.path.startsWith(stem + "（网页冲突副本 ") && has((await dev.read(f.path)).text)) return { ok: true, where: "冲突副本 " + f.path };
	}
	return { ok: false, where: "哪里都没有" };
}
async function restoreDraft(page: any, path: string): Promise<boolean> {
	await openNote(page, path, "read");
	const offered = await page.locator(".edit-notice .banner", { hasText: "草稿" }).waitFor({ timeout: 10000 }).then(() => true).catch(() => false);
	if (!offered) return false;
	await page.getByRole("button", { name: "恢复草稿" }).click();
	await page.locator(".cm-content").waitFor({ timeout: 10000 });
	return true;
}

await new Suite().run(async (s) => {
	const browser = await s.launch(); // close() 由套件骨架在收集完证据后执行
	try {
		const ctx = await s.context(browser);
		let page = await ctx.newPage();
		s.attach(page);
		const accept = (p: any) => p.on("dialog", (d: any) => d.accept().catch(() => undefined));
		accept(page);
		await tokenLogin(page);
		const vaultName = `W2-${Date.now().toString(36)}`;
		const vaultId = await createVault(page, vaultName, PASSWORD);
		const dev = new PluginDevice(vaultId);
		await dev.unlock(PASSWORD);
		const notes = ["旧成功", "逆序", "多标签", "锁定", "刷新", "切库", "换号"].map((n) => `W2/${n}.md`);
		for (const n of notes) await dev.create(n, new TextEncoder().encode(`${n} 基线\n\n第二段\n`));
		await page.reload();
		await unlock(page, PASSWORD);
		const fresh = async () => {
			page = await ctx.newPage();
			accept(page);
			s.attach(page);
			await page.goto(E2E.base + "/");
			await unlock(page, PASSWORD);
		};

		// ---- A. 旧上传成功晚到：较新的草稿 B 必须留着；随后断网 + 强制结束，B 能完整恢复 ----
		const NA = notes[0];
		await openNote(page, NA, "edit");
		let stopNet = await offline(page, "**/api/v1/file", "PUT"); // 之后的上传一律断网
		let put = await hold(page, "**/api/v1/file", "PUT"); // 第一个上传扣住
		await appendLine(page, "A（随上传发出）");
		await page.keyboard.press("Control+s");
		await put.hit;
		await appendLine(page, "B（上传期间输入，已写入本机草稿）");
		await sleep(1500); // 草稿防抖 800ms：B 已加密落盘
		put.release();
		const statusA = await put.done;
		await sleep(800); // 让成功响应被处理完
		s.check("A 前置：第一次上传在服务器上成功（A 已到服务器）", statusA === 200 && (await dev.read(NA)).text.includes("A（随上传发出）"), `status=${statusA}`);
		const recA = await draftRecords(page);
		s.check("A 旧成功晚到：本机仍保留 B 的加密草稿（没有被旧成功删除）", recA.count >= 1, `count=${recA.count}`);
		await put.dispose();
		await crash(ctx, page);
		await fresh();
		const offeredA = await restoreDraft(page, NA);
		const textA = offeredA ? await editorText(page) : "";
		s.check("A 强制结束后重开：提示恢复草稿，恢复内容包含 A 与 B", offeredA && textA.includes("A（随上传发出）") && textA.includes("B（上传期间输入，已写入本机草稿）"), JSON.stringify(textA));
		if (offeredA) {
			await page.keyboard.press("Control+s");
			await waitState(page, "synced", 20000).catch(() => undefined);
		}
		s.check("A 恢复后同步：服务器正文包含 A 与 B", (await dev.read(NA)).text.includes("B（上传期间输入，已写入本机草稿）"));

		// ---- B. 两次草稿写入逆序完成：较早开始、较晚完成的那次不能覆盖较新的草稿 ----
		const NB = notes[1];
		await openNote(page, NB, "edit");
		stopNet = await offline(page, "**/api/v1/file", "PUT");
		await page.evaluate(() => {
			const subtle = crypto.subtle as any;
			const orig = subtle.encrypt.bind(subtle);
			let n = 0;
			subtle.encrypt = async (alg: any, key: CryptoKey, data: BufferSource) => {
				const aad = alg?.additionalData ? new TextDecoder().decode(alg.additionalData) : "";
				const res = await orig(alg, key, data);
				if (aad.startsWith("litesync/web-draft/") && ++n === 1) await new Promise((r) => setTimeout(r, 2200)); // 第一次草稿加密故意变慢
				return res;
			};
		});
		await appendLine(page, "第一版草稿（较早开始）");
		await sleep(1000); // 第一次草稿写入开始（加密被拖慢）
		await appendLine(page, "第二版草稿（较晚开始、先完成）");
		await sleep(2600); // 第二次先落盘；第一次随后才完成——不得覆盖
		await crash(ctx, page);
		await fresh();
		const offeredB = await restoreDraft(page, NB);
		const textB = offeredB ? await editorText(page) : "";
		s.check("B 草稿逆序完成：强制结束后恢复的是较新的草稿（含第二版）", offeredB && textB.includes("第二版草稿（较晚开始、先完成）"), JSON.stringify(textB));
		await stopNet().catch(() => undefined);
		if (offeredB) {
			await page.keyboard.press("Control+s");
			await waitState(page, "synced", 20000).catch(() => undefined);
		}

		// ---- C. 两个标签页同时改同一篇：各自的草稿互不删除；一个保存后另一个崩溃，输入仍能恢复并合并 ----
		const NC = notes[2];
		await openNote(page, NC, "edit");
		const tab2 = await ctx.newPage();
		accept(tab2);
		await tab2.goto(E2E.base + "/");
		await unlock(tab2, PASSWORD);
		await openNote(tab2, NC, "edit");
		await replaceLine(page, 1, "多标签 基线（标签一改）");
		await sleep(1200);
		await replaceLine(tab2, 3, "第二段（标签二改）");
		await sleep(1200);
		const before = await draftRecords(page);
		await page.keyboard.press("Control+s");
		await waitState(page, "synced", 20000).catch(() => undefined);
		await sleep(500);
		const after = await draftRecords(page);
		s.check("C 多标签：标签一保存后，标签二的未同步草稿仍在本机", after.count >= 1, `保存前 ${before.count} 条，保存后 ${after.count} 条`);
		await crash(ctx, tab2);
		const tab3 = await ctx.newPage();
		accept(tab3);
		s.attach(tab3);
		await tab3.goto(E2E.base + "/");
		await unlock(tab3, PASSWORD);
		const offeredC = await restoreDraft(tab3, NC);
		const textC = offeredC ? await editorText(tab3) : "";
		s.check("C 多标签：标签二崩溃后能恢复它的草稿，并与标签一已同步的修改合并", offeredC && textC.includes("第二段（标签二改）") && textC.includes("标签一改"), JSON.stringify(textC));
		if (offeredC) {
			await tab3.keyboard.press("Control+s");
			await waitState(tab3, "synced", 20000).catch(() => undefined);
		}
		const srvC = (await dev.read(NC)).text;
		s.check("C 多标签：服务器最终包含两个标签页的修改", srvC.includes("第二段（标签二改）") && srvC.includes("标签一改"), JSON.stringify(srvC));
		await tab3.close();
		s.attach(page);

		// ---- D~G. 上传进行中锁定 / 刷新 / 切库 / 换号：旧结果不写回新会话；全部输入保存在当前文档、
		//      冲突副本或已验证草稿中；恢复草稿时能认出「随上传发出、其实已经到了服务器」的那部分，干净合并 ----
		const inflight = async (label: string, path: string, trigger: () => Promise<void>, back: () => Promise<void>) => {
			await openNote(page, path, "edit");
			const held = await hold(page, "**/api/v1/file", "PUT");
			await appendLine(page, `${label}前上传的`);
			await page.keyboard.press("Control+s");
			await held.hit;
			await appendLine(page, `${label}前最后输入的`);
			await sleep(1200);
			await trigger();
			held.release(); // 被扣住的旧请求此时才真正发出：它的结果绝不能落到新会话里
			await held.done;
			await held.dispose().catch(() => undefined);
			await back();
			const offered = await restoreDraft(page, path);
			const text = offered ? await editorText(page) : "";
			const needles = [`${label}前上传的`, `${label}前最后输入的`];
			if (offered) {
				await page.keyboard.press("Control+s");
				await waitState(page, "synced", 20000).catch(() => undefined);
			}
			const kept = await preserved(page, dev, vaultId, path, needles);
			s.check(`${label}：全部输入保存在当前文档、冲突副本或已验证草稿中`, kept.ok, kept.where);
			s.check(`${label}：恢复草稿后干净合并（编辑器里就是完整内容，不需要冲突副本）`, offered && needles.every((n) => text.includes(n)), JSON.stringify(text));
		};
		const lockBtn = () => page.locator('button[title="锁定（丢弃内存中的密钥）"]');
		const unlockPage = () => page.locator('input[placeholder="仓库密码"]');
		await inflight("D 锁定", notes[3], async () => {
			await lockBtn().click();
			await unlockPage().waitFor({ timeout: 20000 });
		}, () => unlock(page, PASSWORD));
		await inflight("E 刷新", notes[4], () => page.reload(), () => unlock(page, PASSWORD));

		// 切库需要第二个仓库
		await page.evaluate(() => (location.hash = "#/vaults"));
		const vault2 = await createVault(page, `${vaultName}-二`, PASSWORD2);
		await page.evaluate(() => (location.hash = "#/vaults"));
		await openVaultCard(page, vaultName);
		await unlock(page, PASSWORD);
		let otherDrafts = -1;
		await inflight("F 切库", notes[5], async () => {
			await page.locator("select.vault-switch").selectOption(vault2);
			await unlockPage().waitFor({ timeout: 30000 });
		}, async () => {
			await unlock(page, PASSWORD2);
			await sleep(800);
			otherDrafts = await page.locator(".draft-card").count();
			await page.locator("select.vault-switch").selectOption(vaultId);
			await unlock(page, PASSWORD);
		});
		s.check("F 切库：另一个仓库的首页看不到这个仓库的草稿", otherDrafts === 0, `draft cards=${otherDrafts}`);

		let cleared = false;
		await inflight("G 换号", notes[6], async () => {
			const inv = await api("/api/v1/admin/invites", { method: "POST", body: "{}" });
			const reg = await fetch(`${E2E.base}/join/${inv.body.secret}/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: "w2-b" }) });
			const bToken = (await reg.json()).token;
			// 另一个标签页：退出当前账号，换成 B 登录（同一浏览器共用会话 Cookie）
			const other = await ctx.newPage();
			accept(other);
			await other.goto(E2E.base + "/");
			await other.evaluate(async () => void (await fetch("/web/session", { method: "DELETE" })));
			await tokenLogin(other, bToken);
			await other.getByRole("heading", { name: "我的仓库" }).waitFor({ timeout: 20000 }).catch(() => undefined);
			cleared = await until(async () => !(await page.evaluate(() => document.body.innerText)).includes("G 换号前最后输入的"), 20000);
			await other.close();
		}, async () => {
			// 换回原账号：先退出 B，再用原账号登录并进入原仓库
			await page.evaluate(async () => void (await fetch("/web/session", { method: "DELETE" })));
			await tokenLogin(page);
			await enterVault(page, vaultName, PASSWORD);
		});
		s.check("G 换号：另一个标签页换成别的账号后，本页立即清掉编辑器里的明文", cleared);
		await ctx.close();
	} finally {
		await browser.close();
	}
});
