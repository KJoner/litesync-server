// W5（RC-3）：路径加密仓库的回收站。服务器只保存墓碑里的 LSM1 密文；网页（包括只有仓库密码的
// 新设备）在本机解开原路径后恢复。覆盖：改名后删除（显示改名后的路径）、canonical 重名（原位置被占 →
// 另选位置）、旧墓碑没有 LSM1（明确的手动选择路径降级）、历史清理（不可恢复且如实说明）、新设备恢复，
// 以及服务器数据库文件里找不到任何明文路径。真实 Chromium，合成数据。
//
// 仓库准备：网页建库（E2EE）→ 用 vendor 的 crypto-core 走一遍元数据迁移 API（begin / migrate-tombstone /
// verify / complete）把仓库带到路径加密——与插件迁移时发出的请求同形。
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import * as core from "../../src/vendor/litesync-core/crypto/crypto";
import { api, E2E, sleep, Suite, until } from "../lib/harness";
import { createVault, enterVault, openNote, tokenLogin, unlock } from "../lib/ui";

const PASSWORD = "W5 路径加密测试密码 · 2026-11-21";
const DEVICE = "e2e-meta-migrator";

/* eslint-disable @typescript-eslint/no-explicit-any */
await new Suite().run(async (s) => {
	const browser = await s.launch(); // close() 由套件骨架在收集完证据后执行
	try {
		const ctx = await s.context(browser);
		const page = await ctx.newPage();
		s.attach(page);
		const prompts: string[] = [];
		page.on("dialog", (d: any) => d.accept(d.type() === "prompt" ? (prompts.shift() ?? d.defaultValue()) : undefined).catch(() => undefined));
		await tokenLogin(page);
		const vaultName = `W5-${Date.now().toString(36)}`;
		const vaultId = await createVault(page, vaultName, PASSWORD);
		const call = (path: string, init: RequestInit = {}) => api(path, { ...init, vaultId, headers: { "X-Device-ID": DEVICE, ...((init.headers as Record<string, string>) ?? {}) } });
		const doc = (await call("/api/v1/vault-key")).body;
		const vmk = (await core.unlockVaultKey(doc, PASSWORD))!;
		const raw = await core.exportVmkRaw(vmk);
		const meta = await core.deriveMetaKeys(raw);
		let info = (await call("/api/v1/info")).body;

		// ---- 准备：迁移前删除一篇（它的墓碑没有 LSM1），然后完成元数据迁移 ----
		const legacyPath = "旧记录/迁移前删除.md";
		const legacyId = core.newFileId();
		const putPlain = async (path: string, fileId: string, text: string, base = 0, gen = 1) => {
			const ct = new Uint8Array(await core.encryptFileV3(vmk, { vaultId: info.vaultId, keyEpoch: info.keyEpoch, fileId, generation: gen }, new TextEncoder().encode(text).buffer as ArrayBuffer));
			const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", ct))).map((b) => b.toString(16).padStart(2, "0")).join("");
			return call("/api/v1/file", { method: "PUT", body: ct as BodyInit, headers: { "X-File-Path": encodeURIComponent(path), "X-Base-Revision": String(base), "X-Content-Hash": hash, "X-File-Id": fileId, "Content-Type": "application/octet-stream", "X-Format-Epoch": String(info.formatEpoch ?? 1) } });
		};
		const up = await putPlain(legacyPath, legacyId, "迁移前删除的正文");
		await call("/api/v1/file", { method: "DELETE", body: JSON.stringify({ path: legacyPath, baseRevision: up.body.revision }), headers: { "Content-Type": "application/json", "X-Format-Epoch": String(info.formatEpoch ?? 1) } });
		await call("/api/v1/envelope/complete", { method: "POST" }).catch(() => undefined);
		const begin = await call("/api/v1/meta/begin", { method: "POST" });
		const tombs = (await call("/api/v1/meta/tombstones")).body.tombstones ?? [];
		for (const t of tombs) await call("/api/v1/meta/migrate-tombstone", { method: "POST", body: JSON.stringify({ fileId: t.fileId, canonicalHash: await core.canonicalPathHmac(meta, t.lastPseudonym ?? legacyPath) }) });
		await call("/api/v1/meta/verify", { method: "POST" });
		const done = await call("/api/v1/meta/complete", { method: "POST", body: JSON.stringify({ confirmErase: true, migrationId: begin.body.migrationId }) });
		info = (await call("/api/v1/info")).body;
		s.check("准备：仓库已完成路径加密（metaState = encrypted）", done.status === 200 && info.metaState === "encrypted", `${done.status} ${JSON.stringify(done.body).slice(0, 160)}`);
		await page.reload();
		await unlock(page, PASSWORD);

		// ---- 网页上新建 → 改名 → 删除；新建 → 删除 → 别的文件改名占住原位置；新建 → 删除 → 清理历史 ----
		const newNote = async (path: string, text: string) => {
			prompts.push(path);
			await page.locator(".tree-new").click();
			await page.locator(".cm-content").waitFor({ timeout: 15000 });
			await page.locator(".cm-content").click();
			await page.keyboard.insertText(text);
			await page.keyboard.press("Control+s");
			await page.locator('.save-status[data-state="synced"]').waitFor({ timeout: 20000 });
		};
		const menu = async (label: string) => {
			await page.locator(".note-more summary").click();
			await page.getByRole("button", { name: label }).click();
		};
		// 刚新建的笔记停留在「新笔记」视图（地址仍是 #/、没有「更多」菜单）：先去别的视图，再按普通笔记视图打开
		const reopen = async (path: string) => {
			await page.evaluate(() => (location.hash = "#/trash"));
			await page.locator(".trash-list").waitFor({ timeout: 15000 });
			await openNote(page, path, "read");
		};
		const del = async (path: string) => {
			await reopen(path);
			await menu("删除…");
			await page.waitForFunction(() => location.hash === "#/", undefined, { timeout: 15000 });
		};
		const rename = async (from: string, to: string) => {
			await reopen(from);
			prompts.push(to);
			await menu("改名 / 移动…");
			await page.waitForFunction((p: string) => location.hash === "#/n/" + encodeURIComponent(p), to, { timeout: 15000 });
		};
		await newNote("私密/改名前.md", "改名测试的正文");
		const renamed = await rename("私密/改名前.md", "私密/改名后.md").then(() => true, () => false);
		s.check("路径加密仓库：网页新建后可以改名（采纳服务器记账的元数据世代）", renamed);
		await del(renamed ? "私密/改名后.md" : "私密/改名前.md");
		await newNote("私密/重名.md", "重名测试的正文（被删的那一份）");
		await del("私密/重名.md");
		await newNote("私密/占位.md", "后来占住原位置的另一篇");
		const occupied = await rename("私密/占位.md", "私密/重名.md").then(() => true, () => false);
		if (!occupied) await del("私密/占位.md").catch(() => undefined);
		await newNote("私密/历史清理.md", "历史会被清理的正文");
		await del("私密/历史清理.md");
		await newNote("私密/新设备.md", "新设备恢复的正文");
		await del("私密/新设备.md");

		const trash = async () => (await call("/api/v1/trash")).body.items as any[];
		let items = await trash();
		const decode = async (it: any) => (it.metaEnc ? (await core.decryptMeta(meta, it.metaEnc, info.vaultId, it.fileId))?.meta.path ?? null : null);
		const byPath = new Map<string, any>();
		for (const it of items) byPath.set((await decode(it)) ?? `<无LSM1:${it.fileId}>`, it);
		const purgeItem = byPath.get("私密/历史清理.md");
		if (purgeItem) await call(`/api/v1/history?path=${purgeItem.fileId}&beforeRevision=${purgeItem.deletionRevision}`, { method: "DELETE" });
		items = await trash();
		s.check("回收站接口只给伪名与 LSM1 密文：响应里没有任何明文路径", !JSON.stringify(items).match(/私密|改名|重名|新设备|历史清理/), JSON.stringify(items).slice(0, 200));
		s.check("改名后删除：墓碑里的 LSM1 解开是改名后的路径", byPath.has("私密/改名后.md") && !byPath.has("私密/改名前.md"), [...byPath.keys()].join(" | "));

		// ---- 回收站页面 ----
		await page.evaluate(() => (location.hash = "#/trash"));
		await page.locator(".trash-row").first().waitFor({ timeout: 15000 });
		await s.shot(page, "w5-trash");
		const rowText = (await page.locator(".trash-list").textContent()) ?? "";
		s.check("网页回收站显示解密后的原路径（改名后的名字），不是 fileId", rowText.includes("改名后") && rowText.includes("新设备"), rowText.slice(0, 200));
		const row = (t: string) => page.locator(".trash-row", { hasText: t });
		/** 点行里的恢复按钮；没有按钮（旧实现）就返回 false，由调用方记一项失败。 */
		const clickRestore = async (loc: any, name: RegExp = /恢复/): Promise<boolean> => {
			const btn = loc.first().getByRole("button", { name });
			if ((await btn.count()) === 0 || (await btn.first().isDisabled())) return false;
			await btn.first().click();
			return true;
		};

		// 改名后删除 → 原位恢复
		const c1 = await clickRestore(row("改名后"));
		const r1 = c1 && await page.waitForFunction(() => location.hash === "#/n/" + encodeURIComponent("私密/改名后.md"), undefined, { timeout: 20000 }).then(() => true).catch(() => false);
		const t1 = r1 ? await until(async () => ((await page.locator(".note-wrap").textContent()) ?? "").includes("改名测试的正文"), 15000) : false;
		s.check("改名后删除：在网页恢复到改名后的路径，内容可读", r1 && t1, c1 ? "" : "回收站里没有可用的恢复按钮");

		// canonical 重名：原位置已被另一篇占住 → 提示另选位置
		await page.evaluate(() => (location.hash = "#/trash"));
		await page.locator(".trash-row").first().waitFor({ timeout: 15000 });
		prompts.push("私密/重名（恢复）.md");
		const c2 = await clickRestore(row("私密/重名.md"));
		const r2 = c2 && await page.waitForFunction(() => location.hash === "#/n/" + encodeURIComponent("私密/重名（恢复）.md"), undefined, { timeout: 20000 }).then(() => true).catch(() => false);
		s.check("canonical 重名：原位置已被占用时另选位置恢复，两篇都在", r2 && occupied && (await call("/api/v1/snapshot")).body.files.length >= 3, c2 ? "" : "回收站里没有可用的恢复按钮");

		// 旧墓碑（迁移前删除，没有 LSM1）→ 明确的手动选择路径降级
		await page.evaluate(() => (location.hash = "#/trash"));
		await page.locator(".trash-row").first().waitFor({ timeout: 15000 });
		const legacyRow = page.locator(".trash-row", { hasText: "原路径未知" });
		const legacyShown = (await legacyRow.count()) === 1 && ((await legacyRow.textContent()) ?? "").includes("指定位置");
		s.check("旧墓碑没有 LSM1：如实说明原路径未知，并提供「选择位置恢复」", legacyShown, (await legacyRow.textContent().catch(() => "")) ?? "");
		prompts.push("旧记录/手动恢复.md");
		const c3 = legacyShown && (await clickRestore(legacyRow, /选择位置恢复/));
		const r3 = c3 && await page.waitForFunction(() => location.hash === "#/n/" + encodeURIComponent("旧记录/手动恢复.md"), undefined, { timeout: 20000 }).then(() => true).catch(() => false);
		const t3 = r3 ? await until(async () => ((await page.locator(".note-wrap").textContent()) ?? "").includes("迁移前删除的正文"), 15000) : false;
		s.check("旧墓碑：手动选择路径后恢复成功，内容是删除前的版本", r3 && t3);

		// 历史清理 → 不可恢复，如实说明
		await page.evaluate(() => (location.hash = "#/trash"));
		await page.locator(".trash-row").first().waitFor({ timeout: 15000 });
		const purgedRow = row("历史清理");
		const purgedBtn = purgedRow.getByRole("button", { name: /恢复/ });
		s.check("历史清理后：如实说明删除前的内容已被清理，恢复按钮不可用",
			(await purgedRow.count()) === 1 && (await purgedBtn.isDisabled().catch(() => false)) && ((await purgedRow.textContent()) ?? "").includes("历史清理"));

		// ---- 新设备：全新的浏览器上下文（没有任何本机状态），只凭服务器上的密文与仓库密码 ----
		const ctx2 = await s.context(browser);
		const dev2 = await ctx2.newPage();
		s.attach(dev2);
		dev2.on("dialog", (d: any) => d.accept().catch(() => undefined));
		await tokenLogin(dev2);
		await enterVault(dev2, vaultName, PASSWORD);
		await dev2.evaluate(() => (location.hash = "#/trash"));
		await dev2.locator(".trash-row", { hasText: "新设备" }).waitFor({ timeout: 15000 }).catch(() => undefined);
		const newDevRow = dev2.locator(".trash-row", { hasText: "新设备" });
		s.check("新设备：回收站同样解出原路径", (await newDevRow.count()) === 1);
		const c4 = (await newDevRow.count()) > 0 && (await clickRestore(newDevRow));
		const r4 = c4 && await dev2.waitForFunction(() => location.hash === "#/n/" + encodeURIComponent("私密/新设备.md"), undefined, { timeout: 20000 }).then(() => true).catch(() => false);
		const t4 = r4 ? await until(async () => ((await dev2.locator(".note-wrap").textContent()) ?? "").includes("新设备恢复的正文"), 15000) : false;
		s.check("新设备：恢复到原路径，内容可读", r4 && t4);
		s.attach(page);

		// ---- 服务器侧核对：恢复后的 HEAD 带客户端新给的 LSM1，解开是恢复位置；数据库文件里没有明文路径 ----
		await sleep(500);
		const snap = (await call("/api/v1/snapshot")).body.files as any[];
		const names: string[] = [];
		for (const f of snap) names.push((f.metaEnc && (await core.decryptMeta(meta, f.metaEnc, info.vaultId, f.fileId))?.meta.path) || `<${f.path}>`);
		s.check("恢复后的对象：服务器快照里只有伪名，LSM1 解开是恢复位置", ["私密/改名后.md", "私密/重名（恢复）.md", "旧记录/手动恢复.md", "私密/新设备.md"].every((p) => names.includes(p)) && snap.every((f) => /^[0-9a-f]{32}$/.test(f.path)), names.join(" | "));
		const dataDir = process.env.E2E_DATA_DIR;
		if (dataDir) {
			const needles = ["私密/改名后.md", "私密/改名前.md", "私密/重名（恢复）.md", "私密/新设备.md", "旧记录/手动恢复.md"].map((p) => Buffer.from(p, "utf8"));
			const hits: string[] = [];
			for (const f of readdirSync(dataDir)) {
				if (!/^sync\.db/.test(f)) continue;
				const b = readFileSync(join(dataDir, f));
				for (const n of needles) if (b.includes(n)) hits.push(`${f}:${n.toString()}`);
			}
			s.check("服务器数据库文件（sync.db / -wal）里找不到任何恢复位置或改名的明文路径", hits.length === 0, hits.join(" | "));
		} else {
			console.log("NOTE 服务器数据库文件的明文路径扫描未执行：外部服务端模式没有 E2E_DATA_DIR（不计入通过）");
		}
		await ctx2.close();
		await ctx.close();
	} finally {
		await browser.close();
	}
});
