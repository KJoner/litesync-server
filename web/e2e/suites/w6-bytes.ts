// W6（RC-2）：网页编辑的原文保真。真实 Chromium + 插件写入的精确字节夹具：
//   - 只打开、进入编辑、离开，不改任何字节（含混合换行：旧实现进入编辑就被认作已修改并统一换行上传）；
//   - 纯 CRLF 多行全选加粗不抛「Selection points outside of document」，按 CRLF 写回；
//   - 撤销回原样 = 原始字节（BOM、混合换行都回来）；BOM / emoji / 中文多行的局部编辑只改动被编辑的部分；
//   - 一次插入多行（两个附件引用）在 CRLF 文档里按 CRLF 写回，不写出混用换行。
import { E2E, sleep, Suite } from "../lib/harness";
import { PluginDevice, snapshotPaths } from "../lib/plugin";
import { createVault, openNote, tokenLogin, unlock, waitState } from "../lib/ui";

const PASSWORD = "W6 保真测试密码 · 2026-11-21";
const enc = (s: string) => new TextEncoder().encode(s);
const show = (b: ArrayBuffer | Uint8Array) => JSON.stringify(new TextDecoder().decode(b));

/* eslint-disable @typescript-eslint/no-explicit-any */
await new Suite().run(async (s) => {
	const browser = await s.launch(); // close() 由套件骨架在收集完证据后执行
	try {
		const ctx = await s.context(browser);
		const page = await ctx.newPage();
		s.attach(page);
		const pageErrors: string[] = [];
		page.on("pageerror", (e: any) => pageErrors.push(String(e)));
		page.on("dialog", (d: any) => d.accept().catch(() => undefined));
		await tokenLogin(page);
		const vaultId = await createVault(page, `W6-${Date.now().toString(36)}`, PASSWORD);
		const dev = new PluginDevice(vaultId);
		await dev.unlock(PASSWORD);
		const F = {
			crlf: ["W6/纯CRLF.md", "a\r\nb\r\nc\r\nd"],
			mixed: ["W6/混合换行.md", "第一行\r\n第二行\n第三行\r\n"],
			bom: ["W6/BOM.md", "﻿# 标题\r\n正文\r\n"],
			emoji: ["W6/表情.md", "😀 表情\r\n中文第二行 🎉\r\n第三行"],
			lfTail: ["W6/末尾两个换行.md", "第一行\n第二行\n\n"],
			noTail: ["W6/无末尾换行.md", "只有一行"],
			attach: ["W6/附件插入.md", "附件前\r\n附件后\r\n"],
		} as const;
		for (const [p, t] of Object.values(F)) await dev.create(p, enc(t));
		await page.reload();
		await unlock(page, PASSWORD);
		const rev = async (p: string) => (await snapshotPaths(vaultId)).find((f) => f.path === p)!.revision;
		const bytes = async (p: string) => {
			dev.forget(p);
			return new Uint8Array((await dev.read(p)).plain);
		};
		const same = (a: Uint8Array, b: string) => Buffer.from(a).equals(Buffer.from(enc(b)));

		// ---- 1. 只打开、进入编辑、离开：一个字节都不改，也不上传 ----
		for (const [p, t] of Object.values(F)) {
			const before = await rev(p);
			await openNote(page, p, "edit");
			await sleep(1200);
			await page.evaluate(() => (location.hash = "#/"));
			await sleep(2500); // 离开时若被认作「有修改」会在后台上传
			const after = await rev(p);
			const b = await bytes(p);
			s.check(`只打开不修改：${p} 的 revision 与字节都不变`, after === before && same(b, t), `rev ${before}→${after} bytes=${show(b)}`);
		}

		// ---- 2. 纯 CRLF 多行全选加粗：不越界、按 CRLF 写回；撤销后逐字节回到原文 ----
		const [crlfPath, crlfText] = F.crlf;
		await openNote(page, crlfPath, "edit");
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+a");
		await page.locator('.fmt-bar button[aria-label="粗体"]').click();
		await page.keyboard.press("Control+s");
		await waitState(page, "synced", 15000).catch(() => undefined);
		let b = await bytes(crlfPath);
		s.check("纯 CRLF 多行全选加粗：按 CRLF 写回（**a\\r\\nb\\r\\nc\\r\\nd**）", same(b, `**${crlfText}**`), show(b));
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+z");
		await page.keyboard.press("Control+s");
		await waitState(page, "synced", 15000).catch(() => undefined);
		b = await bytes(crlfPath);
		s.check("撤销加粗再保存：逐字节回到原文（CRLF 保持）", same(b, crlfText), show(b));

		// ---- 3. 混合换行：真实编辑后统一为 LF（事先有说明）；撤销回原样 = 原始字节（混合换行回来） ----
		const [mixPath, mixText] = F.mixed;
		await openNote(page, mixPath, "edit");
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+End");
		await page.keyboard.insertText("追加");
		await page.keyboard.press("Control+s");
		await waitState(page, "synced", 15000).catch(() => undefined);
		b = await bytes(mixPath);
		s.check("混合换行：真实编辑后保存为统一的 LF（只在有修改时）", same(b, "第一行\n第二行\n第三行\n追加"), show(b));
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+z");
		await page.keyboard.press("Control+s");
		await waitState(page, "synced", 15000).catch(() => undefined);
		b = await bytes(mixPath);
		s.check("混合换行：撤销回原样后保存的是原始字节（\\r\\n 与 \\n 原样）", same(b, mixText), show(b));

		// ---- 4. BOM + CRLF：局部编辑后 BOM 与其余字节都在 ----
		const [bomPath, bomText] = F.bom;
		await openNote(page, bomPath, "edit");
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+End");
		await page.keyboard.insertText("追加");
		await page.keyboard.press("Control+s");
		await waitState(page, "synced", 15000).catch(() => undefined);
		b = await bytes(bomPath);
		s.check("BOM + CRLF：末尾追加后 BOM、CRLF 与其余字节完全不变", same(b, bomText + "追加"), show(b));

		// ---- 5. emoji / 中文多行选区加粗（CRLF）；加粗后立刻撤销 = 没有修改、不上传 ----
		const [emPath, emText] = F.emoji;
		await openNote(page, emPath, "edit");
		const emRev = await rev(emPath);
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+Home");
		await page.keyboard.press("Shift+ArrowDown");
		await page.keyboard.press("Shift+End");
		await page.locator('.fmt-bar button[aria-label="粗体"]').click();
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+z");
		await sleep(600);
		const st = await page.locator(".save-status").getAttribute("data-state");
		await page.keyboard.press("Control+s");
		await sleep(1500);
		s.check("emoji 多行加粗后撤销：状态回到「未修改」，Ctrl+S 不上传", ["clean", "synced"].includes(st ?? "") && (await rev(emPath)) === emRev, `state=${st}`);
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+Home");
		await page.keyboard.press("Shift+ArrowDown");
		await page.keyboard.press("Shift+End");
		await page.locator('.fmt-bar button[aria-label="粗体"]').click();
		await page.keyboard.press("Control+s");
		await waitState(page, "synced", 15000).catch(() => undefined);
		b = await bytes(emPath);
		s.check("emoji / 中文多行选区加粗：代理对完整、CRLF 保持", same(b, "**😀 表情\r\n中文第二行 🎉**\r\n第三行"), show(b));

		// ---- 6. LF 末尾两个换行 / 无末尾换行：局部编辑不吞也不加末尾换行 ----
		for (const [p, t] of [F.lfTail, F.noTail]) {
			await openNote(page, p, "edit");
			await page.locator(".cm-content").click();
			await page.keyboard.press("Control+Home");
			await page.keyboard.insertText("前缀");
			await page.keyboard.press("Control+s");
			await waitState(page, "synced", 15000).catch(() => undefined);
			b = await bytes(p);
			s.check(`末尾换行保持：${p}`, same(b, "前缀" + t), show(b));
		}

		// ---- 7. CRLF 文档里一次插入两个附件引用：按 CRLF 写回，不写出混用换行 ----
		const [atPath] = F.attach;
		await openNote(page, atPath, "edit");
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+Home");
		await page.keyboard.press("End");
		const png = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==", "base64");
		await page.locator('.fmt-bar input[type="file"]').setInputFiles([
			{ name: "甲.png", mimeType: "image/png", buffer: png },
			{ name: "乙.png", mimeType: "image/png", buffer: png },
		]);
		await page.waitForFunction(() => Array.from(document.querySelectorAll(".cm-line")).some((l) => (l.textContent ?? "").includes("![[乙.png]]")), undefined, { timeout: 20000 }).catch(() => undefined);
		await page.keyboard.press("Control+s");
		await waitState(page, "synced", 15000).catch(() => undefined);
		b = await bytes(atPath);
		const t = new TextDecoder().decode(b);
		s.check("CRLF 文档插入多行附件引用：按 CRLF 写回（没有孤立的 \\n）", t.includes("![[甲.png]]\r\n![[乙.png]]") && !/[^\r]\n/.test(t), JSON.stringify(t));

		s.check("页面没有抛出异常（含 Selection points outside of document）", pageErrors.length === 0, pageErrors.join(" | "));
		await ctx.close();
	} finally {
		await browser.close();
	}
});
