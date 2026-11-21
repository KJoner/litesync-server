// W1（RC-1）：上传 / 取远端期间用户继续输入，CAS 冲突的合并与保留双方都不能丢掉这些输入；
// 输入法组合期间不做程序化替换。真实 Chromium；在 PUT 与冲突后的 GET 边界注入延迟（扣住请求），
// 远端修改由插件原样代码写入。所有输入必须出现在：当前文档、冲突副本或已验证草稿中。
import { E2E, sleep, Suite, until } from "../lib/harness";
import { PluginDevice, snapshotPaths } from "../lib/plugin";
import { collectErrors, createVault, editorText, hold, openNote, tokenLogin, unlock, waitState } from "../lib/ui";

const PASSWORD = "W1 合并测试密码 · 2026-11-21";

/* eslint-disable @typescript-eslint/no-explicit-any */
async function replaceLine(page: any, n: number, text: string): Promise<void> {
	await page.locator(".cm-content").click();
	await page.keyboard.press("Control+Home");
	for (let i = 1; i < n; i++) await page.keyboard.press("ArrowDown");
	await page.keyboard.press("Home");
	await page.keyboard.press("Shift+End");
	await page.keyboard.insertText(text);
}
async function appendLine(page: any, text: string): Promise<void> {
	await page.locator(".cm-content").click();
	await page.keyboard.press("Control+End");
	await page.keyboard.press("Enter");
	await page.keyboard.insertText(text);
}
const getPath = (p: string) => (u: URL) => u.pathname === "/api/v1/file" && u.searchParams.get("path") === p;

await new Suite().run(async (s) => {
	const browser = await s.launch(); // close() 由套件骨架在收集完证据后执行
	try {
		const ctx = await s.context(browser);
		const page = await ctx.newPage();
		s.attach(page);
		const errors = collectErrors(page, /status of 401|status of 409|ERR_FAILED|ERR_INTERNET_DISCONNECTED/);
		page.on("dialog", (d: any) => d.accept());
		await tokenLogin(page);
		const vaultId = await createVault(page, `W1-${Date.now().toString(36)}`, PASSWORD);
		const dev = new PluginDevice(vaultId);
		await dev.unlock(PASSWORD);
		const A = "W1/干净合并.md", B = "W1/同段冲突.md", C = "W1/远端删除.md", D = "W1/输入法.md";
		await dev.create(A, new TextEncoder().encode("first\n\nmiddle\n\nlast\n"));
		await dev.create(B, new TextEncoder().encode("alpha\n\nbeta\n\ngamma\n"));
		await dev.create(C, new TextEncoder().encode("one\n"));
		await dev.create(D, new TextEncoder().encode("x1\n\nx2\n\nx3\n"));
		await page.reload();
		await unlock(page, PASSWORD);

		// ---- A. 干净合并：PUT 期间输入 B、GET 期间再输入 C，三处修改与远端修改全部保留 ----
		await openNote(page, A, "edit");
		let put = await hold(page, "**/api/v1/file", "PUT");
		await replaceLine(page, 1, "FIRST");
		await page.keyboard.press("Control+s");
		await put.hit;
		await dev.write(A, "first\n\nMIDDLE REMOTE\n\nlast\n");
		await replaceLine(page, 5, "LAST LATE（上传期间输入）");
		let get = await hold(page, getPath(A), "GET");
		put.release();
		await get.hit;
		await appendLine(page, "C（取远端期间输入）");
		get.release();
		await put.dispose();
		await get.dispose();
		const okA = await until(async () => (await page.locator(".save-status").getAttribute("data-state")) === "synced" && (await dev.read(A)).text.includes("C（取远端期间输入）"), 25000);
		const txtA = await editorText(page);
		await s.shot(page, "w1-a-merged");
		s.check("A 干净合并：编辑器同时保留首次上传的修改、上传期间与取远端期间的输入、远端修改",
			["FIRST", "MIDDLE REMOTE", "LAST LATE（上传期间输入）", "C（取远端期间输入）"].every((t) => txtA.includes(t)), JSON.stringify(txtA));
		const srvA = (await dev.read(A)).text;
		s.check("A 干净合并：服务器最终正文包含全部输入与远端修改（插件解密核对）", okA && ["FIRST", "MIDDLE REMOTE", "LAST LATE（上传期间输入）", "C（取远端期间输入）"].every((t) => srvA.includes(t)), JSON.stringify(srvA));
		s.check("A 干净合并：没有产生冲突副本", !(await snapshotPaths(vaultId)).some((f) => f.path.includes("冲突副本") && f.path.startsWith("W1/干净")));

		// ---- B. 同段冲突：保留双方时，冲突副本必须是「当前全文」（含上传与取远端期间的输入） ----
		await openNote(page, B, "edit");
		put = await hold(page, "**/api/v1/file", "PUT");
		await replaceLine(page, 1, "alpha 网页");
		await page.keyboard.press("Control+s");
		await put.hit;
		await dev.write(B, "alpha 插件\n\nbeta\n\ngamma\n");
		await replaceLine(page, 5, "gamma 上传期间输入");
		get = await hold(page, getPath(B), "GET");
		put.release();
		await get.hit;
		await appendLine(page, "取远端期间输入");
		get.release();
		await put.dispose();
		await get.dispose();
		const bannerB = await page.locator(".edit-notice .banner", { hasText: "冲突副本" }).waitFor({ timeout: 20000 }).then(() => true).catch(() => false);
		await s.shot(page, "w1-b-keep-both");
		const copyB = (await snapshotPaths(vaultId)).find((f) => f.path.startsWith("W1/同段冲突（网页冲突副本 "));
		s.check("B 同段冲突：进入保留双方，服务器上多出一份冲突副本", bannerB && !!copyB, copyB?.path);
		if (copyB) {
			const c = (await dev.read(copyB.path)).text;
			s.check("B 同段冲突：冲突副本包含网页的全部输入（首次上传 + 上传期间 + 取远端期间）",
				["alpha 网页", "gamma 上传期间输入", "取远端期间输入"].every((t) => c.includes(t)), JSON.stringify(c));
		} else s.check("B 同段冲突：冲突副本包含网页的全部输入（首次上传 + 上传期间 + 取远端期间）", false, "没有冲突副本");
		s.check("B 同段冲突：原笔记保留插件版本，编辑器载入远端版本", (await dev.read(B)).text === "alpha 插件\n\nbeta\n\ngamma\n" && (await editorText(page)).startsWith("alpha 插件"), await editorText(page));

		// ---- C. 远端删除：「另存为新笔记」保存的是点按钮那一刻编辑器里的全文 ----
		await openNote(page, C, "edit");
		put = await hold(page, "**/api/v1/file", "PUT");
		await replaceLine(page, 1, "one 网页");
		await page.keyboard.press("Control+s");
		await put.hit;
		await dev.remove(C);
		await appendLine(page, "two 上传期间输入");
		put.release();
		await put.dispose();
		const bannerC = await page.locator(".edit-notice .banner", { hasText: "别处被删除" }).waitFor({ timeout: 20000 }).then(() => true).catch(() => false);
		s.check("C 远端删除：如实提示并提供另存为新笔记", bannerC);
		await appendLine(page, "three 看到删除提示之后输入");
		await page.getByRole("button", { name: "另存为新笔记" }).click().catch(() => undefined);
		const savedC = await until(async () => (await snapshotPaths(vaultId)).some((f) => f.path.startsWith("W1/远端删除（网页冲突副本 ")), 20000);
		await sleep(2500); // 给可能的后续自动保存留时间：检查的是「另存那一刻」是否已经完整
		const copyC = (await snapshotPaths(vaultId)).find((f) => f.path.startsWith("W1/远端删除（网页冲突副本 "));
		const cText = copyC ? (await dev.read(copyC.path)).text : "";
		s.check("C 远端删除：新笔记包含首次上传、上传期间与提示之后的全部输入", savedC && ["one 网页", "two 上传期间输入", "three 看到删除提示之后输入"].every((t) => cText.includes(t)), JSON.stringify(cText));

		// ---- D. 输入法组合期间合并结果到达：推迟程序化替换，组合文字与远端修改都保留 ----
		await openNote(page, D, "edit");
		const cdp = await ctx.newCDPSession(page);
		put = await hold(page, "**/api/v1/file", "PUT");
		await replaceLine(page, 1, "x1 网页");
		await page.keyboard.press("Control+s");
		await put.hit;
		await dev.write(D, "x1\n\nX2 远端\n\nx3\n");
		get = await hold(page, getPath(D), "GET");
		put.release();
		await get.hit;
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+End");
		await cdp.send("Input.imeSetComposition", { text: "zhong", selectionStart: 5, selectionEnd: 5 });
		await sleep(300);
		get.release();
		await sleep(1500); // 合并结果已经算出——组合仍在进行，不得在此时替换文档
		const during = await editorText(page);
		s.check("D 输入法：组合进行中不替换文档（组合文字仍在，远端修改尚未套用）", during.includes("zhong") && !during.includes("X2 远端"), JSON.stringify(during));
		await cdp.send("Input.insertText", { text: "中文" });
		await put.dispose();
		await get.dispose();
		const okD = await until(async () => {
			const t = await editorText(page);
			return t.includes("中文") && t.includes("X2 远端");
		}, 15000);
		const txtD = await editorText(page);
		s.check("D 输入法：组合结束后套用合并——组合输入与远端修改都在，没有残留拼音", okD && !txtD.includes("zhong") && txtD.includes("x1 网页"), JSON.stringify(txtD));
		await waitState(page, "synced", 25000).catch(() => undefined);
		const srvD = (await dev.read(D)).text;
		s.check("D 输入法：服务器最终正文包含组合输入、首次修改与远端修改", ["中文", "x1 网页", "X2 远端"].every((t) => srvD.includes(t)), JSON.stringify(srvD));
		s.check("浏览器控制台无意外错误", errors.length === 0, errors.join(" | "));
		await ctx.close();
	} finally {
		await browser.close();
	}
});
