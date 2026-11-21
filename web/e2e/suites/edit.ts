// 网页编辑（批次 F / ADR-015）端到端：真实 Chromium 驱动网页编辑器；
// 插件原样的 ApiClient / uploadFromPlain / downloadPlain 充当「另一台设备」。
// 本机隔离服务端（OBSYNC_WEB_EDITING=true），全部为合成数据。原 edit-e2e.ts（58 项）入库版。
import { readFileSync } from "node:fs";
import { api, E2E, Suite } from "../lib/harness";
import { PluginDevice, rawMagic, snapshotPaths } from "../lib/plugin";
import { collectErrors, createVault, editorText, openNote, tokenLogin, typeLines, unlock, waitState } from "../lib/ui";

const PASSWORD = "编辑联调密码 · 2026-11-21";
const VAULT_NAME = `编辑联调-${Date.now().toString(36)}`;

/* eslint-disable @typescript-eslint/no-explicit-any */
await new Suite().run(async (s) => {
	const browser = await s.launch(); // close() 由套件骨架在收集完证据后执行
	try {
		const ctx = await s.context(browser);
		const page = await ctx.newPage();
		s.attach(page);
		const consoleErrors = collectErrors(page, /status of 401|status of 409|ERR_INTERNET_DISCONNECTED|ERR_FAILED/);
		const prompts: string[] = [];
		const alerts: string[] = [];
		const confirms: string[] = [];
		page.on("dialog", async (d: any) => {
			if (d.type() === "prompt") await d.accept(prompts.shift() ?? d.defaultValue());
			else {
				if (d.type() === "alert") alerts.push(d.message());
				if (d.type() === "confirm") confirms.push(d.message());
				await d.accept();
			}
		});
		await page.addInitScript(() => localStorage.setItem("litesync-theme", "dark"));

		// ---- 登录 + 浏览器端加密建库 + 在网页打开 ----
		await tokenLogin(page);
		const vaultId = await createVault(page, VAULT_NAME, PASSWORD);
		const dev = new PluginDevice(vaultId);
		s.check("插件侧用仓库密码解开浏览器建立的 keyDoc", await dev.unlock(PASSWORD));
		s.check("网页编辑开启时文件树有「新建笔记」", (await page.locator(".tree-new").count()) === 1);

		// ---- 1. 新建笔记 → Ctrl+S → 插件解密 ----
		const P = "联调/网页新建.md";
		prompts.push(P);
		await page.locator(".tree-new").click();
		await page.locator(".cm-content").waitFor({ timeout: 15000 });
		await page.locator(".cm-content").click();
		const v1 = "# 网页新建\n\n第一段\n\n第二段\n";
		await typeLines(page, v1);
		s.check("输入后状态为「未保存」或「已加密保存到本机」", ["dirty", "drafted"].includes(await page.locator(".save-status").getAttribute("data-state")));
		await page.keyboard.press("Control+s");
		await waitState(page, "synced");
		await s.shot(page, "e01-new-synced");
		s.check("新建笔记 Ctrl+S 后显示「已同步」", true, await page.locator(".save-status").textContent());
		s.check("服务器上是 LSE3 密文（不是明文）", (await rawMagic(vaultId, P)) === "LSE3");
		const cm = await page.evaluate(() => {
			const c = document.querySelector(".cm-content")!;
			return {
				adopted: ((document as any).adoptedStyleSheets ?? []).length,
				styleTags: document.querySelectorAll("style").length,
				lineHeight: parseFloat(getComputedStyle(c).lineHeight),
				fontSize: parseFloat(getComputedStyle(c).fontSize),
				ws: getComputedStyle(c).whiteSpace,
			};
		});
		s.check("CodeMirror 主题经 adoptedStyleSheets 生效、没有内联 <style>（CSP 不放宽）",
			cm.adopted >= 1 && cm.styleTags === 0 && Math.abs(cm.lineHeight - cm.fontSize * 1.7) < 1 && /pre-wrap|break-spaces/.test(cm.ws), JSON.stringify(cm));
		let r = await dev.read(P);
		s.check("插件下载解密网页新建的笔记，内容逐字一致", r.text === v1, JSON.stringify(r.text));
		s.check("新文件内容世代 = 1，fileId 是 32 位 hex", r.generation === 1 && /^[0-9a-f]{32}$/.test(r.fileId ?? ""), `gen=${r.generation}`);
		const fileId = r.fileId;

		// ---- 2. 插件改第二段；网页（基于旧版本）改第一段 → CAS 冲突 → 干净三方合并 ----
		const v2plugin = "# 网页新建\n\n第一段\n\n第二段（插件改）\n";
		const w2 = await dev.write(P, v2plugin);
		s.check("插件写入新版本（世代 2）", w2.generation === 2, `rev=${w2.revision}`);
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+Home");
		await page.keyboard.press("ArrowDown");
		await page.keyboard.press("ArrowDown");
		await page.keyboard.press("End");
		await page.keyboard.insertText("（网页改）");
		await page.keyboard.press("Control+s");
		await page.locator(".edit-notice .banner", { hasText: "自动合并" }).waitFor({ timeout: 20000 });
		await waitState(page, "synced");
		await s.shot(page, "e02-merged");
		r = await dev.read(P);
		const merged = "# 网页新建\n\n第一段（网页改）\n\n第二段（插件改）\n";
		s.check("冲突后自动三方合并：插件端拿到双方修改", r.text === merged, JSON.stringify(r.text));
		s.check("合并保存的世代 = 3（单调递增）、fileId 不变", r.generation === 3 && r.fileId === fileId, `gen=${r.generation}`);
		s.check("编辑器内容就是合并结果", (await editorText(page)) === merged.replace(/\n$/, "\n"));

		// ---- 3. 同一行冲突 → 保留双方（冲突副本），绝不最后写覆盖 ----
		const v3plugin = "# 网页新建\n\n第一段（插件再改）\n\n第二段（插件改）\n";
		await dev.write(P, v3plugin);
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+Home");
		await page.keyboard.press("ArrowDown");
		await page.keyboard.press("ArrowDown");
		await page.keyboard.press("Home");
		await page.keyboard.press("Shift+End");
		await page.keyboard.insertText("第一段（网页再改）");
		await page.keyboard.press("Control+s");
		await page.locator(".edit-notice .banner", { hasText: "冲突副本" }).waitFor({ timeout: 20000 });
		await s.shot(page, "e03-keep-both");
		const files3 = await snapshotPaths(vaultId);
		const copy = files3.find((f) => f.path.startsWith("联调/网页新建（网页冲突副本 "));
		s.check("同一行冲突：服务器上多出一份冲突副本", !!copy, copy?.path);
		r = await dev.read(P);
		s.check("原笔记保留插件的版本（没有被网页覆盖）", r.text === v3plugin);
		const copyText = "# 网页新建\n\n第一段（网页再改）\n\n第二段（插件改）\n";
		let copyFileId = "";
		if (copy) {
			const c = await dev.read(copy.path);
			copyFileId = c.fileId ?? "";
			s.check("冲突副本是网页的版本、且是新的 fileId", c.text === copyText && c.fileId !== fileId, JSON.stringify(c.text));
		}
		s.check("编辑器载入远端版本", (await editorText(page)) === v3plugin);
		await page.getByRole("button", { name: "对照两份" }).click();
		await page.locator(".dialog .diff-box .diff-line").first().waitFor({ timeout: 10000 });
		const diffText = (await page.locator(".dialog .diff-box").textContent()) ?? "";
		await s.shot(page, "e03b-compare");
		s.check("保留双方后可「对照两份」：逐行标出两边的不同", diffText.includes("- 第一段（插件再改）") && diffText.includes("+ 第一段（网页再改）"), diffText.slice(0, 120));
		await page.keyboard.press("Escape");

		// ---- 4. 离线：草稿只以密文进 IndexedDB；刷新 + 重新解锁后恢复并同步 ----
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+End");
		await typeLines(page, "离线追加的一段");
		await page.waitForTimeout(1500); // 草稿防抖 800ms
		await page.route("**/api/v1/file", (route: any) => (route.request().method() === "PUT" ? route.abort("internetdisconnected") : route.continue()));
		await page.keyboard.press("Control+s");
		await waitState(page, "offline");
		await s.shot(page, "e04-offline");
		s.check("断网保存显示「离线，待同步」", true, await page.locator(".save-status").textContent());
		const idb = await page.evaluate(async () => {
			const db: IDBDatabase = await new Promise((res, rej) => {
				const q = indexedDB.open("litesync-web-drafts", 1);
				q.onsuccess = () => res(q.result);
				q.onerror = () => rej(q.error);
			});
			const get = <T,>(fn: (s: IDBObjectStore) => IDBRequest<T>) => new Promise<T>((res, rej) => {
				const q = fn(db.transaction("drafts").objectStore("drafts"));
				q.onsuccess = () => res(q.result);
				q.onerror = () => rej(q.error);
			});
			const all = await get((st) => st.getAll());
			const keys = await get((st) => st.getAllKeys());
			db.close();
			return { count: all.length, json: JSON.stringify(all), keys: JSON.stringify(keys) };
		});
		s.check("IndexedDB 里有草稿记录", idb.count >= 1, `count=${idb.count}`);
		s.check("草稿记录与键里都没有明文正文或路径", !idb.json.includes("离线追加") && !idb.json.includes("网页新建") && !idb.keys.includes("网页新建") && !idb.keys.includes("联调"));
		await page.reload();
		await unlock(page, PASSWORD);
		await page.unroute("**/api/v1/file");
		await openNote(page, P, "read");
		await page.locator(".edit-notice .banner", { hasText: "草稿" }).waitFor({ timeout: 15000 });
		await s.shot(page, "e05-draft-offer");
		s.check("刷新并重新解锁后提示恢复本机草稿（阅读模式也提示）", true);
		await page.getByRole("button", { name: "恢复草稿" }).click();
		await page.locator(".cm-content").waitFor();
		s.check("恢复后编辑器里是草稿内容", (await editorText(page)).includes("离线追加的一段"));
		await page.keyboard.press("Control+s");
		await waitState(page, "synced");
		r = await dev.read(P);
		s.check("恢复的草稿同步到服务器，插件端可解密", r.text === v3plugin + "离线追加的一段", JSON.stringify(r.text));
		const idbAfter = await page.evaluate(async () => {
			const db: IDBDatabase = await new Promise((res) => {
				const q = indexedDB.open("litesync-web-drafts", 1);
				q.onsuccess = () => res(q.result);
			});
			const n = await new Promise<number>((res) => {
				const q = db.transaction("drafts").objectStore("drafts").count();
				q.onsuccess = () => res(q.result);
			});
			db.close();
			return n;
		});
		s.check("同步成功后本机草稿被清除", idbAfter === 0, `count=${idbAfter}`);

		// ---- 5. 只打开不修改不会上传 ----
		const revBefore = (await snapshotPaths(vaultId)).find((f) => f.path === P)!.revision;
		await openNote(page, P, "edit");
		await page.waitForTimeout(5000); // 超过自动保存间隔
		s.check("只打开、切到编辑但不修改：服务器版本不变", (await snapshotPaths(vaultId)).find((f) => f.path === P)!.revision === revBefore);

		// ---- 6. 改名：fileId 与历史保持，内容零重传 ----
		const P2 = "联调/改名后.md";
		prompts.push(P2);
		await page.locator(".note-more summary").click();
		await page.getByRole("button", { name: "改名 / 移动…" }).click();
		await page.waitForFunction((p: string) => location.hash === "#/n/" + encodeURIComponent(p), P2, { timeout: 15000 });
		const files6 = await snapshotPaths(vaultId);
		const moved = files6.find((f) => f.path === P2);
		s.check("改名后服务器上是新路径、同一个 fileId，旧路径消失", moved?.fileId === fileId && !files6.some((f) => f.path === P), moved?.path);
		dev.forget(P);
		r = await dev.read(P2);
		s.check("插件按新路径下载解密（内容未变、改名不推进内容世代：仍为 5）", r.text === v3plugin + "离线追加的一段" && r.generation === 5, `gen=${r.generation}`);
		const hist = await dev.history(P2);
		s.check("改名后历史连续（含改名前的版本）", hist.length >= 5, `versions=${hist.length}`);
		await page.locator('.seg button[data-mode="edit"]').click();
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+End");
		await page.keyboard.insertText("（改名后追加）");
		await page.keyboard.press("Control+s");
		await waitState(page, "synced");
		r = await dev.read(P2);
		s.check("改名后继续编辑保存到新位置，世代 6", r.text.endsWith("（改名后追加）") && r.generation === 6, `gen=${r.generation}`);

		// ---- 7. 删除冲突副本 ----
		if (copy) {
			await openNote(page, copy.path, "read");
			await page.locator(".note-more summary").click();
			await page.getByRole("button", { name: "删除…" }).click();
			await page.waitForFunction(() => location.hash === "#/", undefined, { timeout: 15000 });
			s.check("删除后服务器快照里不再有它", !(await snapshotPaths(vaultId)).some((f) => f.path === copy.path));

			// ---- 7b. 回收站：列出并恢复（同一 fileId、revision 连续、内容世代严格前进、HEAD 一致） ----
			await page.evaluate(() => (location.hash = "#/trash"));
			await page.locator(".trash-row", { hasText: "网页冲突副本" }).waitFor({ timeout: 15000 });
			await s.shot(page, "e06a-trash");
			const tomb = (await api("/api/v1/trash", { vaultId })).body.items.find((x: any) => x.fileId === copyFileId);
			s.check("删除的冲突副本出现在回收站且可恢复", !!tomb && tomb.restorable === true, JSON.stringify(tomb));
			await page.locator(".trash-row", { hasText: "网页冲突副本" }).getByRole("button", { name: "恢复" }).click();
			await page.waitForFunction((p: string) => location.hash === "#/n/" + encodeURIComponent(p), copy.path, { timeout: 20000 });
			dev.forget(copy.path);
			const back = await dev.read(copy.path);
			const head = await fetch(`${E2E.base}/api/v1/file?path=${encodeURIComponent(copy.path)}`, { headers: { Authorization: "Bearer " + E2E.token, "X-Vault-ID": vaultId } });
			const headGen = Number(head.headers.get("X-Content-Generation"));
			// 原子恢复（W4 修复后，能力位 restore-with-content）：恢复 = 一个新版本（删除时 revision + 1），
			// 新内容世代 = 删除时 + 1；旧的两阶段协议是 +2 / +2。两种情况下服务器 HEAD 声明的世代都必须
			// 与信封里经认证的世代一致——不允许「旧密文 + 新世代」的中间态留在服务器上
			const atomic = ((await api("/api/v1/info", { vaultId })).body.capabilities ?? []).includes("restore-with-content");
			const step = atomic ? 1 : 2;
			s.check("回收站恢复：同一 fileId、内容是删除前的版本、revision 连续、世代前进且 HEAD 一致",
				back.fileId === copyFileId && back.text === copyText && back.revision === tomb.deletionRevision + step && back.generation === tomb.contentGeneration + step && headGen === back.generation,
				`协议=${atomic ? "原子" : "两阶段"} rev=${back.revision} gen=${back.generation} head=${headGen}`);
			s.check("恢复后回收站里不再有它", !(await api("/api/v1/trash", { vaultId })).body.items.some((x: any) => x.fileId === copyFileId));
		}

		// ---- 7c. 恢复到历史版本：生成新版本，revision 只前进 ----
		await openNote(page, P2, "read");
		const beforeRestore = await dev.read(P2);
		await page.getByRole("button", { name: "🕘 历史版本" }).click();
		await page.locator(".drawer-item", { hasText: "版本 3 " }).click();
		await page.getByRole("button", { name: "恢复到此版本" }).click();
		await page.locator(".edit-bar").waitFor({ timeout: 20000 });
		r = await dev.read(P2);
		s.check("恢复到 rev 3：内容回到当时、revision 前进、世代 +1、fileId 不变",
			r.text === merged && r.revision > beforeRestore.revision && r.generation === (beforeRestore.generation ?? 0) + 1 && r.fileId === fileId,
			`rev ${beforeRestore.revision}→${r.revision} gen ${beforeRestore.generation}→${r.generation}`);
		s.check("恢复前弹出确认说明", confirms.some((m) => m.includes("恢复到 rev 3") && m.includes("新版本")));

		// ---- 7d. 附件：按钮上传 + 粘贴截图，预览从密文解密显示 ----
		await openNote(page, P2, "edit");
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+End");
		await page.keyboard.press("Enter");
		const png = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==", "base64");
		await page.locator('.fmt-bar input[type="file"]').setInputFiles({ name: "图 示.png", mimeType: "image/png", buffer: png });
		await page.waitForFunction(() => Array.from(document.querySelectorAll(".cm-line")).some((l) => (l.textContent ?? "").includes("![[图 示.png]]")), undefined, { timeout: 20000 });
		s.check("按钮上传附件后在光标处插入 ![[图 示.png]]", true);
		const attPath = "联调/图 示.png";
		const att = await dev.read(attPath);
		s.check("附件以 LSE3 密文存储，插件解密得到原始字节", (await rawMagic(vaultId, attPath)) === "LSE3" && Buffer.from(att.plain).equals(png));
		await page.evaluate((b64: string) => {
			const bin = Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0));
			const dt = new DataTransfer();
			dt.items.add(new File([bin], "image.png", { type: "image/png" }));
			document.querySelector(".cm-content")!.dispatchEvent(new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true }));
		}, png.toString("base64"));
		await page.waitForFunction(() => Array.from(document.querySelectorAll(".cm-line")).some((l) => /!\[\[Pasted image \d{14}\.png\]\]/.test(l.textContent ?? "")), undefined, { timeout: 20000 });
		s.check("粘贴截图：上传为「Pasted image 时间戳.png」并插入嵌入", (await snapshotPaths(vaultId)).some((f) => /^联调\/Pasted image \d{14}\.png$/.test(f.path)));
		await page.keyboard.press("Control+s");
		await waitState(page, "synced");
		await page.locator('.seg button[data-mode="split"]').click();
		await page.waitForFunction(() => {
			const img = document.querySelector(".preview-pane img") as HTMLImageElement | null;
			return !!img && img.src.startsWith("blob:") && img.complete && img.naturalWidth === 1;
		}, undefined, { timeout: 15000 });
		await s.shot(page, "e06b-attachment");
		s.check("预览里的附件图片从密文解密后显示（blob: 地址，不向外部请求）", true);
		r = await dev.read(P2);
		s.check("笔记里的附件引用同步到插件端", r.text.includes("![[图 示.png]]") && /!\[\[Pasted image \d{14}\.png\]\]/.test(r.text));

		// ---- 8. 分栏 + 手机宽度 ----
		await openNote(page, P2, "split");
		await s.shot(page, "e06-split-1440");
		await page.setViewportSize({ width: 390, height: 844 });
		await page.waitForTimeout(400);
		await page.screenshot({ path: `${E2E.out}/e07-split-390.png`, fullPage: true });
		const overflowing = () => page.evaluate(() => {
			const w = window.innerWidth;
			if (document.documentElement.scrollWidth <= w) return [] as string[];
			return Array.from(document.querySelectorAll("body *"))
				.filter((e) => e.getBoundingClientRect().right > w + 1)
				.slice(0, 8)
				.map((e) => `${e.tagName.toLowerCase()}.${(e as HTMLElement).className}:${Math.round(e.getBoundingClientRect().right)}`);
		});
		let over = await overflowing();
		s.check("390px 宽度编辑页无横向溢出", over.length === 0, over.join(" "));
		await page.locator(".more-btn").click();
		await page.locator(".header-actions", { hasText: "我的仓库" }).waitFor();
		await s.shot(page, "e07b-menu-390");
		over = await overflowing();
		s.check("390px 顶栏「⋯」菜单可用且展开后不溢出", over.length === 0 && (await page.locator(".header-actions").isVisible()), over.join(" "));
		await page.keyboard.press("Escape");
		s.check("Esc 关闭「⋯」菜单", !(await page.locator(".header-actions").isVisible()));
		await page.setViewportSize({ width: 1440, height: 900 });

		// ---- 8b. 主动离开仓库时本机草稿落不了盘：暂停并导出（需求 §7.3） ----
		await openNote(page, P2, "edit");
		await page.route("**/api/v1/file", (route: any) => (route.request().method() === "PUT" ? route.abort("internetdisconnected") : route.continue()));
		await page.evaluate(() => {
			(IDBObjectStore.prototype as any).put = function () {
				throw new DOMException("模拟：存储配额已满", "QuotaExceededError");
			};
		});
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+End");
		await page.keyboard.insertText("（切库前未保存）");
		await page.waitForTimeout(1200);
		s.check("本机草稿保存失败时状态栏如实显示", ((await page.locator(".save-status").textContent()) ?? "").includes("本机草稿保存失败"));
		confirms.length = 0;
		const downloadP = page.waitForEvent("download", { timeout: 20000 });
		await page.getByRole("button", { name: "我的仓库" }).click();
		const download = await downloadP;
		const exported = readFileSync((await download.path())!, "utf8");
		s.check("离开前先提示，并把未保存的内容导出为 Markdown 文件", confirms.some((m) => m.includes("没能加密保存到本机")) && exported.includes("（切库前未保存）") && download.suggestedFilename() === "改名后.md", download.suggestedFilename());
		await page.getByRole("heading", { name: "我的仓库" }).waitFor({ timeout: 20000 });
		await page.unroute("**/api/v1/file");
		await page.locator(".vault-card", { hasText: VAULT_NAME }).getByRole("button", { name: "解锁并打开" }).click();
		await unlock(page, PASSWORD);

		// ---- 8c. 完整 Markdown 夹具（验收 ED-02）：无修改不改字节；局部编辑后其余字节逐字节保留 ----
		const FX = "联调/夹具.md";
		const FXMIX = "联调/混用换行.md";
		const fixture = "﻿---\r\ntitle: 夹具\r\ntags: [b, a]\r\n---\r\n# 标题  \r\n\r\n> [!note] 提示\r\n> 内容\r\n\r\n" +
			"[[其他笔记#段落|别名]] ![[不存在.png]] ^block-1\r\n\r\n- [ ] 任务\r\n\t- [x] 子任务\r\n\r\n$$E=mc^2$$\r\n\r\n" +
			"```dataviewjs\r\ndv.paragraph(\"x\")\r\n```\r\n\r\n%%注释%%\r\n";
		const fxBytes = new TextEncoder().encode(fixture);
		await dev.create(FX, fxBytes);
		await dev.create(FXMIX, new TextEncoder().encode("第一行\r\n第二行\n第三行\r\n"));
		await page.reload(); // 网页不实时刷新别的设备新建的文件：重新进入
		await unlock(page, PASSWORD);
		await openNote(page, FX, "edit");
		const fxRev = (await snapshotPaths(vaultId)).find((f) => f.path === FX)!.revision;
		await page.keyboard.press("Control+s");
		await page.waitForTimeout(1500);
		s.check("夹具：打开、进入编辑、Ctrl+S 但没有修改 → 不上传（revision 不变）", (await snapshotPaths(vaultId)).find((f) => f.path === FX)!.revision === fxRev);
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+End");
		await page.keyboard.insertText("追加");
		await page.keyboard.press("Control+s");
		await waitState(page, "synced");
		const fxAfter = await dev.read(FX);
		const want = Buffer.concat([Buffer.from(fxBytes), Buffer.from("追加")]);
		s.check("夹具：局部编辑后其余字节完全不变（BOM、CRLF、frontmatter 顺序、callout、Wiki 链接、块引用、公式、未知代码块、注释）",
			Buffer.from(fxAfter.plain).equals(want), `got ${Buffer.from(fxAfter.plain).length} bytes, want ${want.length}`);
		await openNote(page, FXMIX, "edit");
		await page.locator(".edit-notice .banner", { hasText: "混用" }).waitFor({ timeout: 10000 });
		s.check("混用 CRLF/LF 的文件：进入编辑时事先说明保存会统一换行", true);

		// ---- 8d. 不刷新页面就能看到其他设备的修改 ----
		const pollNow = () => page.evaluate(() => window.dispatchEvent(new Event("focus")));
		await openNote(page, P2, "edit");
		r = await dev.read(P2);
		await dev.write(P2, r.text + "\n（插件在别处追加）");
		await pollNow();
		await page.locator(".edit-notice .banner", { hasText: "已载入别处的更新" }).waitFor({ timeout: 15000 });
		s.check("编辑器没有未保存修改时，直接载入别处的新版本", (await editorText(page)).includes("（插件在别处追加）"));
		await dev.create("联调/别处新建.md", new TextEncoder().encode("别的设备刚建的"));
		await pollNow();
		await page.locator(".tree", { hasText: "别处新建" }).waitFor({ timeout: 15000 });
		s.check("别的设备新建的笔记出现在文件树里（无需刷新）", true);
		await page.locator(".cm-content").click();
		await page.keyboard.press("Control+Home");
		await page.keyboard.insertText("【网页在开头加的】");
		r = await dev.read(P2);
		await dev.write(P2, r.text + "\n（插件又追加）");
		await pollNow();
		await page.locator(".edit-notice .banner", { hasText: "保存时会自动与你的修改合并" }).waitFor({ timeout: 15000 });
		s.check("有未保存修改时不覆盖编辑器，只提示保存时会合并", (await editorText(page)).startsWith("【网页在开头加的】") && !(await editorText(page)).includes("（插件又追加）"));
		await page.keyboard.press("Control+s");
		await waitState(page, "synced", 30000);
		r = await dev.read(P2);
		s.check("保存后三方合并：网页与插件两边的修改都在", r.text.startsWith("【网页在开头加的】") && r.text.includes("（插件又追加）") && r.text.includes("（插件在别处追加）"));

		// ---- 8e. 正文全文搜索：本机解密建索引；搜索词不出现在任何发往服务器的请求里 ----
		const QUERY = "插件又追加";
		const leaked: string[] = [];
		const onReq = (req: any) => {
			const u = decodeURIComponent(req.url());
			if (u.includes(QUERY) || (req.postData() ?? "").includes(QUERY)) leaked.push(`${req.method()} ${u}`);
		};
		page.on("request", onReq);
		await page.locator("input.search").fill(QUERY);
		await page.keyboard.press("Enter");
		await page.locator(".search-progress", { hasText: "已在本机索引" }).waitFor({ timeout: 30000 });
		await page.locator(".search-hit mark", { hasText: QUERY }).first().waitFor({ timeout: 10000 });
		await s.shot(page, "e09-fulltext");
		page.off("request", onReq);
		s.check("正文全文搜索：在本机建索引后命中正文并高亮片段", (await page.locator(".search-hit", { hasText: "改名后" }).count()) >= 1);
		s.check("搜索词没有出现在任何发往服务器的请求里", leaked.length === 0, leaked.join(" | "));

		// ---- 9. 手动锁定 ----
		await openNote(page, P2, "read");
		await page.locator('button[title="锁定（丢弃内存中的密钥）"]').click();
		await page.locator(".banner", { hasText: "已锁定" }).waitFor({ timeout: 15000 });
		await s.shot(page, "e08-locked");
		s.check("锁定后回到解锁页并说明原因", true);

		// ---- 10. 空闲自动锁定（虚拟时钟：按实际经过时间判断） ----
		await page.clock.install();
		await page.reload();
		await unlock(page, PASSWORD);
		await openNote(page, P2, "edit");
		await page.clock.fastForward("16:00");
		await page.locator(".banner", { hasText: "空闲超过 15 分钟" }).waitFor({ timeout: 20000 });
		s.check("空闲 15 分钟后自动锁定", true);

		s.check("没有意外的 alert", alerts.length === 0, alerts.join(" | "));
		s.check("浏览器控制台无错误（含 CSP 拒绝）", consoleErrors.length === 0, consoleErrors.join(" | "));
		await ctx.close();
	} finally {
		await browser.close();
	}
});
