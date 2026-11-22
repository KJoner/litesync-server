// UI 焕新 U4b：阅读态与保存状态、新笔记首次保存后的菜单、抽屉的键盘操作、当前仓库、离开工作台的说明、
// 低频操作的产品内表单、连接设备（同设备打开 / 复制失败 / 过期重新生成）、登录页的注册状态。
// 本机隔离服务端，合成仓库与合成笔记；插件原样源码充当「另一台设备」核对服务器上的真实内容。
import { api, E2E, Suite, sleep, until } from "../lib/harness";
import { PluginDevice } from "../lib/plugin";
import { createNote, createVault, openNote, renameNote, tokenLogin, unlock, waitState } from "../lib/ui";

/* eslint-disable @typescript-eslint/no-explicit-any */
const PW = "U4b 界面测试密码 · 2026-11-22";
const VAULT = "U4b 界面";
const VAULT2 = "U4b 界面（改名后）";

const envelopeStatus = async (id: string) => (await fetch(`${E2E.base}/api/v2/pairings/${id}/envelope`)).status;

await new Suite().run(async (s) => {
	const browser = await s.launch();
	const ctx = await s.context(browser, { viewport: { width: 1280, height: 800 } });
	const page = await ctx.newPage();
	s.attach(page);
	const pageErrors: string[] = [];
	page.on("pageerror", (e: any) => pageErrors.push(String(e)));
	page.on("dialog", (d: any) => (d.type() === "beforeunload" ? d.accept() : d.dismiss()).catch(() => undefined));
	await tokenLogin(page);
	const vaultId = await createVault(page, VAULT, PW);
	const dev = new PluginDevice(vaultId);
	await dev.unlock(PW);

	// ---- 1. 新建笔记：第一次保存后就地出现「更多」；已同步之后继续输入，状态不再是「已同步」 ----
	await createNote(page, "U4b/新笔记.md");
	await page.locator(".cm-content").waitFor({ timeout: 15000 });
	await page.evaluate(() => ((document.querySelector(".cm-content") as any).__u4b = 1));
	await page.locator(".cm-content").click();
	await page.keyboard.insertText("# 标题\n第一段");
	await page.keyboard.press("Control+s");
	await waitState(page, "synced");
	await page.locator(".note-more summary").waitFor({ timeout: 10000 });
	const sameEditor = await page.evaluate(() => (document.querySelector(".cm-content") as any)?.__u4b === 1);
	s.check("新笔记第一次保存后就地出现「更多」与「历史版本」，编辑器没有重建", sameEditor && (await page.getByRole("button", { name: "🕘 历史版本" }).count()) === 1);
	await page.keyboard.insertText("，接着输入");
	const typingState = await page.locator(".save-status").getAttribute("data-state");
	s.check("已同步之后继续输入：状态立刻变成「未保存」或「已存本机草稿」，不再显示「已同步」", typingState === "dirty" || typingState === "drafted", `state=${typingState}`);
	await waitState(page, "synced", 20000); // 停止输入 4 秒后自动上传
	const r1 = await dev.read("U4b/新笔记.md");
	s.check("停止输入后自动上传：显示「已同步」时服务器上就是编辑器里的全文", r1.text === "# 标题\n第一段，接着输入", JSON.stringify(r1.text));
	await renameNote(page, "U4b/新笔记.md", "U4b/改名一.md");
	await renameNote(page, "U4b/改名一.md", "U4b/改名二.md");
	const r2 = await dev.read("U4b/改名二.md").catch(() => null);
	s.check("同一个「更多」菜单连续改名两次：服务器上是最后的名字，fileId 与内容不变", !!r2 && r2.fileId === r1.fileId && r2.text === r1.text && (await page.locator(".tree-file", { hasText: "改名一" }).count()) === 0, JSON.stringify({ path: r2 ? "改名二" : null, same: r2?.fileId === r1.fileId }));

	// ---- 2. 阅读态（W05）与分栏宽度 ----
	await page.evaluate(() => (location.hash = "#/trash"));
	await sleep(300);
	await openNote(page, "U4b/改名二.md", "read");
	s.check("阅读态：不显示「保存」主按钮、格式工具栏与「未修改」",
		!(await page.locator(".edit-bar button.primary").isVisible()) && !(await page.locator(".fmt-bar").isVisible()) && !(await page.locator(".save-status").isVisible()));
	await page.locator('.seg button[data-mode="edit"]').click();
	await page.locator(".cm-content").click();
	await page.keyboard.press("Control+End");
	await page.keyboard.insertText("（阅读态保存）");
	await page.locator('.seg button[data-mode="read"]').click();
	const saveVisible = await page.locator(".edit-bar button.primary").isVisible();
	if (saveVisible) await page.locator(".edit-bar button.primary").click();
	await waitState(page, "synced", 20000);
	s.check("阅读态有未同步的修改时「保存」照常显示，点了能保存", saveVisible && (await dev.read("U4b/改名二.md")).text.endsWith("（阅读态保存）"));
	await page.setViewportSize({ width: 1440, height: 900 });
	await page.locator('.seg button[data-mode="split"]').click();
	await page.locator(".cm-content").waitFor({ timeout: 15000 });
	const splitWidth = await page.evaluate(() => document.querySelector(".note-wrap")!.getBoundingClientRect().width);
	s.check("分栏：正文容器放宽到 800 px 以上，右侧大纲收起", splitWidth > 900 && !(await page.locator(".outline").isVisible()), `width=${Math.round(splitWidth)}`);
	await page.locator('.seg button[data-mode="read"]').click();
	await page.setViewportSize({ width: 1280, height: 800 });

	// ---- 3. 历史抽屉（W08）：键盘打开、焦点进出、Tab 不出抽屉、Esc / 遮罩关闭 ----
	const hist = page.getByRole("button", { name: "🕘 历史版本" });
	await hist.focus();
	await page.keyboard.press("Enter");
	await page.locator(".drawer button.drawer-item").first().waitFor({ timeout: 10000 });
	await until(async () => page.evaluate(() => !!document.activeElement?.classList.contains("drawer-item")), 3000);
	s.check("历史抽屉：键盘打开后焦点进入版本列表（版本行是按钮），触发按钮 aria-expanded=true",
		(await page.evaluate(() => document.activeElement?.tagName === "BUTTON" && !!document.activeElement.closest(".drawer"))) && (await hist.getAttribute("aria-expanded")) === "true");
	for (let i = 0; i < 6; i++) await page.keyboard.press("Tab");
	s.check("历史抽屉里连按 Tab 焦点不离开抽屉", await page.evaluate(() => !!document.activeElement?.closest(".drawer")));
	await page.keyboard.press("Escape");
	await page.locator(".drawer").waitFor({ state: "detached", timeout: 5000 });
	s.check("Esc 关闭抽屉：焦点回到「历史版本」，aria-expanded=false",
		(await page.evaluate(() => (document.activeElement?.textContent ?? "").includes("历史版本"))) && (await hist.getAttribute("aria-expanded")) === "false");
	await hist.click();
	await page.locator(".drawer").waitFor({ timeout: 5000 });
	await page.mouse.click(120, 420);
	s.check("点遮罩关闭历史抽屉", await until(async () => (await page.locator(".drawer").count()) === 0, 3000));

	// ---- 4. 手机：文件树抽屉（W08）与当前仓库（W02） ----
	await page.setViewportSize({ width: 390, height: 844 });
	await sleep(300);
	const menu = page.locator(".menu-btn");
	const treeInert = () => page.evaluate(() => (document.getElementById("tree") as any)?.inert === true);
	s.check("手机：文件树收起时整棵树 inert，☰ 的 aria-expanded=false", (await treeInert()) && (await menu.getAttribute("aria-expanded")) === "false");
	await menu.click();
	await until(async () => page.evaluate(() => !!document.activeElement?.closest("#tree")), 3000);
	s.check("手机：点 ☰ 打开文件树，焦点进入树，aria-expanded=true",
		(await page.evaluate(() => !!document.activeElement?.closest("#tree"))) && (await menu.getAttribute("aria-expanded")) === "true" && !(await treeInert()));
	await page.keyboard.press("Escape");
	await sleep(250);
	s.check("手机：Esc 关闭文件树，焦点回到 ☰，树重新 inert",
		(await page.evaluate(() => !!document.activeElement?.classList.contains("menu-btn"))) && (await treeInert()));
	const chip = page.locator(".vault-chip");
	s.check("手机：顶栏一直显示当前仓库名，且没有横向溢出",
		(await chip.isVisible()) && ((await chip.textContent()) ?? "").includes(VAULT) && (await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)));
	await page.setViewportSize({ width: 1280, height: 800 });

	// ---- 5. 离开工作台（W03）：动作之前说明会锁定；回来时写明仓库与原因 ----
	await page.getByRole("button", { name: "我的仓库" }).click();
	const leave = page.getByRole("dialog");
	await leave.waitFor({ timeout: 5000 });
	const leaveText = (await leave.textContent()) ?? "";
	await leave.getByRole("button", { name: "留在这里" }).click();
	s.check("点「我的仓库」先说明会锁定、回来要再输仓库密码；「留在这里」不离开",
		leaveText.includes("锁定") && leaveText.includes("仓库密码") && (await page.locator(".tree").isVisible()) && !(await page.locator(".dialog").count()));
	await page.getByRole("button", { name: "我的仓库" }).click();
	await page.getByRole("dialog").getByRole("button", { name: "锁定并前往" }).click();
	await page.getByRole("heading", { name: "我的仓库" }).waitFor({ timeout: 20000 });
	const card = page.locator(".vault-card", { hasText: VAULT });
	s.check("仓库列表里标出「上次打开」", (await card.locator(".chip", { hasText: "上次打开" }).count()) === 1);
	await card.getByRole("button", { name: "解锁并打开" }).click();
	await page.locator('input[placeholder="仓库密码"]').waitFor({ timeout: 20000 });
	const unlockText = (await page.locator(".center-card").textContent()) ?? "";
	s.check("回来时的解锁页写明仓库名与锁定原因，并有「返回我的仓库」",
		unlockText.includes(`解锁「${VAULT}」`) && unlockText.includes("离开工作台时已锁定") && (await page.getByRole("link", { name: "返回我的仓库" }).count()) === 1, unlockText.slice(0, 120));
	await unlock(page, PW);

	// ---- 6. 低频操作的产品内表单（W04）：用户配额、仓库重命名 ----
	await page.evaluate(() => (location.hash = "#/settings/users"));
	const quotaBtn = page.getByRole("button", { name: "配额…" }).first();
	const adminGate = page.getByRole("heading", { name: "管理员验证" });
	await Promise.race([quotaBtn.waitFor({ timeout: 20000 }), adminGate.waitFor({ timeout: 20000 })]).catch(() => undefined);
	if (await adminGate.isVisible().catch(() => false)) {
		// 用户管理要短期 admin 会话：用同一个管理员 Token 换一次
		await page.locator(".settings-card input[type=password]").fill(E2E.token);
		await page.locator(".settings-card").getByRole("button", { name: "解锁" }).click();
	}
	await quotaBtn.click({ timeout: 20000 });
	const qd = page.getByRole("dialog");
	await qd.getByLabel("存储上限（含历史版本）").fill("两个G");
	await qd.getByRole("button", { name: "保存" }).click();
	const quotaErr = (await qd.locator(".note-form-error").textContent()) ?? "";
	await qd.getByLabel("存储上限（含历史版本）").fill("2GB");
	await qd.getByRole("button", { name: "保存" }).click();
	await qd.waitFor({ state: "detached", timeout: 10000 });
	const me = (await api("/api/v2/me")).body;
	s.check("用户配额用产品内表单：格式错误原位说明，正确的值保存到服务器", quotaErr.includes("格式不对") && me.usage?.bytesLimit === 2 * 1024 ** 3, `${quotaErr} limit=${me.usage?.bytesLimit}`);
	await api(`/api/v1/admin/users/${me.account.id}/quota`, { method: "PUT", body: JSON.stringify({ bytes: 0, vaults: 0 }) });

	await page.evaluate(() => (location.hash = "#/vaults"));
	await page.getByRole("heading", { name: "我的仓库" }).waitFor({ timeout: 20000 });
	await card.locator(".vault-more summary").click();
	await page.getByRole("button", { name: "重命名…" }).click();
	const rd = page.getByRole("dialog", { name: "重命名仓库" });
	await rd.getByLabel("仓库名称").fill("");
	await rd.getByRole("button", { name: "重命名", exact: true }).click();
	const emptyErr = (await rd.locator(".note-form-error").textContent()) ?? "";
	await rd.getByLabel("仓库名称").fill(VAULT2);
	await rd.getByRole("button", { name: "重命名", exact: true }).click();
	await rd.waitFor({ state: "detached", timeout: 10000 });
	const names = (await api("/api/v1/vaults")).body.vaults.map((v: any) => v.name);
	s.check("仓库重命名用产品内表单：空名字原位报错，提交后服务器上是新名字", emptyErr.includes("请填写") && names.includes(VAULT2), JSON.stringify(names));
	const card2 = page.locator(".vault-card", { hasText: VAULT2 });
	await card2.waitFor({ timeout: 10000 });

	// ---- 7. 连接设备（W10）：同设备深链、复制失败、关闭即作废、过期后重新生成 ----
	await card2.getByRole("button", { name: "连接 Obsidian" }).click();
	await page.locator(".dialog .link-input").waitFor({ timeout: 20000 });
	const link1 = await page.locator(".dialog .link-input").inputValue();
	const deep = (await page.getByRole("dialog").getByRole("link", { name: "在 Obsidian 中打开" }).getAttribute("href")) ?? "";
	const m1 = /\/p\/([0-9a-f]+)#secret=([^&]+)$/.exec(link1);
	const du = deep ? new URL(deep) : null;
	s.check("「在 Obsidian 中打开」与扫码落地页交给 Obsidian 的深链相同（同一条链接、同一个密钥）",
		!!m1 && !!du && deep.startsWith("obsidian://litesync-import?") && du.searchParams.get("id") === m1[1] && du.searchParams.get("secret") === decodeURIComponent(m1[2]) && du.searchParams.get("server") === E2E.base);
	await page.evaluate(() => Object.defineProperty(navigator, "clipboard", { value: { writeText: () => Promise.reject(new Error("denied")) }, configurable: true }));
	await page.getByRole("dialog").getByRole("button", { name: "复制链接" }).click();
	await sleep(300);
	const copyNote = (await page.locator(".dialog .copy-note").textContent()) ?? "";
	const selected = await page.evaluate(() => {
		const i = document.querySelector(".dialog .link-input") as HTMLInputElement;
		return document.activeElement === i && i.selectionStart === 0 && i.selectionEnd === i.value.length;
	});
	s.check("复制失败：链接自动选中，并说明怎样手动复制", selected && copyNote.includes("Ctrl+C"), copyNote);
	await page.keyboard.press("Escape");
	s.check("关闭窗口：还没用过的链接立即作废（规则没有变）", !!m1 && (await until(async () => (await envelopeStatus(m1[1])) !== 200, 5000)));

	await page.route("**/api/v2/vaults/*/pairing-grants", async (route: any) => {
		const r = await route.fetch();
		const body = await r.json();
		body.expiresAt = Math.floor(Date.now() / 1000) + 2; // 只让界面以为它快过期了：服务器上仍是 5 分钟
		await route.fulfill({ response: r, json: body });
	});
	await card2.getByRole("button", { name: "连接 Obsidian" }).click();
	await page.locator(".dialog .link-input").waitFor({ timeout: 20000 });
	const link2 = await page.locator(".dialog .link-input").inputValue();
	const regen = page.getByRole("dialog").getByRole("button", { name: "重新生成" });
	await regen.waitFor({ timeout: 10000 });
	const expiredState = (await page.locator(".dialog .link-input").isDisabled()) && (await page.getByRole("dialog").getByRole("button", { name: "复制链接" }).count()) === 0;
	await page.unroute("**/api/v2/vaults/*/pairing-grants");
	await regen.click();
	await until(async () => (await page.locator(".dialog .link-input").inputValue().catch(() => link2)) !== link2 && !(await page.locator(".dialog .link-input").isDisabled()), 15000);
	const link3 = await page.locator(".dialog .link-input").inputValue();
	const id2 = /\/p\/([0-9a-f]+)#/.exec(link2)?.[1] ?? "";
	const id3 = /\/p\/([0-9a-f]+)#/.exec(link3)?.[1] ?? "";
	s.check("过期后：链接与复制收起，原位「重新生成」换成一条新的可用链接，旧的那条作废",
		expiredState && !!id3 && id3 !== id2 && (await envelopeStatus(id3)) === 200 && (await until(async () => (await envelopeStatus(id2)) !== 200, 5000)), `${id2} → ${id3}`);
	await page.keyboard.press("Escape");

	// ---- 8. 删除仓库要输入名字（W04） ----
	await card2.locator(".vault-more summary").click();
	await page.getByRole("button", { name: "删除仓库…" }).click();
	const dd = page.getByRole("dialog");
	await dd.locator("input").fill("不是这个名字");
	const wrongDisabled = await dd.getByRole("button", { name: "删除仓库" }).isDisabled();
	await dd.locator("input").fill(VAULT2);
	const rightEnabled = await dd.getByRole("button", { name: "删除仓库" }).isEnabled();
	await dd.getByRole("button", { name: "删除仓库" }).click();
	await dd.waitFor({ state: "detached", timeout: 15000 });
	const stillThere = (await api("/api/v1/vaults")).body.vaults.some((v: any) => v.name === VAULT2);
	s.check("删除仓库要输入名字：不一致时按钮不可用，一致后删除成功", wrongDisabled && rightEnabled && !stillThere);

	// ---- 9. 登录页的注册状态（U3 未完成项；用拦截模拟统一登录的配置，只看展示） ----
	const ctx2 = await s.context(browser, { viewport: { width: 390, height: 844 } });
	const p2 = await ctx2.newPage();
	const loginCard = async (mode: string, query = "") => {
		await p2.route("**/auth/config", (route: any) => route.fulfill({ json: { oidc: true, legacyTokenLogin: false, registrationMode: mode } }));
		await p2.goto(E2E.base + "/" + query);
		await p2.locator(".login-card").waitFor({ timeout: 15000 });
		const text = (await p2.locator(".login-card").textContent()) ?? "";
		const create = p2.getByRole("link", { name: /创建账号/ });
		const href = (await create.count()) ? await create.getAttribute("href") : null;
		await p2.unroute("**/auth/config");
		return { text, href };
	};
	const open = await loginCard("open");
	s.check("登录页：标题与说明与账号中心一致，开放注册时有「创建账号」",
		open.text.includes("登录你的账号") && open.text.includes("一个账号可用于 LiteSync 和 Nexus") && !!open.href && open.href.includes("intent=register") && (await p2.getByRole("link", { name: "登录", exact: true }).count()) === 1);
	const inviteNoCode = await loginCard("invite");
	s.check("登录页：只接受邀请时没有邀请码就不摆注册按钮，说明要用邀请链接", !inviteNoCode.href && inviteNoCode.text.includes("邀请链接"));
	const invited = await loginCard("invite", "?invite=demo-code");
	s.check("登录页：带邀请码时给「用邀请创建账号」，链接带上邀请码", !!invited.href && invited.href.includes("invite=demo-code") && invited.text.includes("你收到了邀请"));
	const closed = await loginCard("closed");
	s.check("登录页：注册关闭时如实说明，没有注册按钮", !closed.href && closed.text.includes("暂未开放注册"));

	s.check("页面没有抛出异常", pageErrors.length === 0, pageErrors.join(" | "));
});
