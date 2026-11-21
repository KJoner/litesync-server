// 网页编辑默认关闭（OBSYNC_WEB_EDITING 未设置）时：界面只读、服务端拒绝会话写入。
// 入库版改为自包含：在只读实例上自己建库，笔记由插件设备写入（原脚本复用 edit-e2e 的数据目录与浏览器存储）。
import { E2E, Suite } from "../lib/harness";
import { PluginDevice } from "../lib/plugin";
import { createVault, tokenLogin, unlock } from "../lib/ui";

const PASSWORD = "只读联调密码 · 2026-11-21";
const NOTE = "联调/改名后.md";

/* eslint-disable @typescript-eslint/no-explicit-any */
await new Suite().run(async (s) => {
	const browser = await s.launch(); // close() 由套件骨架在收集完证据后执行
	try {
		const ctx = await s.context(browser);
		const page = await ctx.newPage();
		s.attach(page);
		const errors: string[] = [];
		page.on("console", (m: any) => m.type() === "error" && !/status of 401|status of 403/.test(m.text()) && errors.push(m.text()));
		await tokenLogin(page);
		const vaultId = await createVault(page, "只读联调-" + Date.now().toString(36), PASSWORD);
		const dev = new PluginDevice(vaultId);
		await dev.unlock(PASSWORD);
		await dev.create(NOTE, new TextEncoder().encode("# 只读标题\n\n插件写入的正文\n"));
		await page.reload();
		await unlock(page, PASSWORD);
		const me = await page.evaluate(async () => (await fetch("/api/v2/me")).json());
		s.check("/api/v2/me 报告 webEditing=false（默认关闭）", me.features?.webEditing === false, JSON.stringify(me.features));
		s.check("文件树里没有「新建笔记」", (await page.locator(".tree-new").count()) === 0);
		await page.evaluate((p: string) => (location.hash = "#/n/" + encodeURIComponent(p)), NOTE);
		await page.locator(".markdown-body h1, .markdown-body p").first().waitFor({ timeout: 15000 });
		s.check("笔记以只读方式渲染（没有编辑工具栏）", (await page.locator(".edit-bar").count()) === 0);
		await s.shot(page, "e09-readonly-default");
		const vid = await page.evaluate(() => {
			const k = Object.keys(localStorage).find((x) => x.startsWith("litesync-vault:"));
			return k ? localStorage.getItem(k) : null;
		});
		s.check("能拿到当前仓库（按账号分区的选择）", vid === vaultId, String(vid));
		const put = await page.evaluate(async (v: string | null) => {
			const r = await fetch("/api/v1/file", {
				method: "PUT",
				headers: { "X-File-Path": encodeURIComponent("联调/越权写入.md"), "X-Base-Revision": "0", "X-Content-Hash": "00", "Content-Type": "application/octet-stream", ...(v ? { "X-Vault-ID": v } : {}) },
				body: new Uint8Array([1, 2, 3]),
			});
			return { status: r.status, body: await r.text() };
		}, vid);
		s.check("网页会话直接 PUT 被服务端拒绝（403）", put.status === 403, `${put.status} ${put.body.slice(0, 80)}`);
		s.check("浏览器控制台无其他错误", errors.length === 0, errors.join(" | "));
		await ctx.close();
	} finally {
		await browser.close();
	}
});
