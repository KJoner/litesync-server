// 配额在网页上的表现（需求 §12）：编辑器保存遇到永久超限时如实说明且不丢内容；账号页显示用量与上限；
// 管理员放开后同一份修改能正常保存。本机隔离服务端，合成数据。
import { api, E2E, Suite } from "../lib/harness";
import { createNote, createVault, tokenLogin } from "../lib/ui";

const PASSWORD = "配额测试密码 · 2026-11-21";

/* eslint-disable @typescript-eslint/no-explicit-any */
await new Suite().run(async (s) => {
	const browser = await s.launch(); // close() 由套件骨架在收集完证据后执行
	try {
		const ctx = await s.context(browser, { viewport: { width: 1280, height: 860 } });
		const page = await ctx.newPage();
		s.attach(page);
		const errors: string[] = [];
		page.on("console", (m: any) => m.type() === "error" && !/status of (401|409|413)/.test(m.text()) && errors.push(m.text()));
		page.on("dialog", (d: any) => d.accept(d.type() === "prompt" ? "配额/长笔记.md" : undefined));
		await tokenLogin(page);
		await createVault(page, "配额测试", PASSWORD);
		await page.locator(".tree-new").waitFor({ timeout: 30000 });

		await createNote(page, "配额/长笔记.md");
		await page.locator(".cm-content").click();
		await page.keyboard.insertText("短内容");
		await page.keyboard.press("Control+s");
		await page.locator('.save-status[data-state="synced"]').waitFor({ timeout: 20000 });

		const me = (await api("/api/v2/me")).body;
		const adminId = me.account.id;
		const used = me.usage.bytesUsed;
		s.check("/api/v2/me 带用量（管理员默认不受存储默认值约束）", typeof used === "number" && used > 0 && me.usage.bytesLimit === 0, JSON.stringify(me.usage));
		const set = await api(`/api/v1/admin/users/${adminId}/quota`, { method: "PUT", body: JSON.stringify({ bytes: used + 200, vaults: 0 }) });
		s.check("管理员给自己设存储覆盖值", set.status === 200 && set.body.usage.bytesLimit === used + 200, JSON.stringify(set.body));

		await page.keyboard.press("Control+End");
		await page.keyboard.insertText("很长的一段。".repeat(400));
		await page.keyboard.press("Control+s");
		await page.locator(".edit-notice .banner", { hasText: "存储配额" }).waitFor({ timeout: 20000 });
		const notice = (await page.locator(".edit-notice .banner").textContent()) ?? "";
		await s.shot(page, "q01-quota-exceeded");
		s.check("超出配额：编辑器说明原因、给出上限，并说明修改已加密保存在本机", notice.includes("上限") && notice.includes("本机") && (await page.locator(".save-status").getAttribute("data-state")) === "error", notice);
		const editorHas = await page.evaluate(() => Array.from(document.querySelectorAll(".cm-line")).some((l) => (l.textContent ?? "").includes("很长的一段。")));
		s.check("被拒的修改仍在编辑器里（不丢草稿）", editorHas);

		// 放开配额后，同一份修改正常保存
		await api(`/api/v1/admin/users/${adminId}/quota`, { method: "PUT", body: JSON.stringify({ bytes: -1, vaults: 0 }) });
		await page.locator(".edit-bar button.primary", { hasText: "保存" }).click();
		await page.locator('.save-status[data-state="synced"]').waitFor({ timeout: 20000 });
		s.check("管理员放开配额后同一份修改保存成功", true);

		// 账号页显示用量与上限
		await api(`/api/v1/admin/users/${adminId}/quota`, { method: "PUT", body: JSON.stringify({ bytes: 10 * 1024 * 1024, vaults: 5 }) });
		await page.evaluate(() => (location.hash = "#/me"));
		await page.getByRole("heading", { name: "账号与设备" }).waitFor({ timeout: 20000 });
		const facts = (await page.locator("dl.facts").textContent()) ?? "";
		await s.shot(page, "q02-account-usage");
		s.check("账号页显示存储用量 / 上限（含历史版本）与仓库数 / 上限", facts.includes("存储") && facts.includes("10.0 MB") && facts.includes("含历史版本") && /仓库\s*\d+ \/ 5/.test(facts), facts);
		s.check("控制台无意外错误", errors.length === 0, errors.join(" | "));
		await ctx.close();
	} finally {
		await browser.close();
	}
});
