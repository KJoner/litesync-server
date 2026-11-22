// 验收 TN-05（LiteSync 网页部分）：同一浏览器两个标签页；一个标签页退出 / 换成另一个账号时，
// 另一个标签页立刻清掉已解锁的明文；仓库选择等本地记忆按账号分区。本机隔离服务端，合成数据。
import { api, E2E, Suite } from "../lib/harness";
import { createNote, createVault, tokenLogin, unlock } from "../lib/ui";

const PASSWORD = "TN05 仓库密码 · 2026-11-21";
const SECRET_TEXT = "甲的秘密内容-" + Date.now().toString(36);

/* eslint-disable @typescript-eslint/no-explicit-any */
await new Suite().run(async (s) => {
	const browser = await s.launch(); // close() 由套件骨架在收集完证据后执行
	try {
		const ctx = await s.context(browser, { viewport: { width: 1280, height: 860 } });
		const tab1 = await ctx.newPage();
		s.attach(tab1);
		tab1.on("dialog", (d: any) => d.accept(d.type() === "prompt" ? "TN05/甲的笔记.md" : undefined));
		await tokenLogin(tab1);
		await createVault(tab1, "TN05-" + Date.now().toString(36), PASSWORD);
		await createNote(tab1, "TN05/甲的笔记.md");
		await tab1.locator(".cm-content").click();
		await tab1.keyboard.insertText(SECRET_TEXT);
		await tab1.keyboard.press("Control+s");
		await tab1.locator('.save-status[data-state="synced"]').waitFor({ timeout: 20000 });
		const adminId = (await api("/api/v2/me")).body.account.id;

		// 第二个标签页：同一账号、解锁并打开这篇笔记
		const tab2 = await ctx.newPage();
		s.attach(tab2);
		await tab2.goto(E2E.base + "/");
		await unlock(tab2, PASSWORD);
		await tab2.evaluate(() => (location.hash = "#/n/" + encodeURIComponent("TN05/甲的笔记.md")));
		await tab2.getByText(SECRET_TEXT).first().waitFor({ timeout: 15000 });
		s.check("第二个标签页同一账号解锁后看得到内容", true);
		const keys = await tab2.evaluate(() => Object.keys(localStorage));
		s.check("仓库选择按账号分区（litesync-vault:<账号>），不再有不分账号的旧键", keys.includes(`litesync-vault:${adminId}`) && !keys.includes("litesync-vault"), keys.join(","));

		// 标签页 1 退出 → 标签页 2 立刻清掉明文
		await tab1.locator('button[title="退出登录"]').click();
		await tab1.getByRole("button", { name: "使用 Token 登录" }).waitFor({ timeout: 20000 });
		await tab2.getByRole("button", { name: "使用 Token 登录" }).waitFor({ timeout: 20000 });
		const tab2Text = await tab2.evaluate(() => document.body.innerText);
		await s.shot(tab2, "tn05-tab2-after-logout");
		s.check("另一个标签页退出后，本标签页的明文与编辑器立即清空并回到登录页", !tab2Text.includes(SECRET_TEXT) && (await tab2.locator(".cm-content").count()) === 0);

		// 换成另一个账号 B 登录：看不到 A 的任何内容
		const inv = await api("/api/v1/admin/invites", { method: "POST", body: "{}" });
		const reg = await fetch(`${E2E.base}/join/${inv.body.secret}/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: "tn05-b" }) });
		const bToken = (await reg.json()).token;
		s.attach(tab1);
		await tokenLogin(tab1, bToken);
		await tab1.waitForLoadState("networkidle");
		await tab1.waitForTimeout(800);
		const bText = await tab1.evaluate(() => document.body.innerText);
		await s.shot(tab1, "tn05-tab1-as-b");
		s.check("换成账号 B：页面上没有 A 的笔记标题或正文", !bText.includes(SECRET_TEXT) && !bText.includes("甲的笔记"));
		const acct = await tab1.evaluate(() => localStorage.getItem("litesync-account"));
		s.check("跨标签页广播的账号已更新为 B（A 的标签页据此清理）", !!acct && acct !== adminId, String(acct));
		await ctx.close();
	} finally {
		await browser.close();
	}
});
