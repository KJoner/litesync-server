// W4（RC-3）：回收站恢复在「写入新内容」这一步遇到断网 / 401 / 存储配额 / 刷新 / 响应丢失时：
//   - 界面如实说明「恢复没有完成、删除记录原样保留」并可以重试（不再说「打开修改保存一次即可补齐」）；
//   - 服务器上任何时刻都不存在「HEAD 声明新世代、密文仍是旧世代」的对象（其他端不被误导）；
//   - 重试后能完成恢复，恢复出来的笔记能正常打开（本页的防回退检查照常生效，没有被关掉）。
// 旧实现（两阶段：POST restore 先复活旧密文、再 PUT 重新加密）在这里会留下不一致的 HEAD——
// 本套件对两种协议用同一组断言，旧服务端上的失败就是 W4 的真实故障注入复现。
import { api, E2E, sleep, Suite, until } from "../lib/harness";
import { headConsistency, PluginDevice } from "../lib/plugin";
import { createVault, offline, openNote, tokenLogin, unlock } from "../lib/ui";

const PASSWORD = "W4 恢复测试密码 · 2026-11-21";
const enc = (s: string) => new TextEncoder().encode(s);

/* eslint-disable @typescript-eslint/no-explicit-any */
await new Suite().run(async (s) => {
	const browser = await s.launch(); // close() 由套件骨架在收集完证据后执行
	try {
		const ctx = await s.context(browser);
		const page = await ctx.newPage();
		s.attach(page);
		const alerts: string[] = [];
		page.on("dialog", (d: any) => {
			if (d.type() === "alert") alerts.push(d.message());
			d.accept().catch(() => undefined);
		});
		await tokenLogin(page);
		const vaultId = await createVault(page, `W4-${Date.now().toString(36)}`, PASSWORD);
		const dev = new PluginDevice(vaultId);
		await dev.unlock(PASSWORD);
		const atomic = ((await api("/api/v1/info", { vaultId })).body.capabilities ?? []).includes("restore-with-content");
		const N = { A: "W4/断网.md", B: "W4/登录过期.md", C: "W4/配额.md", D: "W4/刷新.md", E: "W4/响应丢失.md" };
		const body = (k: string) => `# ${k}\n\n删除前的正文（${k}）\n`;
		for (const p of Object.values(N)) {
			await dev.create(p, enc(body(p)));
			await dev.write(p, body(p) + "第二版\n"); // 删除前内容世代 = 2
			await dev.remove(p);
		}
		await page.reload();
		await unlock(page, PASSWORD);
		const trashRow = (p: string) => page.locator(".trash-row", { hasText: p.slice(3, -3) });
		const isContentWrite = (u: URL, method: string) => method === "PUT" && (u.pathname === "/api/v1/file" || /^\/api\/v1\/files\/[0-9a-f]{32}\/restore$/.test(u.pathname));
		const inTrash = async (p: string) => ((await api("/api/v1/trash", { vaultId })).body.items as any[]).some((x) => x.path === p);
		/** 失败后的统一断言：界面如实说明、服务器 HEAD 一致、删除记录还在。 */
		const afterFailure = async (label: string, p: string) => {
			await sleep(6500); // 两次自动重试（1.5 s + 3 s）都失败之后
			const pending = await trashRow(p).locator(".trash-pending").textContent({ timeout: 3000 }).catch(() => null);
			s.check(`${label}：界面如实说明恢复没有完成、删除记录原样保留`, !!pending && pending.includes("恢复没有完成") && pending.includes("原样保留"), pending ?? `alert=${alerts.slice(-1)[0] ?? ""}`);
			const h = await headConsistency(vaultId, p);
			s.check(`${label}：服务器上没有「旧密文 + 新世代」的不一致 HEAD`, h.consistent, JSON.stringify(h));
			s.check(`${label}：删除记录仍在回收站（可以重试）`, await inTrash(p));
		};
		/** 重试后的统一断言：恢复完成、能正常打开（防回退检查照常生效）、HEAD 一致、插件能解开。 */
		const afterRetry = async (label: string, p: string) => {
			const retry = trashRow(p).getByRole("button", { name: /重试恢复|恢复/ });
			if (await retry.count()) await retry.first().click();
			const opened = await page.waitForFunction((x: string) => location.hash === "#/n/" + encodeURIComponent(x), p, { timeout: 20000 }).then(() => true).catch(() => false);
			if (!opened) await openNote(page, p, "read").catch(() => undefined);
			const wrapText = async () => ((await page.locator(".note-wrap").first().textContent({ timeout: 2000 }).catch(() => "")) ?? "") + ((await page.locator(".cm-content").first().textContent({ timeout: 500 }).catch(() => "")) ?? "");
			const shown = await until(async () => (await wrapText()).includes("删除前的正文"), 15000);
			const err = (await wrapText()).match(/加载失败[^。]*/)?.[0] ?? "";
			s.check(`${label}：重试后恢复完成，笔记能正常打开（没有「内容回退」被挡）`, shown && !err, err);
			const h = await headConsistency(vaultId, p);
			dev.forget(p);
			const r = await dev.read(p).catch((e) => ({ text: String(e), generation: -1, revision: -1 }));
			s.check(`${label}：HEAD 一致，插件解密得到删除前的内容`, h.live && h.consistent && r.text === body(p) + "第二版\n", `${JSON.stringify(h)} ${JSON.stringify(r.text)}`);
		};
		const goTrash = async () => {
			await page.evaluate(() => (location.hash = "#/trash"));
			await page.locator(".trash-row").first().waitFor({ timeout: 15000 });
		};

		// ---- A. 写入新内容这一步断网 ----
		await goTrash();
		let stop = await offline(page, (u) => u.pathname.startsWith("/api/v1/file"), "PUT");
		await trashRow(N.A).getByRole("button", { name: /恢复/ }).click();
		await afterFailure("A 断网", N.A);
		await stop();
		await goTrash();
		await afterRetry("A 断网", N.A);

		// ---- B. 写入新内容这一步 401（会话过期） ----
		await goTrash();
		const fake401 = async (route: any) => {
			const u = new URL(route.request().url());
			if (!isContentWrite(u, route.request().method())) return route.fallback();
			await route.fulfill({ status: 401, contentType: "application/json", body: JSON.stringify({ code: "UNAUTHORIZED", message: "unauthorized", retryable: false }) });
		};
		await page.route("**/api/v1/**", fake401);
		await trashRow(N.B).getByRole("button", { name: /恢复/ }).click();
		await afterFailure("B 401", N.B);
		await page.unroute("**/api/v1/**", fake401);
		await goTrash();
		await afterRetry("B 401", N.B);

		// ---- C. 存储配额已满（真实的服务端 413 QUOTA_EXCEEDED） ----
		await goTrash();
		const me = (await api("/api/v2/me")).body;
		await api(`/api/v1/admin/users/${me.account.id}/quota`, { method: "PUT", body: JSON.stringify({ bytes: me.usage.bytesUsed + 16, vaults: 0 }) });
		await trashRow(N.C).getByRole("button", { name: /恢复/ }).click();
		await afterFailure("C 配额", N.C);
		await api(`/api/v1/admin/users/${me.account.id}/quota`, { method: "PUT", body: JSON.stringify({ bytes: -1, vaults: 0 }) });
		await goTrash();
		await afterRetry("C 配额", N.C);

		// ---- D. 写入新内容这一步断网时刷新页面 ----
		await goTrash();
		stop = await offline(page, (u) => u.pathname.startsWith("/api/v1/file"), "PUT");
		await trashRow(N.D).getByRole("button", { name: /恢复/ }).click();
		await sleep(400);
		await page.reload();
		await stop();
		await unlock(page, PASSWORD);
		const hD = await headConsistency(vaultId, N.D);
		s.check("D 刷新：刷新之后服务器上没有不一致的 HEAD", hD.consistent, JSON.stringify(hD));
		await goTrash();
		const stillD = await inTrash(N.D);
		s.check("D 刷新：删除记录仍在回收站，刷新后可以重新恢复", stillD);
		if (stillD) await afterRetry("D 刷新", N.D);
		else s.check("D 刷新：重试后恢复完成，笔记能正常打开（没有「内容回退」被挡）", false, "删除记录已不在回收站（旧协议：第一步已复活了旧密文）");

		// ---- E. 服务器已提交、响应在路上丢了：自动重试同一个 operationId → 首次结果，不多出版本 ----
		await goTrash();
		const tombE = ((await api("/api/v1/trash", { vaultId })).body.items as any[]).find((x) => x.path === N.E);
		let dropped = 0;
		const dropOnce = async (route: any) => {
			const u = new URL(route.request().url());
			if (!/\/restore$/.test(u.pathname) || route.request().method() !== "PUT" || dropped > 0) return route.fallback();
			dropped++;
			await route.fetch().catch(() => undefined); // 请求真的到了服务器并提交
			await route.abort("connectionreset"); // 但客户端只看到连接被重置
		};
		await page.route("**/api/v1/files/**", dropOnce);
		await trashRow(N.E).getByRole("button", { name: /恢复/ }).click();
		const doneE = await page.waitForFunction((x: string) => location.hash === "#/n/" + encodeURIComponent(x), N.E, { timeout: 20000 }).then(() => true).catch(() => false);
		await page.unroute("**/api/v1/files/**", dropOnce);
		dev.forget(N.E);
		const rE = await dev.read(N.E).catch(() => ({ revision: -1, generation: -1, text: "" }));
		const histE = await dev.history(N.E).catch(() => [] as any[]);
		s.check("E 响应丢失：自动重试同一个 operationId，恢复完成且只多出一个版本（revision = 删除时 + 1）",
			atomic && dropped === 1 && doneE && rE.revision === tombE.deletionRevision + 1 && histE.filter((v: any) => v.action === "restore").length === 1,
			`协议=${atomic ? "原子" : "两阶段（不支持带新内容的恢复）"} dropped=${dropped} rev=${rE.revision} tomb=${tombE.deletionRevision}`);
		s.check("E 响应丢失：恢复后的 HEAD 一致", (await headConsistency(vaultId, N.E)).consistent);

		s.check("恢复流程没有用 alert 报告状态（状态写在回收站里，可以重试）", alerts.length === 0, alerts.join(" | "));
		await ctx.close();
	} finally {
		await browser.close();
	}
});
