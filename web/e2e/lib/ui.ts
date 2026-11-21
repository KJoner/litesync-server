/** 网页端的常用操作（登录、建库、解锁、打开笔记、输入、等状态、拦截请求）。 */
import { api, E2E, Page } from "./harness";

/* eslint-disable @typescript-eslint/no-explicit-any */

/** 用 API Token 登录网页（会话 Cookie 由服务器下发，JS 看不到）。 */
export async function tokenLogin(page: Page, token = E2E.token): Promise<void> {
	await page.goto(E2E.base + "/");
	await page.locator("input[type=password]").fill(token);
	await page.getByRole("button", { name: "使用 Token 登录" }).click();
}

/** 在网页新建仓库并完成浏览器端加密初始化，进入工作台；返回仓库 ID。 */
export async function createVault(page: Page, name: string, password: string): Promise<string> {
	await page.getByRole("heading", { name: "我的仓库" }).waitFor({ timeout: 20000 });
	await page.getByRole("button", { name: "新建仓库" }).click();
	await page.getByLabel("仓库名称").fill(name);
	await page.getByRole("button", { name: "下一步" }).click();
	const pw = page.locator(".dialog input[type=password]");
	await pw.nth(0).fill(password);
	await pw.nth(1).fill(password);
	await page.locator(".dialog input[type=checkbox]").check();
	await page.getByRole("button", { name: "创建并加密" }).click();
	await page.getByText("已创建并完成加密设置").waitFor({ timeout: 60000 });
	await page.getByRole("dialog").getByRole("button", { name: "在网页打开" }).click();
	await page.locator(".tree").waitFor({ timeout: 30000 });
	const list = await api("/api/v1/vaults");
	return list.body.vaults.find((v: any) => v.name === name).id;
}

/** 仓库中心里点「解锁并打开」（按仓库名精确匹配，避免前缀相同的仓库被误选）。 */
export async function openVaultCard(page: Page, name: string): Promise<void> {
	await page.getByRole("heading", { name: "我的仓库" }).waitFor({ timeout: 20000 });
	const esc = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
	const card = page.locator(".vault-card").filter({ has: page.locator("h3.vault-name", { hasText: new RegExp(`^${esc}$`) }) });
	await card.getByRole("button", { name: /打开/ }).first().click();
}

/** 登录后进入指定仓库：可能直接落在解锁页（记住了上次的仓库），也可能落在仓库中心。 */
export async function enterVault(page: Page, name: string, password: string): Promise<void> {
	const pw = page.locator('input[placeholder="仓库密码"]');
	const center = page.getByRole("heading", { name: "我的仓库" });
	await Promise.race([pw.waitFor({ timeout: 20000 }), center.waitFor({ timeout: 20000 })]).catch(() => undefined);
	if (await center.isVisible().catch(() => false)) await openVaultCard(page, name);
	await unlock(page, password);
}

export async function unlock(page: Page, password: string): Promise<void> {
	await page.locator('input[placeholder="仓库密码"]').waitFor({ timeout: 20000 });
	await page.locator('input[placeholder="仓库密码"]').fill(password);
	await page.getByRole("button", { name: "解锁", exact: true }).click();
	await page.locator(".tree").waitFor({ timeout: 60000 });
}

export async function openNote(page: Page, path: string, mode: "read" | "edit" | "split" = "edit"): Promise<void> {
	await page.evaluate((p: string) => (location.hash = "#/n/" + encodeURIComponent(p)), path);
	await page.locator(".edit-bar").waitFor({ timeout: 15000 });
	if (mode !== "read") {
		await page.locator(`.seg button[data-mode="${mode}"]`).click();
		await page.locator(".cm-content").waitFor({ timeout: 15000 });
	}
}

/** 编辑器里看到的文本（按行拼接；不含 CR）。 */
export const editorText = (page: Page): Promise<string> =>
	page.evaluate(() => Array.from(document.querySelectorAll(".cm-content .cm-line")).map((l) => (l as HTMLElement).textContent).join("\n"));

export async function typeLines(page: Page, text: string): Promise<void> {
	const lines = text.split("\n");
	for (let i = 0; i < lines.length; i++) {
		if (lines[i]) await page.keyboard.insertText(lines[i]);
		if (i < lines.length - 1) await page.keyboard.press("Enter");
	}
}

export async function waitState(page: Page, state: string, timeout = 20000): Promise<void> {
	await page.locator(`.save-status[data-state="${state}"]`).waitFor({ timeout });
}

export const saveState = (page: Page): Promise<string | null> => page.locator(".save-status").getAttribute("data-state");

/** 光标移到第 n 行（从 1 起）行尾。 */
export async function gotoLineEnd(page: Page, n: number): Promise<void> {
	await page.locator(".cm-content").click();
	await page.keyboard.press("Control+Home");
	for (let i = 1; i < n; i++) await page.keyboard.press("ArrowDown");
	await page.keyboard.press("End");
}

/**
 * 扣住第一个匹配的请求，直到调用 release()（注入延迟 / 逆序）。之后的同类请求照常放行。
 * method 为空则不区分方法。
 */
export async function hold(page: Page, pattern: string | ((u: URL) => boolean), method: string | null): Promise<{ hit: Promise<void>; release: () => void; done: Promise<number>; dispose: () => Promise<void> }> {
	let n = 0;
	let release!: () => void;
	const gate = new Promise<void>((r) => (release = r));
	let onHit!: () => void;
	const hit = new Promise<void>((r) => (onHit = r));
	let onDone!: (s: number) => void;
	const done = new Promise<number>((r) => (onDone = r));
	const handler = async (route: any) => {
		if (method && route.request().method() !== method) return route.fallback();
		if (++n !== 1) return route.fallback();
		onHit();
		await gate;
		try {
			const resp = await route.fetch();
			onDone(resp.status());
			await route.fulfill({ response: resp });
		} catch {
			onDone(0);
			await route.abort("failed").catch(() => undefined);
		}
	};
	await page.route(pattern, handler);
	return { hit, release, done, dispose: () => page.unroute(pattern, handler) };
}

/** 让匹配的请求一律断网（直到 dispose）。 */
export async function offline(page: Page, pattern: string | ((u: URL) => boolean), method: string | null): Promise<() => Promise<void>> {
	const handler = (route: any) => (method && route.request().method() !== method ? route.fallback() : route.abort("internetdisconnected"));
	await page.route(pattern, handler);
	return () => page.unroute(pattern, handler);
}

/** 本页 IndexedDB 草稿库的原始记录（只看密文记录与键，绝不解密）。 */
export const draftRecords = (page: Page): Promise<{ keys: string[]; json: string; count: number }> =>
	page.evaluate(async () => {
		const db: IDBDatabase = await new Promise((res, rej) => {
			const q = indexedDB.open("litesync-web-drafts", 1);
			q.onsuccess = () => res(q.result);
			q.onerror = () => rej(q.error);
			q.onupgradeneeded = () => q.result.createObjectStore("drafts");
		});
		const get = <T,>(fn: (s: IDBObjectStore) => IDBRequest<T>) =>
			new Promise<T>((res, rej) => {
				const q = fn(db.transaction("drafts").objectStore("drafts"));
				q.onsuccess = () => res(q.result);
				q.onerror = () => rej(q.error);
			});
		const all = await get((s) => s.getAll());
		const keys = (await get((s) => s.getAllKeys())) as string[];
		db.close();
		return { keys: keys.map(String), json: JSON.stringify(all), count: all.length };
	});

/** 浏览器控制台里的意外错误（白名单之外）。 */
export function collectErrors(page: Page, benign: RegExp): string[] {
	const errs: string[] = [];
	page.on("console", (m: any) => m.type() === "error" && !benign.test(m.text()) && errs.push(m.text()));
	page.on("pageerror", (e: any) => errs.push(String(e)));
	return errs;
}
