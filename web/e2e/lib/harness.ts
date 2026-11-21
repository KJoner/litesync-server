/**
 * 浏览器验收套件的公共骨架（W7）：检查项记录、失败截图 / trace、机器可读结果、Playwright 加载。
 *
 * 每个套件是一个独立进程（由 run.mjs 打包后启动），环境变量：
 *   E2E_BASE / E2E_ADMIN_TOKEN  本次的隔离服务端与它的管理员 Token（Token 不写进任何结果文件）
 *   E2E_OUT / E2E_RESULT        本套件的产物目录与结果 JSON 路径
 *   E2E_PLAYWRIGHT              装了 playwright-core（或 @playwright/test）的目录
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";

/* eslint-disable @typescript-eslint/no-explicit-any */
export type Page = any;
export type Browser = any;
export type BrowserContext = any;

export interface CheckResult {
	name: string;
	ok: boolean;
	detail?: string;
	screenshot?: string;
	at: number;
}

export const E2E = {
	base: process.env.E2E_BASE ?? "",
	token: process.env.E2E_ADMIN_TOKEN ?? "",
	out: process.env.E2E_OUT ?? join(process.cwd(), ".e2e-out"),
	result: process.env.E2E_RESULT ?? "",
	suite: process.env.E2E_SUITE ?? "suite",
	headed: process.env.E2E_HEADED === "1",
};
if (!E2E.base || !E2E.token) {
	console.error("缺少 E2E_BASE / E2E_ADMIN_TOKEN：请通过 web/e2e/run.mjs（npm run test:e2e）启动套件");
	process.exit(2);
}
mkdirSync(E2E.out, { recursive: true });

/** 按 E2E_PLAYWRIGHT 加载 Playwright（playwright-core 优先）。 */
export function playwright(): { chromium: any; version: string } {
	const dir = process.env.E2E_PLAYWRIGHT ?? process.cwd();
	const req = createRequire(join(dir, "package.json"));
	for (const id of ["playwright-core", "@playwright/test", "playwright"]) {
		try {
			const mod = req(id);
			return { chromium: mod.chromium, version: req(`${id}/package.json`).version };
		} catch {
			/* 下一个 */
		}
	}
	throw new Error(`在 ${dir} 找不到 playwright-core / @playwright/test`);
}

export class Suite {
	readonly checks: CheckResult[] = [];
	readonly artifacts: string[] = [];
	private pending: Promise<unknown>[] = [];
	private current: Page | null = null;
	private contexts: BrowserContext[] = [];
	private shotSeq = 0;
	aborted: { error: string; at: number } | null = null;
	readonly t0 = Date.now();

	/** 失败时截这一页（最近 attach 的那一页）。 */
	attach(page: Page): void {
		this.current = page;
	}

	/** 记录一项检查；失败时异步截图（finish 前等它完成）。 */
	check(name: string, ok: boolean, detail = ""): boolean {
		const rec: CheckResult = { name, ok: !!ok, at: Date.now() - this.t0 };
		if (detail) rec.detail = String(detail).slice(0, 2000);
		this.checks.push(rec);
		console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? " — " + String(detail).slice(0, 300) : ""}`);
		if (!ok && this.current) {
			const file = `fail-${String(++this.shotSeq).padStart(2, "0")}.png`;
			rec.screenshot = file;
			this.pending.push(this.current.screenshot({ path: join(E2E.out, file), fullPage: true }).then(() => this.artifacts.push(file)).catch(() => undefined));
		}
		return !!ok;
	}

	/** 主动截图（套件里有意义的状态留证）。 */
	async shot(page: Page, name: string): Promise<void> {
		const file = `${name}.png`;
		await page.screenshot({ path: join(E2E.out, file) }).catch(() => undefined);
		this.artifacts.push(file);
	}

	private browsers: Browser[] = [];
	/** 实际启动的浏览器（名称 + 版本），写进结果：证据要能说清楚是哪个浏览器跑出来的。 */
	private readonly browserIds = new Set<string>();

	/**
	 * 启动 Chromium。返回的对象上 close() 推迟到套件结束：套件体里的 finally 先关浏览器的话，
	 * 中止时就截不到图、存不了 trace——那正是最需要证据的时候。
	 */
	async launch(): Promise<Browser> {
		const { chromium } = playwright();
		const b = await chromium.launch({ headless: !E2E.headed });
		this.browsers.push(b);
		this.browserIds.add(`${b.browserType().name()} ${b.version()}`);
		return new Proxy(b, {
			get(target, prop) {
				if (prop === "close") return async () => undefined;
				const v = Reflect.get(target, prop);
				return typeof v === "function" ? v.bind(target) : v;
			},
		});
	}

	/** 新浏览器上下文：带 trace（只有失败时保存）。 */
	async context(browser: Browser, opts: Record<string, unknown> = {}): Promise<BrowserContext> {
		const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: "zh-CN", ...opts });
		await ctx.tracing.start({ screenshots: true, snapshots: true }).catch(() => undefined);
		this.contexts.push(ctx);
		// close() 同样推迟：有检查项失败时要先把 trace 存下来
		return new Proxy(ctx, {
			get(target, prop) {
				if (prop === "close") return async () => undefined;
				const v = Reflect.get(target, prop);
				return typeof v === "function" ? v.bind(target) : v;
			},
		});
	}

	private async saveTraces(): Promise<void> {
		const failed = this.aborted !== null || this.checks.some((c) => !c.ok);
		let i = 0;
		for (const ctx of this.contexts) {
			const file = `trace-${++i}.zip`;
			try {
				if (failed) {
					await ctx.tracing.stop({ path: join(E2E.out, file) });
					this.artifacts.push(file);
				} else {
					await ctx.tracing.stop();
				}
			} catch {
				/* 上下文已关闭 */
			}
		}
	}

	/** 套件主体：异常 = aborted（剩余检查没有执行，绝不当成通过）。 */
	async run(body: (s: Suite) => Promise<void>): Promise<never> {
		// 事件回调里的异步异常（例如同一个对话框被处理两次）不能让进程无声退出：记成一项失败
		const stray: string[] = [];
		const onStray = (e: unknown) => {
			stray.push(e instanceof Error ? e.message : String(e));
			console.log(`UNHANDLED ${stray[stray.length - 1]}`);
		};
		process.on("unhandledRejection", onStray);
		process.on("uncaughtException", onStray);
		try {
			await body(this);
			if (stray.length) this.check("套件内没有未处理的异步异常", false, stray.join(" | "));
		} catch (e) {
			this.aborted = { error: e instanceof Error ? `${e.message}\n${e.stack ?? ""}`.slice(0, 4000) : String(e), at: Date.now() - this.t0 };
			console.log(`ABORT ${this.aborted.error.split("\n")[0]}`);
			if (this.current) {
				const file = "aborted.png";
				await this.current.screenshot({ path: join(E2E.out, file), fullPage: true }).then(() => this.artifacts.push(file)).catch(() => undefined);
			}
		}
		await Promise.allSettled(this.pending);
		await this.saveTraces();
		for (const c of this.contexts) await c.close().catch(() => undefined);
		for (const b of this.browsers) await b.close().catch(() => undefined);
		const passed = this.checks.filter((c) => c.ok).length;
		const failed = this.checks.length - passed;
		const out = { suite: E2E.suite, passed, failed, aborted: this.aborted, checks: this.checks, artifacts: this.artifacts, browser: [...this.browserIds], durationMs: Date.now() - this.t0 };
		if (E2E.result) writeFileSync(E2E.result, JSON.stringify(out, null, 2));
		console.log(`\n${passed}/${passed + failed} passed${this.aborted ? "（中途中止）" : ""}`);
		if (failed) console.log("FAILED:", this.checks.filter((c) => !c.ok).map((c) => c.name).join(" / "));
		process.exit(failed || this.aborted ? 1 : 0);
	}
}

/** 带管理员 Token 的 API 调用（只用于造数据与核对服务器状态）。 */
export async function api(path: string, init: RequestInit & { vaultId?: string } = {}): Promise<{ status: number; body: any; headers: Headers }> {
	const headers: Record<string, string> = { Authorization: "Bearer " + E2E.token, ...((init.headers as Record<string, string>) ?? {}) };
	if (init.vaultId) headers["X-Vault-ID"] = init.vaultId;
	if (init.body && typeof init.body === "string" && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
	const r = await fetch(E2E.base + path, { ...init, headers });
	const text = await r.text();
	let body: any = null;
	try {
		body = JSON.parse(text);
	} catch {
		body = text;
	}
	return { status: r.status, body, headers: r.headers };
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** 等到条件成立（轮询）；超时返回 false 而不是抛错——由调用方记一项失败。 */
export async function until(fn: () => Promise<boolean> | boolean, ms = 15000, step = 100): Promise<boolean> {
	const end = Date.now() + ms;
	for (;;) {
		try {
			if (await fn()) return true;
		} catch {
			/* 再试 */
		}
		if (Date.now() > end) return false;
		await sleep(step);
	}
}
