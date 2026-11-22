// 联合验收 runner 的共享部分（run.mjs 用 esbuild 把它与各个 runner 打包在一起）：
//   - 读 env.mjs 写出的 <work>/joint-env.json 与它指向的密钥文件，不写死任何路径与端口；
//   - 记检查项、写结果 JSON（runner、时间、三仓 SHA、版本、每项 id/name/ok/detail）；
//   - 脱敏：密钥文件里的全部值、运行中拿到的一次性令牌（设备凭据、连接链接、验证链接、statusToken…）
//     在写进结果、证据文件与控制台之前一律替换为 <已脱敏>；
//   - 浏览器里身份中心与两个产品的常用操作。
import { createRequire } from "node:module";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { fetchPairingEnvelope, redeemDeviceEnrollment, enrollDevice, PLUGIN_VERSION } from "litesync-plugin/src/api/client";
import { openPairingLink, redeemPairing } from "litesync-plugin/src/pairing/pairing-v2";
import { consumePairing, parsePairUrl } from "litesync-plugin/src/pairing/pairing";

const [envFile, outDir] = process.argv.slice(2);
if (!envFile || !outDir) {
	console.error("用法：node e2e/joint/run.mjs <用例> --env <joint-env.json> --plugin <插件目录> --out <输出目录>");
	process.exit(2);
}
export const env = JSON.parse(readFileSync(envFile, "utf8"));
export const secrets: Record<string, string> = JSON.parse(readFileSync(env.secretsFile, "utf8"));
export const OUT = outDir;
mkdirSync(OUT, { recursive: true });
const pwRequire = createRequire(env.playwrightFrom ?? import.meta.url);
export const { chromium } = pwRequire("@playwright/test");
const playwrightVersion = (() => {
	try {
		return pwRequire("@playwright/test/package.json").version as string;
	} catch {
		return null;
	}
})();
export { PLUGIN_VERSION };

export const KC = env.urls.accounts;
export const LS = env.urls.litesync; // 浏览器与 Keycloak 看到的地址
export const LSL = env.urls.litesyncLocal;
export const NX = env.urls.nexus; // host.docker.internal：浏览器经 --host-resolver-rules 映射到本机
export const NXL = env.urls.nexusLocal;
export const MAIL = env.urls.mailpit;
export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ── 脱敏 ──
const sensitive = new Set<string>();
/** 登记一个运行中拿到的敏感值（≥ 8 个字符）；之后写出的任何文本里出现它都会被替换。原样返回。 */
export function sensitiveValue<T extends string | null | undefined>(v: T): T {
	if (typeof v === "string" && v.length >= 8) sensitive.add(v);
	return v;
}
for (const v of Object.values(secrets)) sensitiveValue(v);
const JWT = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
export function scrub(text: string): string {
	let t = text.replace(JWT, "<已脱敏>");
	for (const s of sensitive) t = t.split(s).join("<已脱敏>");
	return t;
}
const SECRET_KEY = /(token|secret|password|credential|cookie)$/i;
/** 深拷贝并脱敏：键名像令牌 / 密钥的字符串值整体替换，其余字符串按登记的敏感值替换。 */
export function redact(v: any): any {
	if (Array.isArray(v)) return v.map(redact);
	if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, SECRET_KEY.test(k) && typeof x === "string" ? "<已脱敏>" : redact(x)]));
	return typeof v === "string" ? scrub(v) : v;
}
/** 把一份证据（例如 C 的响应）写进输出目录，写之前脱敏。 */
export function writeEvidence(name: string, data: unknown) {
	writeFileSync(`${OUT}/${name}`, JSON.stringify(redact(data), null, 2));
}

// ── 检查项与结果 ──
export type Check = { id: string; name: string; ok: boolean; detail: string };
/**
 * 一个 runner 的结果。plan（可选）列出全部预期检查项：中途出错时，没跑到的项记为失败「未执行」，
 * 结果里的 total 始终等于计划的项数，不会因为提前退出而显得「全部通过」。
 */
export function runner(name: string, file: string, plan?: Record<string, string>) {
	const checks: Check[] = [];
	const startedAt = new Date().toISOString();
	const check = (id: string, title: string, ok: boolean, detail = "") => {
		const d = scrub(detail);
		checks.push({ id, name: title, ok, detail: d });
		console.log(`${ok ? "PASS" : "FAIL"} [${id}] ${title}${d ? " — " + d : ""}`);
	};
	const finish = (extra: { chromium?: string | null; error?: unknown } = {}) => {
		const error = extra.error === undefined ? null : scrub(String((extra.error as any)?.stack ?? extra.error)).slice(0, 2000);
		if (plan) {
			for (const [id, title] of Object.entries(plan)) {
				if (!checks.some((c) => c.id === id)) checks.push({ id, name: title, ok: false, detail: "未执行（前面的步骤出错，见 error）" });
			}
		}
		let meta: any = {};
		try {
			meta = JSON.parse(process.env.JOINT_RUN_META ?? "{}");
		} catch {}
		const failed = checks.filter((c) => !c.ok).length;
		const report = {
			runner: name,
			startedAt,
			finishedAt: new Date().toISOString(),
			env: {
				versions: { ...env.versions, chromium: extra.chromium ?? null, playwright: playwrightVersion, plugin: PLUGIN_VERSION },
				shas: { ...(env.shas ?? {}), plugin: meta.plugin?.sha ?? null },
				dirty: { ...(env.dirty ?? {}), plugin: meta.plugin?.dirty ?? null },
			},
			total: checks.length,
			passed: checks.length - failed,
			failed,
			error,
			checks,
		};
		writeFileSync(`${OUT}/${file}`, JSON.stringify(redact(report), null, 2));
		if (error) console.log(`\n运行中出错：${error.split("\n")[0]}`);
		console.log(`\n${report.passed}/${report.total} 通过，结果：${OUT}/${file}`);
		return failed;
	};
	return { checks, check, finish };
}

// ── 身份中心管理（一次性实例的临时管理员，只在本机） ──
export async function kcAdmin(): Promise<string> {
	const r = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, { method: "POST", body: new URLSearchParams({ grant_type: "password", client_id: "admin-cli", username: env.keycloakAdminUser, password: secrets.kcAdmin }) });
	return ((await r.json()) as any).access_token;
}
export async function kc(method: string, path: string, body?: unknown) {
	const r = await fetch(`${KC}/admin/realms/accounts${path}`, { method, headers: { authorization: `Bearer ${await kcAdmin()}`, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
	const text = await r.text();
	return { status: r.status, body: text ? JSON.parse(text) : null, location: r.headers.get("location") };
}
/** 在身份中心建一个已验证邮箱的合成用户（密码随机，只在本进程内存与 <work> 下的文件里）。 */
export async function makeUser(tag: string) {
	const email = `${tag}-${randomBytes(3).toString("hex")}@example.test`;
	const password = sensitiveValue(`Pw-${randomBytes(9).toString("base64url")}`);
	const r = await kc("POST", "/users", { username: email, email, emailVerified: true, enabled: true, firstName: tag, lastName: "合成", credentials: [{ type: "password", value: password, temporary: false }] });
	if (r.status !== 201) throw new Error(`create user ${r.status}`);
	return { email, password, id: r.location!.split("/").pop()! };
}
export const kcSessions = async (userId: string) => ((await kc("GET", `/users/${userId}/sessions`)).body ?? []).length;

// ── 浏览器里的产品请求 ──
export const pageApi = (page: any, path: string, init: any = {}, nexus = false) => page.evaluate(async ([p, i, n]: [string, any, boolean]) => {
	const headers: Record<string, string> = { "content-type": "application/json", ...(i.headers ?? {}) };
	if (n) headers["X-Nexus-Client"] = "1";
	const r = await fetch(p, { ...i, headers });
	return { status: r.status, body: await r.json().catch(() => null) };
}, [path, init, nexus]);

export async function kcLogin(page: any, user: { email: string; password: string }) {
	await page.locator("#username").fill(user.email);
	await page.locator("#password").fill(user.password);
	await page.locator("[type=submit]").first().click();
}
export async function loginNexus(ctx: any, user: any) {
	const p = await ctx.newPage();
	await p.goto(`${NX}/account/connect`);
	if ((await pageApi(p, "/api/v2/me", {}, true)).status === 200) return p; // 已登录
	await p.getByRole("button", { name: "登录或创建账号" }).click();
	await p.waitForURL((u: URL) => u.href.startsWith(KC) || (u.href.startsWith(NX) && !u.pathname.startsWith("/auth/")), { timeout: 30000 });
	if (p.url().startsWith(KC)) await kcLogin(p, user);
	await p.waitForURL((u: URL) => u.href.startsWith(NX) && !u.pathname.startsWith("/auth/"), { timeout: 30000 });
	return p;
}
export async function loginLiteSync(ctx: any, user: any) {
	const p = await ctx.newPage();
	await p.goto(`${LS}/`);
	if ((await pageApi(p, "/api/v2/me")).status === 200) return p; // 已登录
	await p.getByRole("link", { name: "登录账号", exact: true }).click();
	await p.waitForURL((u: URL) => u.href.startsWith(KC) || (u.href.startsWith(LS) && !u.pathname.startsWith("/auth/")), { timeout: 30000 });
	if (p.url().startsWith(KC)) await kcLogin(p, user);
	await p.waitForURL((u: URL) => u.href.startsWith(LS) && !u.pathname.startsWith("/auth/"), { timeout: 30000 });
	return p;
}
export async function createVault(page: any, name: string, password: string, first: boolean) {
	// UI v2：没有仓库时空状态里是「创建第一个仓库」，有仓库时是页头的「新建仓库」
	await page.getByRole("button", { name: first ? "创建第一个仓库" : "新建仓库" }).click();
	await page.getByLabel("仓库名称").fill(name);
	await page.getByRole("button", { name: "下一步" }).click();
	const pw = page.locator(".dialog input[type=password]");
	await pw.nth(0).fill(password);
	await pw.nth(1).fill(password);
	await page.locator(".dialog input[type=checkbox]").check();
	await page.getByRole("button", { name: "创建并加密" }).click();
	await page.getByText("已创建并完成加密设置").waitFor({ timeout: 60000 });
	await page.getByRole("dialog").getByRole("button", { name: "稍后再说" }).click();
	await page.locator(".vault-card", { hasText: name }).waitFor({ timeout: 15000 });
}
/** 在新标签页打开「连接 Obsidian」并读出链接；对话框保持打开（关闭对话框会撤销这次授权）。 */
export async function issueLink(ctx: any, vaultName: string): Promise<{ link: string; page: any }> {
	const p = await ctx.newPage();
	await p.goto(`${LS}/`);
	await p.locator(".vault-card", { hasText: vaultName }).getByRole("button", { name: "连接 Obsidian" }).click();
	await p.locator(".dialog .link-input").waitFor({ timeout: 15000 });
	return { link: sensitiveValue(await p.locator(".dialog .link-input").inputValue()), page: p };
}

// ── 插件一端（插件仓原样的配对 v2 代码；obsidian 的 requestUrl 由插件的 interop shim 提供） ──
export const transport = {
	fetchEnvelope: (s: string, id: string) => fetchPairingEnvelope(s, id),
	redeem: (s: string, req: any) => redeemDeviceEnrollment(s, req),
	consumeLegacy: (s: string, id: string) => consumePairing(s, id),
	enrollLegacy: (s: string, secret: string, name: string) => enrollDevice(s, secret, name),
};
export function memorySecretStore() {
	const store = new Map<string, string>();
	return { getSecret: (k: string) => store.get(k) ?? null, setSecret: (k: string, v: string) => void store.set(k, v) } as any;
}
export async function pluginRedeem(link: string, name: string): Promise<{ kind: string; token?: string }> {
	const parsed = parsePairUrl(link)!;
	const opened: any = await openPairingLink(transport as any, parsed);
	if (opened.kind !== "ready") return { kind: `open:${opened.kind}` };
	const r: any = await redeemPairing(transport as any, memorySecretStore(), { link: parsed, config: opened.config, deviceName: name, platform: "windows", clientVersion: PLUGIN_VERSION, now: Date.now() });
	return { kind: r.kind, token: sensitiveValue(r.credential) };
}
export const lsDevice = async (token: string) => (await fetch(`${LSL}/api/v1/whoami`, { headers: { Authorization: `Bearer ${token}` } })).status;
export const nxDevice = async (token: string) => (await fetch(`${NXL}/api/sync/config`, { headers: { Authorization: `Bearer ${token}` } })).status;

/** Nexus 扩展配对：start →（网页会话批准）→ poll。claim=false 时停在「已批准未领取」。 */
export async function nexusPair(nxPage: any, name: string, claim = true) {
	const sr = await fetch(`${NXL}/api/pair/start`, { method: "POST", headers: { "content-type": "application/json", "X-Nexus-Client": "1" }, body: JSON.stringify({ name, scopes: ["config:read", "items:read", "items:write"] }) });
	const start = (await sr.json()) as any;
	// Nexus 对同一来源 10 分钟内最多 10 次配对（产品限流，不是缺陷）：连续重跑前用 env.mjs stop-nexus / start-nexus 清零
	if (sr.status !== 201) throw new Error(`pair/start ${sr.status}：${JSON.stringify(start)}（同一来源的配对限流：先 stop-nexus / start-nexus 再重跑）`);
	sensitiveValue(start.secret);
	const ok = await pageApi(nxPage, `/api/devices/pairing/${start.code}`, { method: "POST", body: JSON.stringify({ approve: true, scopes: ["config:read", "items:read", "items:write"] }) }, true);
	if (ok.status !== 200) throw new Error(`approve ${ok.status} ${JSON.stringify(ok.body)}`);
	if (!claim) return { pairId: start.pairId, secret: start.secret, token: undefined as string | undefined };
	const polled = (await (await fetch(`${NXL}/api/pair/poll`, { method: "POST", headers: { "content-type": "application/json", "X-Nexus-Client": "1" }, body: JSON.stringify({ pairId: start.pairId, secret: start.secret }) })).json()) as any;
	return { pairId: start.pairId, secret: start.secret, token: sensitiveValue(polled.token as string | undefined) };
}
export const nexusPoll = async (p: { pairId: string; secret: string }) => (await (await fetch(`${NXL}/api/pair/poll`, { method: "POST", headers: { "content-type": "application/json", "X-Nexus-Client": "1" }, body: JSON.stringify(p) })).json()) as any;

export async function waitFor(fn: () => Promise<boolean>, ms: number, step = 2000): Promise<number | null> {
	const start = Date.now();
	while (Date.now() - start < ms) {
		if (await fn()) return Date.now() - start;
		await sleep(step);
	}
	return null;
}
