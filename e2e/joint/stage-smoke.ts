// 隔离 HTTPS 预发布冒烟（RELEASE-GATES G1 的自动化部分）：真实域名、Cloudflare → Nginx → 容器。
// 账号是预先在预发布 Keycloak 建好的合成账号（自助注册关闭）；不需要也不使用任何管理凭据。
//   node stage-smoke.mjs <stage-env.json> <输出目录>
// stage-env.json：{ urls:{accounts,litesync,nexus}, users:{a:{email,password}, b:{email,password}}, playwrightFrom }
import { createRequire } from "node:module";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { fetchPairingEnvelope, redeemDeviceEnrollment, enrollDevice } from "litesync-plugin/src/api/client";
import { openPairingLink, redeemPairing } from "litesync-plugin/src/pairing/pairing-v2";
import { consumePairing, parsePairUrl } from "litesync-plugin/src/pairing/pairing";

const [envFile, OUT] = process.argv.slice(2);
const env = JSON.parse(readFileSync(envFile, "utf8"));
const require = createRequire(env.playwrightFrom);
const { chromium } = require("@playwright/test");
mkdirSync(OUT, { recursive: true });
const { accounts: KC, litesync: LS, nexus: NX } = env.urls;
const A = env.users.a, B = env.users.b;

type Check = { id: string; name: string; ok: boolean; detail: string };
const checks: Check[] = [];
const check = (id: string, name: string, ok: boolean, detail = "") => { checks.push({ id, name, ok, detail }); console.log(`${ok ? "PASS" : "FAIL"} [${id}] ${name}${detail ? " — " + detail : ""}`); };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn: () => Promise<boolean>, ms: number, step = 2000) { const s = Date.now(); while (Date.now() - s < ms) { if (await fn()) return Date.now() - s; await sleep(step); } return null; }
const pageApi = (page: any, path: string, init: any = {}, nexus = false) => page.evaluate(async ([p, i, n]: [string, any, boolean]) => {
	const headers: Record<string, string> = { "content-type": "application/json", ...(i.headers ?? {}) };
	if (n) headers["X-Nexus-Client"] = "1";
	const r = await fetch(p, { ...i, headers });
	return { status: r.status, body: await r.json().catch(() => null) };
}, [path, init, nexus]);
async function kcLogin(p: any, u: any) { await p.locator("#username").fill(u.email); await p.locator("#password").fill(u.password); await p.locator("[type=submit]").first().click(); }
async function loginNexus(ctx: any, u: any) {
	const p = await ctx.newPage();
	await p.goto(`${NX}/account/connect`);
	if ((await pageApi(p, "/api/v2/me", {}, true)).status === 200) return p;
	await p.getByRole("button", { name: "登录或创建账号" }).click();
	await p.waitForURL((x: URL) => x.href.startsWith(KC) || (x.href.startsWith(NX) && !x.pathname.startsWith("/auth/")), { timeout: 45000 });
	if (p.url().startsWith(KC)) await kcLogin(p, u);
	await p.waitForURL((x: URL) => x.href.startsWith(NX) && !x.pathname.startsWith("/auth/"), { timeout: 45000 });
	return p;
}
async function loginLiteSync(ctx: any, u: any) {
	const p = await ctx.newPage();
	await p.goto(`${LS}/`);
	if ((await pageApi(p, "/api/v2/me")).status === 200) return p;
	await p.getByRole("link", { name: "登录账号", exact: true }).click();
	await p.waitForURL((x: URL) => x.href.startsWith(KC) || (x.href.startsWith(LS) && !x.pathname.startsWith("/auth/")), { timeout: 45000 });
	if (p.url().startsWith(KC)) await kcLogin(p, u);
	await p.waitForURL((x: URL) => x.href.startsWith(LS) && !x.pathname.startsWith("/auth/"), { timeout: 45000 });
	return p;
}
async function createVault(page: any, name: string, password: string) {
	// UI v2：没有仓库时空状态里是「创建第一个仓库」，有仓库时是页头的「新建仓库」
	const first = (await page.getByRole("button", { name: "创建第一个仓库" }).count()) > 0;
	await page.getByRole("button", { name: first ? "创建第一个仓库" : "新建仓库" }).click();
	await page.getByLabel("仓库名称").fill(name);
	await page.getByRole("button", { name: "下一步" }).click();
	const pw = page.locator(".dialog input[type=password]");
	await pw.nth(0).fill(password);
	await pw.nth(1).fill(password);
	await page.locator(".dialog input[type=checkbox]").check();
	await page.getByRole("button", { name: "创建并加密" }).click();
	await page.getByText("已创建并完成加密设置").waitFor({ timeout: 90000 });
	await page.getByRole("dialog").getByRole("button", { name: "稍后再说" }).click();
}
const transport = { fetchEnvelope: (s: string, id: string) => fetchPairingEnvelope(s, id), redeem: (s: string, r: any) => redeemDeviceEnrollment(s, r), consumeLegacy: (s: string, id: string) => consumePairing(s, id), enrollLegacy: (s: string, x: string, n: string) => enrollDevice(s, x, n) };
async function pluginRedeem(link: string, name: string) {
	const parsed = parsePairUrl(link)!;
	const m = new Map<string, string>();
	const store = { getSecret: (k: string) => m.get(k) ?? null, setSecret: (k: string, v: string) => void m.set(k, v) } as any;
	const opened: any = await openPairingLink(transport as any, parsed);
	if (opened.kind !== "ready") return { kind: `open:${opened.kind}`, token: undefined as string | undefined };
	const r: any = await redeemPairing(transport as any, store, { link: parsed, config: opened.config, deviceName: name, platform: "windows", clientVersion: "0.20.1", now: Date.now() });
	return { kind: r.kind, token: r.credential as string | undefined };
}
const lsDevice = async (t: string) => (await fetch(`${LS}/api/v1/whoami`, { headers: { Authorization: `Bearer ${t}` } })).status;
const nxDevice = async (t: string) => (await fetch(`${NX}/api/sync/config`, { headers: { Authorization: `Bearer ${t}` } })).status;
async function nexusPair(page: any, name: string) {
	const sr = await fetch(`${NX}/api/pair/start`, { method: "POST", headers: { "content-type": "application/json", "X-Nexus-Client": "1" }, body: JSON.stringify({ name, scopes: ["config:read", "items:read", "items:write"] }) });
	const st = (await sr.json()) as any;
	if (sr.status !== 201) throw new Error(`pair/start ${sr.status} ${JSON.stringify(st)}`);
	const ok = await pageApi(page, `/api/devices/pairing/${st.code}`, { method: "POST", body: JSON.stringify({ approve: true, scopes: ["config:read", "items:read", "items:write"] }) }, true);
	if (ok.status !== 200) throw new Error(`approve ${ok.status}`);
	const pr = (await (await fetch(`${NX}/api/pair/poll`, { method: "POST", headers: { "content-type": "application/json", "X-Nexus-Client": "1" }, body: JSON.stringify({ pairId: st.pairId, secret: st.secret }) })).json()) as any;
	return pr.token as string;
}

const browser = await chromium.launch();
const started = new Date().toISOString();
try {
	// ── G1：HTTPS 与安全头（经 Cloudflare 的真实响应） ──
	const lsHead = await fetch(`${LS}/`);
	check("G1-1", "LiteSync：HTTPS、HSTS、CSP", lsHead.status === 200 && !!lsHead.headers.get("strict-transport-security") && /script-src 'self'/.test(lsHead.headers.get("content-security-policy") ?? ""), `${lsHead.status} hsts=${!!lsHead.headers.get("strict-transport-security")}`);
	const nxHead = await fetch(`${NX}/`);
	check("G1-2", "Nexus：HTTPS 可访问、带安全头", nxHead.status === 200 && !!(nxHead.headers.get("content-security-policy") || nxHead.headers.get("strict-transport-security")), `${nxHead.status}`);
	const disc = (await (await fetch(`${KC}/realms/accounts/.well-known/openid-configuration`)).json()) as any;
	check("G1-3", "账号中心发现文档的 issuer 是公网 https 地址", disc.issuer === `${KC}/realms/accounts`, disc.issuer);
	check("G1-4", "管理控制台与 master realm 不对公网开放", (await fetch(`${KC}/admin/master/console/`)).status === 404 && (await fetch(`${KC}/realms/master/.well-known/openid-configuration`)).status === 404);

	// ── 跨子域 SSO ──
	const ctxA = await browser.newContext({ locale: "zh-CN" });
	const ctxA2 = await browser.newContext({ locale: "zh-CN" });
	const ctxB = await browser.newContext({ locale: "zh-CN" });
	const nA = await loginNexus(ctxA, A);
	check("S-1", "Nexus 经账号中心登录（https，跨子域）", (await pageApi(nA, "/api/v2/me", {}, true)).status === 200);
	const lA = await loginLiteSync(ctxA, A);
	check("S-2", "进入 LiteSync 不需要再输入密码（同一浏览器 SSO）", (await pageApi(lA, "/api/v2/me")).status === 200);
	const cookies = await ctxA.cookies();
	const prodCookies = cookies.filter((c: any) => c.domain.includes("testobsync") || c.domain.includes("testhome"));
	check("S-3", "两个产品的会话 Cookie 都是 Secure + HttpOnly + host-only", prodCookies.length >= 2 && prodCookies.every((c: any) => c.secure && c.httpOnly && !c.domain.startsWith(".")), prodCookies.map((c: any) => `${c.domain}:${c.name}:${c.sameSite}`).join(" "));

	// ── Service Worker 接管后的登录（NEX-01 在真实 HTTPS 上） ──
	// 新版 SW 安装后会立即接管并刷新页面：等它稳定下来再读，不在那次刷新中途取值
	await nA.waitForTimeout(3000);
	await nA.reload();
	await nA.waitForLoadState("networkidle").catch(() => undefined);
	const controlled = await nA.evaluate(async () => { await navigator.serviceWorker.ready; const t0 = Date.now(); while (!navigator.serviceWorker.controller && Date.now() - t0 < 15000) await new Promise((r) => setTimeout(r, 300)); return !!navigator.serviceWorker.controller; }).catch(() => false);
	check("SW-1", "Nexus 页面已被 Service Worker 接管", controlled);
	const outA = await pageApi(nA, "/api/auth/logout", { method: "POST" }, true);
	await nA.goto(`${NX}/account/connect`);
	await nA.getByRole("button", { name: "登录或创建账号" }).click();
	await nA.waitForURL((x: URL) => x.href.startsWith(NX) && !x.pathname.startsWith("/auth/"), { timeout: 45000 }).catch(() => undefined);
	check("SW-2", "SW 接管后退出再登录：/auth/* 走网络、回到 Nexus 且已登录", outA.status < 400 && (await pageApi(nA, "/api/v2/me", {}, true)).status === 200, nA.url());

	// ── 网页建库 → 连接链接 → 插件经 HTTPS 兑换 ──
	const vaultName = `预发布-${randomBytes(2).toString("hex")}`;
	await createVault(lA, vaultName, "预发布仓库密码 " + randomBytes(3).toString("hex"));
	const lp = await ctxA.newPage();
	await lp.goto(`${LS}/`);
	await lp.locator(".vault-card", { hasText: vaultName }).getByRole("button", { name: "连接 Obsidian" }).click();
	await lp.locator(".dialog .link-input").waitFor({ timeout: 20000 });
	const link = await lp.locator(".dialog .link-input").inputValue();
	// 连接链接本身是一次性凭据：结果里只记它指向哪个站点，不记 id 与 secret
	const linkShape = (() => { try { return `${new URL(link).origin}/p/<已脱敏>#secret=<已脱敏>`; } catch { return "无法解析"; } })();
	check("P-1", "连接链接指向 https 预发布地址，不含长期令牌", link.startsWith("obsidian://") || link.startsWith(LS), linkShape);
	const dev = await pluginRedeem(link, "预发布冒烟的 Obsidian");
	check("P-2", "插件原样代码经 HTTPS 兑换出设备凭据", dev.kind === "ok" && (await lsDevice(dev.token!)) === 200, dev.kind);
	const nxTok = await nexusPair(nA, "预发布冒烟的扩展");
	check("P-3", "Nexus 扩展配对经 HTTPS 得到设备凭据", (await nxDevice(nxTok)) === 200);

	// ── A 在第二个浏览器也登录；B 独立 ──
	const nA2 = await loginNexus(ctxA2, A);
	const lB = await loginLiteSync(ctxB, B);
	const nB = await loginNexus(ctxB, B);
	const nxTokB = await nexusPair(nB, "B 的扩展");

	// ── C：从 LiteSync 退出所有产品与设备（真实域名、真实反代、对方经容器网络） ──
	const c = await pageApi(lA, "/api/v2/account/logout-all", { method: "POST" });
	const cSummary = { status: c.status, ok: c.body?.ok, local: c.body?.local?.state, idc: c.body?.identityCenter?.state, peers: c.body?.peers?.map((p: any) => p.state) };
	writeFileSync(`${OUT}/stage-c.json`, JSON.stringify(cSummary, null, 2));
	check("C-1", "C 的三部分都如实报告完成", c.status === 200 && c.body?.ok === true, JSON.stringify(cSummary));
	check("C-2", "A 的 LiteSync 设备立即失效", (await lsDevice(dev.token!)) === 401);
	const nxIn = await waitFor(async () => (await nxDevice(nxTok)) === 401, 75000);
	check("C-3", "A 的 Nexus 扩展在窗口内失效", nxIn !== null, nxIn === null ? "超时" : `${nxIn} ms`);
	const idcIn = await waitFor(async () => (await pageApi(nA2, "/api/v2/me", {}, true)).status === 401, 30000);
	check("C-4", "A 另一个浏览器里的 Nexus 会话结束", idcIn !== null, idcIn === null ? "超时" : `${idcIn} ms`);
	const p2 = await ctxA2.newPage();
	await p2.goto(`${NX}/account/connect`);
	await p2.getByRole("button", { name: "登录或创建账号" }).click();
	await p2.waitForURL((x: URL) => x.href.startsWith(KC) || x.href.startsWith(NX), { timeout: 45000 });
	await sleep(1500);
	check("C-5", "A 另一个浏览器再次登录必须重新输入密码（账号中心会话已结束）", p2.url().startsWith(KC) && (await p2.locator("#password").count()) > 0, p2.url().slice(0, 60));
	check("C-6", "B 不受影响", (await pageApi(lB, "/api/v2/me")).status === 200 && (await nxDevice(nxTokB)) === 200);
	await lA.screenshot({ path: `${OUT}/stage-litesync-after-c.png` }).catch(() => undefined);
} finally {
	const chromiumVersion = browser.version();
	await browser.close();
	const failed = checks.filter((x) => !x.ok).length;
	let meta: any = {};
	try { meta = JSON.parse(process.env.JOINT_RUN_META ?? "{}"); } catch {}
	// shas 取自 stage-env.json（预发布上部署的提交），另加运行时插件 checkout 的提交（run.mjs 传入）
	const report = { runner: "joint/stage-smoke", startedAt: started, finishedAt: new Date().toISOString(), urls: env.urls, shas: { ...(env.shas ?? {}), plugin: meta.plugin?.sha ?? null }, versions: { node: process.version, chromium: chromiumVersion }, total: checks.length, passed: checks.length - failed, failed, checks };
	writeFileSync(`${OUT}/stage-smoke-result.json`, JSON.stringify(report, null, 2));
	console.log(`\n${report.passed}/${report.total} 通过`);
	process.exitCode = failed ? 1 : 0;
}
