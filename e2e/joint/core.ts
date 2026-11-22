// LiteSync × Nexus 联合验收：核心完成场景（需求「核心完成场景」；验收 ID-01 / ID-02 / ID-07 / ID-08 / TN-01 / ID-06 的
// 跨产品部分）。真实 Keycloak + 真实 LiteSync（PostgreSQL 模式）+ 真实 Nexus，都由 env.mjs 起在一次性环境里；插件一端用
// 插件仓原样的配对 v2 / 加密 / 上传下载代码。全部合成账号与数据。
//
//   node e2e/joint/run.mjs core --env <work>/joint-env.json --plugin <插件目录> --out <输出目录>
//
// ADR-019 之后的语义（CORE-18 / CORE-19）：Nexus 的「退出所有设备」（POST /api/v2/account/logout-all）是动作 B——只结束
// Nexus 自己的网页会话、设备与待领取授权，不碰身份中心，不会触发 back-channel，所以 LiteSync 的网页会话**保持**；
// LiteSync 的设备凭据同样不受影响（每个产品的 B 管自己）。跨产品的「退出所有产品与设备」（C）由 revocation.ts 覆盖。
import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { ApiClient } from "litesync-plugin/src/api/client";
import { openPairingLink, redeemPairing } from "litesync-plugin/src/pairing/pairing-v2";
import { parsePairUrl } from "litesync-plugin/src/pairing/pairing";
import { downloadPlain, uploadFromPlain } from "litesync-plugin/src/sync/transfer";
import { unlockVaultKey } from "litesync-plugin/src/crypto/crypto";
import {
	KC, LS, MAIL, NX, OUT, PLUGIN_VERSION, chromium, createVault, env, kc, kcLogin, kcSessions, makeUser, memorySecretStore,
	pageApi, runner, secrets, sensitiveValue, sleep, transport, writeEvidence,
} from "./lib";

const PLAN = {
	"CORE-01": "准备：旧管理员用 API Token 在默认仓库写入资产",
	"CORE-02": "从 Nexus 注册后收到身份服务发出的验证邮件（本机收信器）",
	"CORE-03": "验证邮箱并设置密码后进入 Nexus，是一个新的普通账号",
	"CORE-04": "在 Nexus 添加收藏并固定到首页",
	"CORE-05": "从 Nexus 跳到 LiteSync 无需再注册或输入密码，是同一个统一账号",
	"CORE-06": "LiteSync 里是零仓库账号（正常状态，引导建第一个仓库）",
	"CORE-07": "创建两个仓库，都已完成加密设置",
	"CORE-08": "插件打开连接链接：读取并解密配对包、核对服务器与仓库（不消费）",
	"CORE-09": "插件兑换成功，得到绑定在「联合-工作」的设备凭据",
	"CORE-10": "LiteSync 经 SMTP 给已验证邮箱发出「新设备已连接」通知（本机收信器）",
	"CORE-11": "插件用「联合-工作」的仓库密码解锁；另一个仓库的密码解不开它",
	"CORE-12": "插件把本地笔记加密上传",
	"CORE-13": "网页编辑后，Obsidian 一端拿到加密同步结果并解密（世代前进）",
	"CORE-14": "服务器（PostgreSQL 元数据库）上只有 LSE 密文",
	"CORE-15": "另一个账号在 LiteSync 看不到也拿不到 A 的仓库（列表为空、带 A 的仓库 ID 一律 404）",
	"CORE-16": "另一个账号在 Nexus（SSO 进入）看不到 A 的收藏",
	"CORE-17": "关闭浏览器再打开：会话还在，但仓库必须重新输入仓库密码，页面上没有明文",
	"CORE-18": "在 Nexus「退出所有设备」（ADR-019 的 B）后：Nexus 网页会话结束；身份中心会话与 LiteSync 网页会话保持",
	"CORE-19": "（设计如此）Nexus 的 B 不撤销 LiteSync 的设备凭据——每个产品的「退出所有设备」管自己的设备",
	"CORE-20": "旧管理员认领统一账号后用统一账号登录：仍是管理员，认领前的资产原样都在",
} as const;
type Id = keyof typeof PLAN;
const R = runner("joint/core", "core-result.json", PLAN);
const C = (id: Id, ok: boolean, detail = "") => R.check(id, PLAN[id], ok, detail);

const ADMIN_TOKEN = secrets.lsAdminToken;
// 管理员认领用的合成统一账号：同一环境里重跑时沿用（已经绑定过的管理员不能再绑一次）。只存在 <work> 下，权限 600
const STATE_FILE = `${env.work}/core-state.json`;
const PW1 = sensitiveValue("仓库一的密码 · joint " + randomBytes(3).toString("hex"));
const PW2 = sensitiveValue("仓库二的密码 · joint " + randomBytes(3).toString("hex"));
const DANA = `dana-${randomBytes(3).toString("hex")}@example.test`;
const NEXUS_ITEM_URL = "https://example.org/joint"; // 只作为收藏的字段值保存，测试不访问它

async function mailsTo(addr: string): Promise<any[]> {
	const list = (await (await fetch(`${MAIL}/api/v1/messages?limit=200`)).json()) as any;
	return (list.messages ?? []).filter((m: any) => m.To?.some((t: any) => t.Address === addr));
}
async function waitMail(addr: string, subjectRe: RegExp, ms = 30000): Promise<any | null> {
	const end = Date.now() + ms;
	while (Date.now() < end) {
		const m = (await mailsTo(addr)).find((x) => subjectRe.test(x.Subject ?? ""));
		if (m) return (await (await fetch(`${MAIL}/api/v1/message/${m.ID}`)).json()) as any;
		await sleep(500);
	}
	return null;
}
async function adminClaimAccount() {
	if (existsSync(STATE_FILE)) {
		const saved = JSON.parse(readFileSync(STATE_FILE, "utf8")).adminOld;
		// 同一个 <work> 重新 up 过时，旧状态指向的身份中心用户已经不存在：重新建
		if (saved?.id && (await kc("GET", `/users/${saved.id}`)).status === 200) {
			sensitiveValue(saved.password);
			return { user: saved as { email: string; password: string; id: string }, reused: true };
		}
	}
	const user = await makeUser("admin-old");
	writeFileSync(STATE_FILE, JSON.stringify({ adminOld: user }, null, 2), { mode: 0o600 });
	return { user, reused: false };
}

const browser = await chromium.launch({ args: env.browserArgs });
let failure: unknown;
try {
	// ── 0. 旧管理员在统一账号之前的资产（LiteSync，API Token） ──
	const legacyNote = `旧资产/管理员的笔记-${randomBytes(3).toString("hex")}.md`;
	const legacyBody = "管理员在统一账号之前写的 " + randomBytes(4).toString("hex");
	const up = await fetch(`${LS}/api/v1/file`, {
		method: "PUT",
		headers: { Authorization: `Bearer ${ADMIN_TOKEN}`, "X-File-Path": encodeURIComponent(legacyNote), "X-Base-Revision": "0", "X-Content-Hash": createHash("sha256").update(legacyBody).digest("hex"), "X-File-Mtime": String(Date.now()) },
		body: legacyBody,
	});
	C("CORE-01", up.status === 200, `PUT /api/v1/file → ${up.status}`);
	const adminClaim = await adminClaimAccount();

	// ── 1. 新用户从 Nexus 注册并验证邮箱 ──
	const ctxA = await browser.newContext({ locale: "zh-CN", viewport: { width: 1280, height: 860 } });
	const n = await ctxA.newPage();
	await n.goto(`${NX}/account/connect`);
	await n.getByRole("button", { name: "登录或创建账号" }).click();
	await n.waitForURL((u: URL) => u.href.startsWith(`${KC}/`));
	await n.locator('#kc-registration a, a[href*="registrations"]').first().click();
	await n.locator("#email").fill(DANA);
	if (await n.locator("#firstName").count()) await n.locator("#firstName").fill("达娜");
	if (await n.locator("#lastName").count()) await n.locator("#lastName").fill("测试");
	await n.locator("[type=submit]").first().click();
	const verify = await waitMail(DANA, /./);
	const link = sensitiveValue(verify?.Text?.match(/https?:\/\/\S+action-token\S+/)?.[0] as string | undefined);
	C("CORE-02", !!link, verify?.Subject ?? "未收到");
	if (!link) throw new Error("没有收到验证邮件，无法继续");
	await n.goto(link);
	const danaPw = sensitiveValue(`Pw-${randomBytes(9).toString("base64url")}`);
	await n.locator("#password-new").fill(danaPw);
	await n.locator("#password-confirm").fill(danaPw);
	await n.locator("[type=submit]").first().click();
	await n.waitForURL((u: URL) => u.href.startsWith(NX) && !u.pathname.startsWith("/auth/"), { timeout: 30000 });
	const nMe = await pageApi(n, "/api/v2/me", {}, true);
	C("CORE-03", nMe.status === 200 && nMe.body?.account?.email === DANA && nMe.body?.account?.emailVerified === true, `me ${nMe.status} emailVerified=${nMe.body?.account?.emailVerified}`);

	// ── 2. 添加一个网站到收藏并固定 ──
	const fav = await pageApi(n, "/api/v2/items", { method: "POST", body: JSON.stringify({ opId: "joint-fav-" + randomBytes(4).toString("hex"), item: { title: "联合验收收藏", url: NEXUS_ITEM_URL }, pinToHome: true }) }, true);
	const items = await pageApi(n, "/api/v2/items", {}, true);
	const mine = (items.body?.items ?? []).find((i: any) => i.url === NEXUS_ITEM_URL);
	C("CORE-04", (fav.status === 200 || fav.status === 201) && !!mine && mine.pinned === true, `status=${fav.status} pinned=${mine?.pinned}`);

	// ── 3. 跳到 LiteSync：不需要再注册 / 输密码（SSO） ──
	const l = await ctxA.newPage();
	let kcHops = 0; // 经过身份服务的导航请求（含 302 跳转的每一跳）：SSO 静默登录也要走一趟身份服务
	l.on("request", (req: any) => {
		if (req.isNavigationRequest() && req.url().startsWith(KC)) kcHops++;
	});
	await l.goto(`${LS}/`);
	await l.getByRole("link", { name: "登录", exact: true }).click();
	await l.waitForURL((u: URL) => u.href.startsWith(LS) && !u.pathname.startsWith("/auth/"), { timeout: 30000 });
	await l.getByRole("heading", { name: "我的仓库" }).waitFor({ timeout: 20000 });
	const lMe = await pageApi(l, "/api/v2/me");
	C("CORE-05", lMe.status === 200 && lMe.body?.account?.email === DANA && kcHops >= 1 && (await l.locator("#password").count()) === 0, `经过身份服务 ${kcHops} 次跳转（SSO 静默完成），未出现登录表单`);
	C("CORE-06", lMe.body?.vaultCount === 0 && lMe.body?.onboarding?.state === "needs_first_vault", `vaultCount=${lMe.body?.vaultCount} onboarding=${lMe.body?.onboarding?.state}`);
	await l.screenshot({ path: `${OUT}/core-01-litesync-sso-zero-vault.png` });

	// ── 4. 创建两个密码不同的仓库 ──
	await createVault(l, "联合-工作", PW1, true);
	await createVault(l, "联合-私人", PW2, false);
	const vlist = await pageApi(l, "/api/v1/vaults");
	const v1 = vlist.body?.vaults?.find((v: any) => v.name === "联合-工作");
	const v2 = vlist.body?.vaults?.find((v: any) => v.name === "联合-私人");
	C("CORE-07", v1?.initState === "ready" && v2?.initState === "ready" && v1?.encryptionState === "encrypted" && v2?.encryptionState === "encrypted", `${v1?.initState}/${v1?.encryptionState} · ${v2?.initState}/${v2?.encryptionState}`);
	await l.screenshot({ path: `${OUT}/core-02-two-vaults.png` });

	// ── 5. 在「Obsidian」导入其中一个仓库的连接链接（插件原样配对代码） ──
	await l.locator(".vault-card", { hasText: "联合-工作" }).getByRole("button", { name: "连接 Obsidian" }).click();
	await l.locator(".dialog .link-input").waitFor({ timeout: 15000 });
	const parsed = parsePairUrl(sensitiveValue(await l.locator(".dialog .link-input").inputValue()))!;
	const opened: any = await openPairingLink(transport as any, parsed);
	C("CORE-08", opened.kind === "ready" && opened.config?.selectedVault?.vaultId === v1?.id, opened.kind);
	const redeemed: any = await redeemPairing(transport as any, memorySecretStore(), { link: parsed, config: opened.config, deviceName: "联合验收的 Obsidian", platform: "windows", clientVersion: PLUGIN_VERSION, now: Date.now() });
	const deviceToken = sensitiveValue(redeemed.credential as string);
	C("CORE-09", redeemed.kind === "ok" && redeemed.vaultId === v1?.id, redeemed.kind);
	await l.keyboard.press("Escape");
	const devMail = await waitMail(DANA, /新设备/);
	C("CORE-10", !!devMail && /联合验收的 Obsidian/.test(devMail.Text ?? ""), devMail?.Subject ?? "未收到");

	// 插件用设备凭据 + 仓库密码解锁，写入一篇笔记
	const auth = { headers: { Authorization: `Bearer ${deviceToken}` } };
	const devInfo = (await (await fetch(`${LS}/api/v1/info`, auth)).json()) as any;
	const doc1 = (await (await fetch(`${LS}/api/v1/vault-key`, auth)).json()) as any;
	const vmk = await unlockVaultKey(doc1, PW1);
	C("CORE-11", !!vmk && (await unlockVaultKey(doc1, PW2)) === null);
	const tracked = new Map<string, any>();
	const pctx: any = {
		client: new ApiClient(() => ({ serverUrl: LS, apiToken: deviceToken, deviceId: "joint-obsidian", formatEpoch: devInfo.formatEpoch ?? 1, repoEpoch: devInfo.repoEpoch ?? "", keyEpoch: devInfo.keyEpoch })),
		store: { get: (p: string) => tracked.get(p), state: { bootstrap: { remoteVaultId: devInfo.vaultId, keyEpoch: devInfo.keyEpoch, metaState: "plain" } }, save: async () => undefined },
		queue: { getOp: () => undefined, rememberIdentity: () => undefined },
		e2ee: { enabled: true, unlocked: true, requireKey: () => vmk, metaKeys: async () => { throw new Error("本场景的仓库没有路径加密"); } },
		gate: { markIntegrityError: (m: string) => { throw new Error(m); } },
		padsSize: () => false,
		reportedMtime: (m: number) => m,
		log: () => undefined,
	};
	const NOTE = "来自 Obsidian.md";
	const o1 = await uploadFromPlain(pctx, NOTE, new TextEncoder().encode("# 来自 Obsidian\n\n本地写的第一段\n").buffer as ArrayBuffer, 0, Date.now(), "upsert");
	tracked.set(NOTE, { fileId: o1.fileId, generation: o1.generation, revision: o1.revision });
	C("CORE-12", o1.revision === 1 && o1.generation === 1, `revision=${o1.revision} generation=${o1.generation}`);

	// ── 6. 在网页编辑同一篇 Markdown，另一设备收到加密同步结果 ──
	await l.locator(".vault-card", { hasText: "联合-工作" }).getByRole("button", { name: "解锁并打开" }).click();
	await l.locator('input[placeholder="仓库密码"]').fill(PW1);
	await l.getByRole("button", { name: "解锁", exact: true }).click();
	await l.locator(".tree").waitFor({ timeout: 60000 });
	await l.evaluate((p: string) => (location.hash = "#/n/" + encodeURIComponent(p)), NOTE);
	await l.locator(".edit-bar").waitFor({ timeout: 15000 });
	await l.locator('.seg button[data-mode="edit"]').click();
	await l.locator(".cm-content").click();
	await l.keyboard.press("Control+End");
	await l.keyboard.insertText("网页里补的一段");
	await l.keyboard.press("Control+s");
	await l.locator('.save-status[data-state="synced"]').waitFor({ timeout: 30000 });
	await l.screenshot({ path: `${OUT}/core-03-web-edit.png` });
	const got = await downloadPlain(pctx, NOTE);
	C("CORE-13", new TextDecoder().decode(got.plain).endsWith("网页里补的一段") && got.generation === 2, `generation=${got.generation}`);
	const raw = new Uint8Array(await (await fetch(`${LS}/api/v1/file?path=${encodeURIComponent(NOTE)}`, auth)).arrayBuffer());
	C("CORE-14", new TextDecoder().decode(raw.slice(0, 3)) === "LSE", `前 3 字节 ${new TextDecoder().decode(raw.slice(0, 3))}`);

	// ── 7. 另一个账号无法访问任何对象 ──
	const erin = await makeUser("erin");
	const ctxB = await browser.newContext({ locale: "zh-CN" });
	const lb = await ctxB.newPage();
	await lb.goto(`${LS}/`);
	await lb.getByRole("link", { name: "登录", exact: true }).click();
	await kcLogin(lb, erin);
	await lb.getByRole("heading", { name: "我的仓库" }).waitFor({ timeout: 30000 });
	const eVaults = await pageApi(lb, "/api/v1/vaults");
	const eSnap = await pageApi(lb, "/api/v1/snapshot", { headers: { "X-Vault-ID": v1.id } });
	const eKey = await pageApi(lb, "/api/v1/vault-key", { headers: { "X-Vault-ID": v1.id } });
	C("CORE-15", (eVaults.body?.vaults ?? []).length === 0 && eSnap.status === 404 && eKey.status === 404, `vaults=${(eVaults.body?.vaults ?? []).length} snapshot=${eSnap.status} vault-key=${eKey.status}`);
	const nb = await ctxB.newPage();
	await nb.goto(`${NX}/account/connect`);
	await nb.getByRole("button", { name: "登录或创建账号" }).click();
	await nb.waitForURL((u: URL) => u.href.startsWith(NX) && !u.pathname.startsWith("/auth/"), { timeout: 30000 });
	const eItems = await pageApi(nb, "/api/v2/items", {}, true);
	C("CORE-16", eItems.status === 200 && !(eItems.body?.items ?? []).some((i: any) => i.url === NEXUS_ITEM_URL), `items ${eItems.status}`);
	await ctxB.close();

	// ── 8. 退出并重开后必须重新解锁（浏览器状态只临时落在 <work> 下，用完即删） ──
	const statePath = `${env.work}/core-browser-state.json`;
	await ctxA.storageState({ path: statePath });
	await ctxA.close();
	const ctxA2 = await browser.newContext({ locale: "zh-CN", storageState: statePath });
	rmSync(statePath, { force: true });
	const l2 = await ctxA2.newPage();
	await l2.goto(`${LS}/`);
	await l2.locator('input[placeholder="仓库密码"]').waitFor({ timeout: 30000 });
	C("CORE-17", !(await l2.locator("body").innerText()).includes("网页里补的一段"), "需要仓库密码；页面文本里没有笔记明文");
	await l2.screenshot({ path: `${OUT}/core-04-reopen-needs-unlock.png` });

	// ── 9. 在 Nexus「退出所有设备」（ADR-019 的 B）：只管 Nexus 自己，不碰身份中心 ──
	const n2 = await ctxA2.newPage();
	await n2.goto(`${NX}/`);
	const lsBefore = await pageApi(l2, "/api/v2/me");
	const nxBefore = await pageApi(n2, "/api/v2/me", {}, true);
	const danaKc = (await kc("GET", `/users?email=${encodeURIComponent(DANA)}&exact=true`)).body?.[0]?.id as string | undefined;
	const ssoBefore = danaKc ? await kcSessions(danaKc) : -1;
	const out = await pageApi(n2, "/api/v2/account/logout-all", { method: "POST", body: "{}" }, true);
	writeEvidence("core-nexus-logout-all.json", out);
	const nxAfter = await pageApi(n2, "/api/v2/me", {}, true);
	// 如果身份中心会话被结束，Keycloak 会立刻向 LiteSync 发 back-channel：观察 10 秒，LiteSync 会话必须一直有效
	let lsAfter = 200;
	for (let i = 0; i < 20 && lsAfter === 200; i++) {
		await sleep(500);
		lsAfter = (await pageApi(l2, "/api/v2/me")).status;
	}
	const ssoAfter = danaKc ? await kcSessions(danaKc) : -1;
	C("CORE-18",
		lsBefore.status === 200 && nxBefore.status === 200 && out.status === 200 && !out.body?.endSessionUrl && nxAfter.status === 401 && lsAfter === 200 && ssoAfter >= 1,
		`Nexus B ${out.status}（endSessionUrl=${out.body?.endSessionUrl ?? null}）；Nexus 网页会话 ${nxBefore.status}→${nxAfter.status}；身份中心会话 ${ssoBefore}→${ssoAfter}；LiteSync 网页会话 ${lsBefore.status}→${lsAfter}（观察 10 秒）`);
	const devStill = await fetch(`${LS}/api/v1/info`, auth);
	C("CORE-19", devStill.status === 200, `LiteSync 设备 ${devStill.status}`);
	await ctxA2.close();

	// ── 10. 原管理员认领统一账号后全部资产仍在 ──
	const ctxC = await browser.newContext({ locale: "zh-CN" });
	const c = await ctxC.newPage();
	await c.goto(`${LS}/`);
	await c.getByText("管理员 / 自托管：使用 API Token 登录").click(); // 启用统一登录后 Token 登录折叠在这里
	await c.locator("input[type=password]").fill(ADMIN_TOKEN);
	await c.getByRole("button", { name: "使用 Token 登录" }).click();
	await c.getByRole("heading", { name: "我的仓库" }).waitFor({ timeout: 20000 });
	const linked = (await pageApi(c, "/api/v2/me")).body?.identity?.linked === true;
	if (!linked) {
		await c.goto(`${LS}/#/me`);
		await c.getByRole("link", { name: "绑定统一账号" }).click();
		await kcLogin(c, adminClaim.user);
		await c.waitForURL((u: URL) => u.href.startsWith(LS) && !u.pathname.startsWith("/auth/"), { timeout: 30000 });
	} else if (!adminClaim.reused) {
		throw new Error("管理员已经绑定了统一账号，但 <work> 下没有当时的合成账号：请用新的环境（down + up）重跑");
	}
	await ctxC.close();
	const ctxD = await browser.newContext({ locale: "zh-CN" });
	const d = await ctxD.newPage();
	await d.goto(`${LS}/`);
	await d.getByRole("link", { name: "登录", exact: true }).click();
	await kcLogin(d, adminClaim.user);
	await d.waitForURL((u: URL) => u.href.startsWith(LS) && !u.pathname.startsWith("/auth/"), { timeout: 30000 });
	const dMe = await pageApi(d, "/api/v2/me");
	const legacy = await d.evaluate(async (p: string) => {
		const r = await fetch(`/api/v1/file?path=${encodeURIComponent(p)}`);
		return { status: r.status, text: await r.text() };
	}, legacyNote);
	C("CORE-20", dMe.body?.role === "admin" && legacy.status === 200 && legacy.text === legacyBody, `role=${dMe.body?.role} 旧资产 ${legacy.status}（${linked ? "同一环境里之前已认领，沿用" : "本次认领"}）`);
	await d.screenshot({ path: `${OUT}/core-05-admin-claimed.png` });
	await ctxD.close();
} catch (e) {
	failure = e;
} finally {
	const chromiumVersion = browser.version();
	await browser.close();
	const failed = R.finish({ chromium: chromiumVersion, error: failure });
	process.exitCode = failed || failure ? 1 : 0;
}
