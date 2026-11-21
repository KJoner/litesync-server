// ADR-019 跨产品撤销联合验收：真实 Keycloak + 真实 LiteSync + 真实 Nexus（env.mjs 起的一次性环境）。
// 插件一端用插件仓原样的配对 v2 代码兑换设备凭据；Nexus 扩展一端走真实的设备配对接口。全部合成账号。
//
//   node e2e/joint/run.mjs revocation --env <work>/joint-env.json --plugin <插件目录> --out <输出目录>
//
// 一次运行发起 6 次 Nexus 扩展配对（pair/start；其中 5 次在中途重启 Nexus 之前）。Nexus 对同一来源 10 分钟内最多 10 次、
// 同时最多 10 个待确认配对，计数在内存里：多次重跑（尤其是中途失败、没走到重启的运行）前先
// node e2e/joint/env.mjs stop-nexus / start-nexus --work <work> 清零（见 README）。
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
	OUT, chromium, createVault, env, issueLink, kc, kcSessions, loginLiteSync, loginNexus, lsDevice, makeUser, nexusPair,
	nexusPoll, nxDevice, pageApi, pluginRedeem, runner, sleep, waitFor, writeEvidence,
} from "./lib";

const WINDOW_MS = 75_000; // ADR-019 R-7：60 秒 + 一次检查耗时，留余量
const R = runner("joint/revocation", "revocation-result.json");
const check = R.check;

const browser = await chromium.launch({ args: env.browserArgs });
let failure: unknown;
try {
	const A = await makeUser("rev-a");
	const B = await makeUser("rev-b");
	const ctxA1 = await browser.newContext({ locale: "zh-CN" });
	const ctxA2 = await browser.newContext({ locale: "zh-CN" }); // A 的第二个浏览器（另一个 IdP 会话）
	const ctxB = await browser.newContext({ locale: "zh-CN" });

	// ── 准备：A、B 在两个产品各有网页会话、设备、待领取授权 ──
	const nA1 = await loginNexus(ctxA1, A);
	const lA1 = await loginLiteSync(ctxA1, A);
	const nA2 = await loginNexus(ctxA2, A);
	const nB = await loginNexus(ctxB, B);
	const lB = await loginLiteSync(ctxB, B);
	check("PREP-1", "A 两个浏览器 + B 一个浏览器都登录了两个产品（统一账号）", (await kcSessions(A.id)) === 2 && (await kcSessions(B.id)) === 1, `A ${await kcSessions(A.id)} 个 SSO 会话`);
	const PWA = "撤销联调-A " + randomBytes(3).toString("hex");
	const PWB = "撤销联调-B " + randomBytes(3).toString("hex");
	await createVault(lA1, "撤销-A", PWA, true);
	await createVault(lB, "撤销-B", PWB, true);
	const la1 = await issueLink(ctxA1, "撤销-A");
	const lsA = await pluginRedeem(la1.link, "A 的 Obsidian");
	const laPending = await issueLink(ctxA1, "撤销-A"); // A 未兑换的连接链接（对话框保持打开）
	const lb1 = await issueLink(ctxB, "撤销-B");
	const lsB = await pluginRedeem(lb1.link, "B 的 Obsidian");
	const nxA = await nexusPair(nA1, "A 的扩展");
	const nxAApproved = await nexusPair(nA1, "A 已批准未领取", false);
	const nxB = await nexusPair(nB, "B 的扩展");
	check("PREP-2", "A、B 的 LiteSync 设备与 Nexus 扩展设备都可用", lsA.kind === "ok" && lsB.kind === "ok" && !!nxA.token && !!nxB.token && (await lsDevice(lsA.token!)) === 200 && (await nxDevice(nxA.token!)) === 200, `${lsA.kind}/${lsB.kind}`);

	// ── A：只退出 LiteSync 的这个网页会话（动作 A） ──
	const out1 = await pageApi(lA1, "/auth/logout", { method: "POST" });
	const lsWebAfterA = await pageApi(lA1, "/api/v2/me");
	check("A-1", "退出此会话：LiteSync 网页会话结束", out1.status < 400 && lsWebAfterA.status === 401, `${out1.status} → me ${lsWebAfterA.status}`);
	check("A-2", "退出此会话不撤销设备：A 的 LiteSync / Nexus 设备仍可用", (await lsDevice(lsA.token!)) === 200 && (await nxDevice(nxA.token!)) === 200);
	check("A-3", "退出此会话不影响 Nexus 网页会话与身份中心会话", (await pageApi(nA1, "/api/v2/me", {}, true)).status === 200 && (await kcSessions(A.id)) === 2);
	const lA1b = await loginLiteSync(ctxA1, A); // SSO 静默重登
	check("A-4", "同一浏览器重新进入 LiteSync 不需要输入密码（SSO 仍在）", (await pageApi(lA1b, "/api/v2/me")).status === 200);

	// ── C：从 LiteSync 发起「退出所有产品与设备」 ──
	const c1 = await pageApi(lA1b, "/api/v2/account/logout-all", { method: "POST" });
	writeEvidence("c-from-litesync.json", c1); // statusToken 等一次性令牌在写出前脱敏
	check("C1-1", "LiteSync 的 C：响应逐项报告本产品 / 身份中心 / Nexus 的真实状态", c1.status === 200 && c1.body?.local?.state === "done" && c1.body?.identityCenter?.state === "done" && Array.isArray(c1.body?.peers), JSON.stringify({ ok: c1.body?.ok, idc: c1.body?.identityCenter?.state, peers: c1.body?.peers?.map((p: any) => p.state) }));
	check("C1-2", "本产品立即生效：A 的 LiteSync 设备 401", (await lsDevice(lsA.token!)) === 401);
	const pend = await pluginRedeem(laPending.link, "撤销后才兑换的 Obsidian");
	check("C1-3", "C 之前签发、未兑换的连接链接不能再换出设备", pend.kind !== "ok", pend.kind);
	const nxRevokedIn = await waitFor(async () => (await nxDevice(nxA.token!)) === 401, WINDOW_MS);
	check("C1-4", "另一产品：A 的 Nexus 扩展设备在窗口内失效", nxRevokedIn !== null, nxRevokedIn === null ? "超时" : `${nxRevokedIn} ms`);
	check("C1-5", "另一产品：已批准未领取的 Nexus 配对领取失败", (await nexusPoll(nxAApproved)).status !== "approved");
	check("C1-6", "身份中心：A 在两个浏览器的 SSO 会话全部结束", (await waitFor(async () => (await kcSessions(A.id)) === 0, 15000, 1000)) !== null);
	check("C1-7", "A 的两个 Nexus 网页会话都结束", (await pageApi(nA1, "/api/v2/me", {}, true)).status === 401 && (await pageApi(nA2, "/api/v2/me", {}, true)).status === 401);
	check("C1-8", "B 完全不受影响（两产品网页会话与设备）", (await lsDevice(lsB.token!)) === 200 && (await nxDevice(nxB.token!)) === 200 && (await pageApi(nB, "/api/v2/me", {}, true)).status === 200 && (await pageApi(lB, "/api/v2/me")).status === 200);
	const revs = await waitFor(async () => {
		const p = await loginLiteSync(ctxA1, A).catch(() => null);
		return !!p && (await pageApi(p, "/api/v2/me")).status === 200;
	}, 30000);
	check("C1-9", "A 重新登录（必须重新输入密码）后可以重新授权", revs !== null);

	// ── C：从 Nexus 发起，方向反过来 ──
	const lA1c = await loginLiteSync(ctxA1, A);
	const la2 = await issueLink(ctxA1, "撤销-A");
	const lsA2 = await pluginRedeem(la2.link, "A 重新连接的 Obsidian");
	const nA1c = await loginNexus(ctxA1, A);
	const nxA2 = await nexusPair(nA1c, "A 重新连接的扩展");
	check("C2-0", "重新登录后新签发的两个设备可用（恢复不需要管理员）", lsA2.kind === "ok" && (await lsDevice(lsA2.token!)) === 200 && (await nxDevice(nxA2.token!)) === 200);
	check("C2-0b", "C 之前的旧设备仍然无效（代次只增不减）", (await lsDevice(lsA.token!)) === 401 && (await nxDevice(nxA.token!)) === 401);
	const c2 = await pageApi(nA1c, "/api/v2/account/revoke-everywhere", { method: "POST" }, true);
	writeEvidence("c-from-nexus.json", c2);
	check("C2-1", "Nexus 的 C：响应逐项报告状态", c2.status === 200 && !!c2.body, JSON.stringify(c2.body).slice(0, 300));
	check("C2-2", "Nexus 立即生效：A 的扩展设备 401", (await nxDevice(nxA2.token!)) === 401);
	const lsRevokedIn = await waitFor(async () => (await lsDevice(lsA2.token!)) === 401, WINDOW_MS);
	check("C2-3", "另一产品：A 的 LiteSync 设备在窗口内失效", lsRevokedIn !== null, lsRevokedIn === null ? "超时" : `${lsRevokedIn} ms`);
	check("C2-4", "LiteSync 网页会话也结束", (await pageApi(lA1c, "/api/v2/me")).status === 401);
	check("C2-5", "B 仍不受影响", (await lsDevice(lsB.token!)) === 200 && (await nxDevice(nxB.token!)) === 200);

	// ── 对方产品暂时不可达：pending → 恢复后补投 ──
	const lA1d = await loginLiteSync(ctxA1, A);
	const la3 = await issueLink(ctxA1, "撤销-A");
	const lsA3 = await pluginRedeem(la3.link, "A 第三次连接的 Obsidian");
	const nA1d = await loginNexus(ctxA1, A);
	const nxA3 = await nexusPair(nA1d, "A 第三次连接的扩展");
	execFileSync(process.execPath, [env.envScript, "stop-nexus", "--work", env.work], { stdio: "inherit" });
	const c3 = await pageApi(lA1d, "/api/v2/account/logout-all", { method: "POST" });
	const peerState = c3.body?.peers?.[0]?.state;
	check("P-1", "Nexus 不可达时 LiteSync 如实报告 pending，不谎报全部完成", c3.body?.ok === false && peerState === "pending", JSON.stringify({ ok: c3.body?.ok, peer: peerState }));
	execFileSync(process.execPath, [env.envScript, "start-nexus", "--work", env.work], { stdio: "inherit" });
	const deliveredIn = await waitFor(async () => (await nxDevice(nxA3.token!).catch(() => 0)) === 401, 120_000, 3000);
	check("P-2", "Nexus 恢复后事件被补投：A 的扩展设备随后失效", deliveredIn !== null, deliveredIn === null ? "超时" : `恢复后 ${deliveredIn} ms`);
	check("P-3", "本产品部分在对方不可达时照样立即生效", (await lsDevice(lsA3.token!)) === 401);

	// ── 中心停用（D）与恢复 ──
	const lA1e = await loginLiteSync(ctxA1, A);
	const la4 = await issueLink(ctxA1, "撤销-A");
	const lsA4 = await pluginRedeem(la4.link, "A 第四次连接的 Obsidian");
	const nA1e = await loginNexus(ctxA1, A);
	const nxA4 = await nexusPair(nA1e, "A 第四次连接的扩展");
	const userRep = (await kc("GET", `/users/${A.id}`)).body;
	await kc("PUT", `/users/${A.id}`, { ...userRep, enabled: false });
	const t0 = Date.now();
	const lsD = await waitFor(async () => (await lsDevice(lsA4.token!)) === 401, WINDOW_MS + 15_000, 3000);
	const nxD = await waitFor(async () => (await nxDevice(nxA4.token!)) === 401, Math.max(5000, WINDOW_MS + 15_000 - (Date.now() - t0)), 3000);
	check("D-1", "中心停用后 LiteSync 设备在约定窗口内被拒绝", lsD !== null, lsD === null ? "超时" : `${lsD} ms`);
	check("D-2", "中心停用后 Nexus 扩展设备在约定窗口内被拒绝", nxD !== null, nxD === null ? "超时" : `${Date.now() - t0} ms`);
	check("D-3", "B 不受 A 停用影响", (await lsDevice(lsB.token!)) === 200 && (await nxDevice(nxB.token!)) === 200);
	await kc("PUT", `/users/${A.id}`, { ...userRep, enabled: true });
	await sleep(3000);
	check("D-4", "重新启用不复活旧凭据", (await lsDevice(lsA4.token!)) === 401 && (await nxDevice(nxA4.token!)) === 401);
	const lA1f = await loginLiteSync(ctxA1, A).catch(() => null);
	check("D-5", "重新启用后可以重新登录", !!lA1f && (await pageApi(lA1f, "/api/v2/me")).status === 200);

	// ── 撤销与兑换并发 ──
	if (lA1f) {
		const la5 = await issueLink(ctxA1, "撤销-A");
		const [race] = await Promise.all([pluginRedeem(la5.link, "并发兑换的 Obsidian"), pageApi(lA1f, "/api/v2/account/logout-devices", { method: "POST" })]);
		const raceStatus = race.kind === "ok" ? await lsDevice(race.token!) : 0;
		check("R-1", "撤销（B）与兑换并发：不会留下有效的旧代次设备", race.kind !== "ok" || raceStatus === 401, `${race.kind} → ${raceStatus}`);
	}
	await lA1.screenshot({ path: `${OUT}/revocation-final.png` }).catch(() => undefined);
} catch (e) {
	failure = e;
} finally {
	const chromiumVersion = browser.version();
	await browser.close();
	const failed = R.finish({ chromium: chromiumVersion, error: failure });
	process.exitCode = failed || failure ? 1 : 0;
}
