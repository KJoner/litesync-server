#!/usr/bin/env node
/**
 * LiteSync 网页端浏览器验收 runner（W7）：真实 Chromium + 本机隔离服务端 + 插件原样源码充当「另一台设备」。
 *
 * 用法（在 web/ 下）：
 *   npm run test:e2e                              构建服务端，每个套件起一个独立的本机实例，跑全部套件
 *   npm run test:e2e -- --suite edit,w1-merge     只跑指定套件（--list 列出全部）
 *   E2E_SERVER_BIN=/path/obsync npm run test:e2e  用现成的服务端二进制（例如复现旧版本的缺陷）
 *   E2E_BASE=http://127.0.0.1:39210 E2E_ADMIN_TOKEN=… npm run test:e2e -- --suite ed06
 *                                                 用已经在跑的服务端（需要只读实例的套件另给 E2E_BASE_READONLY）
 *
 * 前置条件：
 *   - Node ≥ 22（WebCrypto、fetch）；未给 E2E_SERVER_BIN / E2E_BASE 时需要 Go（go build ./cmd/obsync）；
 *   - playwright-core（web/ 的 devDependency）与 Chromium：`npx playwright-core install chromium`；
 *     也可以用 E2E_PLAYWRIGHT 指向另一个装了 playwright-core / @playwright/test 的目录；
 *   - 插件 checkout：LITESYNC_PLUGIN_DIR（默认同级 ../../litesync）。需要「另一台设备」的套件
 *     直接 bundle 插件的 src/api/client.ts、src/sync/transfer.ts、src/crypto/crypto.ts；没有插件时这些
 *     套件记为「未执行」，不会算作通过。
 *
 * 全部数据都是合成的：每个实例一个临时数据目录、随机管理员 Token（不写进结果文件），
 * 端口只用 E2E_PORTS（默认 39200-39299）。结果写到 E2E_OUT（默认 web/.e2e-results/<时间>/）：
 *   results.json  机器可读：服务端/网页/插件/浏览器版本与 SHA、每个套件每一项检查的结果；
 *   <套件>/       失败截图、失败 trace（Playwright trace.zip）、套件日志。
 * 退出码：0 全部通过；1 有失败或未执行；2 环境/参数问题。
 */
import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import esbuild from "esbuild";

const here = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(here, "..");
const repoRoot = resolve(webRoot, "..");

/** 套件登记：expect = 套件声明的检查项数量，少跑一项也算失败（防止静默跳过）。 */
const SUITES = [
	{ name: "edit", file: "suites/edit.ts", server: "editing", plugin: true, expect: 58, desc: "网页编辑全流程（原 edit-e2e：ED-01/02、离线草稿、改名、回收站、附件、分栏、搜索、锁定）" },
	{ name: "tn05", file: "suites/tn05.ts", server: "editing", plugin: false, expect: 5, desc: "TN-05：两个标签页换号/退出时立即清掉明文" },
	{ name: "ed06", file: "suites/ed06.ts", server: "editing", plugin: false, expect: 5, desc: "ED-06：恶意 Markdown 不执行脚本、不外发请求" },
	{ name: "quota", file: "suites/quota.ts", server: "editing", plugin: false, expect: 7, desc: "配额超限如实说明且不丢内容" },
	{ name: "edit-off", file: "suites/edit-off.ts", server: "readonly", plugin: true, expect: 6, desc: "网页编辑默认关闭：只读界面 + 服务端拒绝会话写入" },
	{ name: "w1-merge", file: "suites/w1-merge.ts", server: "editing", plugin: true, expect: 12, desc: "W1：上传/取远端期间继续输入，合并与冲突副本不丢输入（含输入法组合）" },
	{ name: "w2-drafts", file: "suites/w2-drafts.ts", server: "editing", plugin: true, expect: 18, desc: "W2：旧上传成功不删更新的草稿；草稿逆序写入；多标签；强制结束后恢复" },
	{ name: "w4-restore", file: "suites/w4-restore.ts", server: "editing", plugin: true, expect: 22, desc: "W4：回收站恢复断网/401/额度/刷新后可继续完成，HEAD 始终一致" },
	{ name: "w5-meta-trash", file: "suites/w5-meta-trash.ts", server: "editing", plugin: false, expect: 14, desc: "W5：路径加密仓库回收站解密原路径并恢复（改名后删除、重名、旧墓碑、历史清理、新设备）" },
	{ name: "w6-bytes", file: "suites/w6-bytes.ts", server: "editing", plugin: true, expect: 18, desc: "W6：CRLF/混合换行/BOM/emoji 的工具栏操作与无编辑不改字节" },
];

function fail(msg, code = 2) {
	console.error(msg);
	process.exit(code);
}

const args = process.argv.slice(2);
const argValue = (flag) => {
	const i = args.indexOf(flag);
	return i >= 0 ? args[i + 1] : undefined;
};
if (args.includes("--list")) {
	for (const s of SUITES) console.log(`${s.name.padEnd(14)} ${s.desc}`);
	process.exit(0);
}
const only = (argValue("--suite") ?? process.env.E2E_SUITES ?? "").split(",").map((s) => s.trim()).filter(Boolean);
for (const n of only) if (!SUITES.some((s) => s.name === n)) fail(`未知套件：${n}（--list 查看全部）`);
const selected = only.length ? SUITES.filter((s) => only.includes(s.name)) : SUITES;
const keep = args.includes("--keep") || process.env.E2E_KEEP === "1";

const stamp = new Date().toISOString().replace(/[:.]/g, "-");
const outRoot = resolve(process.env.E2E_OUT ?? join(webRoot, ".e2e-results", stamp));
mkdirSync(outRoot, { recursive: true });
const work = mkdtempSync(join(process.env.E2E_TMP ?? tmpdir(), "w-e2e-"));

// ---------- 版本与 SHA ----------
const tryExec = (cmd, a, opts = {}) => {
	try {
		return execFileSync(cmd, a, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], ...opts }).trim();
	} catch {
		return "";
	}
};
const gitInfo = (dir) => {
	const sha = tryExec("git", ["-C", dir, "rev-parse", "HEAD"]);
	if (!sha) {
		const f = join(dir, ".source-sha"); // git archive 导出的快照：旁边记一份来源 SHA
		return existsSync(f) ? { sha: readFileSync(f, "utf8").trim(), dirty: false, source: "snapshot" } : { sha: "", dirty: false, source: "unknown" };
	}
	return { sha, dirty: tryExec("git", ["-C", dir, "status", "--porcelain"]) !== "", branch: tryExec("git", ["-C", dir, "branch", "--show-current"]), source: "git" };
};

const pluginDirRaw = process.env.LITESYNC_PLUGIN_DIR ?? join(repoRoot, "..", "litesync");
const pluginDir = existsSync(join(pluginDirRaw, "src", "api", "client.ts")) ? resolve(pluginDirRaw) : null;
const pluginVersion = pluginDir && existsSync(join(pluginDir, "manifest.json")) ? JSON.parse(readFileSync(join(pluginDir, "manifest.json"), "utf8")).version : null;

// ---------- Playwright ----------
const playwrightDir = process.env.E2E_PLAYWRIGHT ? resolve(process.env.E2E_PLAYWRIGHT) : webRoot;
async function playwrightVersion() {
	const { createRequire } = await import("node:module");
	const req = createRequire(join(playwrightDir, "package.json"));
	for (const id of ["playwright-core/package.json", "@playwright/test/package.json", "playwright/package.json"]) {
		try {
			return { module: id.replace("/package.json", ""), version: req(id).version };
		} catch {
			/* 下一个 */
		}
	}
	return null;
}
const pw = await playwrightVersion();
if (!pw) fail(`找不到 Playwright：在 web/ 下 npm ci（devDependency playwright-core），或用 E2E_PLAYWRIGHT 指向装了它的目录（当前 ${playwrightDir}）`);

// ---------- 服务端 ----------
const externalBase = process.env.E2E_BASE ?? "";
const externalReadonly = process.env.E2E_BASE_READONLY ?? "";
let serverBin = process.env.E2E_SERVER_BIN ? resolve(process.env.E2E_SERVER_BIN) : "";
if (!externalBase && !serverBin) {
	serverBin = join(work, process.platform === "win32" ? "obsync-e2e.exe" : "obsync-e2e");
	console.log("构建服务端（go build ./cmd/obsync）…");
	try {
		execFileSync("go", ["build", "-o", serverBin, "./cmd/obsync"], { cwd: repoRoot, stdio: "inherit", env: { ...process.env, CGO_ENABLED: "0" } });
	} catch {
		fail("go build 失败：需要 Go 工具链，或用 E2E_SERVER_BIN 指定现成的服务端二进制");
	}
}
if (serverBin && !existsSync(serverBin)) fail(`服务端二进制不存在：${serverBin}`);

const [portLo, portHi] = (process.env.E2E_PORTS ?? "39200-39299").split("-").map(Number);
const usedPorts = new Set();
async function freePort() {
	for (let p = portLo; p <= portHi; p++) {
		if (usedPorts.has(p)) continue;
		const ok = await new Promise((r) => {
			const s = createServer();
			s.once("error", () => r(false));
			s.listen(p, "127.0.0.1", () => s.close(() => r(true)));
		});
		if (ok) {
			usedPorts.add(p);
			return p;
		}
	}
	fail(`E2E_PORTS ${portLo}-${portHi} 内没有空闲端口`);
}

async function waitHealthy(base, child, ms = 30000) {
	const until = Date.now() + ms;
	while (Date.now() < until) {
		if (child && child.exitCode !== null) return false;
		try {
			const r = await fetch(base + "/health");
			if (r.ok) return true;
		} catch {
			/* 还没起来 */
		}
		await new Promise((r) => setTimeout(r, 200));
	}
	return false;
}

/** 起一个本机隔离实例：独立数据目录、随机管理员 Token。 */
async function startServer(label, editing) {
	const port = await freePort();
	const dataDir = join(work, `data-${label}-${port}`);
	mkdirSync(dataDir, { recursive: true });
	const token = randomBytes(24).toString("hex");
	const env = {
		...process.env,
		OBSYNC_TOKEN: token,
		OBSYNC_LISTEN: `127.0.0.1:${port}`,
		OBSYNC_DATA_DIR: dataDir,
		OBSYNC_LOG_LEVEL: "warn",
		OBSYNC_REGISTRATION_MODE: "invite",
	};
	if (editing) env.OBSYNC_WEB_EDITING = "true";
	else delete env.OBSYNC_WEB_EDITING;
	const logFile = join(outRoot, `server-${label}-${port}.log`);
	const child = spawn(serverBin, [], { env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
	const chunks = [];
	child.stdout.on("data", (d) => chunks.push(d));
	child.stderr.on("data", (d) => chunks.push(d));
	const base = `http://127.0.0.1:${port}`;
	if (!(await waitHealthy(base, child))) {
		child.kill();
		writeFileSync(logFile, Buffer.concat(chunks));
		fail(`服务端没能启动（${label}），日志：${logFile}`);
	}
	const info = await (await fetch(base + "/api/v1/info", { headers: { Authorization: "Bearer " + token } })).json().catch(() => ({}));
	return {
		base, token, editing, dataDir, version: info.version ?? "", capabilities: info.capabilities ?? [],
		async stop() {
			child.kill();
			await new Promise((r) => (child.exitCode !== null ? r() : child.once("exit", r)));
			// 日志里不含 Token（服务端从不记录它），只做截断保护
			writeFileSync(logFile, Buffer.concat(chunks).subarray(-2_000_000));
			usedPorts.delete(port);
			if (!keep) rmSync(dataDir, { recursive: true, force: true });
		},
	};
}

// ---------- 打包套件 ----------
const nodeModules = join(webRoot, "node_modules");
function pluginResolver() {
	return {
		name: "litesync-plugin-alias",
		setup(b) {
			b.onResolve({ filter: /^obsidian$/ }, () => ({ path: join(here, "lib", "obsidian-shim.ts") }));
			b.onResolve({ filter: /^@plugin-mocks\/obsidian$/ }, () => {
				if (!pluginDir) return { errors: [{ text: "缺少插件 checkout（LITESYNC_PLUGIN_DIR）" }] };
				return { path: join(pluginDir, "tests", "mocks", "obsidian.ts") };
			});
			b.onResolve({ filter: /^@plugin\// }, (a) => {
				if (!pluginDir) return { errors: [{ text: "缺少插件 checkout（LITESYNC_PLUGIN_DIR）" }] };
				const rel = a.path.slice("@plugin/".length);
				for (const cand of [`${rel}.ts`, join(rel, "index.ts"), rel]) {
					const p = join(pluginDir, "src", cand);
					if (existsSync(p)) return { path: p };
				}
				return { errors: [{ text: `插件源码里没有 ${rel}` }] };
			});
		},
	};
}
async function bundle(suite) {
	const outfile = join(work, "bundles", `${suite.name}.mjs`);
	await esbuild.build({
		entryPoints: [join(here, suite.file)],
		bundle: true,
		platform: "node",
		format: "esm",
		target: "node22",
		outfile,
		logLevel: "silent",
		nodePaths: [nodeModules],
		external: ["playwright-core", "@playwright/test", "playwright"],
		plugins: [pluginResolver()],
		banner: { js: "import { createRequire as __e2eRequire } from 'node:module'; const require = __e2eRequire(import.meta.url);" },
	});
	return outfile;
}

function runSuite(suite, bundlePath, env) {
	return new Promise((resolveRun) => {
		const dir = join(outRoot, suite.name);
		mkdirSync(dir, { recursive: true });
		const resultFile = join(dir, "result.json");
		const log = [];
		const child = spawn(process.execPath, [bundlePath], {
			env: { ...process.env, ...env, E2E_SUITE: suite.name, E2E_OUT: dir, E2E_RESULT: resultFile, E2E_PLAYWRIGHT: playwrightDir },
			stdio: ["ignore", "pipe", "pipe"],
			windowsHide: true,
		});
		const timeoutMs = Number(process.env.E2E_SUITE_TIMEOUT_MS ?? 15 * 60_000);
		const timer = setTimeout(() => child.kill(), timeoutMs);
		const tee = (d) => {
			log.push(d);
			process.stdout.write(d);
		};
		child.stdout.on("data", tee);
		child.stderr.on("data", tee);
		child.on("exit", (code) => {
			clearTimeout(timer);
			writeFileSync(join(dir, "suite.log"), Buffer.concat(log));
			let result = null;
			try {
				result = JSON.parse(readFileSync(resultFile, "utf8"));
			} catch {
				/* 套件没写出结果：按崩溃处理 */
			}
			resolveRun({ code, result });
		});
	});
}

// ---------- 执行 ----------
const started = Date.now();
const report = {
	format: "litesync-web-e2e/v1",
	startedAt: new Date(started).toISOString(),
	environment: {
		node: process.version,
		os: `${process.platform}-${process.arch}`,
		playwright: pw,
		server: { ...gitInfo(repoRoot), bin: serverBin ? (process.env.E2E_SERVER_BIN ? "E2E_SERVER_BIN" : "go build") : "external", base: externalBase || null },
		web: { version: JSON.parse(readFileSync(join(webRoot, "package.json"), "utf8")).version },
		plugin: pluginDir ? { ...gitInfo(pluginDir), version: pluginVersion } : null,
	},
	suites: [],
};

for (const suite of selected) {
	console.log(`\n==== ${suite.name}：${suite.desc}`);
	const entry = { name: suite.name, description: suite.desc, status: "not-run", passed: 0, failed: 0, checks: [], expectedChecks: suite.expect || null };
	report.suites.push(entry);
	if (suite.plugin && !pluginDir) {
		entry.reason = "未执行：缺少插件 checkout（设置 LITESYNC_PLUGIN_DIR）";
		console.log(entry.reason);
		continue;
	}
	let bundlePath;
	try {
		bundlePath = await bundle(suite);
	} catch (e) {
		entry.status = "error";
		entry.reason = `打包失败：${e instanceof Error ? e.message : String(e)}`;
		console.log(entry.reason);
		continue;
	}
	let server = null;
	let base = externalBase;
	let token = process.env.E2E_ADMIN_TOKEN ?? "";
	if (suite.server === "readonly" && externalBase) {
		base = externalReadonly;
		if (!base) {
			entry.reason = "未执行：外部服务端模式下需要另给一个网页编辑关闭的实例（E2E_BASE_READONLY）";
			console.log(entry.reason);
			continue;
		}
	}
	if (!externalBase) {
		server = await startServer(suite.name, suite.server === "editing");
		base = server.base;
		token = server.token;
		entry.server = { version: server.version, webEditing: server.editing, capabilities: server.capabilities };
	} else if (!token) {
		fail("外部服务端模式需要 E2E_ADMIN_TOKEN（该实例的管理员 Token）");
	}
	const t0 = Date.now();
	// E2E_DATA_DIR：只在本机隔离实例下提供（W5 用它核对数据库文件里没有明文路径）
	const { code, result } = await runSuite(suite, bundlePath, { E2E_BASE: base, E2E_ADMIN_TOKEN: token, ...(server ? { E2E_DATA_DIR: server.dataDir } : {}) });
	if (server) await server.stop();
	entry.durationMs = Date.now() - t0;
	if (result) {
		Object.assign(entry, { checks: result.checks, passed: result.passed, failed: result.failed, aborted: result.aborted ?? null, artifacts: result.artifacts ?? [] });
		const total = result.passed + result.failed;
		if (suite.expect && total !== suite.expect && !result.aborted) {
			entry.failed++;
			entry.checks.push({ name: `检查项数量应为 ${suite.expect}`, ok: false, detail: `实际 ${total}` });
		}
		entry.status = entry.failed === 0 && !result.aborted && code === 0 ? "passed" : "failed";
	} else {
		entry.status = "failed";
		entry.reason = `套件进程异常退出（code ${code}），没有写出结果`;
	}
	console.log(`==== ${suite.name}：${entry.status}（${entry.passed} 通过 / ${entry.failed} 失败）`);
}

report.finishedAt = new Date().toISOString();
report.durationMs = Date.now() - started;
report.totals = {
	suites: report.suites.length,
	passedSuites: report.suites.filter((s) => s.status === "passed").length,
	notRun: report.suites.filter((s) => s.status === "not-run").length,
	checksPassed: report.suites.reduce((n, s) => n + s.passed, 0),
	checksFailed: report.suites.reduce((n, s) => n + s.failed, 0),
};
writeFileSync(join(outRoot, "results.json"), JSON.stringify(report, null, 2));
if (!keep) rmSync(work, { recursive: true, force: true });
console.log(`\n结果：${report.totals.passedSuites}/${report.totals.suites} 个套件通过，检查项 ${report.totals.checksPassed} 通过 / ${report.totals.checksFailed} 失败，未执行 ${report.totals.notRun}`);
console.log(`报告：${join(outRoot, "results.json")}`);
process.exit(report.totals.passedSuites === report.totals.suites ? 0 : 1);
