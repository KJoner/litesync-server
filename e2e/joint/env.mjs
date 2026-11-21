#!/usr/bin/env node
// LiteSync × Nexus 联合验收环境：一次性容器（Keycloak + PostgreSQL 三库三角色 + Mailpit）
// + 本机构建的 LiteSync 服务端 + 本机构建的 Nexus 服务端。全部合成数据、随机密钥。
//
//   node e2e/joint/env.mjs up   --work <临时目录> --nexus <nexus-portal 目录> [--server <litesync-server 目录>] [--port-base 28000] [--project <名字>]
//   node e2e/joint/env.mjs down --work <临时目录> [--purge]
//   node e2e/joint/env.mjs stop-nexus | start-nexus --work <临时目录>
//
// up 结束时写出 <work>/joint-env.json（地址、端口、各密钥文件的路径）。密钥只写进 <work> 下的文件，
// 不打印到终端或日志。Keycloak 与 PostgreSQL 只绑 127.0.0.1；两个产品监听 0.0.0.0（容器里的
// Keycloak 要经 host.docker.internal 回调它们的 back-channel logout），测试结束务必 down。
// --project：compose 项目名（也是容器名前缀），默认由 <work> 的完整路径哈希得到；down --purge 连同 <work>（含密钥）一起删除。
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { cpSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const argv = process.argv.slice(2);
const cmd = argv[0];
const opt = (name, def) => {
	const i = argv.indexOf(`--${name}`);
	return i >= 0 ? argv[i + 1] : def;
};
const work = opt("work") && resolve(opt("work"));
if (!work || !["up", "down", "stop-nexus", "start-nexus"].includes(cmd)) {
	console.error("用法：env.mjs up --work <目录> --nexus <目录> [--server <目录>] [--port-base N] [--project <名字>] | env.mjs down --work <目录> [--purge] | env.mjs stop-nexus|start-nexus --work <目录>");
	process.exit(2);
}
// 项目名优先取 up 时记下的（down / stop / start 不必再传 --project）
const recorded = (() => {
	try {
		return JSON.parse(readFileSync(join(work, "joint-env.json"), "utf8")).project;
	} catch {
		return undefined;
	}
})();
const project = opt("project") ?? recorded ?? "lsjoint" + createHash("sha256").update(work).digest("hex").slice(0, 8);
if (!/^[a-z0-9][a-z0-9_-]*$/.test(project)) {
	console.error(`--project 只能用小写字母、数字、- 和 _：${project}`);
	process.exit(2);
}
const isWin = process.platform === "win32";

function gitSha(dir) {
	return run("git", ["rev-parse", "HEAD"], { cwd: dir, quiet: true }).stdout.trim();
}
function gitDirty(dir) {
	return run("git", ["status", "--porcelain", "--untracked-files=no"], { cwd: dir, quiet: true }).stdout.trim() !== "";
}
function run(bin, args, opts = {}) {
	const r = spawnSync(bin, args, { stdio: opts.quiet ? "pipe" : "inherit", encoding: "utf8", shell: false, ...opts });
	if (r.status !== 0 && !opts.allowFail) throw new Error(`${bin} ${args.slice(0, 3).join(" ")}… 退出码 ${r.status}${r.stderr ? "：" + String(r.stderr).slice(0, 400) : ""}`);
	return r;
}
const secret = (n = 24) => randomBytes(n).toString("base64url");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitHttp(url, okStatus = (s) => s === 200, ms = 180_000) {
	const end = Date.now() + ms;
	while (Date.now() < end) {
		try {
			const r = await fetch(url);
			if (okStatus(r.status)) return true;
		} catch {}
		await sleep(1000);
	}
	throw new Error(`等待超时：${url}`);
}

function startNexus() {
	const cfg = JSON.parse(readFileSync(join(work, "nexus-env.json"), "utf8"));
	const log = openSync(join(work, "nexus.log"), "a");
	const child = spawn(process.execPath, [join(cfg.nexusDir, "apps", "server", "dist", "index.mjs")], { cwd: cfg.nexusDir, env: { ...process.env, ...cfg.env }, stdio: ["ignore", log, log], detached: true });
	child.unref();
	return child;
}
function updatePid(name, pid) {
	const f = join(work, "joint-env.json");
	const e = JSON.parse(readFileSync(f, "utf8"));
	e.pids[name] = pid;
	writeFileSync(f, JSON.stringify(e, null, 2));
}
if (cmd === "stop-nexus") {
	const e = JSON.parse(readFileSync(join(work, "joint-env.json"), "utf8"));
	try { process.kill(e.pids.nexus); } catch {}
	const end = Date.now() + 15000;
	while (Date.now() < end) { try { await fetch(`${e.urls.nexusLocal}/`); await sleep(500); } catch { break; } }
	console.log("Nexus 已停止");
	process.exit(0);
}
if (cmd === "start-nexus") {
	const e = JSON.parse(readFileSync(join(work, "joint-env.json"), "utf8"));
	const child = startNexus();
	updatePid("nexus", child.pid);
	await waitHttp(`${e.urls.nexusLocal}/`, (st) => st < 500);
	console.log("Nexus 已重新启动");
	process.exit(0);
}

if (cmd === "down") {
	const envFile = join(work, "joint-env.json");
	if (existsSync(envFile)) {
		const env = JSON.parse(readFileSync(envFile, "utf8"));
		for (const pid of [env.pids?.litesync, env.pids?.nexus].filter(Boolean)) {
			try { process.kill(pid); } catch {}
		}
	}
	run("docker", ["rm", "-f", `${project}-mailpit`], { allowFail: true, quiet: true });
	if (existsSync(join(work, "identity", "compose.yaml"))) {
		run("docker", ["compose", "-p", project, "down", "-v"], { cwd: join(work, "identity"), allowFail: true });
	}
	if (argv.includes("--purge")) {
		await sleep(1000); // 等两个进程释放日志与数据目录
		rmSync(work, { recursive: true, force: true });
		console.log(`已停止并删除联合验收环境（compose 项目 ${project}）与临时目录（含密钥）：${work}`);
	} else {
		console.log(`已停止并删除联合验收环境（compose 项目 ${project}）。临时目录保留（含密钥，用完请删除或改用 --purge）：${work}`);
	}
	process.exit(0);
}

// ── up ──
const nexusDir = resolve(opt("nexus", ""));
const serverDir = resolve(opt("server", fileURLToPath(new URL("../..", import.meta.url))));
if (!existsSync(join(nexusDir, "infra", "identity", "compose.yaml"))) throw new Error(`--nexus 不是 nexus-portal 目录：${nexusDir}`);
if (!existsSync(join(serverDir, "cmd", "obsync"))) throw new Error(`--server 不是 litesync-server 目录：${serverDir}`);
const base = Number(opt("port-base", "28000"));
const ports = { keycloak: base + 180, postgres: base + 432, mailUi: base + 25, smtp: base + 26, litesync: base + 81, nexus: base + 787 };
mkdirSync(work, { recursive: true });
// 先记下项目名：后面任何一步失败，down 都能找到要删的容器
writeFileSync(join(work, "joint-env.json"), JSON.stringify({ project, work, pids: {} }, null, 2));
const idDir = join(work, "identity");
rmSync(idDir, { recursive: true, force: true });
cpSync(join(nexusDir, "infra", "identity"), idDir, { recursive: true });

const s = {
	pgSuper: secret(), kcDb: secret(), nexusDb: secret(), lsDb: secret(), kcAdmin: secret(),
	nexusClient: secret(32), lsClient: secret(32), peer: secret(32), lsAdminToken: secret(32), nexusSecret: secret(32),
};
writeFileSync(join(work, "secrets.json"), JSON.stringify(s, null, 2), { mode: 0o600 });
const accounts = `http://localhost:${ports.keycloak}`;
const nexusUrl = `http://host.docker.internal:${ports.nexus}`;
// LiteSync 只接受 https 或本机地址作公网地址：浏览器用 127.0.0.1；容器里的 Keycloak 经 host.docker.internal 回调（下面单独改 back-channel 地址）
const lsUrl = `http://127.0.0.1:${ports.litesync}`;
writeFileSync(join(idDir, ".env"), [
	`ACCOUNTS_PUBLIC_URL=${accounts}`, `NEXUS_PUBLIC_URL=${nexusUrl}`, `LITESYNC_PUBLIC_URL=${lsUrl}`,
	`KEYCLOAK_PORT=${ports.keycloak}`, `POSTGRES_PORT=${ports.postgres}`,
	`POSTGRES_SUPERUSER_PASSWORD=${s.pgSuper}`, `KEYCLOAK_DB_PASSWORD=${s.kcDb}`, `NEXUS_DB_PASSWORD=${s.nexusDb}`, `LITESYNC_DB_PASSWORD=${s.lsDb}`,
	`KEYCLOAK_BOOTSTRAP_ADMIN=joint-admin`, `KEYCLOAK_BOOTSTRAP_PASSWORD=${s.kcAdmin}`,
	`NEXUS_OIDC_CLIENT_SECRET=${s.nexusClient}`, `LITESYNC_OIDC_CLIENT_SECRET=${s.lsClient}`,
	`SMTP_HOST=${project}-mailpit`, `SMTP_PORT=1025`, `SMTP_SECURITY=none`, `SMTP_USER=`, `SMTP_PASSWORD=`,
	`SMTP_FROM=no-reply@accounts.example.test`, `SMTP_FROM_NAME=联合验收账号中心`, "",
].join("\n"), { mode: 0o600 });

console.log(`① 启动 Keycloak + PostgreSQL（compose 项目 ${project}）`);
run("docker", ["compose", "-p", project, "up", "-d"], { cwd: idDir });
await waitHttp(`${accounts}/realms/accounts/.well-known/openid-configuration`, (st) => st === 200, 300_000);
// litesync-web 的 back-channel 地址：Keycloak 在容器里，127.0.0.1 指向容器自己，改成 host.docker.internal
run("docker", ["compose", "-p", project, "exec", "-T", "keycloak", "sh", "-c",
	"/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user joint-admin --password \"$KC_BOOTSTRAP_ADMIN_PASSWORD\" >/dev/null && " +
	"/opt/keycloak/bin/kcadm.sh get clients -r accounts -q clientId=litesync-web --fields id --format csv --noquotes | xargs -I{} /opt/keycloak/bin/kcadm.sh update clients/{} -r accounts " +
	`-s 'attributes."backchannel.logout.url"=http://host.docker.internal:${ports.litesync}/auth/backchannel-logout'`], { cwd: idDir, quiet: true });
console.log("② 启动本机收信器 Mailpit 并让 Keycloak 使用它");
run("docker", ["rm", "-f", `${project}-mailpit`], { allowFail: true, quiet: true });
// 关掉反向 DNS：Docker Desktop 上每个 SMTP 连接都要等约 9 秒的 PTR 超时，Keycloak 的发信（读超时 10 秒）会因此失败，
// 产品通知积压时更明显（2026-11-21 实测：开启时 9.35 秒，关闭后 1.3 秒）
run("docker", ["run", "-d", "--name", `${project}-mailpit`, "--network", `${project}_default`, "-e", "MP_SMTP_DISABLE_RDNS=true",
	"-p", `127.0.0.1:${ports.mailUi}:8025`, "-p", `127.0.0.1:${ports.smtp}:1025`, "axllent/mailpit:v1.33.0"], { quiet: true });
run("sh", ["./configure.sh", "smtp"], { cwd: idDir, env: { ...process.env, COMPOSE_PROJECT_NAME: project, MSYS_NO_PATHCONV: "1" }, quiet: true });

console.log("③ 构建并启动 LiteSync 服务端（PostgreSQL 模式，库 litesync）");
const lsBin = join(work, isWin ? "obsync-joint.exe" : "obsync-joint");
run("go", ["build", "-o", lsBin, "./cmd/obsync"], { cwd: serverDir });
const lsData = join(work, "ls-data");
mkdirSync(lsData, { recursive: true });
const lsEnv = {
	...process.env,
	OBSYNC_LISTEN: `0.0.0.0:${ports.litesync}`, OBSYNC_DATA_DIR: lsData, OBSYNC_TOKEN: s.lsAdminToken,
	OBSYNC_DB: "postgres", OBSYNC_PG_DSN: `postgres://litesync_app:${s.lsDb}@127.0.0.1:${ports.postgres}/litesync?sslmode=disable`,
	OBSYNC_PUBLIC_URL: lsUrl, OBSYNC_OIDC_ISSUER: `${accounts}/realms/accounts`, OBSYNC_OIDC_CLIENT_ID: "litesync-web", OBSYNC_OIDC_CLIENT_SECRET: s.lsClient,
	OBSYNC_OIDC_STATUS_CLIENT_ID: "litesync-web", OBSYNC_OIDC_STATUS_CLIENT_SECRET: s.lsClient,
	OBSYNC_PEER_REVOCATION_URL: `http://127.0.0.1:${ports.nexus}`, OBSYNC_PEER_REVOCATION_SECRET: s.peer,
	OBSYNC_REGISTRATION_MODE: "open", OBSYNC_LEGACY_TOKEN_LOGIN: "true", OBSYNC_WEB_EDITING: "true", OBSYNC_QUOTA_BYTES_PER_USER: String(512 * 1024 * 1024),
	OBSYNC_MAIL_PROVIDER: "smtp", OBSYNC_SMTP_HOST: "127.0.0.1", OBSYNC_SMTP_PORT: String(ports.smtp), OBSYNC_SMTP_TLS: "none", OBSYNC_MAIL_FROM: "LiteSync 联合验收 <no-reply@sync.example.test>",
	OBSYNC_LOG_LEVEL: "info",
};
const lsLog = openSync(join(work, "litesync.log"), "a");
const ls = spawn(lsBin, [], { env: lsEnv, stdio: ["ignore", lsLog, lsLog], detached: true });
ls.unref();

console.log("④ 构建并启动 Nexus（PostgreSQL 模式，库 nexus）");
run("npm", ["run", "build"], { cwd: nexusDir, shell: isWin });
const nexusData = join(work, "nexus-data");
mkdirSync(nexusData, { recursive: true });
const nexusEnv = {
	...process.env,
	// 生产模式强制 https；本机 HTTP 环境用 development（前端仍是生产构建，Service Worker 照常注册）
	NODE_ENV: "development", HOST: "0.0.0.0", PORT: String(ports.nexus), NEXUS_DATA_DIR: nexusData, NEXUS_SECRET: s.nexusSecret,
	NEXUS_PUBLIC_URL: nexusUrl, NEXUS_COOKIE_SECURE: "never", NEXUS_DATABASE_URL: `postgres://nexus_app:${s.nexusDb}@127.0.0.1:${ports.postgres}/nexus`,
	NEXUS_OIDC_ISSUER: `${accounts}/realms/accounts`, NEXUS_OIDC_CLIENT_ID: "nexus-web", NEXUS_OIDC_CLIENT_SECRET: s.nexusClient,
	NEXUS_PEER_REVOCATION_URL: `http://127.0.0.1:${ports.litesync}`, NEXUS_PEER_REVOCATION_SECRET: s.peer,
	NEXUS_REGISTRATION_MODE: "open", // NEXUS_LITESYNC_URL 要求 https，本机环境不设
	NEXUS_MAIL_PROVIDER: "smtp", NEXUS_SMTP_URL: `smtp://127.0.0.1:${ports.smtp}`, NEXUS_MAIL_FROM: "Nexus 联合验收 <no-reply@home.example.test>",
};
// ADR-019 §2.5：Nexus 用 nexus-web 自己的只读服务账号做中心状态检查
nexusEnv.NEXUS_IDENTITY_STATUS_CHECK = "on";
writeFileSync(join(work, "nexus-env.json"), JSON.stringify({ nexusDir, env: Object.fromEntries(Object.entries(nexusEnv).filter(([k]) => k.startsWith("NEXUS_") || ["NODE_ENV", "HOST", "PORT"].includes(k))) }), { mode: 0o600 });
const nx = startNexus();
// 先写一份只有 pid 的记录：后面任何一步失败，down 也能停掉这两个进程
writeFileSync(join(work, "joint-env.json"), JSON.stringify({ project, work, pids: { litesync: ls.pid, nexus: nx.pid } }, null, 2));

await waitHttp(`http://127.0.0.1:${ports.litesync}/health`);
await waitHttp(`http://127.0.0.1:${ports.nexus}/`, (st) => st < 500);
const out = {
	project, work, ports, pids: { litesync: ls.pid, nexus: nx.pid },
	urls: { accounts, issuer: `${accounts}/realms/accounts`, nexus: nexusUrl, litesync: lsUrl, mailpit: `http://127.0.0.1:${ports.mailUi}`, litesyncLocal: `http://127.0.0.1:${ports.litesync}`, nexusLocal: `http://127.0.0.1:${ports.nexus}` },
	secretsFile: join(work, "secrets.json"), keycloakAdminUser: "joint-admin",
	browserArgs: ["--host-resolver-rules=MAP host.docker.internal 127.0.0.1"],
	versions: { keycloak: "26.8.1", postgres: "17.10", mailpit: "1.33.0", node: process.version },
	envScript: fileURLToPath(import.meta.url),
	playwrightFrom: join(nexusDir, "package.json"),
	// 构建两个产品时各自 checkout 的提交；dirty = 当时有未提交的已跟踪改动（未跟踪文件不算）
	shas: { server: gitSha(serverDir), nexus: gitSha(nexusDir) },
	dirty: { server: gitDirty(serverDir), nexus: gitDirty(nexusDir) },
};
writeFileSync(join(work, "joint-env.json"), JSON.stringify(out, null, 2));
console.log(`联合验收环境已就绪：${join(work, "joint-env.json")}`);
