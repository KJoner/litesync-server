#!/usr/bin/env node
// 打包并运行联合验收用例（插件原样代码经 esbuild 别名 litesync-plugin 引入）。
//   node e2e/joint/run.mjs <用例名：core | revocation | stage-smoke> --env <环境 JSON> --plugin <litesync 插件目录> --out <输出目录>
// core / revocation 的环境 JSON 是 env.mjs up 写出的 <work>/joint-env.json；stage-smoke 的是本机的 stage-env.json（见 README）。
// esbuild 取自插件目录的 node_modules，Playwright 取自环境 JSON 里 playwrightFrom 指向的目录（Nexus checkout）。
// 输出目录里得到 <用例>-result.json、<用例>.log（控制台输出的副本）与截图；打包产物放在环境 JSON 所在目录的 bundles/ 下。
import { spawn, spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { createWriteStream, existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const argv = process.argv.slice(2);
const name = argv[0];
const opt = (k) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? resolve(argv[i + 1]) : null; };
const envFile = opt("env"), plugin = opt("plugin"), out = opt("out");
const here = dirname(fileURLToPath(import.meta.url));
if (!name || !envFile || !plugin || !out || !existsSync(join(here, `${name}.ts`))) {
	console.error("用法：run.mjs <core | revocation | stage-smoke> --env <环境 JSON> --plugin <插件目录> --out <输出目录>");
	process.exit(2);
}
mkdirSync(out, { recursive: true });
const bundles = join(dirname(envFile), "bundles");
mkdirSync(bundles, { recursive: true });
const esbuild = createRequire(join(plugin, "package.json"))("esbuild");
const bundle = join(bundles, `${name}.bundle.mjs`);
esbuild.buildSync({
	entryPoints: [join(here, `${name}.ts`)], bundle: true, platform: "node", format: "esm", target: "node22", outfile: bundle,
	alias: { "litesync-plugin": plugin, obsidian: join(plugin, "scripts", "interop", "obsidian-shim.ts") },
	external: ["@playwright/test", "playwright", "playwright-core"],
	banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
	logLevel: "warning",
});
// 插件 checkout 的提交（结果 JSON 里与 up 时记下的服务端、Nexus 提交并列）
const git = (args) => spawnSync("git", args, { cwd: plugin, encoding: "utf8" }).stdout?.trim() ?? "";
const meta = { plugin: { sha: git(["rev-parse", "HEAD"]) || null, dirty: git(["status", "--porcelain", "--untracked-files=no"]) !== "" } };
const log = createWriteStream(join(out, `${name}.log`));
const child = spawn(process.execPath, [bundle, envFile, out], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, JOINT_RUN_META: JSON.stringify(meta) } });
for (const s of [child.stdout, child.stderr]) s.on("data", (d) => { process.stdout.write(d); log.write(d); });
const code = await new Promise((r) => child.on("close", r));
await new Promise((r) => log.end(r));
process.exit(code ?? 1);
