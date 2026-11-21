#!/usr/bin/env node
/**
 * 编译并运行 web/test/ 下的全部 *.test.ts（与插件仓 scripts/run-tests.mjs 同款：按目录发现，
 * 新增测试文件不会因为忘了登记而静默不跑）。浏览器 API（Web Crypto）由 Node 22 原生提供。
 */
import { execFileSync } from "node:child_process";
import { readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

const TESTS_DIR = "test";
const OUT_DIR = ".test-build";
const sources = readdirSync(TESTS_DIR).filter((f) => f.endsWith(".test.ts")).sort().map((f) => join(TESTS_DIR, f));
if (sources.length === 0) {
	console.error("web/test/ 下没有找到任何 *.test.ts");
	process.exit(1);
}
console.log(`发现 ${sources.length} 个测试文件`);
rmSync(OUT_DIR, { recursive: true, force: true });
const run = (cmd, args) => execFileSync(cmd, args, { stdio: "inherit", shell: process.platform === "win32" });
run("npx", ["esbuild", ...sources, "--bundle", "--platform=node", "--format=cjs", `--outdir=${OUT_DIR}`, "--log-level=warning"]);
const built = readdirSync(OUT_DIR).filter((f) => f.endsWith(".js")).map((f) => join(OUT_DIR, f));
run("node", ["--test", ...built]);
