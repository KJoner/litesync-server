#!/usr/bin/env node
/**
 * 把插件仓的共享核心原样复制进 Web（v0.20 公开化 / ADR-015）。
 *
 * 权威源码在插件仓（KJoner/litesync）：
 *   src/crypto/crypto.ts、src/crypto/padding.ts、src/utils/validate.ts   → crypto-core
 *   src/merge/**                                                         → merge-core（三方合并）
 *   test-vectors/crypto-core-v1.json                                     → 两仓共同验证的冻结向量
 *
 * Web 不手写「近似实现」：网页建库要生成与插件逐字段一致的 keyDoc，网页编辑要产出
 * 插件解得开的信封——任何一处分叉都是静默的数据损坏。所以这里只复制、不修改，并写
 * MANIFEST.json（相对路径 + SHA-256 + 插件版本）；check-core.mjs 拒绝手改与漂移。
 *
 * 用法：node scripts/vendor-core.mjs [插件仓路径，默认 ../../litesync]
 */
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const plugin = process.argv[2] ?? join(webRoot, "..", "..", "litesync");
const dest = join(webRoot, "src", "vendor", "litesync-core");

/** 需要复制的文件（相对插件仓根目录）。目录会递归展开。 */
export const CORE_SOURCES = [
	"src/crypto/crypto.ts",
	"src/crypto/padding.ts",
	"src/utils/validate.ts",
	"src/merge",
	"test-vectors/crypto-core-v1.json",
];

function walk(abs) {
	const st = statSync(abs);
	if (!st.isDirectory()) return [abs];
	return readdirSync(abs).sort().flatMap((n) => walk(join(abs, n)));
}

const pkg = JSON.parse(readFileSync(join(plugin, "package.json"), "utf8"));
if (pkg.name !== "litesync") {
	console.error(`${plugin} 不是 LiteSync 插件仓（package.json name=${pkg.name}）`);
	process.exit(1);
}

rmSync(dest, { recursive: true, force: true });
const files = {};
for (const src of CORE_SOURCES) {
	for (const abs of walk(join(plugin, ...src.split("/")))) {
		const rel = relative(plugin, abs).split(sep).join("/");
		// 源码相对路径整体平移：src/crypto/crypto.ts → vendor/litesync-core/crypto/crypto.ts，
		// 这样文件内部的相对 import（../utils/validate、./padding）原样可用
		const out = rel.startsWith("src/") ? rel.slice(4) : rel;
		const data = readFileSync(abs);
		mkdirSync(dirname(join(dest, out)), { recursive: true });
		writeFileSync(join(dest, out), data);
		files[out] = createHash("sha256").update(data).digest("hex");
	}
}

for (const imp of Object.keys(files).filter((f) => f.endsWith(".ts"))) {
	const text = readFileSync(join(dest, imp), "utf8");
	if (/from\s+["']obsidian["']/.test(text)) {
		console.error(`${imp} 依赖 obsidian——它不是可共享的纯模块，拒绝 vendor`);
		process.exit(1);
	}
}

const manifest = {
	note: "由 web/scripts/vendor-core.mjs 从 LiteSync 插件仓原样复制；不得手改（npm run check:core 校验）",
	pluginVersion: pkg.version,
	files,
};
writeFileSync(join(dest, "MANIFEST.json"), JSON.stringify(manifest, null, "\t") + "\n");
console.log(`vendored ${Object.keys(files).length} files from litesync ${pkg.version} -> ${relative(webRoot, dest)}`);
