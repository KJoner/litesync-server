#!/usr/bin/env node
/**
 * 校验 vendor 进来的共享核心（ADR-015）。
 *
 *   1. 副本未被手改：每个文件的 SHA-256 必须等于 MANIFEST.json —— 始终强制；
 *   2. 没有漂移：本机存在同级插件仓（../../litesync）时，副本必须与插件当前源码一致。
 *      默认只警告（插件仓可能在别的分支上）；LITESYNC_CORE_STRICT=1 时失败——发版前必开。
 *
 * build 前自动执行（package.json 的 build 脚本），失败即中止构建。
 */
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const dest = join(webRoot, "src", "vendor", "litesync-core");
const manifestPath = join(dest, "MANIFEST.json");
if (!existsSync(manifestPath)) {
	console.error("缺少 src/vendor/litesync-core/MANIFEST.json——先运行 node scripts/vendor-core.mjs");
	process.exit(1);
}
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");

let failed = false;
const listed = new Set(Object.keys(manifest.files));
for (const [rel, want] of Object.entries(manifest.files)) {
	const p = join(dest, ...rel.split("/"));
	if (!existsSync(p)) {
		console.error(`✗ 缺少 vendor 文件 ${rel}`);
		failed = true;
	} else if (sha(p) !== want) {
		console.error(`✗ ${rel} 与 MANIFEST 不符——vendor 副本不得手改；需要改动请先改插件仓再重新 vendor`);
		failed = true;
	}
}
const walk = (abs) => (statSync(abs).isDirectory() ? readdirSync(abs).flatMap((n) => walk(join(abs, n))) : [abs]);
for (const abs of walk(dest)) {
	const rel = relative(dest, abs).split(sep).join("/");
	if (rel !== "MANIFEST.json" && !listed.has(rel)) {
		console.error(`✗ vendor 目录里多出了 MANIFEST 未登记的文件 ${rel}`);
		failed = true;
	}
}

const plugin = join(webRoot, "..", "..", "litesync");
const strict = process.env.LITESYNC_CORE_STRICT === "1";
if (existsSync(join(plugin, "package.json"))) {
	const drift = [];
	for (const [rel, want] of Object.entries(manifest.files)) {
		const src = join(plugin, ...(rel.startsWith("test-vectors/") ? rel : "src/" + rel).split("/"));
		if (!existsSync(src) || sha(src) !== want) drift.push(rel);
	}
	if (drift.length > 0) {
		const msg = `插件仓与 vendor 副本不一致（${drift.length} 个文件）：${drift.join(", ")}——运行 node scripts/vendor-core.mjs 同步`;
		if (strict) {
			console.error("✗ " + msg);
			failed = true;
		} else {
			console.warn("⚠ " + msg);
		}
	}
}

if (failed) process.exit(1);
console.log(`✓ litesync-core vendor 校验通过（插件 ${manifest.pluginVersion}，${listed.size} 个文件）`);
