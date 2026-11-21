#!/usr/bin/env node
/**
 * 构建产物一致性检查（W7 / RC-2）：`npm run build` 之后运行，逐个比对
 * internal/web/dist/ 与 viewer/ 下的入库文件和 git 索引里的字节是否一致。
 *
 * 为什么不直接 `git diff --exit-code`：Windows 上 copy 会保留源文件时间戳，
 * git 的 stat 缓存可能把「字节变了」误判为「没变」。这里用 `git hash-object`
 * 逐个算内容哈希，与平台和缓存无关。CI（Linux）上两者等价，用哪个都行。
 *
 * 退出码：0 = 全部一致；1 = 有不一致（列出文件）；2 = 环境问题（不是 git 仓库等）。
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const git = (...args) => execFileSync("git", ["-C", repo, ...args], { encoding: "utf8" }).trim();

let tracked;
try {
	tracked = git("ls-files", "--", "internal/web/dist", "viewer").split("\n").filter(Boolean);
} catch (e) {
	console.error("无法读取 git 索引：", e instanceof Error ? e.message : e);
	process.exit(2);
}
const diff = [];
for (const rel of tracked) {
	const abs = join(repo, rel);
	if (!existsSync(abs)) {
		diff.push(`${rel}（构建后缺失）`);
		continue;
	}
	const want = git("rev-parse", `:${rel}`);
	const got = git("hash-object", "--no-filters", "--", rel);
	if (want !== got) diff.push(rel);
}
const untracked = git("ls-files", "--others", "--exclude-standard", "--", "internal/web/dist", "viewer").split("\n").filter(Boolean);
for (const rel of untracked) diff.push(`${rel}（未入库的新产物）`);

if (diff.length > 0) {
	console.error(`✗ 构建产物与入库版本不一致（${diff.length} 个）：\n  ${diff.join("\n  ")}`);
	console.error("改了 web/ 源码就必须重新构建并把 internal/web/dist 与 viewer 一起提交。");
	process.exit(1);
}
console.log(`✓ 构建产物与入库版本逐字节一致（${tracked.length} 个文件）`);
