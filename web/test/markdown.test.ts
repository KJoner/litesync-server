// W3（RC-2）：markdown-it 已升到 ≥ 14.3.3；审查给出的两组病态输入在**明确的时间预算**内完成，
// 超过长度门槛的内容直接降级为源码显示（不在主线程上同步渲染）。这是 CPU / 可用性回归，不是 XSS 验收。
//
// 预算取 1500 ms：14.3.0 在本项目配置下这两组输入是 2–4 秒（审查记录：200 KB 多行引用 3901 ms、
// 84 KB linkify 4334 ms；主线程在 7c30b8a 上复测 2321 ms / 2048 ms），14.3.3 约 0.1–0.2 秒——
// 预算对慢一些的 CI 机器留了 7 倍以上余量，又足以抓住回退到受影响版本。
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { performance } from "node:perf_hooks";
import { test } from "node:test";
import { md, RENDER_LIMIT, renderMarkdown } from "../src/markdown";

const BUDGET_MS = 1500;

function timed(src: string): { ms: number; degraded: boolean; html: string } {
	const t = performance.now();
	const r = renderMarkdown(src);
	return { ms: performance.now() - t, degraded: r.degraded, html: r.html };
}

test("依赖版本：markdown-it ≥ 14.3.3（锁文件与打包进产物的是同一个）", () => {
	const req = createRequire(__filename);
	const v = req("markdown-it/package.json").version as string;
	const [maj, min, patch] = v.split(".").map(Number);
	assert.ok(maj > 14 || (maj === 14 && (min > 3 || (min === 3 && patch >= 3))), `markdown-it ${v} 低于 14.3.3`);
});

test("GHSA-gfr2-rv44-r23c：200 KB 未闭合的多行引用标题在预算内渲染", () => {
	const src = '[a]: /u "' + "x\n".repeat(100000);
	assert.ok(src.length < RENDER_LIMIT, "这组输入在长度门槛内：必须真的渲染、并且足够快");
	const r = timed(src);
	assert.equal(r.degraded, false);
	assert.ok(r.ms < BUDGET_MS, `耗时 ${r.ms.toFixed(0)} ms，超过预算 ${BUDGET_MS} ms`);
});

test("GHSA-253c-mchw-3w2r：84 KB 软换行邮箱（linkify）在预算内渲染", () => {
	const src = "a@b.co\n".repeat(12000);
	const r = timed(src);
	assert.equal(r.degraded, false);
	assert.ok(r.ms < BUDGET_MS, `耗时 ${r.ms.toFixed(0)} ms，超过预算 ${BUDGET_MS} ms`);
	assert.ok(r.html.includes('href="mailto:a@b.co"'), "linkify 仍然生效（功能没有被关掉来「修」性能）");
});

test("超过长度门槛：直接降级为源码显示（转义、不渲染），且立即返回", () => {
	const src = "<script>x</script>\n" + '[a]: /u "' + "x\n".repeat(RENDER_LIMIT);
	const r = timed(src);
	assert.equal(r.degraded, true);
	assert.ok(r.ms < 200, `降级路径耗时 ${r.ms.toFixed(0)} ms`);
	assert.ok(r.html.includes("内容过大") && r.html.includes('class="md-source"'));
	assert.ok(!r.html.includes("<script>") && r.html.includes("&lt;script&gt;"), "源码显示同样转义");
	assert.equal(renderMarkdown("# 标题", { force: true }).degraded, false);
});

test("安全配置未变：html 关闭、javascript: 链接被拒、typographer 关闭", () => {
	assert.equal(md.options.html, false);
	assert.equal(md.options.typographer, false);
	for (const p of ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "[click](javascript:alert(1))", "![x](javascript:alert(1))"]) {
		const out = renderMarkdown(p).html;
		assert.equal(/<script|<img[^>]+onerror|(?:href|src)="javascript:/i.test(out), false, p);
	}
});
