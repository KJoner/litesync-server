import MarkdownIt from "markdown-it";

/**
 * Markdown 渲染（html 关闭，杜绝笔记内嵌 HTML 注入）。
 *
 * 依赖版本（W3）：markdown-it ≥ 14.3.3。14.3.0 在本配置下有两条可达的主线程 CPU 放大
 * （GHSA-gfr2-rv44-r23c 未闭合的多行引用标题、GHSA-253c-mchw-3w2r 软换行 + linkify），
 * 200 KB / 84 KB 的病态输入要数秒；这是可用性问题，不是已证明的 XSS。
 */
export const md = new MarkdownIt({
	html: false,
	linkify: true,
	breaks: true, // 贴近 Obsidian 的换行行为
});

/**
 * 预览渲染的长度门槛（字符）。markdown-it 在主线程同步运行、中途无法打断，所以在开始之前判断：
 * 超过门槛直接降级为源码显示（不改写原文，用户可以主动选择仍要渲染）。14.3.3 下 1 MB 的普通笔记
 * 约 0.2 秒；已知的病态输入在门槛内也落在回归测试的时间预算里（web/test/markdown.test.ts）。
 */
export const RENDER_LIMIT = 1_000_000;

export interface Rendered {
	html: string;
	/** 超过门槛，显示的是源码而不是渲染结果 */
	degraded: boolean;
}

/** 渲染（带长度保护）。app 预览、分享页、离线查看器共用这一个入口。 */
export function renderMarkdown(src: string, opts: { force?: boolean } = {}): Rendered {
	if (!opts.force && src.length > RENDER_LIMIT) {
		const kb = Math.round(src.length / 1024);
		return {
			html: `<p class="banner warn md-degraded">内容过大（约 ${kb} KB），为避免页面长时间卡住，这里直接显示源码。</p><pre class="md-source">${md.utils.escapeHtml(src)}</pre>`,
			degraded: true,
		};
	}
	return { html: md.render(src), degraded: false };
}

// 允许内部资源协议（vault: 图片经解密后替换为 blob URL）
const defaultValidate = md.validateLink.bind(md);
md.validateLink = (url: string) => url.startsWith("vault:") || url.startsWith("#/") || defaultValidate(url);

// 外部图片（需求 §7.4 / 验收 ED-06）：预览**不自动请求**第三方——那会把「谁在什么时候看了哪篇笔记」
// 连同 URL 里可能带的敏感路径一起交给图片主机。渲染成占位 + 用户主动点开的链接，而不是 <img>。
// CSP 的 img-src 仍是第二道防线，但不能只靠它：被 CSP 拦下之前浏览器已经尝试过这次加载。
const defaultImage = md.renderer.rules.image!;
md.renderer.rules.image = (tokens, idx, options, env, self) => {
	const token = tokens[idx];
	const src = token.attrGet("src") ?? "";
	if (/^(https?:)?\/\//i.test(src)) {
		const alt = md.utils.escapeHtml(token.content || "外部图片");
		const href = md.utils.escapeHtml(src);
		return `<span class="remote-img-blocked">🖼 外部图片「${alt}」未自动加载（<a href="${href}" target="_blank" rel="noopener noreferrer">在新标签页打开</a>）</span>`;
	}
	return defaultImage(tokens, idx, options, env, self);
};

const IMAGE_EXT = /\.(png|jpe?g|gif|webp|svg|bmp|avif)$/i;

/**
 * 预处理 Obsidian wiki 语法：
 *   ![[img.png]]        → ![](vault:<resolved-path>)
 *   [[Note]] [[N|别名]]  → [别名](#/n/<encoded-path>)（未能解析时保留纯文本）
 */
export function preprocessWiki(src: string, resolve: (target: string) => string | null): string {
	return src.replace(/(!?)\[\[([^\][\n]+?)\]\]/g, (whole, bang: string, inner: string) => {
		const [targetRaw, alias] = inner.split("|", 2);
		const target = targetRaw.split("#", 1)[0].trim(); // 忽略段落锚
		const label = (alias ?? targetRaw).trim();
		const resolved = resolve(target);
		if (!resolved) return label;
		if (bang === "!" && IMAGE_EXT.test(resolved)) {
			return `![${label}](vault:${encodeURIComponent(resolved)})`;
		}
		return `[${label}](#/n/${encodeURIComponent(resolved)})`;
	});
}

export interface OutlineItem {
	level: number;
	text: string;
	id: string;
}

/** 为渲染结果中的标题分配 id 并返回大纲。 */
export function buildOutline(container: HTMLElement): OutlineItem[] {
	const items: OutlineItem[] = [];
	const heads = container.querySelectorAll<HTMLElement>("h1, h2, h3, h4");
	heads.forEach((h, i) => {
		const id = `h-${i}`;
		h.id = id;
		items.push({ level: parseInt(h.tagName[1], 10), text: h.textContent ?? "", id });
	});
	return items;
}
