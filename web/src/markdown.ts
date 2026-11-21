import MarkdownIt from "markdown-it";

/** Markdown 渲染（html 关闭，杜绝笔记内嵌 HTML 注入）。 */
export const md = new MarkdownIt({
	html: false,
	linkify: true,
	breaks: true, // 贴近 Obsidian 的换行行为
});

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
