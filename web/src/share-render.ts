/**
 * 分享笔记的渲染（在线分享页与离线 viewer 共用，0.17.0-rc.3 / 验收 T2.4）。
 *
 * 内嵌图片的字节随分享一起加密（LSN2 帧），这里在本地把
 * `![[img.png]]` 与 `![](img.png)` 解析到附件字节并以 blob URL 内联；
 * 解析不到的引用保持旧行为（wiki 语法降级为纯文本，标准语法保持原样）。
 * 与登录后 reader 的能力对齐：只有图片内联，笔记/PDF 嵌入降级为文本。
 */
import { ShareAttachment } from "./crypto";
import { md, preprocessWiki } from "./markdown";

const MIME: Record<string, string> = {
	png: "image/png",
	jpg: "image/jpeg",
	jpeg: "image/jpeg",
	gif: "image/gif",
	webp: "image/webp",
	svg: "image/svg+xml",
	bmp: "image/bmp",
	avif: "image/avif",
};

function mimeOf(path: string): string {
	const ext = path.slice(path.lastIndexOf(".") + 1).toLowerCase();
	return MIME[ext] ?? "application/octet-stream";
}

const baseName = (p: string): string => p.slice(p.lastIndexOf("/") + 1).toLowerCase();

/** 把分享正文渲染进容器，内嵌图片从附件表取字节本地内联。 */
export function renderSharedNote(container: HTMLElement, text: string, attachments: ShareAttachment[]): void {
	const byPath = new Map<string, ShareAttachment>();
	const byBase = new Map<string, ShareAttachment>();
	for (const a of attachments) {
		byPath.set(a.path, a);
		if (!byBase.has(baseName(a.path))) byBase.set(baseName(a.path), a);
	}
	const find = (target: string): ShareAttachment | undefined => {
		return byPath.get(target) ?? byBase.get(baseName(target));
	};
	// wiki 语法：附件表里有的解析为 vault: 图片；其余保持「降级为纯文本」的旧行为
	//（附件表只含图片，因此 preprocessWiki 的笔记链接分支在分享页永远不会命中）
	const resolve = (target: string): string | null => find(target)?.path ?? null;

	container.innerHTML = md.render(preprocessWiki(text, resolve));

	// 标准 markdown 图片：`![](dir/img.png)` 的 src 是相对路径 → 同样查附件表；
	// 外链图片不动（在线页由服务器 CSP 拦、离线 viewer 由页面 CSP 拦）
	for (const img of Array.from(container.querySelectorAll("img"))) {
		const src = img.getAttribute("src") ?? "";
		let att: ShareAttachment | undefined;
		if (src.startsWith("vault:")) {
			att = byPath.get(tryDecode(src.slice(6)));
		} else if (!/^[a-z][a-z0-9+.-]*:/i.test(src)) {
			att = find(tryDecode(src));
		}
		if (att) {
			img.src = URL.createObjectURL(new Blob([att.data], { type: mimeOf(att.path) }));
		} else if (src.startsWith("vault:")) {
			// 附件缺失的 vault: 引用：还原为文件名文本，别留一个坏 src
			img.replaceWith(document.createTextNode(img.getAttribute("alt") || tryDecode(src.slice(6))));
		}
	}
}

function tryDecode(s: string): string {
	try {
		return decodeURIComponent(s);
	} catch {
		return s;
	}
}
