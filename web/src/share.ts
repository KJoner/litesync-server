/** 公开分享查看页：/share.html#<id>.<keyB64url>
 *  Share Key 在 URL fragment 中，浏览器不会把 fragment 发给服务器。 */
import { b64urlDecode, decryptShare, subtleAvailable, unbundleShare } from "./crypto";
import { renderSharedNote } from "./share-render";

const app = document.getElementById("app")!;

function show(html: string): void {
	app.innerHTML = `<div class="center-screen"><div class="share-card">${html}</div></div>`;
}

function esc(s: string): string {
	return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

async function boot(): Promise<void> {
	document.documentElement.dataset.theme = localStorage.getItem("litesync-theme") ?? "dark";
	const frag = location.hash.slice(1);
	const dot = frag.indexOf(".");
	if (dot <= 0) {
		show(`<div class="brand">◈ LiteSync</div><p class="muted">分享链接不完整。</p>`);
		return;
	}
	const id = frag.slice(0, dot);
	const keyB64 = frag.slice(dot + 1);
	if (!subtleAvailable()) {
		show(`<div class="brand">◈ LiteSync</div><p class="muted">解密需要 HTTPS 环境，请通过 https 链接访问。</p>`);
		return;
	}

	show(`<div class="brand">◈ LiteSync</div><p class="muted">Decrypting locally…</p>`);
	try {
		const res = await fetch(`/share/${encodeURIComponent(id)}`);
		if (res.status === 404) {
			show(`<div class="brand">◈ LiteSync</div><p class="muted">分享不存在、已撤销或已过期。</p>`);
			return;
		}
		if (!res.ok) throw new Error(`HTTP ${res.status}`);
		const payload = await res.arrayBuffer();
		const plain = await decryptShare(b64urlDecode(keyB64), payload);
		if (plain === null) {
			show(`<div class="brand">◈ LiteSync</div><p class="muted">解密失败：链接可能不完整或已被篡改。</p>`);
			return;
		}
		// §7.4：显示名从密文帧里取——它和内容一样受 GCM 保护，
		// 服务器既不知道也改不了。T2.4：内嵌图片附件同帧携带，本地内联渲染
		const framed = unbundleShare(plain);
		const text = new TextDecoder().decode(framed.content);
		if (framed.name !== null) document.title = `${framed.name} — LiteSync`;
		app.innerHTML = "";
		const wrap = document.createElement("div");
		wrap.className = "share-page";
		const head = document.createElement("div");
		head.className = "share-head";
		const title = framed.name === null ? "" : `<span class="share-name">${esc(framed.name)}</span>`;
		head.innerHTML = `<span class="brand-small">◈ LiteSync</span>${title}<span class="muted small">端到端加密分享 · 本地解密</span>`;
		const body = document.createElement("div");
		body.className = "markdown-body note-wrap";
		renderSharedNote(body, text, framed.attachments);
		wrap.append(head, body);
		app.append(wrap);
	} catch (e) {
		show(`<div class="brand">◈ LiteSync</div><p class="muted">加载失败：${esc(e instanceof Error ? e.message : String(e))}</p>`);
	}
}

void boot();
