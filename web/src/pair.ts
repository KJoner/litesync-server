/**
 * 扫码落地页（v8 新设备接入）。
 *
 * 二维码内容是 https://server/p/{id}#secret=…；本页从 location 读出
 * id 与 fragment 中的 secret，拼成 obsidian:// 深链交给 Obsidian 插件。
 * secret 在 #fragment 中，浏览器不会把它发给服务器；obsidian:// 跳转
 * 由操作系统本地传递给 Obsidian，同样不经过网络。
 */

const app = document.getElementById("app")!;

function render(children: HTMLElement[]): void {
	app.innerHTML = "";
	const wrap = document.createElement("div");
	wrap.className = "center-screen";
	const card = document.createElement("div");
	card.className = "center-card";
	const brand = document.createElement("div");
	brand.className = "brand";
	brand.textContent = "◈ LiteSync";
	card.append(brand, ...children);
	wrap.append(card);
	app.append(wrap);
}

function el(tag: string, cls: string, text: string): HTMLElement {
	const node = document.createElement(tag);
	node.className = cls;
	node.textContent = text;
	return node;
}

const idMatch = /^\/p\/([0-9a-f]+)$/i.exec(location.pathname);
const pairId = idMatch?.[1] ?? "";
const secret = new URLSearchParams(location.hash.slice(1)).get("secret") ?? "";

if (!pairId || !secret) {
	render([
		el("p", "muted", "配对链接不完整。"),
		el("p", "muted small", "请在原设备上重新生成「添加新设备」二维码，并使用完整链接打开本页。"),
	]);
} else {
	const target =
		"obsidian://litesync-import?server=" +
		encodeURIComponent(location.origin) +
		"&id=" +
		encodeURIComponent(pairId) +
		"&secret=" +
		encodeURIComponent(secret);

	const sub = el("p", "muted", "正在添加此设备");
	const hint = el("p", "muted small", "请确保本设备已安装 Obsidian 与 LiteSync 插件，然后点击下方按钮。");
	const btn = document.createElement("button");
	btn.className = "primary";
	btn.textContent = "在 Obsidian 中打开";
	btn.onclick = () => {
		location.href = target;
	};
	const note = el("p", "muted small", "配对链接 5 分钟内有效，且只能使用一次。");
	render([sub, hint, btn, note]);
}
