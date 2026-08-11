/**
 * 离线单文件分享查看器（v9.2，审查 17）。
 *
 * 信任边界：服务器下发的查看页 JS 可以被「已控制服务器的攻击者」替换，
 * 把 fragment 里的 Share Key 偷传回去——「服务器无法解密」对恶意服务器不成立。
 * 本文件构建为完全自包含的 HTML（无任何外部请求，除了拉取分享密文本身），
 * 用户从代码仓库下载一次、本地保存打开，之后即使服务器被攻陷也偷不到密钥。
 *
 * 用法：本地打开 litesync-viewer.html → 粘贴分享链接 → 本地解密渲染。
 */
import { b64urlDecode, decryptShare, subtleAvailable } from "./crypto";
import { md } from "./markdown";

const $ = (id: string): HTMLElement => document.getElementById(id)!;

function esc(s: string): string {
	return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function status(html: string): void {
	$("status").innerHTML = html;
	$("note").innerHTML = "";
}

/** 解析分享链接：https://server/share.html#<id>.<keyB64url> */
function parseShareUrl(raw: string): { origin: string; id: string; keyB64: string } | null {
	try {
		const u = new URL(raw.trim());
		if (u.protocol !== "https:" && u.protocol !== "http:") return null;
		const frag = u.hash.slice(1);
		const dot = frag.indexOf(".");
		if (dot <= 0) return null;
		return { origin: u.origin, id: frag.slice(0, dot), keyB64: frag.slice(dot + 1) };
	} catch {
		return null;
	}
}

async function view(): Promise<void> {
	const input = $("link") as HTMLInputElement;
	const parsed = parseShareUrl(input.value);
	if (!parsed) {
		status(`<span class="err">链接格式不正确（需要形如 https://server/share.html#id.key 的完整分享链接）</span>`);
		return;
	}
	if (!subtleAvailable()) {
		status(`<span class="err">此环境不支持 WebCrypto，无法本地解密</span>`);
		return;
	}
	status("正在获取密文并本地解密…（密钥不会发送给任何服务器）");
	try {
		const res = await fetch(`${parsed.origin}/share/${encodeURIComponent(parsed.id)}`);
		if (res.status === 404) {
			status(`<span class="err">分享不存在、已撤销或已过期</span>`);
			return;
		}
		if (!res.ok) throw new Error(`HTTP ${res.status}`);
		const payload = await res.arrayBuffer();
		const plain = await decryptShare(b64urlDecode(parsed.keyB64), payload);
		if (plain === null) {
			status(`<span class="err">解密失败：链接可能不完整或数据被篡改</span>`);
			return;
		}
		const text = new TextDecoder().decode(plain);
		$("status").innerHTML = `<span class="ok">✓ 已本地解密（服务器只见过密文）</span>`;
		$("note").innerHTML = md.render(
			text.replace(/(!?)\[\[([^\][\n]+?)\]\]/g, (_w, _b, inner: string) => esc(inner.split("|").pop() ?? "")),
		);
	} catch (e) {
		status(
			`<span class="err">加载失败：${esc(e instanceof Error ? e.message : String(e))}</span>` +
				`<br><span class="muted">提示：服务器需要 0.10.0+（/share 接口开放跨源读取）；本地 file:// 页面访问 http 站点可能被浏览器拦截</span>`,
		);
	}
}

$("view").onclick = () => void view();
($("link") as HTMLInputElement).addEventListener("keydown", (e) => {
	if (e.key === "Enter") void view();
});
