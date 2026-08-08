/** LiteSync Web 只读端主应用：文件树 + Markdown 阅读 + Outline + 历史 + Diff。 */
import { Api, AuthError, FileEntry, VersionEntry } from "./api";
import {
	b64decode,
	b64encode,
	decryptFile,
	importVmk,
	isEncryptedFile,
	subtleAvailable,
	unlockVaultKey,
	VaultKeyDoc,
} from "./crypto";
import { DiffLine, diffLines } from "./diff";
import { buildOutline, md, preprocessWiki } from "./markdown";

const TOKEN_KEY = "litesync-token";
const THEME_KEY = "litesync-theme";
const VMK_KEY = "litesync-vmk"; // sessionStorage：仅本浏览器会话

const IMAGE_EXT = /\.(png|jpe?g|gif|webp|svg|bmp|avif)$/i;

interface State {
	api: Api;
	files: FileEntry[];
	byPath: Map<string, FileEntry>;
	vaultDoc: VaultKeyDoc | null;
	vmk: CryptoKey | null;
}

let S: State | null = null;
const app = document.getElementById("app")!;
const blobUrls: string[] = [];

// ---------- 主题 ----------
function applyTheme(): void {
	document.documentElement.dataset.theme = localStorage.getItem(THEME_KEY) ?? "dark";
}
function toggleTheme(): void {
	const cur = localStorage.getItem(THEME_KEY) ?? "dark";
	localStorage.setItem(THEME_KEY, cur === "dark" ? "light" : "dark");
	applyTheme();
}

// ---------- 工具 ----------
function el<K extends keyof HTMLElementTagNameMap>(
	tag: K,
	cls?: string,
	text?: string,
): HTMLElementTagNameMap[K] {
	const node = document.createElement(tag);
	if (cls) node.className = cls;
	if (text !== undefined) node.textContent = text;
	return node;
}

function fmtTime(unixMs: number): string {
	return new Date(unixMs).toLocaleString();
}

function noteTitle(path: string): string {
	const base = path.slice(path.lastIndexOf("/") + 1);
	return base.replace(/\.md$/i, "");
}

function isVisible(path: string): boolean {
	return !path.split("/").some((seg) => seg.startsWith("."));
}

async function decodeContent(path: string, data: ArrayBuffer): Promise<ArrayBuffer> {
	if (!isEncryptedFile(data)) return data;
	if (!S?.vmk) throw new Error("已加密内容需要先解锁");
	const dec = await decryptFile(S.vmk, path, data);
	if (dec === null) throw new Error("解密失败（密钥不匹配或数据损坏）");
	return dec;
}

/** 解析 wiki 链接目标：精确路径 → 同名 .md → 同名任意文件。 */
function resolveTarget(target: string): string | null {
	if (!S) return null;
	const t = target.replace(/\\/g, "/");
	if (S.byPath.has(t)) return t;
	if (S.byPath.has(t + ".md")) return t + ".md";
	const base = t.slice(t.lastIndexOf("/") + 1).toLowerCase();
	for (const f of S.files) {
		const name = f.path.slice(f.path.lastIndexOf("/") + 1).toLowerCase();
		if (name === base || name === base + ".md") return f.path;
	}
	return null;
}

// ---------- 入口 ----------
async function boot(): Promise<void> {
	applyTheme();
	const token = localStorage.getItem(TOKEN_KEY);
	if (!token) {
		renderLogin();
		return;
	}
	const api = new Api(token);
	try {
		await api.info();
		const vaultDoc = await api.vaultKey();
		S = { api, files: [], byPath: new Map(), vaultDoc, vmk: null };
		if (vaultDoc?.enabled) {
			if (!subtleAvailable()) {
				renderMessage("此 Vault 已启用端到端加密，浏览器解密需要 HTTPS（或 localhost）访问。");
				return;
			}
			const cached = sessionStorage.getItem(VMK_KEY);
			if (cached) {
				S.vmk = await importVmk(b64decode(cached));
			} else {
				renderUnlock();
				return;
			}
		}
		await enterMain();
	} catch (e) {
		if (e instanceof AuthError) {
			localStorage.removeItem(TOKEN_KEY);
			renderLogin("Token 无效或已更换，请重新输入");
			return;
		}
		renderMessage(`无法连接服务器：${e instanceof Error ? e.message : String(e)}`);
	}
}

async function enterMain(): Promise<void> {
	const snap = await S!.api.snapshot();
	S!.files = snap.files.filter((f) => isVisible(f.path));
	S!.byPath = new Map(S!.files.map((f) => [f.path, f]));
	renderMain();
	onRoute();
}

// ---------- 登录 / 解锁 ----------
function renderCentered(children: HTMLElement[]): void {
	app.innerHTML = "";
	const wrap = el("div", "center-screen");
	const card = el("div", "center-card");
	const brand = el("div", "brand", "◈ LiteSync");
	card.append(brand, ...children);
	wrap.append(card);
	app.append(wrap);
}

function renderMessage(msg: string): void {
	renderCentered([el("p", "muted", msg)]);
}

function renderLogin(err?: string): void {
	const sub = el("p", "muted", "Your private vault");
	const input = el("input") as HTMLInputElement;
	input.type = "password";
	input.placeholder = "API Token";
	const btn = el("button", "primary", "连接");
	const errEl = el("p", "error", err ?? "");
	const submit = async () => {
		btn.textContent = "连接中…";
		btn.disabled = true;
		try {
			const api = new Api(input.value.trim());
			await api.info();
			localStorage.setItem(TOKEN_KEY, input.value.trim());
			await boot();
		} catch {
			errEl.textContent = "连接失败：Token 错误或服务器不可达";
			btn.textContent = "连接";
			btn.disabled = false;
		}
	};
	btn.onclick = () => void submit();
	input.onkeydown = (e) => {
		if (e.key === "Enter") void submit();
	};
	renderCentered([sub, input, btn, errEl]);
	input.focus();
}

function renderUnlock(err?: string): void {
	const sub = el("p", "muted", "输入 E2EE 密码解锁（在本地解密，密钥不会离开此设备）");
	const input = el("input") as HTMLInputElement;
	input.type = "password";
	input.placeholder = "E2EE Password";
	const btn = el("button", "primary", "Unlock vault");
	const errEl = el("p", "error", err ?? "");
	const hint = el("p", "muted small", "🔒 Decrypted locally · 会话结束后需重新解锁");
	const submit = async () => {
		btn.textContent = "解锁中…";
		btn.disabled = true;
		const raw = await unlockVaultKey(S!.vaultDoc!, input.value);
		if (!raw) {
			errEl.textContent = "密码错误";
			btn.textContent = "Unlock vault";
			btn.disabled = false;
			return;
		}
		S!.vmk = await importVmk(raw);
		sessionStorage.setItem(VMK_KEY, b64encode(raw));
		raw.fill(0);
		await enterMain();
	};
	btn.onclick = () => void submit();
	input.onkeydown = (e) => {
		if (e.key === "Enter") void submit();
	};
	renderCentered([sub, input, btn, errEl, hint]);
	input.focus();
}

// ---------- 主布局 ----------
let treeEl: HTMLElement;
let contentEl: HTMLElement;
let outlineEl: HTMLElement;
let statusEl: HTMLElement;
let searchInput: HTMLInputElement;
let searchResults: HTMLElement;

function renderMain(): void {
	app.innerHTML = "";
	const layout = el("div", "layout");

	// Header
	const header = el("header");
	const menuBtn = el("button", "icon-btn menu-btn", "☰");
	menuBtn.onclick = () => document.body.classList.toggle("sidebar-open");
	const brand = el("a", "brand-small", "◈ LiteSync") as HTMLAnchorElement;
	brand.href = "#/";
	const searchWrap = el("div", "search-wrap");
	searchInput = el("input", "search") as HTMLInputElement;
	searchInput.placeholder = "🔍 Search vault…";
	searchResults = el("div", "search-results");
	searchResults.hidden = true;
	searchInput.oninput = () => renderSearch(searchInput.value.trim());
	searchInput.onblur = () => setTimeout(() => (searchResults.hidden = true), 200);
	searchInput.onfocus = () => renderSearch(searchInput.value.trim());
	searchWrap.append(searchInput, searchResults);
	const spacer = el("div", "spacer");
	const themeBtn = el("button", "icon-btn", "☀");
	themeBtn.title = "切换主题";
	themeBtn.onclick = toggleTheme;
	const lockBtn = el("button", "icon-btn", "🔒");
	lockBtn.title = S!.vaultDoc?.enabled ? "锁定（清除本会话密钥）" : "退出登录";
	lockBtn.onclick = () => {
		if (S!.vaultDoc?.enabled) {
			sessionStorage.removeItem(VMK_KEY);
		} else {
			localStorage.removeItem(TOKEN_KEY);
		}
		location.hash = "";
		location.reload();
	};
	header.append(menuBtn, brand, searchWrap, spacer, themeBtn, lockBtn);

	// 三栏
	treeEl = el("aside", "tree");
	contentEl = el("main", "content");
	outlineEl = el("aside", "outline");

	// Footer
	statusEl = el("footer");

	layout.append(header, treeEl, contentEl, outlineEl, statusEl);
	app.append(layout);

	renderTree();
	updateStatus();
	window.onhashchange = onRoute;
}

function updateStatus(extra?: string): void {
	const e2ee = S!.vaultDoc?.enabled ? "E2EE unlocked" : "Plaintext vault";
	const latest = S!.files.reduce((m, f) => Math.max(m, f.mtime), 0);
	statusEl.textContent =
		`${e2ee} · ${S!.files.length} files` +
		(latest ? ` · Updated ${fmtTime(latest)}` : "") +
		(extra ? ` · ${extra}` : "");
}

// ---------- 文件树 ----------
interface TreeDir {
	name: string;
	dirs: Map<string, TreeDir>;
	files: FileEntry[];
}

function buildTreeModel(): TreeDir {
	const root: TreeDir = { name: "", dirs: new Map(), files: [] };
	for (const f of S!.files) {
		const parts = f.path.split("/");
		let dir = root;
		for (let i = 0; i < parts.length - 1; i++) {
			let next = dir.dirs.get(parts[i]);
			if (!next) {
				next = { name: parts[i], dirs: new Map(), files: [] };
				dir.dirs.set(parts[i], next);
			}
			dir = next;
		}
		dir.files.push(f);
	}
	return root;
}

function renderTree(): void {
	treeEl.innerHTML = "";
	const root = buildTreeModel();
	treeEl.append(renderDirChildren(root));
}

function renderDirChildren(dir: TreeDir): HTMLElement {
	const box = el("div", "tree-children");
	const dirs = [...dir.dirs.values()].sort((a, b) => a.name.localeCompare(b.name, "zh"));
	for (const sub of dirs) {
		const details = document.createElement("details");
		details.open = true;
		const summary = document.createElement("summary");
		summary.textContent = `📁 ${sub.name}`;
		details.append(summary, renderDirChildren(sub));
		box.append(details);
	}
	const files = [...dir.files].sort((a, b) => a.path.localeCompare(b.path, "zh"));
	for (const f of files) {
		const a = el("a", "tree-file") as HTMLAnchorElement;
		a.href = `#/n/${encodeURIComponent(f.path)}`;
		a.textContent = `${f.path.toLowerCase().endsWith(".md") ? "📄" : "📎"} ${noteTitle(f.path)}`;
		a.dataset.path = f.path;
		box.append(a);
	}
	return box;
}

function markActive(path: string | null): void {
	treeEl.querySelectorAll(".tree-file.active").forEach((n) => n.classList.remove("active"));
	if (path) {
		const node = treeEl.querySelector(`.tree-file[data-path="${CSS.escape(path)}"]`);
		node?.classList.add("active");
		node?.scrollIntoView({ block: "nearest" });
	}
}

// ---------- 搜索（文件名） ----------
function renderSearch(query: string): void {
	searchResults.innerHTML = "";
	if (!query) {
		searchResults.hidden = true;
		return;
	}
	const q = query.toLowerCase();
	const hits = S!.files.filter((f) => f.path.toLowerCase().includes(q)).slice(0, 20);
	for (const f of hits) {
		const item = el("a", "search-item") as HTMLAnchorElement;
		item.href = `#/n/${encodeURIComponent(f.path)}`;
		item.append(el("div", "", noteTitle(f.path)), el("div", "muted small", f.path));
		item.onclick = () => {
			searchResults.hidden = true;
			searchInput.value = "";
		};
		searchResults.append(item);
	}
	if (hits.length === 0) searchResults.append(el("div", "search-item muted", "没有匹配的文件"));
	searchResults.hidden = false;
}

// ---------- 路由 ----------
function onRoute(): void {
	document.body.classList.remove("sidebar-open");
	const hash = location.hash;
	if (hash.startsWith("#/n/")) {
		const path = decodeURIComponent(hash.slice(4));
		void showNote(path);
	} else {
		showHome();
	}
}

// ---------- 首页：最近笔记 ----------
function showHome(): void {
	markActive(null);
	outlineEl.innerHTML = "";
	contentEl.innerHTML = "";
	const wrap = el("div", "note-wrap");
	const hour = new Date().getHours();
	const greeting = hour < 6 ? "夜深了" : hour < 12 ? "早上好" : hour < 18 ? "下午好" : "晚上好";
	wrap.append(el("h1", "", greeting));
	wrap.append(el("p", "muted", "Recent notes"));
	const recent = [...S!.files]
		.filter((f) => f.path.toLowerCase().endsWith(".md"))
		.sort((a, b) => b.mtime - a.mtime)
		.slice(0, 12);
	const list = el("div", "recent-list");
	for (const f of recent) {
		const card = el("a", "recent-card") as HTMLAnchorElement;
		card.href = `#/n/${encodeURIComponent(f.path)}`;
		const dir = f.path.includes("/") ? f.path.slice(0, f.path.lastIndexOf("/")) : "/";
		card.append(
			el("div", "recent-title", noteTitle(f.path)),
			el("div", "muted small", dir),
			el("div", "muted small", `Updated ${fmtTime(f.mtime)}`),
		);
		list.append(card);
	}
	wrap.append(list);
	contentEl.append(wrap);
	updateStatus();
}

// ---------- 笔记视图 ----------
async function showNote(path: string): Promise<void> {
	markActive(path);
	contentEl.innerHTML = "";
	outlineEl.innerHTML = "";
	const wrap = el("div", "note-wrap");
	contentEl.append(wrap);

	const entry = S!.byPath.get(path);
	if (!entry) {
		wrap.append(el("p", "error", `文件不存在：${path}`));
		return;
	}

	// breadcrumb + 标题 + 元信息 + History 按钮
	const crumb = el("div", "crumb");
	const parts = path.split("/");
	parts.forEach((p, i) => {
		if (i === parts.length - 1) crumb.append(el("span", "", noteTitle(p)));
		else crumb.append(el("span", "muted", p), el("span", "muted", " / "));
	});
	const headRow = el("div", "note-head");
	headRow.append(crumb);
	const histBtn = el("button", "ghost", "🕘 History");
	histBtn.onclick = () => void openHistory(path);
	headRow.append(histBtn);
	wrap.append(headRow);
	wrap.append(el("h1", "note-title", noteTitle(path)));
	wrap.append(el("p", "muted small", `Last modified ${fmtTime(entry.mtime)} · rev ${entry.revision}`));

	const body = el("div", "markdown-body");
	wrap.append(body);
	body.textContent = "加载中…";

	try {
		const raw = await S!.api.file(path);
		const data = await decodeContent(path, raw);
		if (path.toLowerCase().endsWith(".md")) {
			renderMarkdownInto(body, path, new TextDecoder().decode(data));
			const items = buildOutline(body);
			renderOutline(items);
		} else if (IMAGE_EXT.test(path)) {
			body.innerHTML = "";
			const img = el("img") as HTMLImageElement;
			img.src = trackBlob(new Blob([data]));
			img.className = "attachment-img";
			body.append(img);
		} else {
			body.innerHTML = "";
			const a = el("a", "primary-link", `下载 ${noteTitle(path)}（${(entry.size / 1024).toFixed(1)} KB）`) as HTMLAnchorElement;
			a.href = trackBlob(new Blob([data]));
			a.download = path.slice(path.lastIndexOf("/") + 1);
			body.append(a);
		}
		updateStatus();
	} catch (e) {
		body.textContent = `加载失败：${e instanceof Error ? e.message : String(e)}`;
	}
}

function trackBlob(blob: Blob): string {
	const url = URL.createObjectURL(blob);
	blobUrls.push(url);
	if (blobUrls.length > 64) URL.revokeObjectURL(blobUrls.shift()!);
	return url;
}

function renderMarkdownInto(container: HTMLElement, path: string, src: string): void {
	const pre = preprocessWiki(src, resolveTarget);
	container.innerHTML = md.render(pre);
	// vault: 图片 → 认证下载 + 解密 → blob URL
	container.querySelectorAll<HTMLImageElement>("img").forEach((img) => {
		const src = img.getAttribute("src") ?? "";
		let target: string | null = null;
		if (src.startsWith("vault:")) {
			target = decodeURIComponent(src.slice(6));
		} else if (!/^([a-z]+:)?\/\//i.test(src) && !src.startsWith("data:") && !src.startsWith("blob:")) {
			// 相对路径附件：相对笔记目录或 vault 根解析
			const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
			const rel = decodeURIComponent(src);
			target = S!.byPath.has(dir ? `${dir}/${rel}` : rel) ? (dir ? `${dir}/${rel}` : rel) : S!.byPath.has(rel) ? rel : null;
		}
		if (!target) return;
		const finalTarget = target;
		img.removeAttribute("src");
		void (async () => {
			try {
				const data = await decodeContent(finalTarget, await S!.api.file(finalTarget));
				img.src = trackBlob(new Blob([data]));
			} catch {
				img.alt = `⚠ 无法加载 ${finalTarget}`;
			}
		})();
	});
}

function renderOutline(items: { level: number; text: string; id: string }[]): void {
	outlineEl.innerHTML = "";
	if (items.length === 0) return;
	outlineEl.append(el("div", "outline-title", "On this page"));
	for (const item of items) {
		const a = el("a", `outline-item lv${item.level}`, item.text) as HTMLAnchorElement;
		a.href = "javascript:void 0";
		a.onclick = () => document.getElementById(item.id)?.scrollIntoView({ behavior: "smooth" });
		outlineEl.append(a);
	}
}

// ---------- 历史抽屉 + 版本查看 + Diff ----------
async function openHistory(path: string): Promise<void> {
	closeDrawer();
	const drawer = el("div", "drawer");
	drawer.id = "drawer";
	drawer.append(el("div", "drawer-title", "Version history"));
	const list = el("div", "drawer-list");
	drawer.append(list);
	const closeBtn = el("button", "ghost", "关闭");
	closeBtn.onclick = closeDrawer;
	drawer.append(closeBtn);
	document.body.append(drawer);

	try {
		const versions = await S!.api.history(path);
		if (versions.length === 0) {
			list.append(el("p", "muted", "暂无历史版本"));
			return;
		}
		const cur = S!.byPath.get(path);
		for (const v of versions) {
			const row = el("a", "drawer-item") as HTMLAnchorElement;
			row.href = "javascript:void 0";
			const label =
				v.revision === cur?.revision ? `● Current (rev ${v.revision})` : `● Revision ${v.revision}`;
			row.append(el("div", "", `${label} · ${v.action}`));
			row.append(el("div", "muted small", fmtTime(v.createdAt * 1000)));
			if (v.action !== "delete") {
				row.onclick = () => void showRevision(path, v);
			} else {
				row.classList.add("muted");
			}
			list.append(row);
		}
	} catch (e) {
		list.append(el("p", "error", `加载失败：${e instanceof Error ? e.message : String(e)}`));
	}
}

function closeDrawer(): void {
	document.getElementById("drawer")?.remove();
}

async function showRevision(path: string, v: VersionEntry): Promise<void> {
	closeDrawer();
	contentEl.innerHTML = "";
	outlineEl.innerHTML = "";
	const wrap = el("div", "note-wrap");
	contentEl.append(wrap);

	const banner = el("div", "banner");
	banner.append(el("span", "", `Viewing revision ${v.revision} · ${fmtTime(v.createdAt * 1000)}`));
	const cmpBtn = el("button", "ghost", "Compare with current");
	const backBtn = el("button", "ghost", "返回当前版本");
	backBtn.onclick = () => void showNote(path);
	banner.append(cmpBtn, backBtn);
	wrap.append(banner);
	wrap.append(el("h1", "note-title", noteTitle(path)));
	const body = el("div", "markdown-body");
	wrap.append(body);
	body.textContent = "加载中…";

	try {
		const data = await decodeContent(path, await S!.api.version(path, v.revision));
		if (!path.toLowerCase().endsWith(".md")) {
			body.innerHTML = "";
			const a = el("a", "primary-link", "下载此版本") as HTMLAnchorElement;
			a.href = trackBlob(new Blob([data]));
			a.download = `rev-${v.revision}-${path.slice(path.lastIndexOf("/") + 1)}`;
			body.append(a);
			return;
		}
		const oldText = new TextDecoder().decode(data);
		renderMarkdownInto(body, path, oldText);
		cmpBtn.onclick = () => void showDiff(path, v, oldText);
	} catch (e) {
		body.textContent = `加载失败：${e instanceof Error ? e.message : String(e)}`;
	}
}

async function showDiff(path: string, v: VersionEntry, oldText: string): Promise<void> {
	contentEl.innerHTML = "";
	outlineEl.innerHTML = "";
	const wrap = el("div", "note-wrap");
	contentEl.append(wrap);
	const banner = el("div", "banner");
	banner.append(el("span", "", `Revision ${v.revision} → Current`));
	const backBtn = el("button", "ghost", "返回当前版本");
	backBtn.onclick = () => void showNote(path);
	banner.append(backBtn);
	wrap.append(banner, el("h1", "note-title", noteTitle(path)));
	const box = el("pre", "diff-box");
	wrap.append(box);
	box.textContent = "对比中…";

	try {
		const curData = await decodeContent(path, await S!.api.file(path));
		const curText = new TextDecoder().decode(curData);
		const lines: DiffLine[] | null = diffLines(oldText, curText);
		box.innerHTML = "";
		if (lines === null) {
			box.textContent = "文件差异过大，无法对比";
			return;
		}
		let changed = false;
		for (const line of lines) {
			if (line.type !== "same") changed = true;
			const div = el("div", `diff-line diff-${line.type}`);
			div.textContent = (line.type === "add" ? "+ " : line.type === "del" ? "- " : "  ") + line.text;
			box.append(div);
		}
		if (!changed) box.textContent = "两个版本内容相同。";
	} catch (e) {
		box.textContent = `对比失败：${e instanceof Error ? e.message : String(e)}`;
	}
}

void boot();
