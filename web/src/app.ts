/** LiteSync Web 只读端主应用：文件树 + Markdown 阅读 + Outline + 历史 + Diff。
 *
 * v4 安全模型：
 * - 凭据：HttpOnly 只读会话 Cookie（JS 不可见），根 Token 不落浏览器存储
 * - VMK：解锁后只存在于内存 CryptoKey；刷新/关闭页面即需重新输入密码
 */
import {
	Api,
	AuthError,
	BackupConfigView,
	BackupStatus,
	FileEntry,
	login,
	logout,
	VersionEntry,
} from "./api";
import {
	decryptFile,
	importVmk,
	isEncryptedFile,
	subtleAvailable,
	unlockVaultKey,
	VaultKeyDoc,
} from "./crypto";
import { DiffLine, diffLines } from "./diff";
import { buildOutline, md, preprocessWiki } from "./markdown";

const THEME_KEY = "litesync-theme";

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
let blobUrls: string[] = [];

/** 切换视图时立即回收上一个笔记的所有附件 Blob URL，避免大图累积占内存。 */
function revokeAllBlobs(): void {
	for (const url of blobUrls) URL.revokeObjectURL(url);
	blobUrls = [];
}

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
	const api = new Api();
	try {
		await api.info(); // 会话 Cookie 无效 → AuthError → 登录页
		const vaultDoc = await api.vaultKey();
		S = { api, files: [], byPath: new Map(), vaultDoc, vmk: null };
		if (vaultDoc?.enabled) {
			if (!subtleAvailable()) {
				renderMessage("此 Vault 已启用端到端加密，浏览器解密需要 HTTPS（或 localhost）访问。");
				return;
			}
			// VMK 只存在内存：每次进入页面都需要解锁
			renderUnlock();
			return;
		}
		await enterMain();
	} catch (e) {
		if (e instanceof AuthError) {
			renderLogin();
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
	const hint = el("p", "muted small", "Token 只用于换取只读会话，不会保存在浏览器中");
	const submit = async () => {
		btn.textContent = "连接中…";
		btn.disabled = true;
		try {
			if (!(await login(input.value.trim()))) {
				throw new Error("unauthorized");
			}
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
	renderCentered([sub, input, btn, errEl, hint]);
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
		// VMK 只保留在内存 CryptoKey：不写任何浏览器存储，刷新即需重新解锁
		S!.vmk = await importVmk(raw);
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
	const settingsBtn = el("button", "icon-btn", "⚙");
	settingsBtn.title = "设置（备份管理）";
	settingsBtn.onclick = () => {
		location.hash = "#/settings/backup";
	};
	const themeBtn = el("button", "icon-btn", "☀");
	themeBtn.title = "切换主题";
	themeBtn.onclick = toggleTheme;
	const lockBtn = el("button", "icon-btn", "🔒");
	lockBtn.title = "锁定（丢弃内存中的密钥）";
	lockBtn.hidden = !S!.vaultDoc?.enabled;
	lockBtn.onclick = () => {
		S!.vmk = null;
		location.hash = "";
		location.reload(); // 内存密钥随页面刷新彻底消失
	};
	const outBtn = el("button", "icon-btn", "⏻");
	outBtn.title = "退出登录";
	outBtn.onclick = () => {
		void logout().then(() => {
			location.hash = "";
			location.reload();
		});
	};
	header.append(menuBtn, brand, searchWrap, spacer, settingsBtn, themeBtn, lockBtn, outBtn);

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
	} else if (hash === "#/settings/backup") {
		void showBackupSettings();
	} else {
		showHome();
	}
}

// ---------- 首页：最近笔记 ----------
function showHome(): void {
	revokeAllBlobs();
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
	revokeAllBlobs();
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
		// 不用 href="javascript:"（严格 CSP 下被禁止），纯 onclick
		const a = el("a", `outline-item lv${item.level}`, item.text);
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
			const row = el("a", "drawer-item");
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
	revokeAllBlobs();
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
	revokeAllBlobs();
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

// ---------- 备份设置（ADMIN capability，v6） ----------
//
// 备份配置属于管理操作：只读会话不够，需要用 Token 换取短期 admin 会话
//（HttpOnly cookie，30 分钟过期）。Secret 永远不会从服务器返回；
// 表单中的 Secret 输入留空 = 保持服务器上的原值。

function fmtBytes(n: number): string {
	if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(2)} GB`;
	if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MB`;
	if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
	return `${n} B`;
}

async function showBackupSettings(): Promise<void> {
	revokeAllBlobs();
	markActive(null);
	outlineEl.innerHTML = "";
	contentEl.innerHTML = "";
	const wrap = el("div", "note-wrap settings-wrap");
	contentEl.append(wrap);
	const head = el("div", "note-head");
	head.append(el("h1", "note-title", "Backup"));
	const backBtn = el("button", "ghost", "← 返回");
	backBtn.onclick = () => {
		location.hash = "#/";
	};
	head.append(backBtn);
	wrap.append(head);
	wrap.append(
		el(
			"p",
			"muted small",
			"服务器 → Restic → Cloudflare R2 的灾难备份。凭据加密保存在服务器上，永远不会下发给任何客户端。",
		),
	);
	const box = el("div", "settings-box");
	wrap.append(box);
	await renderBackupInto(box);
}

async function renderBackupInto(box: HTMLElement): Promise<void> {
	box.textContent = "加载中…";
	let status: BackupStatus;
	let cfg: BackupConfigView;
	try {
		status = await S!.api.backupStatus();
		cfg = await S!.api.backupConfig();
	} catch (e) {
		if (e instanceof AuthError) {
			renderAdminUnlock(box);
			return;
		}
		box.textContent = `加载失败：${e instanceof Error ? e.message : String(e)}`;
		return;
	}
	box.innerHTML = "";
	renderBackupStatusCard(box, status);
	renderBackupConfigForm(box, cfg, status);
	renderSnapshotsSection(box, status);

	// 任务运行中每 4 秒刷新一次状态
	if (status.running && location.hash === "#/settings/backup") {
		window.setTimeout(() => {
			if (location.hash === "#/settings/backup" && box.isConnected) void renderBackupInto(box);
		}, 4000);
	}
}

function renderAdminUnlock(box: HTMLElement): void {
	box.innerHTML = "";
	const card = el("div", "settings-card");
	card.append(el("h2", "", "Admin unlock"));
	card.append(el("p", "muted small", "备份管理需要管理员权限：请输入 API Token 换取短期 admin 会话（30 分钟）。"));
	const input = el("input") as HTMLInputElement;
	input.type = "password";
	input.placeholder = "API Token";
	const btn = el("button", "primary", "解锁");
	const errEl = el("p", "error", "");
	const submit = async (): Promise<void> => {
		btn.disabled = true;
		if (await login(input.value.trim(), true)) {
			await renderBackupInto(box);
			return;
		}
		errEl.textContent = "Token 错误";
		btn.disabled = false;
	};
	btn.onclick = () => void submit();
	input.onkeydown = (e) => {
		if (e.key === "Enter") void submit();
	};
	const row = el("div", "settings-row");
	row.append(input, btn);
	card.append(row, errEl);
	box.append(card);
	input.focus();
}

function renderBackupStatusCard(box: HTMLElement, st: BackupStatus): void {
	const card = el("div", "settings-card");
	card.append(el("h2", "", "Status"));

	if (!st.keyAvailable) {
		card.append(el("p", "error", `备份不可用：${st.keyError ?? "backup-config.key 缺失"}`));
		card.append(el("p", "muted small", "请在服务器上重新执行一键部署脚本生成 backup-config.key。"));
		box.append(card);
		return;
	}
	if (!st.resticOk) {
		card.append(el("p", "error", "restic 不可用：请使用包含 restic 的服务器镜像（重新执行一键部署）。"));
	}

	const grid = el("div", "settings-grid");
	const item = (label: string, value: string, cls = ""): void => {
		grid.append(el("div", "muted small", label), el("div", cls, value));
	};
	const state = st.running
		? `● 任务执行中（${st.runningOp ?? "backup"}…）`
		: st.enabled
			? "● Enabled"
			: st.configured
				? "● 已配置 · 自动备份关闭"
				: "○ 未配置";
	item("Backup", state, st.enabled && !st.running ? "ok" : "");
	if (st.resticVersion) item("Restic", st.resticVersion);
	item("Last backup", st.lastCompletedAt ? fmtTime(st.lastCompletedAt * 1000) : "从未");
	if (st.lastDurationMs) item("Duration", `${(st.lastDurationMs / 1000).toFixed(1)} s`);
	if (st.lastSnapshotId) item("Snapshot", st.lastSnapshotId.slice(0, 8));
	item("Next backup", st.enabled && st.nextRunAt ? fmtTime(st.nextRunAt * 1000) : "—");
	if (st.snapshotCount) item("Snapshots", String(st.snapshotCount));
	if (st.repositorySize) item("Repository size", `${fmtBytes(st.repositorySize)}（估算）`);
	card.append(grid);

	if (st.lastError) {
		card.append(el("p", "error", `上次失败：${st.lastError}`));
	}

	// 用量条：只做展示与告警，超预算绝不自动删除对象（只允许 restic forget/prune）
	if (st.budgetBytes && st.repositorySize) {
		const pct = Math.min(100, Math.round((st.repositorySize / st.budgetBytes) * 100));
		const barWrap = el("div", "usage-bar");
		const bar = el("div", `usage-fill ${pct > 85 ? "red" : pct > 70 ? "yellow" : ""}`);
		bar.style.width = `${pct}%`;
		barWrap.append(bar);
		card.append(
			barWrap,
			el("p", "muted small", `Usage ${pct}% · Budget ${fmtBytes(st.budgetBytes)}`),
		);
		if (st.repositorySize > st.budgetBytes * 0.8) {
			card.append(el("p", "warn", "⚠ Backup repository is approaching the configured budget."));
		}
	}
	box.append(card);
}

function renderBackupConfigForm(box: HTMLElement, cfg: BackupConfigView, st: BackupStatus): void {
	const card = el("div", "settings-card");
	card.append(el("h2", "", "Cloudflare R2"));
	card.append(
		el(
			"p",
			"muted small",
			"创建仅限该 Bucket 的 Object Read & Write S3 凭据（Bucket 保持 private，无需公开访问/CORS/自定义域名）。",
		),
	);

	const msgEl = el("p", "settings-msg", "");
	const field = (
		label: string,
		value: string,
		opts: { secret?: boolean; configured?: boolean; placeholder?: string } = {},
	): HTMLInputElement => {
		card.append(el("label", "settings-label", label));
		const input = el("input", "settings-input") as HTMLInputElement;
		if (opts.secret) {
			input.type = "password";
			input.placeholder = opts.configured ? "已配置（留空保持不变）" : (opts.placeholder ?? "");
		} else {
			input.value = value;
			if (opts.placeholder) input.placeholder = opts.placeholder;
		}
		card.append(input);
		return input;
	};

	const accountEl = field("Account ID", cfg.accountId);
	const bucketEl = field("Bucket", cfg.bucket, { placeholder: "litesync-backup" });
	const accessEl = field("Access Key ID", "", { secret: true, configured: cfg.accessKeyConfigured });
	const secretEl = field("Secret Access Key", "", { secret: true, configured: cfg.secretKeyConfigured });
	const prefixEl = field("Repository prefix", cfg.prefix, { placeholder: "restic" });

	// Restic password：整个备份系统唯一需要用户另外保存的恢复秘密
	card.append(el("label", "settings-label", "Restic password（恢复密码）"));
	const pwRow = el("div", "settings-row");
	const pwEl = el("input", "settings-input") as HTMLInputElement;
	pwEl.type = "password";
	pwEl.placeholder = cfg.resticPasswordConfigured ? "已配置（留空保持不变）" : "";
	const genBtn = el("button", "ghost", "Generate");
	pwRow.append(pwEl, genBtn);
	card.append(pwRow);
	const pwWarn = el("div", "settings-pw-warn");
	pwWarn.hidden = true;
	card.append(pwWarn);
	let pwConfirmed = cfg.resticPasswordConfigured; // 已配置过 = 无需再确认
	let confirmCb: HTMLInputElement | null = null;
	const requireConfirm = (): void => {
		if (!pwWarn.hidden) return;
		pwWarn.hidden = false;
		pwWarn.append(
			el(
				"p",
				"warn",
				"IMPORTANT：请立刻把这个恢复密码保存到密码管理器。服务器损毁后若密码丢失，R2 上的备份将永远无法恢复。",
			),
		);
		const lbl = el("label", "settings-check");
		confirmCb = el("input") as HTMLInputElement;
		confirmCb.type = "checkbox";
		lbl.append(confirmCb, document.createTextNode(" 我已把恢复密码保存到密码管理器"));
		pwWarn.append(lbl);
	};
	genBtn.onclick = () => {
		const raw = new Uint8Array(32);
		crypto.getRandomValues(raw);
		pwEl.value = btoa(String.fromCharCode(...raw)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
		pwEl.type = "text"; // 生成的密码显示一次，保存后不再可见
		pwConfirmed = false;
		requireConfirm();
	};
	pwEl.oninput = () => {
		if (pwEl.value !== "") {
			pwConfirmed = false;
			requireConfirm();
		}
	};

	const endpointEl = field("S3 Endpoint（可选，默认 Cloudflare R2）", cfg.endpoint, {
		placeholder: "https://<ACCOUNT_ID>.r2.cloudflarestorage.com",
	});
	const budgetEl = field("Budget（GB，仅告警展示）", String(cfg.budgetGb));

	const enableLbl = el("label", "settings-check");
	const enableCb = el("input") as HTMLInputElement;
	enableCb.type = "checkbox";
	enableCb.checked = cfg.enabled;
	enableLbl.append(enableCb, document.createTextNode(" Enable automatic backup（每 6 小时）"));
	card.append(enableLbl);

	const say = (text: string, isError = false): void => {
		msgEl.textContent = text;
		msgEl.className = isError ? "error" : "settings-msg ok";
	};

	const collect = (): Record<string, unknown> => {
		const update: Record<string, unknown> = {
			enabled: enableCb.checked,
			accountId: accountEl.value.trim(),
			bucket: bucketEl.value.trim(),
			prefix: prefixEl.value.trim(),
			endpoint: endpointEl.value.trim(),
			budgetGb: parseInt(budgetEl.value, 10) || 10,
		};
		// Secret 留空 = 不修改（服务器保持原值）
		if (accessEl.value !== "") update.accessKeyId = accessEl.value.trim();
		if (secretEl.value !== "") update.secretAccessKey = secretEl.value.trim();
		if (pwEl.value !== "") update.resticPassword = pwEl.value;
		return update;
	};

	const save = async (): Promise<BackupConfigView | null> => {
		if (pwEl.value !== "" && !pwConfirmed && confirmCb && !confirmCb.checked) {
			say("请先确认已保存 Restic 恢复密码", true);
			return null;
		}
		try {
			const view = await S!.api.backupSaveConfig(collect());
			say("已保存 ✓");
			return view;
		} catch (e) {
			say(`保存失败：${e instanceof Error ? e.message : String(e)}`, true);
			return null;
		}
	};

	const actions = el("div", "settings-actions");
	const testBtn = el("button", "ghost", "Test connection");
	testBtn.onclick = async () => {
		testBtn.disabled = true;
		try {
			if ((await save()) === null) return;
			const r = await S!.api.backupTest();
			if (!r.ok) say(`连接失败：${r.error ?? "未知错误"}`, true);
			else if (!r.initialized) say("连接成功 ✓ 仓库尚未初始化，请点击 Initialize");
			else say("连接成功 ✓ 仓库已就绪");
		} catch (e) {
			say(`测试失败：${e instanceof Error ? e.message : String(e)}`, true);
		} finally {
			testBtn.disabled = false;
		}
	};
	const saveBtn = el("button", "primary", "Save");
	saveBtn.onclick = async () => {
		saveBtn.disabled = true;
		try {
			if ((await save()) !== null) void renderBackupInto(box.parentElement ? box : box);
		} finally {
			saveBtn.disabled = false;
		}
	};
	const initBtn = el("button", "ghost", "Initialize");
	initBtn.onclick = async () => {
		initBtn.disabled = true;
		try {
			await S!.api.backupInit();
			say("仓库初始化完成 ✓ 现在可以 Backup now");
		} catch (e) {
			say(`初始化失败：${e instanceof Error ? e.message : String(e)}`, true);
		} finally {
			initBtn.disabled = false;
		}
	};
	const runBtn = el("button", "primary", "Backup now");
	runBtn.onclick = async () => {
		runBtn.disabled = true;
		try {
			await S!.api.backupRun();
			say("备份已开始（后台执行）");
			window.setTimeout(() => void renderBackupInto(box), 1500);
		} catch (e) {
			say(`${e instanceof Error ? e.message : String(e)}`, true);
			runBtn.disabled = false;
		}
	};
	const checkBtn = el("button", "ghost", "Check repository");
	checkBtn.onclick = async () => {
		checkBtn.disabled = true;
		try {
			await S!.api.backupCheck();
			say("完整性检查已开始（后台执行）");
			window.setTimeout(() => void renderBackupInto(box), 1500);
		} catch (e) {
			say(`${e instanceof Error ? e.message : String(e)}`, true);
			checkBtn.disabled = false;
		}
	};
	actions.append(testBtn, saveBtn, initBtn, runBtn, checkBtn);
	if (st.running) {
		for (const b of [initBtn, runBtn, checkBtn]) b.disabled = true;
	}
	card.append(actions, msgEl);
	box.append(card);
}

function renderSnapshotsSection(box: HTMLElement, st: BackupStatus): void {
	if (!st.configured) return;
	const card = el("div", "settings-card");
	card.append(el("h2", "", "Snapshots"));
	const list = el("div");
	const loadBtn = el("button", "ghost", "加载快照列表");
	loadBtn.onclick = async () => {
		loadBtn.disabled = true;
		list.textContent = "加载中…";
		try {
			const r = await S!.api.backupSnapshots();
			list.innerHTML = "";
			if (!r.initialized) {
				list.append(el("p", "muted", "仓库尚未初始化"));
				return;
			}
			if (r.snapshots.length === 0) {
				list.append(el("p", "muted", "暂无快照"));
				return;
			}
			for (const s of [...r.snapshots].reverse()) {
				const row = el("div", "snapshot-row");
				row.append(
					el("code", "", s.short_id || s.id.slice(0, 8)),
					el("span", "muted small", fmtTime(Date.parse(s.time))),
				);
				list.append(row);
			}
		} catch (e) {
			list.textContent = `加载失败：${e instanceof Error ? e.message : String(e)}`;
		} finally {
			loadBtn.disabled = false;
		}
	};
	card.append(loadBtn, list);
	box.append(card);
}

void boot();
