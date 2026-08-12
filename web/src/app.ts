/** LiteSync Web 只读端主应用：文件树 + Markdown 阅读 + Outline + 历史 + Diff。
 *
 * v4 安全模型：
 * - 凭据：HttpOnly 只读会话 Cookie（JS 不可见），根 Token 不落浏览器存储
 * - VMK：解锁后只存在于内存 CryptoKey；刷新/关闭页面即需重新输入密码
 */
import {
	AdminDevice,
	AdminMigrationStatus,
	AdminShare,
	Api,
	AuthError,
	BackupConfigView,
	BackupSnapshot,
	BackupStatus,
	FileEntry,
	IntegrityError,
	IntegrityEvent,
	login,
	logout,
	VersionEntry,
} from "./api";
import {
	decryptFile,
	lse3Header,
	decryptMeta,
	deriveMetaKeys,
	FileKeyBinding,
	importVmk,
	isEncryptedFile,
	MetaKeys,
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
	/** LSE2 信封的 AAD 绑定材料（v9.2，来自 /info） */
	binding?: FileKeyBinding;
	/** 元数据解密密钥（v9.3 三期，meta 模式；解锁时派生） */
	metaKeys?: MetaKeys;
	/**
	 * 各对象已见过的最大 contentGeneration（v0.13.3 / 计划书 §7.5）。
	 *
	 * 只在本次会话内有效——查看器没有本地持久状态，做不到跨会话的抗回退。
	 * 但会话内的回退（同一次浏览中服务器先给新版本再给旧版本）必须挡住。
	 */
	seenGeneration: Map<string, number>;
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

/**
 * 解密并校验一份下载下来的内容（v0.13.3 / 计划书 §7.5）。
 *
 * 光能解开不等于可信。查看器和插件一样要做三项检查：
 *
 *  1. **fileId 匹配**：服务器返回的身份必须是我们请求的那个对象；
 *  2. **keyEpoch 校验**：信封里的密钥世代必须等于仓库当前世代；
 *  3. **generation 防回退**：同一会话里不接受比已见过的更旧的版本。
 *
 * `expectFileId` 传 null 表示「用快照里记的当前身份」（普通浏览）；
 * 历史版本必须传**版本级** fileId，否则删除重建过的旧版本会被误判。
 */
async function decodeContent(
	path: string,
	data: ArrayBuffer,
	identity?: { fileId: string | null; generation?: number | null; historical?: boolean },
): Promise<ArrayBuffer> {
	if (!isEncryptedFile(data)) return data;
	if (!S?.vmk) throw new Error("已加密内容需要先解锁");

	const expected = S.byPath.get(path)?.fileId;
	const served = identity?.fileId ?? undefined;
	// §7.5 第 1 项：服务器换掉身份 = 用另一份内容冒充这个文件
	if (!identity?.historical && expected && served && served !== expected) {
		throw new Error("服务器返回的文件身份与预期不符，已拒绝显示（可能被篡改）");
	}
	const useFileId = served ?? expected;

	const head = lse3Header(data);
	if (head !== null) {
		// §7.5 第 2 项：keyEpoch 必须与仓库当前世代一致。
		// GCM 会认证这个字段，但「认证过的旧世代」仍然是旧世代——
		// 密钥轮换之后还接受它，等于轮换白做
		const repoEpoch = S.binding?.keyEpoch;
		if (repoEpoch !== undefined && repoEpoch > 0 && head.keyEpoch !== repoEpoch) {
			throw new Error(`内容的密钥世代（${head.keyEpoch}）与仓库当前世代（${repoEpoch}）不符，已拒绝显示`);
		}
		// §7.5 第 3 项：HEAD 不得回退（历史版本本来就是旧的，豁免）
		if (!identity?.historical && useFileId) {
			const seen = S.seenGeneration.get(useFileId);
			if (seen !== undefined && head.generation < seen) {
				throw new Error(`检测到内容回退（generation ${head.generation} < 已见 ${seen}），已拒绝显示`);
			}
			S.seenGeneration.set(useFileId, Math.max(seen ?? 0, head.generation));
		}
	}

	const dec = await decryptFile(S.vmk, path, data, S.binding, useFileId);
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
		const info = await api.info(); // 会话 Cookie 无效 → AuthError → 登录页
		const vaultDoc = await api.vaultKey();
		const binding =
			info.vaultId && (info.keyEpoch ?? 0) > 0
				? { vaultId: info.vaultId, keyEpoch: info.keyEpoch! }
				: undefined;
		S = { api, files: [], byPath: new Map(), vaultDoc, vmk: null, binding, seenGeneration: new Map() };
		// §7.5：仓库处于迁移中等非常态时，必须让用户看到——
		// 此时看到的内容可能是不完整或过渡态的，静默展示等于误导
		showRepoStateBanner(info.metaState);
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
	// meta 模式（v9.3 三期）：条目是伪名 + 加密元数据 → 本地解出真实路径建树
	for (const f of snap.files) {
		if (!f.metaEnc || !f.fileId) continue;
		f.serverPath = f.path;
		if (!S!.metaKeys || !S!.binding?.vaultId) continue; // 无法解密：以伪名显示
		const dec = await decryptMeta(S!.metaKeys, f.metaEnc, S!.binding.vaultId, f.fileId);
		if (dec) f.path = dec.path;
	}
	S!.files = snap.files.filter((f) => isVisible(f.path));
	S!.byPath = new Map(S!.files.map((f) => [f.path, f]));
	renderMain();
	onRoute();
}

/** 内容/历史请求用的服务器路径（meta 模式为伪名）。 */
function serverPathFor(path: string): string {
	return S?.byPath.get(path)?.serverPath ?? path;
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
		// 元数据密钥（v9.3）：派生后立即清零原始字节
		S!.metaKeys = await deriveMetaKeys(raw);
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
	// 运维入口（§11.3）：设备撤销、迁移进度、完整性告警、分享与灾备恢复。
	// 单独一个入口而不是塞进备份页——出事时要能一眼找到
	const opsBtn = el("button", "icon-btn", "🛠");
	opsBtn.title = "运维（设备 / 迁移 / 完整性 / 恢复）";
	opsBtn.onclick = () => {
		location.hash = "#/settings/ops";
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
	header.append(menuBtn, brand, searchWrap, spacer, opsBtn, settingsBtn, themeBtn, lockBtn, outBtn);

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
	} else if (hash === "#/settings/ops") {
		void showOpsSettings();
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
		const dl = await S!.api.fileWithIdentity(serverPathFor(path));
		const data = await decodeContent(path, dl.data, { fileId: dl.fileId, generation: dl.generation });
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
		if (e instanceof IntegrityError) {
			// §7.5：完整性错误要和「加载失败」区分开——前者需要管理员从备份恢复，
			// 后者用户刷新一下可能就好了。混为一谈会让真正的数据损坏被当成网络抖动
			showIntegrityBanner(path);
			body.textContent = "这份内容在服务器上未通过完整性校验，已停止提供。请联系管理员从备份恢复。";
			return;
		}
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
				const dlLink = await S!.api.fileWithIdentity(serverPathFor(finalTarget));
				const data = await decodeContent(finalTarget, dlLink.data, {
					fileId: dlLink.fileId,
					generation: dlLink.generation,
				});
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
		const versions = await S!.api.history(serverPathFor(path));
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
		// §7.5：历史版本用**版本级** fileId（删除重建过的旧版本属于旧对象）
		const dlVer = await S!.api.versionWithIdentity(serverPathFor(path), v.revision);
		const data = await decodeContent(path, dlVer.data, { fileId: dlVer.fileId, historical: true });
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
		const dlCur = await S!.api.fileWithIdentity(serverPathFor(path));
		const curData = await decodeContent(path, dlCur.data, {
			fileId: dlCur.fileId,
			generation: dlCur.generation,
		});
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

/**
 * 仓库状态横幅（v0.13.3 / 计划书 §7.5）。
 *
 * migrating / verifying 期间仓库正在被重写：此刻看到的目录与内容都可能是过渡态。
 * 不说明就展示，用户会以为「文件不见了」而去做一些更糟的补救动作。
 *
 * 注意这里显示的是**服务器自报**的状态，只用于提示，不用来改变任何安全判断
 * （§7.5 最后一条：Web 不使用服务器未认证值更新安全状态）。
 * 真正的安全判断在 decodeContent 里，靠 GCM 认证过的字段做。
 */
function showRepoStateBanner(metaState: string | undefined): void {
	const existing = document.getElementById("repo-state-banner");
	if (existing) existing.remove();
	if (metaState !== "migrating" && metaState !== "verifying") return;
	const bar = el("div", "repo-banner");
	bar.id = "repo-state-banner";
	bar.textContent =
		metaState === "migrating"
			? "仓库正在进行元数据迁移：此时看到的目录可能不完整，请稍后再查看。"
			: "仓库正在做迁移后校验：内容只读可看，校验完成前请勿在其他设备上做大量改动。";
	document.body.prepend(bar);
}

/**
 * 完整性错误横幅（§7.5）：服务器明确告知内容损坏时展示。
 * 与「文件不存在」区分开——后者用户会去回收站找，前者需要管理员处理。
 */
function showIntegrityBanner(what: string): void {
	const bar = el("div", "repo-banner repo-banner-error");
	bar.textContent = `服务器上的内容未通过完整性校验：${what}`;
	document.body.prepend(bar);
}

// ---------- 运维页（v0.17 / 计划书 §11.3） ----------
//
// 设备撤销、迁移状态、完整性告警、备份恢复、分享恢复——这五件事的共同点是
// **出事的时候才会用到**。它们最常见的失败不是写错了，而是「只能 SSH 上服务器
// 敲命令」。事故当天，能不能在手机上撤销一台丢失的设备，和这个功能写得优不优雅
// 相比，是完全不同量级的问题。
//
// 与备份页共用 admin 会话（30 分钟）。

function fmtTs(sec: number): string {
	return sec > 0 ? fmtTime(sec * 1000) : "—";
}

async function showOpsSettings(): Promise<void> {
	revokeAllBlobs();
	markActive(null);
	outlineEl.innerHTML = "";
	contentEl.innerHTML = "";
	const wrap = el("div", "note-wrap settings-wrap");
	contentEl.append(wrap);
	const head = el("div", "note-head");
	head.append(el("h1", "note-title", "Operations"));
	const backBtn = el("button", "ghost", "← 返回");
	backBtn.onclick = () => {
		location.hash = "#/";
	};
	head.append(backBtn);
	wrap.append(head);
	wrap.append(
		el("p", "muted small", "出事时会用到的几件事：设备撤销、迁移进度、完整性告警、分享恢复、灾备恢复预检。"),
	);
	const box = el("div", "settings-box");
	wrap.append(box);
	await renderOpsInto(box);
}

async function renderOpsInto(box: HTMLElement): Promise<void> {
	box.textContent = "加载中…";
	let devices: AdminDevice[];
	let migration: AdminMigrationStatus;
	let events: IntegrityEvent[];
	let shares: AdminShare[];
	try {
		[devices, migration, events, shares] = await Promise.all([
			S!.api.adminDevices().then((r) => r.devices ?? []),
			S!.api.adminMigrationStatus(),
			S!.api.adminIntegrityEvents().then((r) => r.events ?? []),
			S!.api.adminShares().then((r) => r.shares ?? []),
		]);
	} catch (e) {
		const msg = e instanceof Error ? e.message : String(e);
		// 401/403 一律当作「需要 admin 会话」：只读会话在这里不够
		if (/40[13]|unauthorized|admin/i.test(msg)) {
			renderOpsUnlock(box);
			return;
		}
		box.textContent = `加载失败：${msg}`;
		return;
	}
	box.innerHTML = "";
	renderIntegrityCard(box, events);
	renderMigrationCard(box, migration);
	renderDeviceCard(box, devices);
	renderShareCard(box, shares);
	void renderRestoreCard(box);
}

function renderOpsUnlock(box: HTMLElement): void {
	box.innerHTML = "";
	const card = el("div", "settings-card");
	card.append(el("h2", "", "Admin unlock"));
	card.append(el("p", "muted small", "运维操作需要管理员权限：请输入 API Token 换取短期 admin 会话（30 分钟）。"));
	const input = el("input") as HTMLInputElement;
	input.type = "password";
	input.placeholder = "API Token";
	const btn = el("button", "primary", "解锁");
	const errEl = el("p", "error", "");
	const submit = async (): Promise<void> => {
		btn.disabled = true;
		if (await login(input.value.trim(), true)) {
			await renderOpsInto(box);
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

// 完整性告警放在最上面：它是唯一一类「已经有内容读不出来了」的信号。
function renderIntegrityCard(box: HTMLElement, events: IntegrityEvent[]): void {
	const card = el("div", "settings-card");
	card.append(el("h2", "", "Integrity"));
	if (events.length === 0) {
		card.append(el("p", "muted small", "没有完整性事件。"));
		box.append(card);
		return;
	}
	const unresolved = events.filter((e) => !e.resolved);
	const unservable = events.filter((e) => !e.serving);
	if (unservable.length > 0) {
		card.append(
			el(
				"p",
				"error",
				`${unservable.length} 份内容已停止对外提供（确认损坏且无法自愈）。` +
					"这些文件在客户端会读取失败——请从备份恢复，不要试图忽略。",
			),
		);
	}
	card.append(el("p", "muted small", `共 ${events.length} 条事件，其中 ${unresolved.length} 条未处理。`));
	const list = el("div", "settings-grid");
	for (const ev of events.slice(0, 20)) {
		list.append(
			el("div", "muted small", fmtTs(ev.detectedAt)),
			el(
				"div",
				ev.serving ? "" : "error",
				`${ev.kind}（${ev.detail}）· 影响 ${ev.affectedRefs} 处引用 · ` +
					(ev.serving ? "仍在服务" : "已停止服务") +
					(ev.resolved ? " · 已修复" : ""),
			),
		);
	}
	card.append(list);
	box.append(card);
}

function renderMigrationCard(box: HTMLElement, st: AdminMigrationStatus): void {
	const card = el("div", "settings-card");
	card.append(el("h2", "", "Migration"));
	const grid = el("div", "settings-grid");
	const item = (label: string, value: string, cls = ""): void => {
		grid.append(el("div", "muted small", label), el("div", cls, value));
	};
	const meta = (st.meta ?? {}) as Record<string, unknown>;
	item("Metadata state", String(meta.metaState ?? meta.state ?? "—"));
	if (meta.ownerDeviceId) item("Lease holder", String(meta.ownerDeviceId));
	if (meta.leaseExpiresAt) item("Lease expires", fmtTs(Number(meta.leaseExpiresAt)));
	if (meta.cutoffSequence) item("Cutoff sequence", String(meta.cutoffSequence));
	item("blobID domain", st.needsBlobIdMigration ? "待迁移" : "已完成", st.needsBlobIdMigration ? "error" : "");
	item(
		"Vault key rewrap",
		st.pendingRewrapEpoch > 0 ? `待重新封装（epoch ${st.pendingRewrapEpoch}）` : "无待办",
		st.pendingRewrapEpoch > 0 ? "error" : "",
	);
	card.append(grid);
	if (st.needsBlobIdMigration) {
		card.append(
			el(
				"p",
				"muted small",
				"存量 blob 仍按裸内容哈希命名：跨租户存在性隔离对老数据尚未生效。" +
					"先执行 obsync backup create，再执行 obsync blobid migrate --confirm（不可逆）。",
			),
		);
	}
	if (st.pendingRewrapEpoch > 0) {
		card.append(
			el(
				"p",
				"muted small",
				"有成员被移除后密钥已轮换，但 Vault Key 还没为新世代重新封装。" +
					"在一台管理员设备上重新封装并上传，剩余设备才能继续写入。",
			),
		);
	}
	box.append(card);
}

function renderDeviceCard(box: HTMLElement, devices: AdminDevice[]): void {
	const card = el("div", "settings-card");
	card.append(el("h2", "", "Devices"));
	card.append(
		el(
			"p",
			"muted small",
			"撤销立刻生效：长期凭据作废，它换出去的短期 access token 也一起失效。丢设备时争的就是这几分钟。",
		),
	);
	const list = el("div", "device-list");
	for (const d of devices) {
		const row = el("div", "settings-row");
		const info = el("div");
		info.append(el("div", d.revoked ? "muted" : "", `${d.name || "（未命名）"}${d.revoked ? "（已撤销）" : ""}`));
		info.append(
			el(
				"div",
				"muted small",
				`最后活动 ${fmtTs(d.lastSeenAt)} · 接入于 ${fmtTs(d.createdAt)} · ${d.scopes.join(", ") || "无权限"}`,
			),
		);
		row.append(info);
		if (!d.revoked) {
			const btn = el("button", "danger", "撤销");
			btn.onclick = () => {
				// 撤销不可逆，值得一次确认——但只要一次：事故当天多一层弹窗就是多一分钟
				if (!confirm(`撤销「${d.name || d.id}」？该设备将立刻无法同步。`)) return;
				btn.disabled = true;
				void S!.api
					.adminRevokeDevice(d.id)
					.then(() => renderOpsInto(box))
					.catch((e: unknown) => {
						btn.disabled = false;
						alert(`撤销失败：${e instanceof Error ? e.message : String(e)}`);
					});
			};
			row.append(btn);
		}
		list.append(row);
	}
	if (devices.length === 0) list.append(el("p", "muted small", "还没有设备接入。"));
	card.append(list);
	box.append(card);
}

function renderShareCard(box: HTMLElement, shares: AdminShare[]): void {
	const card = el("div", "settings-card");
	card.append(el("h2", "", "Shares"));
	card.append(
		el(
			"p",
			"muted small",
			"「恢复」只能把一个有效期设短了的分享往后延。密文一旦被过期回收就真的没了——" +
				"分享密钥从不上传，服务器手上没有任何能重建它的材料，只能重新分享。",
		),
	);
	const list = el("div", "share-list");
	for (const s of shares) {
		const row = el("div", "settings-row");
		const state = s.revoked ? "已撤销" : s.expired ? "已过期" : "有效";
		const info = el("div");
		info.append(el("div", s.revoked ? "muted" : "", `${s.id.slice(0, 12)}… · ${fmtBytes(s.size)} · ${state}`));
		info.append(
			el(
				"div",
				"muted small",
				`创建于 ${fmtTs(s.createdAt)} · 到期 ${s.expiresAt > 0 ? fmtTs(s.expiresAt) : "永不"}`,
			),
		);
		row.append(info);
		if (s.recoverable && !s.revoked) {
			const btn = el("button", "ghost", "延长 7 天");
			btn.onclick = () => {
				btn.disabled = true;
				const until = Math.floor(Date.now() / 1000) + 7 * 86400;
				void S!.api
					.adminRecoverShare(s.id, until)
					.then(() => renderOpsInto(box))
					.catch((e: unknown) => {
						btn.disabled = false;
						alert(`恢复失败：${e instanceof Error ? e.message : String(e)}`);
					});
			};
			row.append(btn);
		} else if (!s.revoked) {
			row.append(el("span", "muted small", "密文已回收，无法恢复"));
		}
		list.append(row);
	}
	if (shares.length === 0) list.append(el("p", "muted small", "没有分享记录。"));
	card.append(list);
	box.append(card);
}

// 灾备恢复：只做能安全做的部分——列快照、算后果、给出可粘贴的命令。
// 真正的切换必须停机后由 CLI 执行，原因见服务端 adminRestorePlan 的注释。
async function renderRestoreCard(box: HTMLElement): Promise<void> {
	const card = el("div", "settings-card");
	card.append(el("h2", "", "Disaster recovery"));
	box.append(card);

	let snapshots: BackupSnapshot[] = [];
	try {
		snapshots = (await S!.api.backupSnapshots()).snapshots ?? [];
	} catch {
		card.append(el("p", "muted small", "快照列表不可用（备份尚未配置或 restic 不可用）。"));
		return;
	}
	if (snapshots.length === 0) {
		card.append(el("p", "error", "仓库里没有任何快照。没有演练过恢复的备份，等于没有备份。"));
		return;
	}
	const select = el("select") as HTMLSelectElement;
	for (const s of snapshots) {
		const opt = el("option") as HTMLOptionElement;
		opt.value = s.id;
		opt.textContent = `${s.id.slice(0, 8)} · ${fmtTime(Date.parse(s.time))}`;
		select.append(opt);
	}
	const planBox = el("div", "restore-plan");
	const btn = el("button", "primary", "生成恢复预检");
	btn.onclick = () => {
		planBox.textContent = "计算中…";
		void S!.api
			.adminRestorePlan(select.value)
			.then((plan) => {
				planBox.innerHTML = "";
				planBox.append(
					el("p", "", `当前 sequence ${plan.currentSequence} · 在用设备 ${plan.activeDevices} 台`),
				);
				const ul = el("ul", "muted small");
				for (const c of plan.consequences) ul.append(el("li", "", c));
				planBox.append(ul);
				planBox.append(el("pre", "cmd", plan.command));
				const copy = el("button", "ghost", "复制命令");
				copy.onclick = () => void navigator.clipboard?.writeText(plan.command);
				planBox.append(copy);
				planBox.append(el("p", "muted small", plan.whyNotAButton));
			})
			.catch((e: unknown) => {
				planBox.textContent = `预检失败：${e instanceof Error ? e.message : String(e)}`;
			});
	};
	const row = el("div", "settings-row");
	row.append(select, btn);
	card.append(row, planBox);
}
