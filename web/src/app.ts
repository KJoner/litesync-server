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
	TrashItem,
	IntegrityError,
	IntegrityEvent,
	login,
	logout,
	VersionEntry,
	WebVault,
	Whoami,
	AdminInvite,
	AdminUser,
	accountApi,
	ACCOUNT_KEY,
	announceAccount,
	authConfig,
	Me,
	Usage,
} from "./api";
import { openConnectDialog, PortalHost, portalHeader, renderAccountCenter, renderLoginPage, renderVaultCenter } from "./portal";
import { DrawerHandle, openDialog, openDrawer } from "./dialog";
import { followSystemTheme, toggleTheme } from "./theme";
import { icon, IconName } from "./icons";
import { brand, fmtRelative, iconButton, labelButton, themeButton } from "./ui";
import { confirmDialog, fieldsDialog, folderOf, foldersOf, noteLocationDialog, titleOf, typedConfirmDialog } from "./forms";
import {
	deriveMetaKeys as coreDeriveMetaKeys,
	exportVmkRaw as coreExportVmkRaw,
	MetaKeys as CoreMetaKeys,
	VaultKeyDoc as CoreVaultKeyDoc,
} from "./vendor/litesync-core/crypto/crypto";
import { LockOutcome, NoteEditor, NoteEditorHost } from "./note-editor";
import {
	attachmentLink,
	attachmentPath,
	deleteFile,
	deriveDraftKey,
	DraftStore,
	indexedDbBackend,
	memoryBackend,
	newTrackedFile,
	PreparedRestore,
	prepareRestore,
	renameFile,
	RepoBinding,
	saveWithRetry,
	TrackedFile,
	uploadRestore,
} from "./write";
import {
	decryptFile,
	lse3Header,
	decryptMeta,
	deriveMetaKeys,
	deriveResetAuth,
	FileKeyBinding,
	importVmk,
	isEncryptedFile,
	MetaKeys,
	subtleAvailable,
	unlockVaultKey,
	VaultKeyDoc,
} from "./crypto";
import { DiffLine, diffLines } from "./diff";
import { buildOutline, preprocessWiki, renderMarkdown } from "./markdown";

const VAULT_KEY = "litesync-vault";

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
	/** 当前会话身份（v0.18 多用户）：user 角色不渲染运维/设置/用户管理入口 */
	me?: Whoami;
	/** 名下仓库（v0.19 多仓库；单仓库时不渲染切换器） */
	vaults: WebVault[];
	/** 解锁 E2EE 时派生的重置凭证（v11 设计 §3.1）；重置 Token 时提交 */
	resetAuth?: string;
	/** 服务端是否已登记重置凭证（info.resetAuthConfigured） */
	resetAuthConfigured?: boolean;
	/**
	 * 各对象已见过的最大 contentGeneration（v0.13.3 / 计划书 §7.5）。
	 *
	 * 只在本次会话内有效——查看器没有本地持久状态，做不到跨会话的抗回退。
	 * 但会话内的回退（同一次浏览中服务器先给新版本再给旧版本）必须挡住。
	 */
	seenGeneration: Map<string, number>;
	// ---- v0.20 网页编辑（ADR-015） ----
	/**
	 * /api/v1/info 的写入相关字段（逐请求世代校验要带上它们）。canWrite：本账号在这个仓库里的成员角色
	 * 能否写内容（v0.20.1；只读成员一打开就隐藏编辑 / 新建，最终裁决仍在服务端）；旧服务端没有这个字段。
	 */
	repo?: { repoEpoch: string; formatEpoch: number; minimumEnvelopeVersion: number; encryptionState: string; metaState?: string; canWrite?: boolean; role?: string };
	/** 可写的仓库密钥（encrypt+decrypt，不可导出；只在内存） */
	writeKey?: CryptoKey;
	/** 插件同源的元数据密钥（enc+mac；meta 模式写入用） */
	coreMeta?: CoreMetaKeys;
	/** 加密草稿（解锁后才存在；锁定即随内存一起消失） */
	drafts?: DraftStore;
	/** 浏览器不允许持久存储（隐私模式等）：草稿只在本页内存里，界面要如实说明 */
	draftsVolatile?: boolean;
	/** 账号（统一身份）与网页编辑开关 */
	account?: Me;
	/** 当前打开的编辑器（离开/锁定前先把草稿加密落盘） */
	editor?: NoteEditor;
}

let S: State | null = null;
const app = document.getElementById("app")!;
let blobUrls: string[] = [];

/**
 * 会话代次（RC-1）：锁定、身份变化、切库会让它前进。异步任务开始时用 fence() 记下
 * 「代次 + 账号 + 仓库 + 状态对象」，每个 await 之后先问一句还成不成立——旧会话的结果
 * （上传成功、合并结果、搜索解密、附件图片）一律不得落到新会话的界面、草稿或命名空间里。
 */
let sessionGen = 0;
function fence(): () => boolean {
	const gen = sessionGen;
	const account = bootAccountId;
	const state = S;
	const vault = currentVaultId();
	return () => gen === sessionGen && account === bootAccountId && state !== null && state === S && vault === currentVaultId();
}

/** 切换视图时立即回收上一个笔记的所有附件 Blob URL，避免大图累积占内存。 */
/** 当前视图里已解密的附件（路径@revision → blob URL）：分栏预览重绘时复用，不重复下载解密。 */
const attachmentUrlCache = new Map<string, string>();

function revokeAllBlobs(): void {
	for (const url of blobUrls) URL.revokeObjectURL(url);
	blobUrls = [];
	attachmentUrlCache.clear();
}

// ---------- 主题 ----------
// UI 焕新 U4：没有手动选择时跟随系统（theme.ts，网页、分享页、加入页共用）。
const applyTheme = followSystemTheme;

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
const portalHost: PortalHost = {
	root: app,
	toggleTheme,
	lastVault: () => rememberedVault(),
	openVault: (vaultId, preset) => {
		rememberVault(vaultId);
		if (preset) {
			// 刚建好的仓库：密钥已在内存里，直接进入（不落盘、不刷新，避免立刻再输一次密码）。
			// 用 replaceState 改地址：直接赋值 location.hash 会触发门户页的 hashchange → 再跑一遍
			// 不带密钥的 boot()，两条启动路径赛跑，后完成的那条会把解锁页盖到已进入的工作台上（实测）
			history.replaceState(null, "", "#/");
			const api = new Api();
			api.vaultId = vaultId;
			void bootVault(api, preset);
			return;
		}
		location.hash = "#/";
		location.reload(); // 仓库间的密钥/状态彻底隔离：整页重进最干净
	},
};

// ---------- 账号命名空间与跨标签页身份变化（验收 TN-05） ----------
//
// 浏览器存储里的一切都要按账号分区：同一浏览器换成 B 登录时，B 不能看到 A 留下的任何东西，
// 也不能拿 A 的选择去发请求。另一个标签页切换 / 退出账号时，本页要立刻发现并清掉可见状态
// （已解锁的明文、编辑器、撤销栈）——共享的会话 Cookie 已经是 B 的了，再留着 A 的内容就是泄露。

/** 本页面启动时确认的账号（null = 尚未登录 / 已在处理身份变化）。 */
let bootAccountId: string | null = null;

/** 记住的仓库选择按账号分区：litesync-vault:<账号>。 */
function vaultKey(): string {
	return bootAccountId ? `${VAULT_KEY}:${bootAccountId}` : VAULT_KEY;
}

function rememberedVault(): string {
	try {
		return localStorage.getItem(vaultKey()) ?? "";
	} catch {
		return ""; // 隐私模式等场景读不了 storage
	}
}

function rememberVault(id: string): void {
	try {
		localStorage.setItem(vaultKey(), id);
	} catch {
		/* ignore */
	}
}

function forgetVault(): void {
	try {
		localStorage.removeItem(vaultKey());
	} catch {
		/* ignore */
	}
}

/** 账号变了（另一个标签页登录了别人 / 退出了 / 会话失效）：先把草稿加密落盘，再整页重载清空。 */
async function identityChanged(): Promise<void> {
	if (bootAccountId === null) return;
	bootAccountId = null; // 防重入
	if (S?.vmk) {
		await lockNow("账号已在另一个标签页切换或退出");
		return;
	}
	location.reload();
}

window.addEventListener("storage", (e) => {
	if (e.key !== ACCOUNT_KEY || bootAccountId === null) return;
	if ((e.newValue ?? "") !== bootAccountId) void identityChanged();
});
document.addEventListener("visibilitychange", () => {
	if (document.visibilityState !== "visible" || bootAccountId === null) return;
	void accountApi
		.me()
		.then((m) => {
			if (m.account.id !== bootAccountId) void identityChanged();
		})
		.catch((e) => {
			if (e instanceof AuthError) void identityChanged();
		});
});

/**
 * v0.20：先确认账号身份（统一登录 / API Token 会话），再决定进入哪个页面——
 * 零仓库账号是正常状态，不能再像以前那样以「当前仓库的 /api/v1/info」作为入口。
 */
async function boot(): Promise<void> {
	applyTheme();
	const cfg = await authConfig();
	let me: Me;
	try {
		me = await accountApi.me();
	} catch (e) {
		if (e instanceof AuthError) {
			bootAccountId = null;
			announceAccount(""); // 未登录：其他标签页若还显示着某个账号的内容，它们会自行清理
			const err = new URLSearchParams(location.search).get("loginError") ?? undefined;
			renderLoginPage(portalHost, cfg, err);
			return;
		}
		renderMessage(`无法连接服务器：${e instanceof Error ? e.message : String(e)}`);
		return;
	}
	bootAccountId = me.account.id;
	announceAccount(me.account.id);
	try {
		localStorage.removeItem(VAULT_KEY); // 旧版本留下的不分账号的仓库选择：一次性清理
	} catch {
		/* ignore */
	}
	const hash = location.hash;
	window.onhashchange = () => void boot();
	if (hash.startsWith("#/me")) {
		await renderAccountCenter(portalHost, me, cfg);
		return;
	}
	if (hash.startsWith("#/vaults") || me.vaultCount === 0 || (!rememberedVault() && (hash === "" || hash === "#/"))) {
		await renderVaultCenter(portalHost, me);
		return;
	}
	const api = new Api();
	api.vaultId = rememberedVault();
	await bootVault(api);
}

/** 进入一个仓库的笔记工作台（v0.19 起的原有流程）。preset：刚建库时已在内存中的密钥。 */
async function bootVault(api: Api, preset?: { doc: CoreVaultKeyDoc; vmk: CryptoKey }): Promise<void> {
	try {
		const info = await api.info(); // 会话 Cookie 无效 → AuthError → 登录页
		const vaultDoc = await api.vaultKey();
		const binding =
			info.vaultId && (info.keyEpoch ?? 0) > 0
				? { vaultId: info.vaultId, keyEpoch: info.keyEpoch! }
				: undefined;
		S = { api, files: [], byPath: new Map(), vaultDoc, vmk: null, binding, seenGeneration: new Map(), vaults: [] };
		S.repo = {
			repoEpoch: info.repoEpoch ?? "", formatEpoch: info.formatEpoch ?? 1,
			minimumEnvelopeVersion: info.minimumEnvelopeVersion ?? 0, encryptionState: info.encryptionState ?? "plaintext", metaState: info.metaState,
			canWrite: info.access?.canWrite, role: info.access?.role,
		};
		S.account = await accountApi.me().catch(() => undefined);
		S.resetAuthConfigured = info.resetAuthConfigured;
		// 身份（v0.18）：角色决定导航渲染；服务端对 admin API 另有硬关卡
		S.me = await api.whoami().catch(() => undefined);
		S.vaults = await api.listVaults();
		// v0.20：还没完成加密设置的仓库没有可看的内容——回到仓库中心完成设置
		const cur = S.vaults.find((v) => v.current);
		if (cur && cur.initState && cur.initState !== "ready") {
			location.hash = "#/vaults";
			return;
		}
		// §7.5：仓库处于迁移中等非常态时，必须让用户看到——
		// 此时看到的内容可能是不完整或过渡态的，静默展示等于误导
		showRepoStateBanner(info.metaState);
		if (vaultDoc?.enabled) {
			if (!subtleAvailable()) {
				renderMessage("此仓库已启用端到端加密，浏览器解密需要 HTTPS（或 localhost）访问。");
				return;
			}
			if (preset && preset.doc.wrappedKey === vaultDoc.wrappedKey) {
				// 刚在本页建好的仓库：密钥已在内存里（同一份 keyDoc 才采纳）
				const raw = await coreExportVmkRaw(preset.vmk);
				try {
					await adoptVaultKey(raw);
				} finally {
					raw.fill(0);
				}
				await enterMain();
				return;
			}
			// VMK 只存在内存：每次进入页面都需要解锁
			renderUnlock();
			return;
		}
		await enterMain();
	} catch (e) {
		if (e instanceof AuthError) {
			await boot(); // 会话失效 → 统一的登录页
			return;
		}
		// v0.19：上次选择的仓库已不存在/无权限（404）→ 清掉记忆回默认仓库重试
		if (api.vaultId && e instanceof Error && /404/.test(e.message)) {
			forgetVault();
			api.vaultId = "";
			await boot();
			return;
		}
		renderMessage(`无法连接服务器：${e instanceof Error ? e.message : String(e)}`);
	}
}

/** 取 snapshot 并在本地解出真实路径（meta 模式：条目是伪名 + 加密元数据）。 */
async function loadFileList(): Promise<{ sequence: number; files: FileEntry[] }> {
	const snap = await S!.api.snapshot();
	for (const f of snap.files) {
		if (!f.metaEnc || !f.fileId) continue;
		f.serverPath = f.path;
		if (!S!.metaKeys || !S!.binding?.vaultId) continue; // 无法解密：以伪名显示
		const dec = await decryptMeta(S!.metaKeys, f.metaEnc, S!.binding.vaultId, f.fileId);
		if (dec) f.path = dec.path;
	}
	return { sequence: snap.sequence, files: snap.files.filter((f) => isVisible(f.path)) };
}

async function enterMain(): Promise<void> {
	const list = await loadFileList();
	S!.files = list.files;
	S!.byPath = new Map(S!.files.map((f) => [f.path, f]));
	lastSequence = list.sequence;
	renderMain();
	onRoute();
	window.clearInterval(pollTimer);
	pollTimer = window.setInterval(() => void pollRemote(), 30_000);
}

// ---------- 发现其他设备的修改（v0.20） ----------
//
// 网页此前只在进入时取一次 snapshot：别的设备新建 / 修改 / 删除的笔记要刷新页面才看得到。
// 现在每 30 秒（以及标签页回到前台、窗口获得焦点时）问一次 changes 游标——没有新变更时这只是
// 一个空列表；有变更就重取 snapshot 刷新文件树。正在打开的笔记：没有未保存的修改就直接载入
// 新版本；有的话不动它，提示「保存时会自动合并」（保存走 CAS → 三方合并 → 合并不了保留双方）。
let lastSequence = 0;
let pollTimer = 0;
let polling = false;

async function pollRemote(): Promise<void> {
	if (!S || polling || document.visibilityState !== "visible") return;
	if (S.vaultDoc?.enabled && !S.vmk) return; // 已锁定
	polling = true;
	const alive = fence();
	try {
		const c = await S.api.changes(lastSequence, 1);
		if (pollOffline) {
			pollOffline = false;
			updateSyncPill();
		}
		if (!alive() || (!c.resyncRequired && c.changes.length === 0)) return;
		const list = await loadFileList();
		if (!alive() || !S) return; // 轮询期间锁定 / 换号：结果作废
		lastSequence = list.sequence;
		S.files = list.files; // 本页新建但还没保存成功的笔记从不进文件列表，这里不会被冲掉
		S.byPath = new Map(S.files.map((f) => [f.path, f]));
		renderTree();
		const ed = S.editor;
		if (ed) {
			markActive(ed.file.path);
			const cur = S.files.find((f) => f.fileId && f.fileId === ed.file.fileId);
			if (!cur && ed.file.revision > 0) ed.remoteDeleted();
			else if (cur && cur.revision > ed.file.revision) await ed.remoteChanged();
		}
		updateStatus("已载入其他设备的修改");
	} catch (e) {
		// 网络抖动：下一次再问；连不上服务器时顶栏如实显示「离线」
		if (e instanceof TypeError) {
			pollOffline = true;
			updateSyncPill();
		}
	} finally {
		polling = false;
	}
}
document.addEventListener("visibilitychange", () => {
	if (document.visibilityState === "visible") void pollRemote();
});
window.addEventListener("focus", () => void pollRemote());

// ---------- v0.20 网页编辑：密钥、写入绑定、自动锁定 ----------

/**
 * 解锁后在内存里派生全部密钥（raw 由调用方清零）：
 *   - vmk：解密 + 加密（不可导出）；metaKeys / coreMeta：路径元数据；resetAuth；
 *   - drafts：加密草稿（HKDF 派生的独立密钥；命名空间 = 服务器 | 账号 | 仓库）。
 * 不写任何浏览器存储；锁定 = 整页重载，这些对象随之释放。
 */
async function adoptVaultKey(raw: Uint8Array): Promise<void> {
	S!.vmk = await crypto.subtle.importKey("raw", raw as BufferSource, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
	S!.writeKey = S!.vmk;
	S!.metaKeys = await deriveMetaKeys(raw);
	S!.coreMeta = await coreDeriveMetaKeys(raw);
	S!.resetAuth = await deriveResetAuth(raw);
	const draftKey = await deriveDraftKey(raw);
	let backend;
	try {
		backend = indexedDbBackend();
		await backend.keys("probe"); // 隐私模式等场景打不开 IndexedDB：降级为内存（界面会说明不跨刷新保留）
		S!.draftsVolatile = false;
	} catch {
		backend = memoryBackend();
		S!.draftsVolatile = true;
	}
	const ns = `${location.origin}|${S!.account?.account.id ?? S!.me?.userId ?? "anon"}|${currentVaultId()}`;
	S!.drafts = new DraftStore(backend, ns, draftKey, `${S!.binding?.vaultId ?? ""}|${S!.binding?.keyEpoch ?? 0}`);
}

function currentVaultId(): string {
	return S?.vaults.find((v) => v.current)?.id ?? S?.api.vaultId ?? "";
}

/** 网页编辑是否可用：服务端开关 + 仓库就绪 + （加密仓库）已解锁。角色由服务端裁决。 */
function canEdit(): boolean {
	if (!S || S.account?.features?.webEditing !== true) return false;
	const enc = S.vaultDoc?.enabled === true;
	if (enc && !S.writeKey) return false;
	// 路径加密迁移进行中：只读（服务端对非迁移持有者同样会拒绝写入）
	if (S.repo?.metaState === "migrating" || S.repo?.metaState === "verifying") return false;
	// 只读成员（reader）：一打开就不提供编辑 / 新建——不要等用户写了半天，保存时才收到 403
	if (S.repo?.canWrite === false) return false;
	return true;
}

/** 网页编辑开着、但本账号在这个仓库里是只读成员。 */
function readOnlyMember(): boolean {
	return S?.account?.features?.webEditing === true && S.repo?.canWrite === false;
}

function repoBinding(): RepoBinding {
	return {
		vaultId: currentVaultId(),
		vaultIdentity: S!.binding?.vaultId ?? "",
		keyEpoch: S!.binding?.keyEpoch ?? 0,
		repoEpoch: S!.repo?.repoEpoch ?? "",
		formatEpoch: S!.repo?.formatEpoch ?? 1,
		minimumEnvelopeVersion: S!.repo?.minimumEnvelopeVersion ?? 0,
		encrypted: S!.vaultDoc?.enabled === true,
		metaMode: S!.repo?.metaState === "encrypted",
	};
}

function envelopeOf(data: ArrayBuffer): { envelope: TrackedFile["envelope"]; padded: boolean } {
	const head = new Uint8Array(data, 0, Math.min(5, data.byteLength));
	const magic = String.fromCharCode(...head.slice(0, 4));
	if (magic === "LSE4") return { envelope: "LSE4", padded: (head[4] & 1) === 1 };
	if (magic.startsWith("LSE")) return { envelope: "LSE3", padded: false };
	return { envelope: "plain", padded: false };
}

function trackedFor(entry: FileEntry, raw: ArrayBuffer, generation: number | null): TrackedFile {
	const env = envelopeOf(raw);
	return {
		path: entry.path, serverPath: entry.serverPath ?? entry.path, fileId: entry.fileId ?? "",
		revision: entry.revision,
		generation: generation ?? (entry.fileId ? S!.seenGeneration.get(entry.fileId) ?? 0 : 0),
		envelope: env.envelope, padded: env.padded, metaGeneration: entry.metaGeneration ?? 0,
	};
}

/** 空闲自动锁定（默认 15 分钟，按实际经过时间判断：后台标签页的计时器暂停也不会漏判）。 */
const IDLE_KEY = "litesync-idle-minutes";
let lastActivity = Date.now();
function idleMinutes(): number {
	try {
		const v = Number(localStorage.getItem(IDLE_KEY));
		return v >= 1 && v <= 240 ? v : 15;
	} catch {
		return 15;
	}
}
/** 锁定提示：按草稿的真实结局说，不笼统地写「已加密保存在本机」。 */
function lockMessage(reason: string, o: LockOutcome): string {
	if (!o.unsynced) return reason + "。";
	if (o.volatile) return reason + "。浏览器不允许持久存储：锁定前还没有同步的修改只在页面内存里，已随页面一起释放，无法恢复。";
	if (!o.persisted) return reason + "。最后一段未同步的输入没能写入本机草稿（存储不可用或超时）。";
	return reason + "。未同步的修改已加密保存在本机，解锁后打开这篇笔记即可恢复并继续同步。";
}

async function lockNow(reason: string, interactive = false): Promise<void> {
	if (!S?.vmk) return;
	// 只在内存里的草稿会随整页重载消失：主动锁定时先问一句，可以先导出
	if (interactive && S.draftsVolatile && S.editor?.unsynced) {
		if (!confirm("浏览器不允许持久存储：这篇笔记还没同步的修改只在页面内存里，锁定后会丢失。\n\n确定：先导出为文件，再锁定\n取消：先不锁定")) return;
		S.editor.exportText();
	}
	sessionGen++; // 在途的上传 / 合并 / 搜索结果从这一刻起一律作废
	const outcome = (await S.editor?.lock()) ?? { unsynced: false, persisted: true, volatile: S.draftsVolatile === true };
	S.vmk = null;
	S.writeKey = undefined;
	S.drafts = undefined;
	try {
		sessionStorage.setItem("litesync-lock-reason", lockMessage(reason, outcome));
	} catch {
		/* ignore */
	}
	location.reload(); // 内存里的密钥、明文、撤销栈、对象 URL 随页面一起释放
}
for (const ev of ["keydown", "pointerdown", "wheel"]) {
	window.addEventListener(ev, () => (lastActivity = Date.now()), { passive: true });
}
function checkIdle(): void {
	if (S?.vmk && S.vaultDoc?.enabled && Date.now() - lastActivity > idleMinutes() * 60_000) void lockNow(`空闲超过 ${idleMinutes()} 分钟，已自动锁定`);
}
window.setInterval(checkIdle, 30_000);
document.addEventListener("visibilitychange", () => {
	if (document.visibilityState === "visible") checkIdle();
});

function editorHost(): NoteEditorHost {
	return {
		binding: repoBinding,
		keys: () => (S?.writeKey ? { vmk: S.writeKey, meta: S.coreMeta } : null),
		drafts: () => S?.drafts ?? null,
		draftsVolatile: () => S?.draftsVolatile === true,
		alive: fence(), // 编辑器创建时的会话：锁定 / 换号 / 切库之后它的异步结果一律作废
		renderPreview: (c, t) => renderMarkdownInto(c, S?.editor?.file.path ?? "", t),
		fetchRemote: async (f) => {
			const dl = await S!.api.fileWithIdentity(f.serverPath);
			const plain = await decodeContent(f.path, dl.data, { fileId: dl.fileId, generation: dl.generation });
			return {
				text: new TextDecoder("utf-8", { ignoreBOM: true }).decode(plain),
				revision: dl.revision, generation: dl.generation ?? 0, fileId: dl.fileId ?? f.fileId,
			};
		},
		onSaved: (f, created) => {
			recordSaved(f, created);
			// 正在编辑的这篇第一次落到服务器：树里高亮它，去掉「新笔记」提示，并就地挂上
			// 「位置 / 历史版本 / 更多」（不重建视图：编辑器的光标、撤销栈、草稿都不动）
			if (created && S!.editor?.file.fileId === f.fileId) {
				markActive(f.path);
				contentEl.querySelector(".new-note-hint")?.remove();
				const head = contentEl.querySelector<HTMLElement>(".note-head");
				if (head && !head.hasChildNodes()) {
					const id = f.fileId;
					head.append(...noteHeadParts(f.path, id), noteMenu(() => editingFile(id) ?? f));
				}
			}
		},
		onAuthExpired: (claim) => {
			updateStatus(`登录已过期，修改没有上传。${claim || "没有未保存的修改。"}重新登录并解锁后可以继续`);
		},
		uploadAttachment,
		showCompare,
	};
}

/** 一次成功写入后更新本地索引（文件树、已见世代、底栏）。 */
function recordSaved(f: TrackedFile, created: boolean, size = 0): void {
	if (f.fileId) S!.seenGeneration.set(f.fileId, Math.max(S!.seenGeneration.get(f.fileId) ?? 0, f.generation));
	const cur = S!.byPath.get(f.path);
	if (cur) {
		cur.revision = f.revision;
		cur.fileId = f.fileId;
		cur.metaGeneration = f.metaGeneration; // 之后改名的 CAS 以服务器记账的元数据世代为准
		cur.mtime = Date.now();
	} else if (created) {
		const entry: FileEntry = { path: f.path, revision: f.revision, hash: "", size, mtime: Date.now(), fileId: f.fileId, serverPath: f.serverPath, metaGeneration: f.metaGeneration };
		S!.files.push(entry);
		S!.byPath.set(f.path, entry);
		renderTree();
		if (S!.editor) markActive(S!.editor.file.path);
	}
	updateStatus();
}

/**
 * 附件上传（需求 §7.2「附件上传及引用」）：放在笔记所在文件夹，与笔记同一套加密写入
 * （新 fileId、LSE3/LSE4、路径加密仓库附 LSM1）；成功后才返回引用文本，
 * 失败抛错——编辑器里不会出现指向不存在文件的引用。
 */
async function uploadAttachment(file: File, notePath: string): Promise<string> {
	const canonPaths = new Set(S!.files.map((f) => f.path.normalize("NFC").toLowerCase()));
	const path = attachmentPath(notePath, file.name || "image.png", (c) => canonPaths.has(c));
	const bytes = new Uint8Array(await file.arrayBuffer());
	const tracked = newTrackedFile(path, repoBinding());
	const out = await saveWithRetry(repoBinding(), S?.writeKey ? { vmk: S.writeKey, meta: S.coreMeta } : null, tracked, bytes);
	if (out.kind === "rejected") throw new Error(out.code === "TOO_LARGE" ? "超过服务器允许的单文件大小" : writeError(out.code, out.message));
	if (out.kind === "conflict") throw new Error("同名文件刚被别的设备创建，请重试");
	if (out.kind === "auth") throw new Error("登录已过期");
	if (out.kind === "offline") throw new Error("网络连接失败");
	recordSaved({ ...tracked, revision: out.revision, generation: out.generation, fileId: out.fileId, metaGeneration: out.metaGeneration ?? tracked.metaGeneration }, true, bytes.length);
	const name = path.slice(path.lastIndexOf("/") + 1).normalize("NFC").toLowerCase();
	const unique = S!.files.filter((f) => f.path.slice(f.path.lastIndexOf("/") + 1).normalize("NFC").toLowerCase() === name).length === 1;
	return attachmentLink(path, unique);
}

/** 对照两份文本（保留双方之后的处理界面；只读，不改动任何一份）。 */
function showCompare(title: string, a: { label: string; text: string }, b: { label: string; text: string }): void {
	const dlg = openDialog(title);
	dlg.body.append(el("p", "muted small", `「−」只在${a.label}里，「+」只在${b.label}里。确认后在编辑器里合并，再删除不需要的那一份。`));
	const box = el("pre", "diff-box");
	const lines = diffLines(a.text, b.text);
	if (lines === null) box.textContent = "两份差异过大，无法逐行对比。";
	else
		for (const line of lines) {
			const div = el("div", `diff-line diff-${line.type}`);
			div.textContent = (line.type === "add" ? "+ " : line.type === "del" ? "- " : "  ") + line.text;
			box.append(div);
		}
	dlg.body.append(box);
}

function mountEditor(container: HTMLElement, tracked: TrackedFile, text: string, created: boolean, mode: "read" | "edit"): NoteEditor {
	const ed = new NoteEditor(container, editorHost(), tracked, text, created);
	S!.editor = ed;
	void ed.setMode(mode);
	return ed;
}

/** 已离开、仍在后台上传最后一版的编辑器（按 fileId）。 */
const backgroundSaves = new Map<string, Promise<void>>();

/** 离开当前笔记：未保存的内容先加密落盘，再在后台上传一次（不阻塞导航）。 */
async function leaveEditor(): Promise<void> {
	const ed = S?.editor;
	if (!ed) return;
	S!.editor = undefined;
	const pending = await ed.leave();
	if (!pending) return;
	const id = ed.file.fileId;
	const p = pending.done.finally(() => {
		if (backgroundSaves.get(id) === p) backgroundSaves.delete(id);
		if (location.hash === "#/" || location.hash === "") void renderDraftList();
		else void refreshDraftCount();
	});
	backgroundSaves.set(id, p);
	updateSyncPill();
}

/** 打开一篇笔记前：它若还在后台上传，先等那一轮结束（最多 5 秒），免得读到上传前的版本。 */
async function settleBackground(fileId: string | undefined): Promise<void> {
	const p = fileId ? backgroundSaves.get(fileId) : undefined;
	if (p) await Promise.race([p, new Promise((r) => setTimeout(r, 5000))]);
}

// 离开页面：还有服务器没确认的内容时让浏览器提示（草稿在输入停顿后已加密落盘）
window.addEventListener("beforeunload", (e) => {
	if (S?.editor?.unsynced || backgroundSaves.size > 0) {
		void S?.editor?.flush();
		e.preventDefault();
		e.returnValue = "";
	}
});
document.addEventListener("visibilitychange", () => {
	if (document.visibilityState === "hidden") void S?.editor?.flush();
});

/** 首页：本机还有未同步的加密草稿（离线时离开、冲突待处理、新建后未保存成功）。 */
async function renderDraftList(): Promise<void> {
	const box = document.getElementById("draft-list");
	const ds = S?.drafts;
	if (!box || !ds) return;
	const alive = fence();
	const all = await ds.listFiles().catch(() => []);
	if (!alive()) return;
	const items = all.filter((d) => !backgroundSaves.has(d.fileKey));
	draftCount = items.length;
	updateSyncPill();
	box.innerHTML = "";
	if (items.length === 0) return;
	box.append(el("h2", "section-title", "本机未同步的草稿"));
	box.append(el("p", "muted small", S?.draftsVolatile
		? "这些修改只在这个页面的内存里（浏览器不允许持久存储），还没有到达服务器；关闭或刷新页面就会丢失。打开即可继续同步。"
		: "这些修改只以加密形式保存在这台设备的浏览器里，还没有到达服务器。打开即可继续同步。"));
	const list = el("div", "note-list");
	for (const it of items) {
		const card = el("button", "note-row draft-card") as HTMLButtonElement;
		card.type = "button";
		const sym = el("span", "note-symbol");
		sym.append(icon("clock"));
		const meta = el("span", "note-meta");
		meta.append(el("strong", "", noteTitle(it.path)), el("small", "", `本机草稿 · ${fmtRelative(it.savedAt)}${it.count > 1 ? `（共 ${it.count} 份）` : ""}`));
		card.append(sym, meta, icon("chevron", "row-chev"));
		card.onclick = () => {
			const existing = S!.files.find((f) => f.fileId === it.fileKey);
			if (existing) {
				location.hash = "#/n/" + encodeURIComponent(existing.path);
				return;
			}
			void openDraftAsNew(it.file);
		};
		list.append(card);
	}
	box.append(list);
}

/** 从未成功创建的新笔记草稿继续（新 fileId 保持不变，保存时才在服务器上创建）。 */
async function openDraftAsNew(file: TrackedFile): Promise<void> {
	await leaveEditor();
	revokeAllBlobs();
	markActive(null);
	contentEl.innerHTML = "";
	outlineEl.innerHTML = "";
	setHere(noteTitle(file.path));
	const wrap = el("div", "note-wrap");
	wrap.append(el("div", "note-head"), el("h1", "note-title", noteTitle(file.path)), el("p", "muted small new-note-hint", "新笔记：第一次保存后才会出现在服务器与其他设备上"));
	const body = el("div", "note-editor");
	wrap.append(body);
	contentEl.append(wrap);
	mountEditor(body, { ...file, revision: 0 }, "", true, "edit");
}

/** 规范化用户输入的笔记路径（不允许绝对路径、..、隐藏段；补 .md）。 */
function normalizeNotePath(input: string): string | null {
	let p = input.trim().replace(/\\/g, "/").replace(/\/+/g, "/").replace(/^\/+/, "");
	if (!p) return null;
	if (!/\.[^/.]+$/.test(p)) p += ".md";
	const segs = p.split("/");
	if (segs.some((s) => s === "" || s === "." || s === ".." || s.startsWith(".") || s.trim() !== s)) return null;
	return p;
}

function writeError(code: string, message: string): string {
	switch (code) {
		case "CANONICAL_COLLISION":
		case "CONFLICT":
			return "目标位置已有同名文件（大小写或 Unicode 归一后同名也算），请换一个名字。";
		case "FORBIDDEN":
			return "你在这个仓库里只有只读权限，或网页编辑未开启。";
		case "OFFLINE":
			return "网络连接失败，请稍后重试。";
		case "QUOTA_EXCEEDED":
			return "已达到账号的存储配额（历史版本也计入）。删除不需要的文件或清理历史后再试，或联系管理员调整配额。";
		case "RATE_LIMITED":
			return "操作太频繁，请稍后再试。";
		default:
			return `操作失败（${code}）：${message}`;
	}
}

/** 笔记的「更多」菜单：重命名、移动到、删除（都走同步协议，保留 fileId 与历史）。UI 焕新 U4：产品内对话框。 */
/**
 * 笔记的「更多」菜单。current()：这篇笔记**现在**的跟踪状态——改名 / 移动之后视图不重建，
 * 菜单和历史按钮都要在点击时取最新的路径，不能用创建菜单那一刻的快照。
 */
function noteMenu(current: () => TrackedFile): HTMLElement {
	const more = el("details", "note-more");
	more.append(el("summary", "", "更多"));
	const menu = el("div", "vault-menu");
	const clash = (from: string, to: string): string | null => {
		const canon = (p: string) => p.normalize("NFC").toLowerCase();
		const other = S!.files.find((f) => f.path !== from && canon(f.path) === canon(to));
		return other ? `已有同名笔记「${other.path}」（大小写或 Unicode 归一后同名也算），请换一个名字。` : null;
	};
	const rename = el("button", "ghost", "重命名…");
	rename.onclick = () => {
		more.open = false;
		const t = current();
		noteLocationDialog({ title: "重命名笔记", okLabel: "重命名", name: titleOf(t.path), folder: folderOf(t.path), folders: foldersOf(S!.files.map((f) => f.path)), askName: true, askFolder: false, normalize: normalizeNotePath, check: (to) => clash(t.path, to), submit: (to) => moveNote(t, to) });
	};
	const move = el("button", "ghost", "移动到…");
	move.onclick = () => {
		more.open = false;
		const t = current();
		noteLocationDialog({ title: "移动到", okLabel: "移动", name: titleOf(t.path), folder: folderOf(t.path), folders: foldersOf(S!.files.map((f) => f.path)), askName: false, askFolder: true, normalize: normalizeNotePath, check: (to) => clash(t.path, to), submit: (to) => moveNote(t, to) });
	};
	const del = el("button", "ghost danger-text", "删除…");
	del.onclick = () => {
		more.open = false;
		const t = current();
		confirmDialog({
			title: `删除「${noteTitle(t.path)}」？`,
			message: "删除会同步到所有设备。历史版本仍保留：可以在回收站或其他设备上找回。",
			okLabel: "删除笔记",
			danger: true,
			confirm: async () => {
				const f = current();
				const r = await deleteFile(repoBinding(), f);
				if (r.kind !== "saved") return r.kind === "conflict" ? "这篇笔记刚在别处被修改过，请刷新后再删除。" : r.kind === "rejected" ? writeError(r.code, r.message) : "网络连接失败，请稍后重试。";
				// 只删本编辑器自己的草稿：别的标签页里同一篇的未同步输入留着（保存时会走「远端已删除」另存为新笔记）
				if (S!.editor) await S!.drafts?.remove(f.fileId, S!.editor.draftId).catch(() => undefined);
				S!.editor = undefined;
				S!.files = S!.files.filter((x) => x.path !== f.path);
				S!.byPath.delete(f.path);
				renderTree();
				location.hash = "#/";
				return null;
			},
		});
	};
	menu.append(rename, move, del);
	more.append(menu);
	return more;
}

/** 正在编辑的就是这篇（按 fileId）：返回编辑器里的跟踪状态，否则 null。 */
function editingFile(fileId: string | undefined): TrackedFile | null {
	return fileId && S?.editor?.file.fileId === fileId ? S.editor.file : null;
}

/** 笔记标题上方一行的「位置 + 历史版本」。历史按钮在点击时取这篇笔记现在的路径（改名 / 移动后不过时）。 */
function fillCrumb(crumb: HTMLElement, path: string): void {
	crumb.replaceChildren(icon("folder"));
	const parts = path.split("/").slice(0, -1);
	if (parts.length === 0) crumb.append(el("span", "", "仓库根目录"));
	parts.forEach((p, i) => {
		if (i > 0) crumb.append(icon("chevron", "sep"));
		crumb.append(el("span", "", p));
	});
}

function noteHeadParts(path: string, fileId: string | undefined): HTMLElement[] {
	const crumb = el("div", "crumb");
	crumb.setAttribute("aria-label", "位置");
	fillCrumb(crumb, path);
	const histBtn = labelButton("history", "历史版本", "btn ghost hist-btn");
	histBtn.setAttribute("aria-controls", "drawer");
	histBtn.setAttribute("aria-expanded", "false");
	histBtn.onclick = () => void openHistory(editingFile(fileId)?.path ?? path, histBtn);
	return [crumb, histBtn];
}

/** 改名 / 移动一篇笔记（同一个同步操作）：成功返回 null，失败返回给表单显示的错误。 */
async function moveNote(tracked: TrackedFile, to: string): Promise<string | null> {
	if (to === tracked.path) return null;
	if (S!.byPath.has(to)) return "目标位置已有同名文件。";
	await S!.editor?.flush();
	const r = await renameFile(repoBinding(), S?.writeKey ? { vmk: S.writeKey, meta: S.coreMeta } : null, S!.editor?.file ?? tracked, to);
	if (!r.ok) return writeError(r.code, r.message);
	// 编辑器里的跟踪状态同步更新：之后的内容保存要寻址新位置、以新的对象版本为 CAS 前提
	if (S!.editor) S!.editor.file = { ...S!.editor.file, path: to, serverPath: r.serverPath, metaGeneration: r.metaGeneration, revision: r.revision };
	const entry = S!.byPath.get(tracked.path);
	if (entry) {
		S!.byPath.delete(tracked.path);
		entry.path = to;
		entry.serverPath = r.serverPath;
		entry.metaGeneration = r.metaGeneration;
		entry.revision = r.revision;
		S!.byPath.set(to, entry);
	}
	renderTree();
	markActive(to);
	const title = contentEl.querySelector(".note-title");
	if (title) title.textContent = noteTitle(to);
	const crumb = contentEl.querySelector<HTMLElement>(".crumb");
	if (crumb) fillCrumb(crumb, to);
	setHere(noteTitle(to));
	location.hash = "#/n/" + encodeURIComponent(to);
	return null;
}

/** 新建笔记：只在编辑器里存在，第一次保存时才在服务器上创建（新 fileId，revision 0）。
 * UI 焕新 U4：填标题、选位置（默认当前笔记所在的文件夹），不要求手写路径。 */
function showNewNote(): void {
	const here = S?.editor?.file.path ? folderOf(S.editor.file.path) : "";
	const canon = (p: string) => p.normalize("NFC").toLowerCase();
	noteLocationDialog({
		title: "新建笔记",
		okLabel: "新建",
		name: `未命名 ${new Date().toISOString().slice(0, 10)}`,
		folder: here,
		folders: foldersOf(S!.files.map((f) => f.path)),
		askName: true,
		askFolder: true,
		normalize: normalizeNotePath,
		// 撞名按最严解释判断（大小写、Unicode 归一后同名即视为同一文件；服务器同样会拒绝）
		check: (path) => {
			if (S!.byPath.has(path)) return null; // the same note: it just opens
			const clash = S!.files.find((f) => canon(f.path) === canon(path));
			return clash ? `已有同名笔记「${clash.path}」（大小写或 Unicode 归一后同名也算），请换一个名字。` : null;
		},
		submit: async (path) => {
			if (S!.byPath.has(path)) {
				location.hash = "#/n/" + encodeURIComponent(path);
				return null;
			}
			await openNewNote(path);
			return null;
		},
	});
}

async function openNewNote(path: string): Promise<void> {
	await leaveEditor();
	revokeAllBlobs();
	markActive(null);
	contentEl.innerHTML = "";
	outlineEl.innerHTML = "";
	setHere(noteTitle(path));
	const wrap = el("div", "note-wrap");
	wrap.append(el("div", "note-head"), el("h1", "note-title", noteTitle(path)), el("p", "muted small new-note-hint", "新笔记：第一次保存后才会出现在服务器与其他设备上"));
	const body = el("div", "note-editor");
	wrap.append(body);
	contentEl.append(wrap);
	mountEditor(body, newTrackedFile(path, repoBinding()), "", true, "edit");
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
	card.append(brand(), ...children);
	wrap.append(card);
	app.append(wrap);
}

function renderMessage(msg: string): void {
	renderCentered([el("p", "muted", msg)]);
}

function renderLogin(err?: string): void {
	const sub = el("p", "muted", "你的私人笔记仓库");
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

/**
 * 解锁页（V2 / L2）：左边说明、右边独立的解锁卡片，写明解锁的是哪个仓库；页头与「我的仓库」相同。
 * 密码处理、锁定原因、异步隔离（fence）与切库语义都沿用原来的实现——这里只换版式。
 */
function renderUnlock(err?: string): void {
	// 多仓库（v0.19）：解锁的对象是**当前选中的仓库**——把这一点讲明白，
	// 并让「密码其实是另一个仓库的」当场就能切，而不是对着「密码错误」发呆
	const multi = (S?.vaults.length ?? 0) > 1;
	const name = currentVaultName();
	app.innerHTML = "";
	const page = el("div", "portal unlock-page");
	const main = el("main", "unlock-layout");

	const info = el("section", "unlock-info");
	info.setAttribute("aria-label", "关于仓库密码");
	const glyph = el("div", "vault-glyph");
	glyph.append(icon("lock"));
	const head = el("p", "unlock-headline");
	head.append("你的笔记，", el("br"), "只向你打开。");
	const lead = el("p", "lead");
	lead.append(`正在打开「${name}」。`, el("br"), "输入这个仓库的独立密码，继续上次的思考。");
	const points = el("ul", "unlock-points");
	for (const [n, t] of [["shield", "仓库密码与账号密码相互独立"], ["monitor", "只在这台设备上解密"], ["lock", "锁定或离开工作台后，需要重新解锁"]] as const) {
		const li = el("li");
		li.append(icon(n), el("span", "", t));
		points.append(li);
	}
	info.append(glyph, el("p", "eyebrow", "A little privacy, by design"), head, lead, points);

	const card = el("section", "unlock-card");
	// UI 焕新 W02 / W03：单仓库也写明解锁的是哪个仓库；离开工作台回来的人一眼看到「输入密码 → 继续」
	const title = el("h1", "unlock-title", `解锁「${name}」`);
	title.id = "unlock-title";
	card.setAttribute("aria-labelledby", title.id);
	// UI 规格：一句关键说明 + 密码框 + 明确的错误反馈 + 帮助入口；术语统一用「仓库密码」
	card.append(title, el("p", "sub", "仓库密码只在这台设备上用来解密，和账号的登录密码不是同一个。"));
	// 锁定原因（手动锁定 / 空闲自动锁定 / 离开工作台）：只显示一次
	try {
		const why = sessionStorage.getItem("litesync-lock-reason");
		if (why) {
			// 原因里已经按草稿的真实结局说明了「修改现在在哪里」（lockMessage），这里不再笼统补一句
			sessionStorage.removeItem("litesync-lock-reason");
			card.append(el("p", "banner info", why));
		}
	} catch {
		/* ignore */
	}
	const form = el("form", "unlock-form");
	form.noValidate = true;
	const label = el("label", "field-label", "仓库密码") as HTMLLabelElement;
	label.htmlFor = "vault-password";
	const input = el("input") as HTMLInputElement;
	input.id = "vault-password";
	input.type = "password";
	input.placeholder = "输入仓库密码";
	input.autocomplete = "current-password";
	input.setAttribute("aria-describedby", "unlock-error");
	const reveal = iconButton("eye", "显示仓库密码", "icon-btn pw-toggle");
	reveal.setAttribute("aria-pressed", "false");
	reveal.onclick = () => {
		const show = input.type === "password";
		input.type = show ? "text" : "password";
		reveal.replaceChildren(icon(show ? "eyeOff" : "eye"));
		reveal.setAttribute("aria-label", show ? "隐藏仓库密码" : "显示仓库密码");
		reveal.title = reveal.getAttribute("aria-label")!;
		reveal.setAttribute("aria-pressed", String(show));
		input.focus();
	};
	const pw = el("div", "password-wrap");
	pw.append(input, reveal);
	const errEl = el("p", "error unlock-error", err ?? "");
	errEl.id = "unlock-error";
	errEl.setAttribute("role", "alert");
	const btn = labelButton("unlock", "解锁并打开", "btn primary wide unlock-submit");
	btn.type = "submit";
	form.append(label, pw, errEl, btn);
	card.append(form);
	if (multi) {
		const sw = labelButton("folder", "切换到其他仓库", "btn text switch-vault", () => openVaultSwitcher(false));
		card.append(el("p", "muted small switch-note", "每个仓库的仓库密码相互独立；密码是另一个仓库的，就先切换过去。"), sw);
	}
	const hint = el("details", "unlock-help");
	hint.append(
		el("summary", "", "忘记了仓库密码？"),
		el("p", "muted small", "服务器从来没有见过仓库密码，所以无法替你找回。如果还有一台已解锁的设备（比如 Obsidian），可以在那台设备上更换仓库密码；否则这个仓库里的内容无法解密。重置账号的登录密码也解不开仓库。"),
	);
	const back = el("a", "back-link") as HTMLAnchorElement;
	back.href = "#/vaults";
	back.append(icon("back"), el("span", "", "返回我的仓库"));
	card.append(hint, back);
	main.append(info, card);
	page.append(portalHeader(portalHost, ""), main);
	app.append(page);

	const busy = (on: boolean) => {
		btn.disabled = on;
		btn.replaceChildren(icon("unlock"), el("span", "", on ? "解锁中…" : "解锁并打开"));
	};
	const submit = async () => {
		busy(true);
		const alive = fence();
		const raw = await unlockVaultKey(S!.vaultDoc!, input.value);
		if (!alive()) {
			raw?.fill(0); // 解锁期间换号 / 切库：这把钥匙属于旧会话，丢弃
			return;
		}
		if (!raw) {
			errEl.textContent = multi
				? "仓库密码不对。如果这是你另一个仓库的密码，请先切换到那个仓库。"
				: "仓库密码不对。注意它不是账号的登录密码。";
			input.setAttribute("aria-invalid", "true");
			busy(false);
			input.focus();
			return;
		}
		// VMK 只保留在内存 CryptoKey：不写任何浏览器存储，刷新即需重新解锁
		await adoptVaultKey(raw);
		raw.fill(0);
		if (S!.resetAuthConfigured === false && S!.resetAuth) {
			void S!.api.putResetAuth(S!.resetAuth).then(() => {
				S!.resetAuthConfigured = true;
			});
		}
		await enterMain();
	};
	form.onsubmit = (e) => {
		e.preventDefault();
		if (!btn.disabled) void submit();
	};
	input.oninput = () => input.removeAttribute("aria-invalid");
	input.focus();
}

/**
 * 切换仓库（侧栏的仓库选择器、解锁页）：列出名下仓库，选中另一个 = 整页重进那个仓库（各仓库的 E2EE 独立解锁，
 * 与原来的下拉切换器同一语义）。在工作台里先走草稿保护：未同步的修改落不了盘就不切（需求 §7.3）。
 */
function openVaultSwitcher(inWorkspace: boolean, opener?: HTMLElement): void {
	const dlg = openDialog("切换仓库");
	const list = el("div", "modal-list");
	for (const v of S?.vaults ?? []) {
		const b = el("button", "modal-item" + (v.current ? " current" : "")) as HTMLButtonElement;
		b.type = "button";
		const text = el("span", "modal-item-text");
		const pending = v.initState !== undefined && v.initState !== "ready";
		const note = v.current ? "当前仓库"
			: pending ? "还没有完成加密设置"
			: v.encryptionState === "encrypted" ? "切换后需要输入它的仓库密码"
			: v.encryptionState === "migrating" ? "加密迁移中"
			: "未加密的旧仓库";
		text.append(el("strong", "", v.name || "默认仓库"), el("small", "", note));
		b.append(icon("folder"), text, icon(v.current ? "check" : "chevron"));
		if (v.current) b.setAttribute("aria-current", "true");
		b.onclick = () => {
			if (v.current) {
				dlg.close();
				return;
			}
			dlg.close(true);
			void switchVault(v.id, inWorkspace);
		};
		list.append(b);
	}
	const actions = el("div", "dialog-actions");
	const all = labelButton("folder", "我的仓库", "btn", () => {
		dlg.close(true);
		opener?.focus();
		if (inWorkspace) confirmLeave("#/vaults");
		else location.hash = "#/vaults";
	});
	const cancel = el("button", "btn ghost", "取消") as HTMLButtonElement;
	cancel.type = "button";
	cancel.onclick = () => dlg.close();
	actions.append(all, cancel);
	dlg.body.append(el("p", "muted small", "每个仓库都用自己的仓库密码；切换后要输入那个仓库的密码。"), list, actions);
}

async function switchVault(id: string, inWorkspace: boolean): Promise<void> {
	if (inWorkspace) {
		// 主动切库：草稿落不了盘就暂停切换（需求 §7.3）
		if (!(await guardVaultLeave())) return;
		await leaveEditor();
		await waitBackgroundSaves();
	}
	rememberVault(id);
	history.replaceState(null, "", "#/");
	location.reload(); // 仓库间的密钥/状态彻底隔离：整页重进最干净
}

/** 当前仓库的显示名（默认仓库没有名字）。 */
function currentVaultName(): string {
	const cur = S?.vaults.find((v) => v.current);
	return cur ? cur.name || "默认仓库" : "当前仓库";
}

// ---------- 离开工作台（W03）：动作之前就说清会锁定 ----------
const LEAVE_HINT_KEY = "litesync-leave-hint";
const LEAVE_REASON = "离开工作台时已锁定这个仓库（密钥只在页面内存里）。输入仓库密码继续。";

/**
 * 去「我的仓库」「账号与设备」= 离开笔记工作台，整页重载释放密钥（严格会话解锁，规则不变）。
 * 这里只是在动作之前说明：已解锁的加密仓库先弹一次说明，可以选「以后不再提示」（只是界面偏好）。
 */
function confirmLeave(target: "#/vaults" | "#/me"): void {
	let skip = false;
	try {
		skip = localStorage.getItem(LEAVE_HINT_KEY) === "off";
	} catch {
		/* 读不了偏好就照常提示 */
	}
	if (!(S?.vmk && S.vaultDoc?.enabled) || skip) {
		location.hash = target;
		return;
	}
	const dlg = openDialog(`离开工作台会锁定「${currentVaultName()}」`);
	const where = target === "#/me" ? "「账号与设备」" : "「我的仓库」";
	const unsynced = S.editor?.dirty ? "这篇笔记还没同步的修改会在离开前加密保存到本机（保存不了会先请你导出一份），解锁后打开它就能继续。" : "";
	const keep = el("input") as HTMLInputElement;
	keep.type = "checkbox";
	const keepLine = el("label", "check-line");
	keepLine.append(keep, document.createTextNode(" 以后不再提示"));
	const actions = el("div", "dialog-actions");
	const stay = el("button", "btn ghost", "留在这里") as HTMLButtonElement;
	stay.type = "button";
	stay.onclick = () => dlg.close();
	const go = el("button", "btn primary", "锁定并前往") as HTMLButtonElement;
	go.type = "button";
	go.onclick = () => {
		if (keep.checked) {
			try {
				localStorage.setItem(LEAVE_HINT_KEY, "off");
			} catch {
				/* 存不了就下次再提示 */
			}
		}
		dlg.close(true);
		location.hash = target;
	};
	actions.append(stay, go);
	dlg.body.append(
		el("p", "", `${where}在笔记工作台之外。离开时这个仓库会锁定：密钥和已经解密的内容只在这个页面的内存里，随页面一起释放。`),
		el("p", "muted small", `回来时要再输入一次仓库密码。${unsynced}`),
		keepLine,
		actions,
	);
	setTimeout(() => go.focus(), 0);
}

// ---------- 主布局（UI 焕新 v2 / V2：240 侧栏 + 顶栏 + 正文） ----------
//
// 侧栏：品牌 → 仓库选择器（锁定状态）→ 搜索 / 新建 → 概览与文件树 → 回收站、实例管理（管理员）、账号与设备。
// 顶栏：仓库 / 位置、真实的保存同步状态、主题、锁定。离开工作台（我的仓库、账号与设备）仍先说明会锁定
// （confirmLeave），整页重载释放密钥——共享的外观不是绕过锁定的捷径。
let treeEl: HTMLElement;
let contentEl: HTMLElement;
let outlineEl: HTMLElement;
let statusEl: HTMLElement;
let sidebarEl: HTMLElement | null = null;
let mainEl: HTMLElement | null = null;
let crumbHereEl: HTMLElement | null = null;
let syncPillEl: HTMLElement | null = null;
let homeLinkEl: HTMLAnchorElement | null = null;

// ---------- 手机上的侧栏抽屉（W08）：键盘可开关，焦点进出正确，关着时整个侧栏 inert，开着时正文 inert ----------
const narrowScreen = window.matchMedia("(max-width: 760px)");
let menuBtnEl: HTMLButtonElement | null = null;

function syncSidebar(): void {
	const open = document.body.classList.contains("sidebar-open");
	const narrow = narrowScreen.matches;
	menuBtnEl?.setAttribute("aria-expanded", String(open && narrow));
	if (sidebarEl) sidebarEl.inert = narrow && !open;
	if (mainEl) mainEl.inert = narrow && open;
}

function setSidebar(open: boolean, moveFocus = true): void {
	const was = document.body.classList.contains("sidebar-open");
	document.body.classList.toggle("sidebar-open", open);
	syncSidebar();
	if (!moveFocus || open === was || !narrowScreen.matches) return;
	if (open) (sidebarEl?.querySelector<HTMLElement>(".tree-file.active") ?? sidebarEl?.querySelector<HTMLElement>(".mobile-close"))?.focus();
	else if (!sidebarEl || sidebarEl.contains(document.activeElement) || document.activeElement === document.body) menuBtnEl?.focus();
}
narrowScreen.addEventListener("change", syncSidebar);
document.addEventListener("keydown", (e) => {
	if (!document.body.classList.contains("sidebar-open") || !narrowScreen.matches || !sidebarEl) return;
	if (document.querySelector(".dialog-backdrop, .drawer")) return; // 上面还有对话框 / 抽屉：交给它们
	if (e.key === "Escape") {
		setSidebar(false);
		return;
	}
	if (e.key !== "Tab") return;
	// 抽屉开着时 Tab 只在抽屉里循环（正文已 inert）
	const f = Array.from(sidebarEl.querySelectorAll<HTMLElement>("a[href],button:not([disabled]),summary,input,select"))
		.filter((n) => n.offsetParent !== null && !n.closest("[hidden]"));
	if (f.length === 0) return;
	const first = f[0], last = f[f.length - 1];
	if (e.shiftKey && (document.activeElement === first || !sidebarEl.contains(document.activeElement))) {
		last.focus();
		e.preventDefault();
	} else if (!e.shiftKey && (document.activeElement === last || !sidebarEl.contains(document.activeElement))) {
		first.focus();
		e.preventDefault();
	}
});
// Ctrl/⌘+K：在工作台里打开搜索
document.addEventListener("keydown", (e) => {
	if (e.isComposing || !(e.ctrlKey || e.metaKey) || e.key.toLowerCase() !== "k") return;
	if (!sidebarEl?.isConnected || document.querySelector(".dialog-backdrop")) return;
	e.preventDefault();
	openSearchDialog();
});

const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

function sideLink(href: string, name: IconName, text: string, cls = "side-link"): HTMLAnchorElement {
	const a = el("a", cls) as HTMLAnchorElement;
	a.href = href;
	a.append(icon(name), el("span", "", text));
	return a;
}

function renderMain(): void {
	app.innerHTML = "";
	const shell = el("div", "shell");
	const name = currentVaultName();
	const encrypted = S!.vaultDoc?.enabled === true;

	// ---- 侧栏 ----
	sidebarEl = el("aside", "sidebar");
	sidebarEl.id = "sidebar";
	sidebarEl.setAttribute("aria-label", "仓库导航");
	const top = el("div", "sidebar-top");
	top.append(brand("#/", "LiteSync 概览"), iconButton("close", "关闭仓库导航", "icon-btn mobile-close", () => setSidebar(false)));
	// 仓库选择器：当前仓库与锁定状态一直看得到（W02），点开切换仓库或去「我的仓库」
	const vaultSel = el("button", "vault-select") as HTMLButtonElement;
	vaultSel.type = "button";
	vaultSel.setAttribute("aria-haspopup", "dialog");
	const vs = el("span", "vault-select-text");
	vs.append(el("strong", "", name), el("small", "", encrypted ? "已解锁 · 仅本次会话" : "未加密的旧仓库"), el("span", "sr-only", "，切换仓库"));
	vaultSel.append(icon("folder"), vs, icon("down", "chev"));
	vaultSel.onclick = () => openVaultSwitcher(true, vaultSel);
	const tools = el("div", "sidebar-tools");
	const search = el("button", "btn side-search") as HTMLButtonElement;
	search.type = "button";
	search.append(icon("search"), el("span", "", "搜索笔记"), el("kbd", "", isMac ? "⌘ K" : "Ctrl K"));
	search.onclick = () => openSearchDialog();
	tools.append(search);
	if (canEdit()) {
		tools.append(labelButton("plus", "新建笔记", "btn subtle tree-new", () => showNewNote()));
	} else if (readOnlyMember()) {
		tools.append(el("p", "muted small tree-readonly", "你在这个仓库里是只读成员：可以阅读和搜索，不能新建或修改。"));
	}
	const nav = el("nav", "side-nav");
	nav.setAttribute("aria-label", "笔记目录");
	homeLinkEl = sideLink("#/", "home", "概览", "side-link home-link");
	treeEl = el("div", "tree");
	treeEl.id = "tree";
	nav.append(homeLinkEl, el("p", "side-label", "笔记"), treeEl);
	const bottom = el("div", "sidebar-bottom");
	bottom.append(sideLink("#/trash", "trash", "回收站"));
	// v0.18 角色化导航：运维/设置/用户管理只属于管理员（服务端另有硬关卡，这里只是别把用户点不动的入口摆出来）；
	// 实例管理与普通用户的动作分开放
	if (S!.me?.role !== "user") {
		const admin = document.createElement("details");
		admin.className = "side-group";
		const sum = document.createElement("summary");
		sum.className = "side-link";
		sum.append(icon("tools"), el("span", "", "实例管理"), icon("chevron", "trail chev"));
		admin.append(sum,
			sideLink("#/settings/backup", "database", "备份"),
			sideLink("#/settings/ops", "tools", "运维"),
			sideLink("#/settings/users", "users", "用户管理"));
		admin.open = location.hash.startsWith("#/settings/");
		bottom.append(admin);
	}
	bottom.append(themeButton(toggleTheme, "side-link theme-row", true));
	const account = el("button", "side-link account-link") as HTMLButtonElement;
	account.type = "button";
	account.title = "账号与设备（会锁定当前仓库）";
	account.append(icon("settings"), el("span", "", "账号与设备"), icon("lock", "trail"));
	account.onclick = () => confirmLeave("#/me");
	bottom.append(account);
	sidebarEl.append(top, vaultSel, tools, nav, bottom);

	// ---- 顶栏 + 正文 ----
	mainEl = el("div", "main");
	const header = el("header", "app-header");
	const menuBtn = iconButton("menu", "打开仓库导航", "icon-btn menu-btn");
	menuBtn.setAttribute("aria-controls", "sidebar");
	menuBtn.setAttribute("aria-expanded", "false");
	menuBtn.onclick = () => setSidebar(!document.body.classList.contains("sidebar-open"));
	menuBtnEl = menuBtn;
	const crumbs = el("nav", "crumbs");
	crumbs.setAttribute("aria-label", "当前位置");
	// W02：单仓库、手机宽度也一直看得到当前仓库
	const chip = el("span", "vault-crumb vault-chip");
	chip.title = `当前仓库：${name}`;
	chip.append(el("span", "sr-only", "当前仓库："), document.createTextNode(name));
	crumbHereEl = el("span", "crumb-here", "概览");
	crumbs.append(chip, el("span", "slash", "/"), crumbHereEl);
	const right = el("div", "header-right");
	syncPillEl = el("span", "pill sync-pill");
	const lockBtn = iconButton("lock", "锁定当前仓库", "icon-btn lock-btn", () => {
		// 先把未保存的编辑加密写入本机草稿（有限等待），再丢弃内存里的密钥
		void lockNow("已锁定", true);
	});
	lockBtn.title = "锁定仓库（丢弃内存中的密钥）";
	lockBtn.hidden = !encrypted;
	right.append(syncPillEl, themeButton(toggleTheme), lockBtn);
	header.append(menuBtn, crumbs, right);
	const body = el("div", "main-body");
	contentEl = el("main", "content");
	contentEl.id = "content";
	outlineEl = el("aside", "outline");
	outlineEl.setAttribute("aria-label", "本页目录");
	body.append(contentEl, outlineEl);
	statusEl = el("footer", "app-footer");
	mainEl.append(header, body, statusEl);
	shell.append(sidebarEl, mainEl);
	// 手机上侧栏是抽屉：遮罩点一下就关
	const scrim = el("div", "sidebar-backdrop");
	scrim.onclick = () => setSidebar(false);
	app.append(shell, scrim);
	syncSidebar();
	// 顶栏状态跟着编辑器的真实保存状态走（.save-status 的 data-state）
	new MutationObserver(() => updateSyncPill()).observe(contentEl, { subtree: true, attributes: true, attributeFilter: ["data-state"] });

	renderTree();
	updateStatus();
	void refreshDraftCount();
	window.onhashchange = onRoute;
}

/** 顶栏面包屑里「当前位置」那一段。 */
function setHere(text: string): void {
	if (crumbHereEl) {
		crumbHereEl.textContent = text;
		crumbHereEl.title = text;
	}
	// 侧栏里对应当前页面的入口（概览、回收站、实例管理）标成当前位置
	const here = location.hash === "" ? "#/" : location.hash;
	sidebarEl?.querySelectorAll<HTMLAnchorElement>("a.side-link").forEach((a) => {
		const on = a.getAttribute("href") === here;
		a.classList.toggle("active", on);
		if (on) a.setAttribute("aria-current", "page");
		else a.removeAttribute("aria-current");
	});
}

// ---------- 顶栏的保存同步状态（真实来源：编辑器状态、后台上传、本机草稿、最近一次与服务器通信） ----------
let pollOffline = false;
let draftCount = 0;

interface PillView {
	tone: "ok" | "warn" | "danger" | "info" | "";
	icon: IconName;
	text: string;
	title: string;
}

function pillView(): PillView {
	if (!canEdit()) {
		return { tone: "", icon: "eye", text: "只读", title: readOnlyMember() ? "你在这个仓库里是只读成员：可以阅读和搜索，不能修改" : "这里只能阅读（网页编辑没有开启，或仓库暂时只读）" };
	}
	const st = S?.editor ? contentEl?.querySelector<HTMLElement>(".save-status")?.dataset.state : undefined;
	switch (st) {
		case "dirty":
			return { tone: "warn", icon: "clock", text: "未保存", title: "这篇笔记有还没保存的修改" };
		case "drafted":
			return { tone: "warn", icon: "clock", text: "本机草稿", title: "修改已加密保存在这台设备上，等待同步到服务器" };
		case "uploading":
			return { tone: "info", icon: "refresh", text: "同步中", title: "正在上传到服务器" };
		case "offline":
			return { tone: "warn", icon: "cloud", text: "离线", title: "网络断开：修改留在本机，恢复后自动同步" };
		case "conflict":
			return { tone: "danger", icon: "warn", text: "有冲突", title: "这篇笔记有冲突，需要处理" };
		case "quota":
			return { tone: "danger", icon: "warn", text: "容量不足", title: "存储配额已满，修改没有上传" };
		case "auth":
			return { tone: "danger", icon: "warn", text: "需重新登录", title: "登录已过期，修改没有上传" };
		case "error":
			return { tone: "danger", icon: "warn", text: "保存失败", title: "保存失败，修改还在编辑器里" };
	}
	if (backgroundSaves.size > 0) return { tone: "info", icon: "refresh", text: "同步中", title: "正在把刚离开的笔记上传到服务器" };
	if (pollOffline) return { tone: "warn", icon: "cloud", text: "离线", title: "连不上服务器：显示的是上一次载入的内容" };
	if (draftCount > 0) return { tone: "warn", icon: "clock", text: "本机草稿", title: `有 ${draftCount} 篇笔记的修改只在这台设备上，打开即可继续同步` };
	return { tone: "ok", icon: "check", text: "已同步", title: "这台浏览器里的修改都已保存到服务器" };
}

function updateSyncPill(): void {
	if (!syncPillEl) return;
	const v = pillView();
	const key = `${v.tone}|${v.text}|${v.title}`;
	if (syncPillEl.dataset.key === key) return;
	syncPillEl.dataset.key = key;
	syncPillEl.className = "pill sync-pill" + (v.tone ? " " + v.tone : "");
	syncPillEl.replaceChildren(icon(v.icon), el("span", "", v.text));
	syncPillEl.title = v.title;
}

/** 本机还有未同步的加密草稿的笔记数（不算正在后台上传的）。 */
async function refreshDraftCount(): Promise<void> {
	const ds = S?.drafts;
	if (!ds) return;
	const alive = fence();
	const all = await ds.listFiles().catch(() => []);
	if (!alive()) return;
	draftCount = all.filter((d) => !backgroundSaves.has(d.fileKey)).length;
	updateSyncPill();
}
window.addEventListener("offline", () => {
	pollOffline = true;
	updateSyncPill();
});
window.addEventListener("online", () => void pollRemote());

function updateStatus(extra?: string): void {
	if (!statusEl || !S) return;
	const latest = S.files.reduce((m, f) => Math.max(m, f.mtime), 0);
	const left = el("span", "footer-main",
		`${S.files.length} 个文件 · ${currentVaultName()}` +
		(latest ? ` · 更新于 ${fmtTime(latest)}` : "") +
		(extra ? ` · ${extra}` : ""));
	const right = el("span", "footer-session");
	right.append(icon(S.vaultDoc?.enabled ? "lock" : "info"), el("span", "", S.vaultDoc?.enabled ? "仅本次会话已解锁 · 离开工作台会锁定" : "未加密的旧仓库"));
	statusEl.replaceChildren(left, right);
	updateSyncPill();
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
	if (S!.files.length === 0) treeEl.append(el("p", "muted small tree-empty", "还没有笔记"));
	treeEl.append(renderDirChildren(buildTreeModel()));
}

function fileIcon(path: string): IconName {
	return path.toLowerCase().endsWith(".md") ? "file" : IMAGE_EXT.test(path) ? "image" : "attachment";
}

function renderDirChildren(dir: TreeDir): HTMLElement {
	const box = el("div", "tree-children");
	const dirs = [...dir.dirs.values()].sort((a, b) => a.name.localeCompare(b.name, "zh"));
	for (const sub of dirs) {
		const details = document.createElement("details");
		details.open = true;
		const summary = document.createElement("summary");
		summary.append(icon("chevron", "chev"), icon("folder"), el("span", "", sub.name));
		summary.title = sub.name;
		details.append(summary, renderDirChildren(sub));
		box.append(details);
	}
	const files = [...dir.files].sort((a, b) => a.path.localeCompare(b.path, "zh"));
	for (const f of files) {
		const a = el("a", "tree-file") as HTMLAnchorElement;
		a.href = `#/n/${encodeURIComponent(f.path)}`;
		a.append(icon(fileIcon(f.path)), el("span", "", noteTitle(f.path)));
		a.title = f.path;
		a.dataset.path = f.path;
		box.append(a);
	}
	return box;
}

function markActive(path: string | null): void {
	treeEl.querySelectorAll(".tree-file.active").forEach((n) => {
		n.classList.remove("active");
		n.removeAttribute("aria-current");
	});
	if (path) {
		const node = treeEl.querySelector(`.tree-file[data-path="${CSS.escape(path)}"]`);
		node?.classList.add("active");
		node?.setAttribute("aria-current", "page");
		node?.scrollIntoView({ block: "nearest" });
	}
}

// ---------- 搜索（V2：侧栏「搜索笔记」/ Ctrl+K 打开的对话框；标题与路径即时匹配，回车在正文中搜索） ----------
function openSearchDialog(): void {
	if (!S || document.querySelector(".dialog-backdrop")) return;
	const dlg = openDialog("搜索笔记");
	const field = el("label", "field search-field");
	field.append(el("span", "", `在已解锁的「${currentVaultName()}」中查找`));
	const input = el("input", "search") as HTMLInputElement;
	input.type = "search";
	input.placeholder = "标题或路径；回车在正文中搜索";
	input.autocomplete = "off";
	input.spellcheck = false;
	field.append(input);
	const results = el("div", "modal-list search-list");
	const go = (hash: string) => {
		dlg.close(true);
		location.hash = hash;
	};
	const item = (f: FileEntry): HTMLElement => {
		const a = el("a", "modal-item") as HTMLAnchorElement;
		a.href = `#/n/${encodeURIComponent(f.path)}`;
		const text = el("span", "modal-item-text");
		text.append(el("strong", "", noteTitle(f.path)), el("small", "", f.path));
		a.append(icon(fileIcon(f.path)), text, icon("chevron"));
		a.onclick = (e) => {
			e.preventDefault();
			go(a.getAttribute("href")!);
		};
		return a;
	};
	const render = () => {
		const q = input.value.trim();
		results.innerHTML = "";
		if (!q) {
			const recent = [...S!.files].filter((f) => f.path.toLowerCase().endsWith(".md")).sort((a, b) => b.mtime - a.mtime).slice(0, 6);
			if (recent.length) results.append(el("p", "side-label", "最近编辑"), ...recent.map(item));
			else results.append(el("p", "empty-note", "这个仓库还没有笔记。"));
			return;
		}
		const lower = q.toLowerCase();
		const hits = S!.files.filter((f) => f.path.toLowerCase().includes(lower)).slice(0, 20);
		if (hits.length) results.append(...hits.map(item));
		else results.append(el("p", "empty-note", "没有匹配的标题或路径。"));
		// 正文全文搜索（需求 §7.2）：在本机建索引，不把明文发给服务器
		const full = el("a", "modal-item search-fulltext") as HTMLAnchorElement;
		full.href = `#/search/${encodeURIComponent(q)}`;
		const text = el("span", "modal-item-text");
		text.append(el("strong", "", `在正文中搜索「${q}」`), el("small", "", "在这台设备上解密建索引（回车也可以）"));
		full.append(icon("search"), text, icon("chevron"));
		full.onclick = (e) => {
			e.preventDefault();
			go(full.getAttribute("href")!);
		};
		results.append(full);
	};
	input.oninput = render;
	input.onkeydown = (e) => {
		if (e.key === "Enter" && !e.isComposing && input.value.trim()) {
			e.preventDefault();
			go(`#/search/${encodeURIComponent(input.value.trim())}`);
		}
	};
	dlg.body.append(field, results, el("p", "muted small", "正文搜索只在这台设备上解密建索引，搜索词不会发给服务器。"));
	render();
	setTimeout(() => input.focus(), 0);
}

// ---------- 正文全文搜索（需求 §7.2；验收 KY-03） ----------
//
// 只能在已解锁的客户端建索引：逐篇下载密文、在本机解密，正文只存在这个页面的内存里——
// 锁定、刷新、切换仓库或账号（都会整页重载）即随页面一起释放。大库按需建索引并显示进度；
// 只重新下载 revision 变了的笔记。搜索本身完全在本地，服务器只看到普通的文件下载。
const textIndex = new Map<string, { revision: number; text: string }>();
/** 当前这一轮搜索的编号：离开搜索页（或开始新的搜索）即作废正在进行的建索引。 */
let searchRun = 0;

async function showSearchPage(q: string): Promise<void> {
	const run = ++searchRun;
	revokeAllBlobs();
	markActive(null);
	outlineEl.innerHTML = "";
	contentEl.innerHTML = "";
	const wrap = el("div", "note-wrap");
	contentEl.append(wrap);
	setHere("搜索");
	wrap.append(el("h1", "", `搜索「${q}」`));
	wrap.append(el("p", "muted small", "正文索引只在这个浏览器的内存里建立，锁定、刷新或离开仓库即清除；搜索时不会把任何明文发给服务器。"));
	const progress = el("p", "muted small search-progress");
	progress.setAttribute("role", "status");
	const list = el("div", "search-page-list");
	wrap.append(progress, list);
	const notes = S!.files.filter((f) => f.path.toLowerCase().endsWith(".md"));
	const todo = notes.filter((f) => textIndex.get(f.path)?.revision !== f.revision);
	let done = notes.length - todo.length;
	const needle = q.toLowerCase();

	const renderHits = () => {
		list.innerHTML = "";
		let n = 0;
		for (const f of notes) {
			const text = textIndex.get(f.path)?.text;
			const pos = text ? text.toLowerCase().indexOf(needle) : -1;
			if (pos < 0 && !f.path.toLowerCase().includes(needle)) continue;
			const a = el("a", "search-hit") as HTMLAnchorElement;
			a.href = `#/n/${encodeURIComponent(f.path)}`;
			a.append(el("div", "recent-title", noteTitle(f.path)), el("div", "muted small", f.path));
			if (text && pos >= 0) {
				// 片段用文本节点拼出来：正文是不可信内容，绝不走 innerHTML
				const start = Math.max(0, pos - 40);
				const end = Math.min(text.length, pos + needle.length + 60);
				const snip = el("div", "search-snippet");
				snip.append(document.createTextNode((start > 0 ? "…" : "") + text.slice(start, pos)));
				snip.append(el("mark", "", text.slice(pos, pos + needle.length)));
				snip.append(document.createTextNode(text.slice(pos + needle.length, end) + (end < text.length ? "…" : "")));
				a.append(snip);
			}
			list.append(a);
			if (++n >= 100) break;
		}
		if (n === 0) list.append(el("p", "muted", done < notes.length ? "还在建立索引…" : "没有找到。"));
	};
	const update = () => {
		progress.textContent = done < notes.length ? `正在本机建立正文索引 ${done}/${notes.length}…` : `已在本机索引 ${notes.length} 篇笔记`;
	};
	update();
	renderHits();
	let next = 0;
	const alive = fence();
	const worker = async () => {
		while (run === searchRun && alive() && next < todo.length) {
			const f = todo[next++];
			try {
				const dl = await S!.api.fileWithIdentity(serverPathFor(f.path));
				if (!alive()) return;
				const data = await decodeContent(f.path, dl.data, { fileId: dl.fileId, generation: dl.generation });
				if (!alive()) return; // 建索引期间锁定 / 换号：解出来的明文不得留在新会话的索引里
				textIndex.set(f.path, { revision: dl.revision || f.revision, text: new TextDecoder().decode(data) });
			} catch {
				/* 单篇失败（被删、解不开）：跳过，不中断整体 */
			}
			done++;
			if (run === searchRun && (done % 10 === 0 || done === notes.length)) {
				update();
				renderHits();
			}
		}
	};
	await Promise.all([worker(), worker(), worker(), worker()]);
	if (run !== searchRun) return;
	update();
	renderHits();
}

// ---------- 路由 ----------
function onRoute(): void {
	void routeTo();
}

/** 最近一次成功进入的地址（离开被拦下时回到这里）。 */
let lastRoutedHash = "";

/**
 * 主动切换仓库 / 离开工作台前（需求 §7.3）：未同步的修改必须先加密落盘；
 * 落不了盘（浏览器存储不可用等）就暂停切换，让用户选择先导出。
 */
async function guardVaultLeave(): Promise<boolean> {
	const ed = S?.editor;
	if (!ed || !ed.dirty) return true;
	if (await ed.flush()) return true;
	if (!confirm("这篇笔记有未同步的修改，而且没能加密保存到本机（浏览器存储不可用）。\n\n确定：先把它导出为文件，再继续\n取消：留在当前页面")) return false;
	ed.exportText();
	return true;
}

/** 整页重载前给后台上传一点时间（最多 ms 毫秒；没完成的仍在加密草稿里）。 */
async function waitBackgroundSaves(ms = 5000): Promise<void> {
	if (backgroundSaves.size === 0) return;
	await Promise.race([Promise.allSettled([...backgroundSaves.values()]), new Promise((r) => setTimeout(r, ms))]);
}

async function routeTo(): Promise<void> {
	setSidebar(false, false);
	closeDrawer();
	const hash = location.hash;
	const target = hash.startsWith("#/n/") ? decodeURIComponent(hash.slice(4)) : null;
	// 指向正在编辑的同一篇笔记（点了树里的自己、改名后的 hash 更新）：不打断编辑
	if (target && S?.editor?.file.path === target && contentEl.querySelector(".edit-bar")) return;
	const leavingWorkspace = hash.startsWith("#/vaults") || hash.startsWith("#/me");
	if (leavingWorkspace && !(await guardVaultLeave())) {
		history.replaceState(null, "", lastRoutedHash || "#/");
		return;
	}
	lastRoutedHash = hash;
	await leaveEditor();
	// 离开编辑器期间地址又变了（连续快速导航）：交给处理新地址的那一轮，旧的这一轮不再渲染，
	// 否则较早的路由会在较晚的视图之后完成，把新视图覆盖掉
	if (location.hash !== hash) return;
	searchRun++; // 离开搜索页：正在进行的建索引就此停下
	viewSeq++; // 之前发起、尚未完成的笔记加载作废
	if (hash === "#/trash") {
		void showTrash();
	} else if (hash.startsWith("#/search/")) {
		void showSearchPage(decodeURIComponent(hash.slice("#/search/".length)));
	} else if (hash.startsWith("#/n/")) {
		const path = decodeURIComponent(hash.slice(4));
		void showNote(path);
	} else if (hash === "#/settings/backup") {
		void showBackupSettings();
	} else if (hash === "#/settings/ops") {
		void showOpsSettings();
	} else if (hash === "#/settings/users") {
		void showUsersAdmin();
	} else if (leavingWorkspace) {
		// 离开笔记工作台去账号级页面：整页重载，内存里的密钥与明文随之释放（严格会话解锁）
		await waitBackgroundSaves();
		if (S?.vmk && S.vaultDoc?.enabled) {
			try {
				sessionStorage.setItem("litesync-lock-reason", LEAVE_REASON); // 回来解锁时说明为什么要再输一次
			} catch {
				/* ignore */
			}
		}
		location.reload();
	} else if (hash === "#/account") {
		showAccount();
	} else {
		showHome();
	}
}

/** 笔记所在的文件夹（列表里的第二行）。 */
function folderLabel(path: string): string {
	return path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "仓库根目录";
}

/** 最近编辑里的一行：标题、位置、相对时间（数据来自文件列表的真实修改时间）。 */
function noteRow(f: FileEntry): HTMLElement {
	const a = el("a", "note-row") as HTMLAnchorElement;
	a.href = `#/n/${encodeURIComponent(f.path)}`;
	const sym = el("span", "note-symbol");
	sym.append(icon("file"));
	const meta = el("span", "note-meta");
	meta.append(el("strong", "", noteTitle(f.path)), el("small", "", `${folderLabel(f.path)} · ${fmtRelative(f.mtime)}`));
	a.append(sym, meta, icon("chevron", "row-chev"));
	return a;
}

/** 两个次要任务：连接 Obsidian、管理仓库（离开工作台，先说明会锁定）。 */
function quickActions(vaultName: string): HTMLElement {
	const box = el("div", "quick-actions");
	if (S!.account) {
		const connect = el("button", "action-card") as HTMLButtonElement;
		connect.type = "button";
		const t = el("span", "action-text");
		t.append(el("strong", "", "连接 Obsidian"), el("small", "", "在设备之间继续你的笔记"));
		connect.append(icon("logo", "lead-icon"), t, icon("arrow"));
		connect.onclick = () => void openConnectDialog(S!.account!, { id: currentVaultId(), name: vaultName || "当前仓库" });
		box.append(connect);
	}
	const vaults = el("button", "action-card") as HTMLButtonElement;
	vaults.type = "button";
	const t2 = el("span", "action-text");
	t2.append(el("strong", "", "管理仓库"), el("small", "", "新建仓库，或换一个仓库（会锁定当前仓库）"));
	vaults.append(icon("folder", "lead-icon"), t2, icon("arrow"));
	vaults.onclick = () => confirmLeave("#/vaults");
	box.append(vaults);
	return box;
}

const RECENT_FIRST = 6;
const RECENT_MORE = 12;

// ---------- 首页（概览）：标题、最近编辑、两个次要任务 ----------
function showHome(): void {
	revokeAllBlobs();
	markActive(null);
	setHere("概览");
	outlineEl.innerHTML = "";
	contentEl.innerHTML = "";
	const wrap = el("div", "overview");
	const notes = [...S!.files]
		.filter((f) => f.path.toLowerCase().endsWith(".md"))
		.sort((a, b) => b.mtime - a.mtime);
	const vaultName = S!.vaults.find((v) => v.current)?.name ?? "";
	const writable = canEdit();
	const head = el("div", "headline");
	const text = el("div", "headline-text");
	text.append(el("p", "eyebrow", "继续你的思考"));
	head.append(text);
	if (notes.length === 0) {
		// 空仓库：短空态 + 唯一的创建动作（审查 02）；不能新建时如实说明为什么
		text.append(el("h1", "", vaultName ? `「${vaultName}」还没有笔记` : "还没有笔记"),
			el("p", "lead", writable ? "写下第一篇，或者连接 Obsidian，把这个仓库同步到你的电脑和手机。" : "连接 Obsidian 后，这里会显示同步上来的笔记。"));
		wrap.append(head);
		const empty = el("section", "empty-card");
		empty.append(icon("file", "empty-icon"), el("p", "", writable
			? "已经有本地笔记的，连接 Obsidian 时可以选择怎么导入。"
			: "网页编辑在这个仓库里不可用（只读成员、未开启网页编辑，或者仓库还没有解锁）。"));
		if (writable) empty.append(labelButton("plus", "新建第一篇笔记", "btn primary", () => showNewNote()));
		wrap.append(empty);
	} else {
		text.append(el("h1", "", "把想法，写成下一步。"), el("p", "lead", "最近的笔记和常用操作，都在这里。"));
		if (writable) head.append(labelButton("plus", "新建笔记", "btn primary home-new", () => showNewNote()));
		wrap.append(head);
		const sec = el("section", "recent");
		const title = el("div", "section-title");
		const h2 = el("h2", "", "最近编辑");
		h2.id = "recent-title";
		sec.setAttribute("aria-labelledby", h2.id);
		title.append(h2, el("span", "small muted", `共 ${notes.length} 篇`));
		const list = el("div", "note-list");
		let shown = Math.min(RECENT_FIRST, notes.length);
		const more = labelButton("down", "", "btn text more-notes");
		const renderRows = () => {
			list.replaceChildren(...notes.slice(0, shown).map(noteRow));
			const left = notes.length - shown;
			more.hidden = left <= 0;
			more.replaceChildren(icon("down"), el("span", "", `再显示 ${Math.min(RECENT_MORE, left)} 篇`));
		};
		more.onclick = () => {
			const first = shown;
			shown = Math.min(notes.length, shown + RECENT_MORE);
			renderRows();
			list.querySelectorAll<HTMLElement>(".note-row")[first]?.focus();
		};
		renderRows();
		sec.append(title, list, more);
		wrap.append(sec);
		if (writable) {
			const drafts = el("div", "draft-list");
			drafts.id = "draft-list";
			wrap.append(drafts);
		}
	}
	wrap.append(quickActions(vaultName));
	contentEl.append(wrap);
	void renderDraftList();
	updateStatus();
}

// ---------- 笔记视图 ----------
/** 每次进入一个视图 +1：较早发起、较晚完成的加载（快速连点、改路由）不得覆盖较新的视图。 */
let viewSeq = 0;

async function showNote(path: string): Promise<void> {
	const seq = ++viewSeq;
	const alive = fence();
	const current = () => alive() && seq === viewSeq;
	await settleBackground(S!.byPath.get(path)?.fileId);
	if (!current()) return;
	revokeAllBlobs();
	markActive(path);
	setHere(noteTitle(path));
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
	const headRow = el("div", "note-head");
	headRow.append(...noteHeadParts(path, entry.fileId));
	wrap.append(headRow);
	wrap.append(el("h1", "note-title", noteTitle(path)));
	wrap.append(el("p", "muted small note-meta-line", `最后修改 ${fmtTime(entry.mtime)} · 版本 ${entry.revision}`));

	const body = el("div", "markdown-body");
	wrap.append(body);
	body.textContent = "加载中…";

	try {
		const dl = await S!.api.fileWithIdentity(serverPathFor(path));
		if (!current()) return;
		const data = await decodeContent(path, dl.data, { fileId: dl.fileId, generation: dl.generation });
		if (!current()) return; // 加载期间锁定 / 换号 / 去了别的视图：不渲染旧结果
		if (path.toLowerCase().endsWith(".md")) {
			if (canEdit()) {
				// ignoreBOM：保留原文的 BOM，只打开不修改时绝不改写任何字节
				const text = new TextDecoder("utf-8", { ignoreBOM: true }).decode(data);
				const tracked = trackedFor({ ...entry, revision: dl.revision || entry.revision, fileId: dl.fileId ?? entry.fileId }, dl.data, dl.generation);
				body.className = "note-editor";
				mountEditor(body, tracked, text, false, "read");
				headRow.append(noteMenu(() => editingFile(tracked.fileId) ?? tracked));
			} else {
				renderMarkdownInto(body, path, new TextDecoder().decode(data));
			}
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

function renderMarkdownInto(container: HTMLElement, path: string, src: string, force = false): void {
	const pre = preprocessWiki(src, resolveTarget);
	// 带长度保护（W3）：超过门槛显示源码，用户可以主动选择仍要渲染
	const r = renderMarkdown(pre, { force });
	container.innerHTML = r.html;
	if (r.degraded) {
		const btn = el("button", "ghost small-btn", "仍要渲染（可能卡顿一会儿）");
		btn.onclick = () => renderMarkdownInto(container, path, src, true);
		container.querySelector(".md-degraded")?.append(" ", btn);
		return;
	}
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
		const cacheKey = `${finalTarget}@${S!.byPath.get(finalTarget)?.revision ?? 0}`;
		const cached = attachmentUrlCache.get(cacheKey);
		if (cached) {
			img.src = cached;
			return;
		}
		const alive = fence();
		void (async () => {
			try {
				const dlLink = await S!.api.fileWithIdentity(serverPathFor(finalTarget));
				if (!alive()) return;
				const data = await decodeContent(finalTarget, dlLink.data, {
					fileId: dlLink.fileId,
					generation: dlLink.generation,
				});
				if (!alive()) return; // 锁定 / 换号之后到达：不再生成对象 URL
				const url = trackBlob(new Blob([data]));
				attachmentUrlCache.set(cacheKey, url);
				img.src = url;
			} catch {
				img.alt = `⚠ 无法加载 ${finalTarget}`;
			}
		})();
	});
}

function renderOutline(items: { level: number; text: string; id: string }[]): void {
	outlineEl.innerHTML = "";
	if (items.length === 0) return;
	outlineEl.append(el("div", "outline-title", "本页目录"));
	for (const item of items) {
		// 不用 href="javascript:"（严格 CSP 下被禁止），纯 onclick
		const a = el("a", `outline-item lv${item.level}`, item.text);
		a.onclick = () => document.getElementById(item.id)?.scrollIntoView({ behavior: "smooth" });
		outlineEl.append(a);
	}
}

// ---------- 历史抽屉 + 版本查看 + Diff ----------
let drawer: DrawerHandle | null = null;

async function openHistory(path: string, opener?: HTMLElement): Promise<void> {
	closeDrawer();
	const d: DrawerHandle = openDrawer({
		id: "drawer",
		title: "历史版本",
		opener,
		onClose: () => {
			if (drawer === d) drawer = null;
		},
	});
	drawer = d;
	const list = el("ul", "drawer-list");
	list.setAttribute("aria-label", "这篇笔记的版本");
	d.body.append(list);

	try {
		const versions = await S!.api.history(serverPathFor(path));
		if (drawer !== d) return; // 加载期间已关闭
		if (versions.length === 0) {
			list.append(el("li", "muted", "暂无历史版本"));
			return;
		}
		const cur = S!.byPath.get(path);
		const actionText: Record<string, string> = { upload: "修改", upsert: "修改", create: "新建", delete: "删除", restore: "恢复", rename: "改名", move: "移动" };
		for (const v of versions) {
			const li = el("li");
			const label = v.revision === cur?.revision ? `● 当前版本（${v.revision}）` : `● 版本 ${v.revision}`;
			// 版本行是按钮（W08）：键盘能聚焦，Enter / 空格打开；删除记录打不开，只是文字
			const openable = v.action !== "delete";
			const row = el(openable ? "button" : "div", openable ? "drawer-item" : "drawer-item muted");
			if (row instanceof HTMLButtonElement) {
				row.type = "button";
				row.onclick = () => void showRevision(path, v);
			}
			row.append(el("span", "drawer-item-title", `${label} · ${actionText[v.action] ?? v.action}`), el("span", "muted small", fmtTime(v.createdAt * 1000)));
			li.append(row);
			list.append(li);
		}
		// 焦点还在面板标题上（用户还没动）：移到第一个能打开的版本
		if (document.activeElement?.id === "drawer-title") list.querySelector<HTMLElement>("button.drawer-item")?.focus();
	} catch (e) {
		if (drawer === d) list.append(el("li", "error", `加载失败：${e instanceof Error ? e.message : String(e)}`));
	}
}

function closeDrawer(): void {
	drawer?.close(true);
	drawer = null;
}

async function showRevision(path: string, v: VersionEntry): Promise<void> {
	closeDrawer();
	await leaveEditor(); // 未保存的编辑先加密落盘并后台上传，再离开编辑器
	revokeAllBlobs();
	contentEl.innerHTML = "";
	outlineEl.innerHTML = "";
	const wrap = el("div", "note-wrap");
	contentEl.append(wrap);

	setHere(`${noteTitle(path)} · 版本 ${v.revision}`);
	const banner = el("div", "banner");
	banner.append(el("span", "", `正在查看版本 ${v.revision} · ${fmtTime(v.createdAt * 1000)}`));
	const cmpBtn = el("button", "ghost", "与当前版本对比");
	const restoreBtn = el("button", "ghost", "恢复到此版本") as HTMLButtonElement;
	restoreBtn.hidden = true;
	const backBtn = el("button", "ghost", "返回当前版本");
	backBtn.onclick = () => void showNote(path);
	banner.append(cmpBtn, restoreBtn, backBtn);
	wrap.append(banner);
	wrap.append(el("h1", "note-title", noteTitle(path)));
	const body = el("div", "markdown-body");
	wrap.append(body);
	body.textContent = "加载中…";

	try {
		// §7.5：历史版本用**版本级** fileId（删除重建过的旧版本属于旧对象）
		const dlVer = await S!.api.versionWithIdentity(serverPathFor(path), v.revision);
		const data = await decodeContent(path, dlVer.data, { fileId: dlVer.fileId, historical: true });
		if (canEdit() && v.revision !== S!.byPath.get(path)?.revision) {
			restoreBtn.hidden = false;
			restoreBtn.onclick = () => restoreVersion(path, v, data);
		}
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

/**
 * 恢复到历史版本 = 以该版本的内容写一个**新**版本（需求 §7.3：revision 只前进、fileId 不变，
 * 当前内容仍留在历史里）。以当前 HEAD 为 CAS 前提、已见世代为下限；期间被别处改动则如实失败。
 */
function restoreVersion(path: string, v: VersionEntry, plain: ArrayBuffer): void {
	confirmDialog({
		title: `恢复到版本 ${v.revision}？`,
		message: `把「${noteTitle(path)}」的内容恢复成版本 ${v.revision}。这会生成一个新版本，当前内容仍保留在历史里。`,
		okLabel: "恢复",
		confirm: () => restoreVersionNow(path, v, plain),
	});
}

async function restoreVersionNow(path: string, v: VersionEntry, plain: ArrayBuffer): Promise<string | null> {
	try {
		const entry = S!.byPath.get(path);
		if (!entry) throw new Error("文件已不存在");
		await settleBackground(entry.fileId);
		const dl = await S!.api.fileWithIdentity(serverPathFor(path));
		await decodeContent(path, dl.data, { fileId: dl.fileId, generation: dl.generation }); // 先按常规校验当前 HEAD（身份 / 世代）
		const tracked = trackedFor({ ...entry, revision: dl.revision || entry.revision, fileId: dl.fileId ?? entry.fileId }, dl.data, dl.generation);
		const out = await saveWithRetry(repoBinding(), S?.writeKey ? { vmk: S.writeKey, meta: S.coreMeta } : null, tracked, new Uint8Array(plain));
		if (out.kind !== "saved") {
			throw new Error(
				out.kind === "conflict" ? "这篇笔记刚在别处被修改，请重新打开历史再恢复"
				: out.kind === "rejected" ? writeError(out.code, out.message)
				: out.kind === "auth" ? "登录已过期" : "网络连接失败",
			);
		}
		recordSaved({ ...tracked, revision: out.revision, generation: out.generation, fileId: out.fileId, metaGeneration: out.metaGeneration ?? tracked.metaGeneration }, false);
		void showNote(path);
		return null;
	} catch (e) {
		return `恢复失败：${e instanceof Error ? e.message : String(e)}`;
	}
}

// ---------- 回收站（需求 §7.2「删除回收」；v0.20.1 W4 原子恢复 / W5 路径加密仓库） ----------
//
// 恢复 = 先取回删除前的内容（按 fileId 寻址的历史版本，在本机解密）→ 以严格更新的世代重新加密
// → PUT /api/v1/files/{fileId}/restore **一次**提交（期望的墓碑 revision / 世代 + operationId）。
// 要么什么都没发生（删除记录原样留在回收站，可以重试），要么恢复与新内容同时生效——服务器上
// 不再有「旧密文 + 新世代」的中间态，本页的防回退检查与其他设备都不会被它误导。
// 断网 / 限流用同一份密文与同一个 operationId 重试；响应丢失后的重试由服务器返回首次结果。
//
// 路径加密仓库：删除记录里带着删除前最后一份 LSM1（客户端密文），这里用元数据密钥解开得到原路径
// （新设备只要有仓库密码同样可以）。较早的记录没有 LSM1、或解不开时，让用户自己选择恢复位置。

interface TrashView {
	it: TrashItem;
	/** 解出来的原路径（明文仓库就是 it.path）；null = 不知道原路径 */
	path: string | null;
	pathNote: string;
}

/** 本页内未完成的恢复（同一份密文与 operationId，用于重试）与它们最后一次失败的原因。 */
const pendingRestores = new Map<string, PreparedRestore>();
const restoreErrors = new Map<string, string>();

const canonPath = (p: string) => p.normalize("NFC").toLowerCase();

/** 原位置被占用时建议的恢复位置：「名字（恢复）.md」。 */
function restoredCopyName(path: string): string {
	const dot = path.lastIndexOf(".");
	const slash = path.lastIndexOf("/");
	return dot > slash ? `${path.slice(0, dot)}（恢复）${path.slice(dot)}` : `${path}（恢复）`;
}

async function trashViewOf(it: TrashItem, meta: boolean): Promise<TrashView> {
	if (!meta) return { it, path: it.path, pathNote: it.path };
	if (!it.metaEnc) {
		return { it, path: null, pathNote: "这条删除记录没有保存加密的原路径（较早的版本删除，或在启用路径加密之前删除）：恢复时需要你指定位置。" };
	}
	const dec = S!.metaKeys && S!.binding?.vaultId ? await decryptMeta(S!.metaKeys, it.metaEnc, S!.binding.vaultId, it.fileId).catch(() => null) : null;
	if (!dec) return { it, path: null, pathNote: "这条删除记录里的原路径用当前密钥解不开（可能来自密钥轮换之前）：恢复时需要你指定位置。" };
	return { it, path: dec.path, pathNote: dec.path };
}

async function showTrash(): Promise<void> {
	const alive = fence();
	revokeAllBlobs();
	markActive(null);
	outlineEl.innerHTML = "";
	contentEl.innerHTML = "";
	const wrap = el("div", "note-wrap");
	contentEl.append(wrap);
	setHere("回收站");
	wrap.append(el("h1", "", "回收站"));
	wrap.append(el("p", "muted", "删除的文件在这里保留一段时间。恢复会沿用原来的文件身份和全部历史，并生成一个新版本，所有设备都会收到。"));
	const list = el("div", "trash-list");
	wrap.append(list);
	list.textContent = "加载中…";
	let items: TrashItem[];
	try {
		items = await S!.api.trash();
	} catch (e) {
		if (alive()) list.textContent = `加载失败：${e instanceof Error ? e.message : String(e)}`;
		return;
	}
	if (!alive()) return;
	const meta = repoBinding().metaMode;
	const views: TrashView[] = [];
	for (const it of items) views.push(await trashViewOf(it, meta));
	if (!alive()) return;
	list.innerHTML = "";
	if (meta) {
		wrap.insertBefore(el("p", "muted small", "这个仓库启用了路径加密：服务器只保存删除记录的密文，原路径在这台设备上用仓库密钥解开后显示。"), list);
	}
	if (views.length === 0) {
		list.append(el("p", "muted", "回收站是空的。"));
		return;
	}
	for (const v of views) list.append(trashRow(v));
}

function trashRow(v: TrashView): HTMLElement {
	const { it } = v;
	const row = el("div", "trash-row");
	row.dataset.fileId = it.fileId;
	const info = el("div", "trash-info");
	info.append(
		el("div", "recent-title", v.path ? noteTitle(v.path) : `原路径未知的文件（${it.fileId.slice(0, 8)}…）`),
		el("div", "muted small", `${v.pathNote} · 删除于 ${fmtTime(it.deletedAt * 1000)}`),
	);
	const err = restoreErrors.get(it.fileId);
	if (err) {
		const e = el("div", "banner warn small trash-pending", err);
		e.setAttribute("role", "alert");
		info.append(e);
	}
	row.append(info);
	if (canEdit()) {
		const clash = v.path ? S!.files.find((f) => canonPath(f.path) === canonPath(v.path!)) : undefined;
		const label = pendingRestores.has(it.fileId) ? "重试恢复" : !v.path ? "选择位置恢复…" : clash ? "恢复到其他位置…" : "恢复";
		const btn = el("button", "ghost small-btn", label) as HTMLButtonElement;
		if (!it.restorable) {
			btn.disabled = true;
			btn.title = "删除前的内容已被历史清理，无法恢复内容";
			info.append(el("div", "muted small", "删除前的内容已被历史清理，无法恢复。"));
		} else if (clash) {
			btn.title = `原位置已有文件「${clash.path}」：恢复时请换一个位置`;
		}
		btn.onclick = () => void restoreFromTrash(v, btn);
		row.append(btn);
	}
	return row;
}

/** 让用户选择 / 确认恢复位置；返回规范化后的路径，取消返回 null。 */
function chooseRestorePath(v: TrashView, reason: string): string | null {
	for (;;) {
		const suggestion = v.path ? restoredCopyName(v.path) : "";
		const input = prompt(`${reason}\n请输入恢复后的路径（可以包含文件夹，例如「工作/周记.md」）`, suggestion);
		if (input === null) return null;
		const p = normalizeNotePath(input);
		if (!p) {
			alert("路径不合法：不能为空、不能以 / 开头、不能包含 .. 或以 . 开头的段。");
			continue;
		}
		const clash = S!.files.find((f) => canonPath(f.path) === canonPath(p));
		if (clash) {
			reason = `「${clash.path}」已经存在（大小写或 Unicode 归一后同名也算）。`;
			continue;
		}
		return p;
	}
}

async function restoreFromTrash(v: TrashView, btn: HTMLButtonElement): Promise<void> {
	const alive = fence();
	const { it } = v;
	let target = pendingRestores.get(it.fileId)?.path ?? v.path;
	if (!target) {
		target = chooseRestorePath(v, v.pathNote);
	} else if (!pendingRestores.has(it.fileId) && S!.files.some((f) => canonPath(f.path) === canonPath(target!))) {
		target = chooseRestorePath(v, `原位置「${target}」已有文件。`);
	}
	if (!target) return;
	btn.disabled = true;
	btn.textContent = "恢复中…";
	restoreErrors.delete(it.fileId);
	const fail = (msg: string, keepPending: boolean) => {
		if (!alive()) return;
		if (!keepPending) pendingRestores.delete(it.fileId);
		restoreErrors.set(it.fileId, msg);
		if (location.hash === "#/trash") void showTrash(); // 用户已经去了别处：状态留着，回到回收站时显示
	};
	try {
		const b = repoBinding();
		let prepared = pendingRestores.get(it.fileId);
		if (!prepared || prepared.path !== target) {
			if (!it.priorRevision) return fail("删除前的内容已被历史清理，无法恢复。", false);
			// 1) 按 fileId 取回删除前的内容（历史版本本来就是旧世代：不做 HEAD 防回退比较）
			const ver = await S!.api.versionById(it.fileId, it.priorRevision);
			if (!alive()) return;
			if (ver.fileId !== it.fileId) return fail("服务器返回的内容身份与删除记录不符，已停止恢复。", false);
			const plain = await decodeContent(target, ver.data, { fileId: ver.fileId, historical: true });
			if (!alive()) return;
			const env = envelopeOf(ver.data);
			const priorGen = lse3Header(ver.data)?.generation ?? it.priorGeneration ?? 0;
			const keys = S?.writeKey ? { vmk: S.writeKey, meta: S.coreMeta } : null;
			// 2) 以严格更新的世代重新加密（路径加密仓库另附 LSM1）——固定下来，重试复用同一份字节
			prepared = await prepareRestore(b, keys, it, target, new Uint8Array(plain), { envelope: env.envelope, padded: env.padded, generation: priorGen });
			if (!alive()) return;
			pendingRestores.set(it.fileId, prepared);
		}
		// 3) 一次提交；断网 / 限流用同一份密文与 operationId 重试
		let out = await uploadRestore(b, prepared);
		for (let i = 0; i < 2 && out.kind === "offline" && alive(); i++) {
			await new Promise((r) => setTimeout(r, 1500 * (i + 1)));
			out = await uploadRestore(b, prepared);
		}
		if (!alive()) return;
		switch (out.kind) {
			case "restored": {
				pendingRestores.delete(it.fileId);
				restoreErrors.delete(it.fileId);
				recordSaved({
					path: target, serverPath: out.path, fileId: out.fileId, revision: out.revision, generation: out.generation,
					envelope: prepared.envelope, padded: prepared.padded, metaGeneration: out.metaGeneration,
				}, true);
				location.hash = "#/n/" + encodeURIComponent(target);
				return;
			}
			case "offline":
				return fail("恢复没有完成：网络连接中断。服务器上的删除记录原样保留，内容没有任何改动——联网后点「重试恢复」。", true);
			case "auth":
				return fail("恢复没有完成：登录已过期。删除记录原样保留——重新登录并解锁后回到回收站重试。", true);
			case "changed":
				return fail("这个文件刚在别处被恢复或改动过（删除记录已变化）：已刷新回收站，请按最新状态操作。", false);
			case "collision": {
				pendingRestores.delete(it.fileId);
				const again = chooseRestorePath({ ...v, path: target }, `「${target}」已被别的文件占用（大小写或 Unicode 归一后同名也算）。`);
				if (!again) return fail("恢复没有完成：恢复位置已被占用。", false);
				btn.disabled = false;
				return restoreFromTrash({ ...v, path: again }, btn);
			}
			case "rejected":
				if (out.code === "QUOTA_EXCEEDED") {
					return fail("恢复没有完成：已达到账号的存储配额（恢复会写入一份新的加密内容，历史版本也计入）。删除记录原样保留——清理空间或联系管理员调整配额后点「重试恢复」。", true);
				}
				return fail(`恢复被服务器拒绝：${writeError(out.code, out.message)}`, false);
		}
	} catch (e) {
		if (e instanceof AuthError) return fail("恢复没有完成：登录已过期。删除记录原样保留——重新登录并解锁后回到回收站重试。", true);
		fail(`恢复没有完成：${e instanceof Error ? e.message : String(e)}。删除记录原样保留，可以重试。`, true);
	}
}

async function showDiff(path: string, v: VersionEntry, oldText: string): Promise<void> {
	revokeAllBlobs();
	contentEl.innerHTML = "";
	outlineEl.innerHTML = "";
	const wrap = el("div", "note-wrap");
	contentEl.append(wrap);
	const banner = el("div", "banner");
	banner.append(el("span", "", `版本 ${v.revision} → 当前版本`));
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
	setHere("备份");
	head.append(el("h1", "note-title", "备份"));
	const backBtn = labelButton("back", "返回", "btn ghost");
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
	card.append(el("h2", "", "管理员验证"));
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
	card.append(el("h2", "", "状态"));

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
	item("备份", state, st.enabled && !st.running ? "ok" : "");
	if (st.resticVersion) item("Restic", st.resticVersion);
	item("上次备份", st.lastCompletedAt ? fmtTime(st.lastCompletedAt * 1000) : "从未");
	if (st.lastDurationMs) item("耗时", `${(st.lastDurationMs / 1000).toFixed(1)} s`);
	if (st.lastSnapshotId) item("快照", st.lastSnapshotId.slice(0, 8));
	item("下次备份", st.enabled && st.nextRunAt ? fmtTime(st.nextRunAt * 1000) : "—");
	if (st.snapshotCount) item("快照数", String(st.snapshotCount));
	if (st.repositorySize) item("仓库占用", `${fmtBytes(st.repositorySize)}（估算）`);
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
			el("p", "muted small", `已用 ${pct}% · 预算 ${fmtBytes(st.budgetBytes)}`),
		);
		if (st.repositorySize > st.budgetBytes * 0.8) {
			card.append(el("p", "warn", "⚠ 备份仓库的占用已接近设定的预算。"));
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
	const genBtn = el("button", "ghost", "生成");
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
	const testBtn = el("button", "ghost", "测试连接");
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
	const saveBtn = el("button", "primary", "保存");
	saveBtn.onclick = async () => {
		saveBtn.disabled = true;
		try {
			if ((await save()) !== null) void renderBackupInto(box.parentElement ? box : box);
		} finally {
			saveBtn.disabled = false;
		}
	};
	const initBtn = el("button", "ghost", "初始化");
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
	const runBtn = el("button", "primary", "立即备份");
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
	const checkBtn = el("button", "ghost", "检查仓库");
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
	card.append(el("h2", "", "快照"));
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
	setHere("运维");
	head.append(el("h1", "note-title", "运维"));
	const backBtn = labelButton("back", "返回", "btn ghost");
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
	card.append(el("h2", "", "管理员验证"));
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
	card.append(el("h2", "", "完整性"));
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
	card.append(el("h2", "", "迁移"));
	const grid = el("div", "settings-grid");
	const item = (label: string, value: string, cls = ""): void => {
		grid.append(el("div", "muted small", label), el("div", cls, value));
	};
	const meta = (st.meta ?? {}) as Record<string, unknown>;
	item("元数据状态", String(meta.metaState ?? meta.state ?? "—"));
	if (meta.ownerDeviceId) item("租约持有者", String(meta.ownerDeviceId));
	if (meta.leaseExpiresAt) item("租约到期", fmtTs(Number(meta.leaseExpiresAt)));
	if (meta.cutoffSequence) item("截止序号", String(meta.cutoffSequence));
	item("blobID 域化", st.needsBlobIdMigration ? "待迁移" : "已完成", st.needsBlobIdMigration ? "error" : "");
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
	card.append(el("h2", "", "设备"));
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
		// 平台 / 客户端版本 / 最近 IP：丢设备那天要能一眼认出「哪台是那部手机」。
		// 空值显示 —（旧客户端没上报过，不是 undefined）
		info.append(
			el(
				"div",
				"muted small",
				`${d.platform || "—"} · ${d.clientVersion || "—"} · IP ${d.lastIp || "—"}`,
			),
		);
		row.append(info);
		if (!d.revoked) {
			const btn = el("button", "danger", "撤销…");
			btn.onclick = () => {
				// 撤销不可逆，值得一次确认——但只要一次：事故当天多一层弹窗就是多一分钟
				confirmDialog({
					title: `撤销「${d.name || d.id}」？`,
					message: "这台设备立刻无法同步：长期凭据作废，它换出去的短期 access token 也一起失效。已经下载到它上面的笔记不会被远程删除。",
					okLabel: "撤销设备",
					danger: true,
					confirm: async () => {
						try {
							await S!.api.adminRevokeDevice(d.id);
						} catch (e) {
							return `撤销失败：${e instanceof Error ? e.message : String(e)}`;
						}
						void renderOpsInto(box);
						return null;
					},
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
	card.append(el("h2", "", "分享"));
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
			// ExtendShare 的语义是「设定新的到期时间」而不是在原值上叠加——文案照实说
			const sel = el("select");
			for (const days of [7, 30, 90]) {
				const opt = el("option", "", `${days} 天后`);
				opt.value = String(days);
				sel.append(opt);
			}
			const customOpt = el("option", "", "自定义天数…");
			customOpt.value = "custom";
			sel.append(customOpt);
			const custom = el("input");
			custom.type = "number";
			custom.min = "1";
			custom.step = "1";
			custom.placeholder = "天数";
			custom.hidden = true;
			sel.onchange = () => (custom.hidden = sel.value !== "custom");
			const btn = el("button", "ghost", "设置新的到期时间");
			const failed = el("span", "error small");
			failed.setAttribute("role", "alert");
			btn.onclick = () => {
				failed.textContent = "";
				const days = sel.value === "custom" ? Number(custom.value) : Number(sel.value);
				if (!Number.isInteger(days) || days <= 0) {
					failed.textContent = "自定义天数必须是正整数。";
					custom.focus();
					return;
				}
				btn.disabled = true;
				const until = Math.floor(Date.now() / 1000) + days * 86400;
				void S!.api
					.adminRecoverShare(s.id, until)
					.then(() => renderOpsInto(box))
					.catch((e: unknown) => {
						btn.disabled = false;
						failed.textContent = `设置失败：${e instanceof Error ? e.message : String(e)}`;
					});
			};
			row.append(sel, custom, btn, failed);
		} else if (!s.revoked) {
			row.append(el("span", "muted small", "密文已回收，无法恢复"));
		}
		if (!s.revoked) {
			const revokeBtn = el("button", "danger", "撤销…");
			revokeBtn.onclick = () => {
				// 撤销不可逆且密文一并回收，值得一次确认——但只要一次
				confirmDialog({
					title: `撤销分享「${s.id.slice(0, 12)}…」？`,
					message: "链接立刻失效，密文一并回收，不能恢复。",
					okLabel: "撤销分享",
					danger: true,
					confirm: async () => {
						try {
							await S!.api.adminRevokeShare(s.id);
						} catch (e) {
							return `撤销失败：${e instanceof Error ? e.message : String(e)}`;
						}
						void renderOpsInto(box);
						return null;
					},
				});
			};
			row.append(revokeBtn);
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
	card.append(el("h2", "", "灾难恢复"));
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

// ---------- 账户（v0.18 / v11 设计 §4.4）：重置 API Token ----------

function showAccount(): void {
	revokeAllBlobs();
	markActive(null);
	outlineEl.innerHTML = "";
	contentEl.innerHTML = "";
	const wrap = el("div", "note-wrap settings-wrap");
	contentEl.append(wrap);
	const head = el("div", "note-head");
	setHere("API Token");
	head.append(el("h1", "note-title", "账户"));
	const backBtn = labelButton("back", "返回", "btn ghost");
	backBtn.onclick = () => {
		location.hash = "#/";
	};
	head.append(backBtn);
	wrap.append(head);
	const box = el("div", "settings-box");
	wrap.append(box);

	const who = el("div", "settings-card");
	who.append(el("h2", "", "身份"));
	const role = S!.me?.role === "admin" ? "管理员" : "用户";
	who.append(el("p", "", `${S!.me?.name ?? "（未知）"} · ${role}`));
	box.append(who);

	// 我的仓库（v0.19.x）：此前删除/新建只有 curl，用户找不到管理入口
	const vc = el("div", "settings-card");
	vc.append(el("h2", "", "我的仓库"));
	vc.append(el("p", "muted small",
		"名下的远端仓库，彼此完全隔离。新建的仓库是空的：在 Obsidian 插件里" +
		"重新运行接入向导并选择它，即可把本地笔记初始化上去（必须设置 E2EE）。" +
		"切换查看用右上角的仓库切换器。"));
	const vList = el("div", "settings-list");
	vc.append(vList);
	const vErr = el("p", "error", "");
	const createWrap = el("div", "settings-item");
	const createInput = el("input") as HTMLInputElement;
	createInput.placeholder = "新仓库名（1–64 字符）";
	const createBtn = el("button", "primary", "新建仓库");
	createBtn.onclick = () => {
		const n = createInput.value.trim();
		if (!n) {
			vErr.textContent = "请输入新仓库的名字。";
			return;
		}
		createBtn.disabled = true;
		void S!.api.createVault(n)
			.then(() => {
				createInput.value = "";
				vErr.textContent = "";
				return renderVaultList(vList, vErr);
			})
			.catch((e) => { vErr.textContent = e instanceof Error ? e.message : String(e); })
			.finally(() => { createBtn.disabled = false; });
	};
	createWrap.append(createInput, createBtn);
	vc.append(createWrap, vErr);
	box.append(vc);
	void renderVaultList(vList, vErr);

	const card = el("div", "settings-card");
	card.append(el("h2", "", "重置 API Token"));
	card.append(el("p", "muted small",
		"怀疑 API Token 泄露时使用：立即作废旧 Token 并撤销你的全部设备凭据。" +
		"之后每台设备只需在插件设置里填入新 Token → 点「测试连接」即可恢复同步，" +
		"本地笔记、历史与端到端加密密钥都不受影响。"));
	if (S!.vaultDoc?.enabled) {
		card.append(el("p", "muted small",
			S!.resetAuth
				? "✓ 本次重置将附带 E2EE 密码证明（只拿到 Token 的人无法执行此操作）。"
				: "⚠ 尚未解锁 E2EE：请先返回首页解锁，再执行重置。"));
	} else {
		card.append(el("p", "muted small",
			"⚠ 此 Vault 未启用端到端加密：任何持有 Token 的人（包括取得它的攻击者）都能执行重置。" +
			"启用 E2EE 后，重置将要求加密密码证明。"));
	}
	card.append(el("p", "muted small",
		"注意：重置不能追回泄露期间已被下载的内容——那部分只由 E2EE 密码强度保护。"));
	const btn = el("button", "danger", "重置 API Token");
	const errEl = el("p", "error", "");
	btn.onclick = () => {
		if (S!.vaultDoc?.enabled && !S!.resetAuth) {
			errEl.textContent = "请先解锁 E2EE 再重置。";
			return;
		}
		confirmDialog({
			title: "重置 API Token？",
			message: "· 旧 Token 立即失效，所有设备断开同步\n· 每台设备需填入新 Token 并点「测试连接」\n· 这一步不能追回泄露期间已被下载的密文",
			okLabel: "重置 API Token",
			danger: true,
			confirm: async () => {
				try {
					renderNewToken(box, await S!.api.resetToken(S!.resetAuth ?? ""));
				} catch (e) {
					return e instanceof Error ? e.message : String(e);
				}
				return null;
			},
		});
	};
	card.append(btn, errEl);
	box.append(card);
}

/**
 * 账户页「我的仓库」列表（v0.19.x）：重命名 / 删除（输入仓库名确认；
 * 默认仓库名为空串，删除前必须先起名——否则「输入名字确认」形同虚设）。
 * 删除当前正在查看的仓库后整页重进（boot 的 404 兜底会回落默认仓库）。
 */
async function renderVaultList(listEl: HTMLElement, errEl: HTMLElement): Promise<void> {
	listEl.innerHTML = "";
	listEl.append(el("p", "muted small", "加载中…"));
	const vaults = await S!.api.listVaults();
	S!.vaults = vaults; // 同步给 header 切换器（下次整页渲染时生效）
	listEl.innerHTML = "";
	for (const v of vaults) {
		const row = el("div", "settings-item");
		const left = el("div", "");
		left.append(el("strong", "", v.name || "默认仓库"));
		left.append(el("p", "muted small",
			`${v.fileCount} 个文件 · ${fmtBytes(v.bytesUsed)}` + (v.current ? " · 当前查看" : "")));
		row.append(left);
		const btns = el("div", "");
		const rn = el("button", "ghost", "重命名…");
		rn.onclick = () => {
			fieldsDialog({
				title: "重命名仓库",
				message: "只改显示名，不影响同步与加密。",
				fields: [{ label: "仓库名称", value: v.name, hint: "1–64 个字符" }],
				okLabel: "重命名",
				validate: ([name]) => (!name ? "请填写仓库名称。" : [...name].length > 64 ? "仓库名称最多 64 个字符。" : null),
				submit: async ([name]) => {
					if (name === v.name) return null;
					try {
						await S!.api.renameVault(v.id, name);
					} catch (e) {
						return e instanceof Error ? e.message : String(e);
					}
					void renderVaultList(listEl, errEl);
					return null;
				},
			});
		};
		const del = el("button", "danger", "删除…");
		del.onclick = () => {
			if (!v.name) {
				errEl.textContent = "此仓库尚未命名：请先重命名，删除确认需要输入仓库名。";
				return;
			}
			typedConfirmDialog({
				title: `删除仓库「${v.name}」？`,
				message: "不能恢复：这个仓库的全部内容、历史、分享与设备凭据都会被清除。",
				expect: v.name,
				label: `输入仓库名称「${v.name}」确认`,
				okLabel: "删除仓库",
				confirm: async (typed) => {
					try {
						await S!.api.deleteVault(v.id, typed);
					} catch (e) {
						return e instanceof Error ? e.message : String(e);
					}
					if (v.current) {
						forgetVault();
						location.hash = "";
						location.reload();
						return null;
					}
					errEl.textContent = "";
					void renderVaultList(listEl, errEl);
					return null;
				},
			});
		};
		btns.append(rn, del);
		row.append(btns);
		listEl.append(row);
	}
}

function renderNewToken(
	box: HTMLElement,
	res: { token: string; revokedDevices: number; resetAuthEnforced: boolean },
): void {
	box.innerHTML = "";
	const card = el("div", "settings-card");
	card.append(el("h2", "", "新的 API Token"));
	card.append(el("p", "", `已撤销 ${res.revokedDevices} 台设备的凭据；旧 Token 与其他登录会话全部失效。`));
	if (!res.resetAuthEnforced) {
		card.append(el("p", "muted small", "（本次重置未经 E2EE 密码确认——该 Vault 尚未登记重置凭证。）"));
	}
	const tokenEl = el("code", "token-display", res.token);
	card.append(tokenEl);
	const copyBtn = el("button", "primary", "复制");
	copyBtn.onclick = () => {
		void navigator.clipboard.writeText(res.token).then(() => {
			copyBtn.textContent = "已复制 ✓";
			setTimeout(() => (copyBtn.textContent = "复制"), 1500);
		});
	};
	card.append(copyBtn);
	card.append(el("p", "muted small",
		"明文只显示这一次（服务器只存哈希）。请立即抄写保存，然后在每台设备的" +
		"插件设置里替换 API Token → 点「测试连接」，同步会自动恢复，其他设置都不用改。"));
	box.append(card);
}

// ---------- 用户管理（v0.18 / v11 设计 §5.6–§5.7，仅管理员） ----------

async function showUsersAdmin(): Promise<void> {
	revokeAllBlobs();
	markActive(null);
	outlineEl.innerHTML = "";
	contentEl.innerHTML = "";
	const wrap = el("div", "note-wrap settings-wrap");
	contentEl.append(wrap);
	const head = el("div", "note-head");
	setHere("用户管理");
	head.append(el("h1", "note-title", "用户管理"));
	const backBtn = labelButton("back", "返回", "btn ghost");
	backBtn.onclick = () => {
		location.hash = "#/";
	};
	head.append(backBtn);
	wrap.append(head);
	wrap.append(el("p", "muted small",
		"小范围多用户：生成邀请链接给对方自助注册；每个用户拥有完全独立的仓库，" +
		"彼此不可见。你能看到用户名与用量，但拿不到任何人的 API Token 或加密密码。"));
	const box = el("div", "settings-box");
	wrap.append(box);
	await renderUsersInto(box);
}

async function renderUsersInto(box: HTMLElement): Promise<void> {
	box.textContent = "加载中…";
	let invites: AdminInvite[];
	let users: AdminUser[];
	try {
		[invites, users] = await Promise.all([S!.api.listInvites(), S!.api.listUsers()]);
	} catch (e) {
		const msg = e instanceof Error ? e.message : String(e);
		if (/40[13]|unauthorized|admin/i.test(msg)) {
			renderUsersUnlock(box);
			return;
		}
		box.textContent = `加载失败：${msg}`;
		return;
	}
	box.innerHTML = "";
	renderInviteCard(box, invites);
	renderUserListCard(box, users);
}

function renderUsersUnlock(box: HTMLElement): void {
	box.innerHTML = "";
	const card = el("div", "settings-card");
	card.append(el("h2", "", "管理员验证"));
	card.append(el("p", "muted small", "用户管理需要管理员权限：请输入 API Token 换取短期 admin 会话（30 分钟）。"));
	const input = el("input") as HTMLInputElement;
	input.type = "password";
	input.placeholder = "API Token";
	const btn = el("button", "primary", "解锁");
	const errEl = el("p", "error", "");
	const submit = async (): Promise<void> => {
		btn.disabled = true;
		if (await login(input.value.trim(), true)) {
			await renderUsersInto(box);
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

function renderInviteCard(box: HTMLElement, invites: AdminInvite[]): void {
	const card = el("div", "settings-card");
	card.append(el("h2", "", "邀请"));
	card.append(el("p", "muted small",
		"邀请链接后缀随机（32 字节）、一次性、默认 24 小时过期。" +
		"对方打开链接，输入用户名即可注册并拿到自己的 API Token。"));

	const row = el("div", "settings-row");
	const ttlSel = el("select") as HTMLSelectElement;
	for (const [label, hours] of [["1 小时", 1], ["24 小时", 24], ["7 天", 168]] as const) {
		const opt = el("option", "", label) as HTMLOptionElement;
		opt.value = String(hours);
		if (hours === 24) opt.selected = true;
		ttlSel.append(opt);
	}
	const urlInput = el("input") as HTMLInputElement;
	urlInput.placeholder = `注册页展示的 Server URL（默认 ${location.origin}）`;
	const genBtn = el("button", "primary", "生成邀请");
	row.append(ttlSel, urlInput, genBtn);
	card.append(row);
	const out = el("div");
	card.append(out);
	genBtn.onclick = () => {
		genBtn.disabled = true;
		void S!.api
			.createInvite(Number(ttlSel.value), urlInput.value.trim() || location.origin)
			.then((inv) => {
				out.innerHTML = "";
				const link = `${location.origin}${inv.path}`;
				const code = el("code", "token-display", link);
				const copyBtn = el("button", "primary", "复制链接");
				copyBtn.onclick = () => {
					void navigator.clipboard.writeText(link).then(() => {
						copyBtn.textContent = "已复制 ✓";
						setTimeout(() => (copyBtn.textContent = "复制链接"), 1500);
					});
				};
				out.append(code, copyBtn,
					el("p", "muted small", "链接只显示这一次（服务器只存指纹）。请通过可信渠道发给对方。"));
			})
			.catch((e) => {
				out.textContent = `生成失败：${e instanceof Error ? e.message : String(e)}`;
			})
			.finally(() => (genBtn.disabled = false));
	};

	const pending = invites.filter((i) => !i.usedAt && !i.revoked && i.expiresAt * 1000 > Date.now());
	if (pending.length > 0) {
		const list = el("div", "settings-list");
		for (const inv of pending) {
			const item = el("div", "settings-item");
			item.append(el("span", "", `#${inv.id} · 过期 ${fmtTime(inv.expiresAt * 1000)}`));
			const rv = el("button", "ghost", "撤销");
			rv.onclick = () => {
				void S!.api.revokeInvite(inv.id).then(() => renderUsersInto(box));
			};
			item.append(rv);
			list.append(item);
		}
		card.append(el("p", "muted small", `未使用的邀请（${pending.length}）：`), list);
	}
	box.append(card);
}

/** 「存储 1.2 MB / 2 GB · 仓库 1 / 20」；limit 0 = 不限。 */
function quotaLine(u: Usage): string {
	const storage = `存储 ${fmtBytes(u.bytesUsed)} / ${u.bytesLimit > 0 ? fmtBytes(u.bytesLimit) : "不限"}（含历史版本）`;
	const vaults = `仓库 ${u.vaults} / ${u.vaultsLimit > 0 ? u.vaultsLimit : "不限"}`;
	const custom = u.overrideBytes !== 0 || u.overrideVaults !== 0 ? " · 已单独设置" : "";
	return `${storage} · ${vaults}${custom}`;
}

function overrideText(n: number, isBytes: boolean): string {
	if (n === 0 || n === -1) return String(n);
	return isBytes ? (n % (1 << 30) === 0 ? `${n / (1 << 30)}GB` : n % (1 << 20) === 0 ? `${n / (1 << 20)}MB` : String(n)) : String(n);
}

/** 「2GB / 500MB / 1048576 / 0 / -1」→ 字节数（1024 进制）；格式不对返回 null。 */
function parseSizeInput(s: string): number | null {
	const m = /^\s*(-1|\d+)\s*(t|g|m|k)?i?b?\s*$/i.exec(s);
	if (!m) return null;
	const n = Number(m[1]);
	if (n === -1) return m[2] ? null : -1;
	const mult = { t: 2 ** 40, g: 2 ** 30, m: 2 ** 20, k: 2 ** 10 }[(m[2] ?? "").toLowerCase() as "t" | "g" | "m" | "k"] ?? 1;
	return n * mult;
}

function renderUserListCard(box: HTMLElement, users: AdminUser[]): void {
	const card = el("div", "settings-card");
	card.append(el("h2", "", "账号"));
	const list = el("div", "settings-list");
	for (const u of users) {
		const item = el("div", "settings-item");
		const label = u.isAdmin ? `${u.name}（管理员）` : u.name;
		const meta = `${u.vaults ?? 1} 个仓库 · ${u.devices} 台设备 · ${u.objects} 个文件 · ${fmtBytes(u.bytesUsed)}` +
			(u.lastSeenAt ? ` · 最近活动 ${fmtTime(u.lastSeenAt * 1000)}` : " · 从未活动") +
			(u.disabled ? " · 已禁用" : "");
		const info = el("div", "settings-item-main");
		info.append(el("div", "", label), el("div", "muted small", meta));
		if (u.usage) info.append(el("div", "muted small", quotaLine(u.usage)));
		item.append(info);
		// 配额覆盖值（需求 §12：管理员可管理账号配额）
		const quotaBtn = el("button", "ghost", "配额…");
		quotaBtn.onclick = () => {
			const cur = u.usage;
			fieldsDialog({
				title: `${u.name} 的配额`,
				fields: [
					{ label: "存储上限（含历史版本）", value: cur ? overrideText(cur.overrideBytes, true) : "0", hint: "例如 2GB、500MB；0 = 跟随服务器默认；-1 = 不限" },
					{ label: "仓库数上限", value: cur ? String(cur.overrideVaults) : "0", hint: "整数；0 = 跟随服务器默认；-1 = 不限", inputMode: "numeric" },
				],
				okLabel: "保存",
				validate: ([b, v]) => {
					if (parseSizeInput(b) === null) return "存储上限的格式不对：写成 2GB、500MB、0 或 -1。";
					if (!/^-?\d+$/.test(v) || Number(v) < -1) return "仓库数上限要写整数、0 或 -1。";
					return null;
				},
				submit: async ([b, v]) => {
					try {
						await S!.api.setUserQuota(u.userId, parseSizeInput(b)!, Number(v));
					} catch (e) {
						return `设置配额失败：${e instanceof Error ? e.message : String(e)}`;
					}
					void renderUsersInto(box);
					return null;
				},
			});
		};
		item.append(quotaBtn);
		if (!u.isAdmin) {
			const disBtn = el("button", "ghost", u.disabled ? "解禁" : "禁用");
			const failed = el("span", "error small");
			failed.setAttribute("role", "alert");
			disBtn.onclick = () => {
				const verb = u.disabled ? "解禁" : "禁用";
				const apply = async (): Promise<string | null> => {
					try {
						await S!.api.setUserDisabled(u.userId, !u.disabled);
					} catch (e) {
						return `${verb}失败：${e instanceof Error ? e.message : String(e)}`;
					}
					void renderUsersInto(box);
					return null;
				};
				if (u.disabled) {
					failed.textContent = "";
					void apply().then((err) => (failed.textContent = err ?? ""));
					return;
				}
				confirmDialog({
					title: `禁用 ${u.name}？`,
					message: "其全部设备凭据与登录会话立即失效；数据保留，解禁后需要重新接入设备。",
					okLabel: "禁用",
					danger: true,
					confirm: apply,
				});
			};
			const delBtn = el("button", "danger", "删除…");
			delBtn.onclick = () => {
				typedConfirmDialog({
					title: `删除 ${u.name}？`,
					message: "不能恢复：其全部笔记、历史、分享一并永久删除。",
					expect: u.name,
					label: `输入用户名「${u.name}」确认`,
					okLabel: "删除用户",
					confirm: async (typed) => {
						try {
							await S!.api.deleteUser(u.userId, typed);
						} catch (e) {
							return `删除失败：${e instanceof Error ? e.message : String(e)}`;
						}
						void renderUsersInto(box);
						return null;
					},
				});
			};
			item.append(disBtn, delBtn, failed);
		}
		list.append(item);
	}
	card.append(list);
	box.append(card);
}
