/**
 * LiteSync 网页写端协议层（v0.20 公开化 / ADR-015）。
 *
 * 不新增任何绕过同步协议的保存端点：沿用 /api/v1 的 fileId / X-Base-Revision（CAS）/
 * contentGeneration / X-Operation-Id（幂等）/ tombstone 语义，与插件完全相同。
 *
 *   - 加密只用 vendor 进来的插件源码（crypto-core）；信封**不降级**：已是 LSE4 的对象
 *     继续写 LSE4（保持其填充标记），其余写 LSE3；新世代 = 已见世代 + 1。
 *   - 一次保存 = 一个 operationId + 一份**固定的密文**：网络重试复用同一份字节；
 *     内容或前置版本变了才换新的 operationId 与新 IV（同 ID 换载荷是协议禁止的）。
 *   - CAS 冲突：取远端版本，在本地三方合并（base = 打开时的版本）；合并不干净或没有
 *     共同 base 时保留双方，绝不最后写覆盖。
 *   - 草稿：IndexedDB 只存密文。草稿密钥 = HKDF(VMK, "litesync/v1/web-draft")，
 *     AAD 绑定 服务器/账号/仓库/文件/仓库身份/密钥世代/草稿格式版本；锁定即丢弃密钥。
 */
import * as core from "./vendor/litesync-core/crypto/crypto";
import { smartThreeWayMerge } from "./vendor/litesync-core/merge/smart-merge";

export const WEB_DRAFT_INFO = "litesync/v1/web-draft";
const DRAFT_FORMAT = "wd1";

/** 写入时需要的仓库绑定（来自 /api/v1/info 与仓库列表）。 */
export interface RepoBinding {
	vaultId: string; // 选择器（X-Vault-ID）
	vaultIdentity: string; // 加密 AAD 绑定（= info.vaultId）
	keyEpoch: number;
	repoEpoch: string;
	formatEpoch: number;
	minimumEnvelopeVersion: number;
	encrypted: boolean;
	metaMode: boolean;
}

export interface WriteKeys {
	vmk: CryptoKey; // encrypt + decrypt，不可导出
	meta?: core.MetaKeys; // meta 模式：enc + mac
}

/** 编辑器手里的一个文件的同步状态。 */
export interface TrackedFile {
	path: string; // 真实路径
	serverPath: string; // 服务器寻址名（meta 模式 = fileId）
	fileId: string; // 新文件在加密前预生成
	revision: number; // 0 = 新文件
	generation: number; // 已见内容世代
	envelope: "LSE3" | "LSE4" | "plain";
	padded: boolean;
	metaGeneration: number;
}

export interface PreparedUpload {
	payload: Uint8Array;
	cipherHash: string;
	generation: number;
	meta?: { metaEnc: string; canonicalHash: string };
	operationId: string;
}

export type SaveOutcome =
	| { kind: "saved"; revision: number; generation: number; fileId: string; hash: string }
	| { kind: "conflict"; revision: number; hash: string; deleted: boolean; fileId?: string }
	| { kind: "offline"; message: string }
	| { kind: "auth" }
	| { kind: "rejected"; status: number; code: string; message: string; details?: Record<string, unknown> };

async function sha256HexOf(data: Uint8Array): Promise<string> {
	const d = new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
	return Array.from(d).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function newOperationId(): string {
	return "web_" + Array.from(core.randomBytes(16)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** 新建文件的跟踪状态（fileId 在加密前就要确定）。 */
export function newTrackedFile(path: string, b: RepoBinding): TrackedFile {
	const fileId = core.newFileId();
	return {
		path, serverPath: b.metaMode ? fileId : path, fileId, revision: 0, generation: 0,
		envelope: b.encrypted ? "LSE3" : "plain", padded: false, metaGeneration: 0,
	};
}

/** 加密一份要上传的内容（固定下来供重试复用）。 */
export async function prepareUpload(b: RepoBinding, k: WriteKeys | null, f: TrackedFile, plain: Uint8Array): Promise<PreparedUpload> {
	const operationId = newOperationId();
	if (!b.encrypted) {
		const payload = plain;
		return { payload, cipherHash: await sha256HexOf(payload), generation: f.generation + 1, operationId };
	}
	if (!k) throw new Error("仓库已锁定");
	const generation = f.generation + 1;
	const binding3 = { vaultId: b.vaultIdentity, keyEpoch: b.keyEpoch, fileId: f.fileId, generation };
	const buf = plain.buffer.slice(plain.byteOffset, plain.byteOffset + plain.byteLength) as ArrayBuffer;
	// 不降级：LSE4 对象保持 LSE4（与它原来的填充标记）；仓库下限 ≥4 时同样写 LSE4
	const useV4 = f.envelope === "LSE4" || b.minimumEnvelopeVersion >= 4;
	const ct = new Uint8Array(useV4
		? await core.encryptFileV4(k.vmk, binding3, buf, f.padded)
		: await core.encryptFileV3(k.vmk, binding3, buf));
	let meta: PreparedUpload["meta"];
	if (b.metaMode && f.revision === 0) {
		if (!k.meta) throw new Error("路径加密仓库需要元数据密钥");
		meta = {
			metaEnc: await core.encryptMeta(k.meta, { vaultId: b.vaultIdentity, keyEpoch: b.keyEpoch, fileId: f.fileId, metaGeneration: 1 }, { path: f.path }),
			canonicalHash: await core.canonicalPathHmac(k.meta, f.path),
		};
	}
	return { payload: ct, cipherHash: await sha256HexOf(ct), generation, meta, operationId };
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

function protocolHeaders(b: RepoBinding, operationId: string): Record<string, string> {
	const h: Record<string, string> = {
		"X-LiteSync-Protocol": "6",
		"X-Operation-Id": operationId,
		"X-Client-Platform": "web",
	};
	if (b.vaultId) h["X-Vault-ID"] = b.vaultId;
	if (b.formatEpoch > 0) h["X-Format-Epoch"] = String(b.formatEpoch);
	if (b.repoEpoch) h["X-Repo-Epoch"] = b.repoEpoch;
	if (b.keyEpoch > 0) h["X-Key-Epoch"] = String(b.keyEpoch);
	return h;
}

async function readCode(res: Response): Promise<{ code: string; message: string; body: Record<string, unknown> }> {
	const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
	return { code: String(body.code ?? `HTTP_${res.status}`), message: String(body.message ?? body.error ?? res.statusText), body };
}

/** 上传一份已准备好的内容；网络失败时调用方用**同一个** prepared 重试。 */
export async function uploadPrepared(b: RepoBinding, f: TrackedFile, p: PreparedUpload, fetchFn: FetchLike = fetch): Promise<SaveOutcome> {
	const headers: Record<string, string> = {
		...protocolHeaders(b, p.operationId),
		"Content-Type": "application/octet-stream",
		"X-File-Path": encodeURIComponent(f.serverPath),
		"X-Base-Revision": String(f.revision),
		"X-Content-Hash": p.cipherHash,
		"X-File-Mtime": String(Date.now()),
	};
	if (b.encrypted) headers["X-File-Id"] = f.fileId;
	if (p.meta) {
		headers["X-Meta-Enc"] = p.meta.metaEnc;
		headers["X-Canonical-Hash"] = p.meta.canonicalHash;
	}
	let res: Response;
	try {
		res = await fetchFn("/api/v1/file", { method: "PUT", headers, body: p.payload as BodyInit });
	} catch (e) {
		return { kind: "offline", message: e instanceof Error ? e.message : String(e) };
	}
	if (res.status === 401) return { kind: "auth" };
	if (res.status >= 500) return { kind: "offline", message: `HTTP ${res.status}` };
	// 临时限流（429 RATE_LIMITED）：和断网一样用同一份密文退避重试；永久配额超限另走 rejected
	if (res.status === 429) return { kind: "offline", message: "服务器限流，稍后自动重试" };
	if (res.status === 409) {
		const { code, message, body } = await readCode(res);
		if (code === "CONFLICT") {
			return { kind: "conflict", revision: Number(body.revision ?? 0), hash: String(body.hash ?? ""), deleted: body.deleted === true, fileId: body.fileId as string | undefined };
		}
		return { kind: "rejected", status: 409, code, message };
	}
	if (!res.ok) {
		const { code, message, body } = await readCode(res);
		return { kind: "rejected", status: res.status, code, message, details: body.details as Record<string, unknown> | undefined };
	}
	const out = (await res.json()) as { revision: number; hash: string; fileId?: string; contentGeneration?: number };
	// 服务端回报的身份必须与本次加密用的一致，否则这份密文将来解不开
	if (b.encrypted && out.fileId && out.fileId !== f.fileId) {
		return { kind: "rejected", status: 200, code: "FILE_ID_MISMATCH", message: "服务器返回的文件身份与加密时不一致，已停止" };
	}
	// 服务端确认的世代为准（幂等重放命中首次结果时同样成立）
	const generation = typeof out.contentGeneration === "number" && out.contentGeneration > 0 ? out.contentGeneration : p.generation;
	return { kind: "saved", revision: out.revision, generation, fileId: out.fileId ?? f.fileId, hash: out.hash };
}

/** 删除（产生 tombstone；带前置版本 CAS）。请求体与插件 ApiClient.remove 相同：JSON {path, baseRevision}。 */
export async function deleteFile(b: RepoBinding, f: TrackedFile, fetchFn: FetchLike = fetch): Promise<SaveOutcome> {
	const headers = { ...protocolHeaders(b, newOperationId()), "Content-Type": "application/json" };
	let res: Response;
	try {
		res = await fetchFn("/api/v1/file", { method: "DELETE", headers, body: JSON.stringify({ path: f.serverPath, baseRevision: f.revision }) });
	} catch (e) {
		return { kind: "offline", message: e instanceof Error ? e.message : String(e) };
	}
	if (res.status === 401) return { kind: "auth" };
	if (res.status === 409) {
		const { code, message, body } = await readCode(res);
		if (code === "CONFLICT") return { kind: "conflict", revision: Number(body.revision ?? 0), hash: String(body.hash ?? ""), deleted: body.deleted === true };
		return { kind: "rejected", status: 409, code, message };
	}
	if (!res.ok) {
		const { code, message } = await readCode(res);
		return { kind: "rejected", status: res.status, code, message };
	}
	const out = (await res.json()) as { revision: number };
	return { kind: "saved", revision: out.revision, generation: f.generation, fileId: f.fileId, hash: "" };
}

/** 改名 / 移动：元数据更新，不产生 tombstone、内容零重传（ADR-001）。 */
export async function renameFile(b: RepoBinding, k: WriteKeys | null, f: TrackedFile, toPath: string, fetchFn: FetchLike = fetch): Promise<{ ok: true; serverPath: string; metaGeneration: number; revision: number } | { ok: false; code: string; message: string }> {
	let toServer = toPath;
	let metaEnc = "";
	let canonicalHash = "";
	if (b.metaMode) {
		if (!k?.meta) return { ok: false, code: "LOCKED", message: "仓库已锁定" };
		const next = f.metaGeneration + 1;
		metaEnc = await core.encryptMeta(k.meta, { vaultId: b.vaultIdentity, keyEpoch: b.keyEpoch, fileId: f.fileId, metaGeneration: next }, { path: toPath });
		canonicalHash = await core.canonicalPathHmac(k.meta, toPath);
		toServer = f.serverPath; // meta 模式寻址名就是 fileId，不随改名变化
	}
	let res: Response;
	try {
		res = await fetchFn("/api/v1/file/rename", {
			method: "POST",
			headers: { ...protocolHeaders(b, newOperationId()), "Content-Type": "application/json" },
			body: JSON.stringify({ fromPath: f.serverPath, toPath: toServer, baseMetaGeneration: f.metaGeneration, metaEnc, canonicalHash }),
		});
	} catch (e) {
		return { ok: false, code: "OFFLINE", message: e instanceof Error ? e.message : String(e) };
	}
	if (!res.ok) {
		const { code, message } = await readCode(res);
		return { ok: false, code, message };
	}
	const out = (await res.json()) as { toPath: string; metaGeneration: number; revision: number };
	return { ok: true, serverPath: out.toPath ?? toServer, metaGeneration: out.metaGeneration ?? f.metaGeneration, revision: out.revision ?? f.revision };
}

/**
 * 显式恢复已删除对象（回收站；与插件 push.restoreObject 同协议）：
 * revision 连续、fileId 不变；contentGeneration 必须新于删除时的值。
 * 成功后服务器上的 HEAD 是删除前的内容（旧世代密文），调用方必须紧接着以
 * contentGeneration + 1 重新加密上传（否则 HEAD 世代与密文内的世代不一致）。
 */
export async function restoreTombstone(
	b: RepoBinding,
	fileId: string,
	body: { expectedTombstoneRevision: number; contentGeneration: number; pseudonym: string; metaEnc?: string; canonicalHash?: string },
	operationId = newOperationId(),
	fetchFn: FetchLike = fetch,
): Promise<{ ok: true; fileId: string; path: string; revision: number; metaGeneration: number } | { ok: false; code: string; message: string }> {
	let res: Response;
	try {
		res = await fetchFn(`/api/v1/files/${encodeURIComponent(fileId)}/restore`, {
			method: "POST",
			headers: { ...protocolHeaders(b, operationId), "Content-Type": "application/json" },
			body: JSON.stringify({ metaEnc: "", canonicalHash: "", ...body }),
		});
	} catch (e) {
		return { ok: false, code: "OFFLINE", message: e instanceof Error ? e.message : String(e) };
	}
	if (!res.ok) {
		const { code, message } = await readCode(res);
		return { ok: false, code, message };
	}
	const out = (await res.json()) as { fileId: string; path: string; revision: number; metaGeneration?: number };
	if (out.fileId !== fileId) return { ok: false, code: "FILE_ID_MISMATCH", message: "服务器恢复的不是请求的那个对象" };
	return { ok: true, fileId: out.fileId, path: out.path, revision: out.revision, metaGeneration: out.metaGeneration ?? 0 };
}

/** 上传一份内容（新建或覆盖前置版本）；网络失败时用**同一份**密文最多重试 retries 次。 */
export async function saveWithRetry(b: RepoBinding, k: WriteKeys | null, f: TrackedFile, plain: Uint8Array, retries = 2, fetchFn: FetchLike = fetch): Promise<SaveOutcome> {
	const p = await prepareUpload(b, k, f, plain);
	let out = await uploadPrepared(b, f, p, fetchFn);
	for (let i = 0; i < retries && out.kind === "offline"; i++) {
		await new Promise((r) => setTimeout(r, 1500 * (i + 1)));
		out = await uploadPrepared(b, f, p, fetchFn);
	}
	return out;
}

/** Obsidian 不允许出现在文件名里的字符（以及控制字符）一律换成「-」。 */
export function sanitizeFileName(name: string): string {
	const cleaned = name.normalize("NFC").replace(/[\\\/:*?"<>|#^[\]\u0000-\u001f]/g, "-").replace(/^\.+/, "").trim();
	return cleaned || "附件";
}

/** 附件放在笔记所在文件夹；同名（大小写/Unicode 归一后）时按 Obsidian 习惯追加「 1」「 2」。 */
export function attachmentPath(notePath: string, fileName: string, exists: (canonicalPath: string) => boolean, when = new Date()): string {
	const dir = notePath.includes("/") ? notePath.slice(0, notePath.lastIndexOf("/") + 1) : "";
	let name = sanitizeFileName(fileName);
	// 粘贴的截图往往叫 image.png：换成 Obsidian 的「Pasted image 时间戳」命名
	if (/^image\.(png|jpe?g|gif|webp)$/i.test(name)) {
		const p2 = (n: number) => String(n).padStart(2, "0");
		const stamp = `${when.getFullYear()}${p2(when.getMonth() + 1)}${p2(when.getDate())}${p2(when.getHours())}${p2(when.getMinutes())}${p2(when.getSeconds())}`;
		name = `Pasted image ${stamp}${name.slice(name.lastIndexOf("."))}`;
	}
	const dot = name.lastIndexOf(".");
	const base = dot > 0 ? name.slice(0, dot) : name;
	const ext = dot > 0 ? name.slice(dot) : "";
	const canon = (p: string) => p.normalize("NFC").toLowerCase();
	let candidate = dir + name;
	for (let n = 1; exists(canon(candidate)); n++) candidate = `${dir}${base} ${n}${ext}`;
	return candidate;
}

/** 插入笔记的引用：图片/PDF/音视频用嵌入 ![[…]]，其他用链接 [[…]]。名字在库内唯一时用短名（Obsidian 默认），否则用完整路径。 */
export function attachmentLink(path: string, nameIsUnique: boolean): string {
	const name = path.slice(path.lastIndexOf("/") + 1);
	const target = nameIsUnique ? name : path;
	return /\.(png|jpe?g|gif|webp|svg|bmp|avif|pdf|mp3|wav|m4a|ogg|flac|mp4|webm|mov)$/i.test(path) ? `![[${target}]]` : `[[${target}]]`;
}

/** 本地三方合并（vendor 的插件合并引擎）。没有 base 时绝不假装能合并。 */
export function mergeTexts(base: string | null, local: string, remote: string): { clean: true; text: string } | { clean: false; conflicts: number } {
	if (base === null) return { clean: false, conflicts: 1 };
	if (local === remote) return { clean: true, text: local };
	const r = smartThreeWayMerge({ base, local, remote });
	return r.clean ? { clean: true, text: r.mergedText } : { clean: false, conflicts: r.conflicts.length };
}

/** 冲突副本的文件名：保留双方时本地版本另存为它（不覆盖任何一边）。 */
export function conflictCopyPath(path: string, when = new Date()): string {
	const stamp = `${when.getFullYear()}-${String(when.getMonth() + 1).padStart(2, "0")}-${String(when.getDate()).padStart(2, "0")} ${String(when.getHours()).padStart(2, "0")}${String(when.getMinutes()).padStart(2, "0")}`;
	const dot = path.toLowerCase().endsWith(".md") ? path.length - 3 : path.length;
	return `${path.slice(0, dot)}（网页冲突副本 ${stamp}）${path.slice(dot)}`;
}

// ---------------------------------------------------------------- 加密草稿

export async function deriveDraftKey(vmkRaw: Uint8Array): Promise<CryptoKey> {
	const master = await crypto.subtle.importKey("raw", vmkRaw as BufferSource, "HKDF", false, ["deriveKey"]);
	return crypto.subtle.deriveKey(
		{ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32) as BufferSource, info: new TextEncoder().encode(WEB_DRAFT_INFO) as BufferSource },
		master, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export interface DraftContent {
	text: string;
	baseText: string | null;
	baseRevision: number;
	path: string;
	file: TrackedFile;
}

/** 草稿的持久化后端（浏览器用 IndexedDB；测试用内存）。值是不透明的密文记录。 */
export interface DraftBackend {
	get(key: string): Promise<DraftRecord | undefined>;
	put(key: string, rec: DraftRecord): Promise<void>;
	delete(key: string): Promise<void>;
	keys(prefix: string): Promise<string[]>;
}

export interface DraftRecord {
	format: string;
	iv: string;
	ct: string;
	savedAt: number;
}

export class DraftStore {
	/** ns = 服务器源|账号|仓库；aadBase = 仓库身份|密钥世代。 */
	constructor(private backend: DraftBackend, private ns: string, private key: CryptoKey, private aadBase: string) {}

	private aad(fileKey: string): Uint8Array {
		return new TextEncoder().encode(`litesync/web-draft/${DRAFT_FORMAT}|${this.ns}|${fileKey}|${this.aadBase}`);
	}

	async save(fileKey: string, c: DraftContent): Promise<number> {
		const iv = core.randomBytes(12);
		const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource, additionalData: this.aad(fileKey) as BufferSource },
			this.key, new TextEncoder().encode(JSON.stringify(c)) as BufferSource));
		const savedAt = Date.now();
		await this.backend.put(this.ns + "|" + fileKey, { format: DRAFT_FORMAT, iv: core.b64encode(iv), ct: core.b64encode(ct), savedAt });
		return savedAt;
	}

	async load(fileKey: string): Promise<(DraftContent & { savedAt: number }) | null> {
		const rec = await this.backend.get(this.ns + "|" + fileKey);
		if (!rec || rec.format !== DRAFT_FORMAT) return null;
		try {
			const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: core.b64decode(rec.iv) as BufferSource, additionalData: this.aad(fileKey) as BufferSource },
				this.key, core.b64decode(rec.ct) as BufferSource);
			return { ...(JSON.parse(new TextDecoder().decode(plain)) as DraftContent), savedAt: rec.savedAt };
		} catch {
			return null; // 别的账号/仓库/密钥世代的草稿：解不开就是不存在
		}
	}

	async remove(fileKey: string): Promise<void> {
		await this.backend.delete(this.ns + "|" + fileKey);
	}

	async listKeys(): Promise<string[]> {
		return (await this.backend.keys(this.ns + "|")).map((k) => k.slice(this.ns.length + 1));
	}
}

/** IndexedDB 后端（浏览器）。打开失败（隐私模式、配额）时抛出，调用方显示「本机草稿不可用」。 */
export function indexedDbBackend(dbName = "litesync-web-drafts"): DraftBackend {
	let dbp: Promise<IDBDatabase> | null = null;
	const open = () => (dbp ??= new Promise((resolve, reject) => {
		const req = indexedDB.open(dbName, 1);
		req.onupgradeneeded = () => req.result.createObjectStore("drafts");
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error);
	}));
	const tx = async <T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> => {
		const db = await open();
		return new Promise<T>((resolve, reject) => {
			const r = fn(db.transaction("drafts", mode).objectStore("drafts"));
			r.onsuccess = () => resolve(r.result);
			r.onerror = () => reject(r.error);
		});
	};
	return {
		get: (k) => tx<DraftRecord | undefined>("readonly", (s) => s.get(k) as IDBRequest<DraftRecord | undefined>),
		put: async (k, rec) => void (await tx("readwrite", (s) => s.put(rec, k))),
		delete: async (k) => void (await tx("readwrite", (s) => s.delete(k))),
		keys: async (prefix) => ((await tx<IDBValidKey[]>("readonly", (s) => s.getAllKeys())) as string[]).filter((k) => typeof k === "string" && k.startsWith(prefix)),
	};
}

/** 内存后端（测试 / 存储不可用时的降级——此时界面明确提示草稿不会跨刷新保留）。 */
export function memoryBackend(): DraftBackend & { dump(): Map<string, DraftRecord> } {
	const m = new Map<string, DraftRecord>();
	return {
		get: async (k) => m.get(k),
		put: async (k, r) => void m.set(k, r),
		delete: async (k) => void m.delete(k),
		keys: async (p) => [...m.keys()].filter((k) => k.startsWith(p)),
		dump: () => m,
	};
}
