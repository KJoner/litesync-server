import { VaultKeyDoc } from "./crypto";

export interface FileEntry {
	path: string;
	revision: number;
	hash: string;
	size: number;
	mtime: number;
	/** 稳定文件身份（0.11.0+；LSE3 解密的 AAD 输入） */
	fileId?: string;
	/** 加密元数据（0.12.0+，meta 模式；真实路径在里面） */
	metaEnc?: string;
	metaGeneration?: number;
	/** meta 模式下的服务器伪名（path 已被替换为解密出的真实路径，前端字段） */
	serverPath?: string;
}

export interface TrashItem {
	fileId: string;
	/** 删除前最后的寻址名（明文路径仓库 = 真实路径；路径加密仓库 = fileId） */
	path: string;
	deletionRevision: number;
	contentGeneration: number;
	metaGeneration: number;
	deletedAt: number;
	retainUntil?: number;
	restorable: boolean;
}

export interface VersionEntry {
	revision: number;
	action: string;
	size: number;
	mtime: number;
	hash?: string;
	deviceId?: string;
	createdAt: number;
}

/** 服务器判定该内容已损坏并停止对外提供（§7.2 CONTENT_CORRUPTED）。 */
export class IntegrityError extends Error {
	constructor() {
		super("服务器上的这份内容未通过完整性校验，已停止提供");
		this.name = "IntegrityError";
	}
}

export class AuthError extends Error {
	constructor() {
		super("unauthorized");
		this.name = "AuthError";
	}
}

/**
 * v4：浏览器不再持有根 API Token。
 * 登录用 Token 换取 HttpOnly + SameSite=Strict 的只读会话 Cookie，
 * JavaScript 完全接触不到凭据；之后所有请求靠 Cookie 自动携带。
 * v6：admin=true 时额外下发短期 admin 会话（备份管理页需要）。
 */
export async function login(token: string, admin = false): Promise<boolean> {
	const res = await fetch("/web/session", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ token, admin }),
	});
	return res.ok;
}

/** 名下仓库（v0.19 多仓库）。 */
export interface WebVault {
	id: string;
	name: string;
	fileCount: number;
	bytesUsed: number;
	encryptionState: string;
	current: boolean;
	/** v0.20：初始化状态（ADR-012）；旧服务端没有这个字段 */
	initState?: "pending_encryption" | "initializing" | "ready";
}

/** 当前会话的身份（v0.18 多用户）：前端据此渲染角色相关 UI；硬关卡在服务端。 */
export interface Whoami {
	role: "admin" | "user";
	name: string;
	userId?: string;
}

/**
 * 跨标签页广播「本浏览器当前登录的是哪个账号」（空串 = 未登录；验收 TN-05）。
 * 其他标签页监听 storage 事件，发现账号变了就把可见状态清掉。值没变时不写，免得触发多余的事件。
 */
export const ACCOUNT_KEY = "litesync-account";
export function announceAccount(id: string): void {
	try {
		if ((localStorage.getItem(ACCOUNT_KEY) ?? "") !== id) localStorage.setItem(ACCOUNT_KEY, id);
	} catch {
		/* 隐私模式等场景写不了 storage：各标签页仍会在可见时自查 */
	}
}

export async function logout(): Promise<void> {
	await fetch("/web/session", { method: "DELETE" }).catch(() => undefined);
}

export class Api {
	/** 目标仓库（v0.19 多仓库；空 = 默认仓库）。设置后所有请求携带 X-Vault-ID */
	vaultId = "";

	private async req(path: string, init?: RequestInit): Promise<Response> {
		if (this.vaultId) {
			init = init ?? {};
			init.headers = { ...(init.headers as Record<string, string> | undefined), "X-Vault-ID": this.vaultId };
		}
		const res = await fetch(path, init);
		if (res.status === 401 || res.status === 403) throw new AuthError();
		// §7.2 / §7.5：服务器明确说「这份内容坏了」时要单独成一类错误。
		// 混进普通 HTTP 错误里，用户看到的会是「加载失败」——那读起来像网络问题，
		// 而实际需要的是管理员从备份恢复
		if (res.status === 503) {
			const body = (await res.clone().json().catch(() => ({}))) as { code?: string };
			if (body.code === "CONTENT_CORRUPTED") throw new IntegrityError();
		}
		return res;
	}

	async info(): Promise<{
		version: string;
		latestSequence: number;
		vaultId?: string;
		keyEpoch?: number;
		/** 仓库当前的元数据加密状态（plain / migrating / verifying / encrypted） */
		metaState?: string;
		formatEpoch?: number;
		repoEpoch?: string;
		/** 重置凭证是否已登记（v0.18）：false 时解锁后自动补登记 */
		resetAuthConfigured?: boolean;
		/** v0.20：写入时逐请求校验用的世代与信封下限 */
		encryptionState?: string;
		minimumEnvelopeVersion?: number;
		capabilities?: string[];
	}> {
		const res = await this.req("/api/v1/info");
		if (!res.ok) throw new Error(`HTTP ${res.status}`);
		return res.json();
	}

	/** 名下仓库列表（v0.19 多仓库）。旧服务器无此端点时返回空数组。 */
	async listVaults(): Promise<WebVault[]> {
		try {
			const res = await this.req("/api/v1/vaults");
			if (!res.ok) return [];
			return ((await res.json()).vaults ?? []) as WebVault[];
		} catch {
			return [];
		}
	}

	async whoami(): Promise<Whoami> {
		const res = await this.req("/api/v1/whoami");
		if (!res.ok) throw new Error(`whoami: HTTP ${res.status}`);
		return res.json();
	}

	/** 新建仓库（v0.19.x 账户页）。同名/超上限 → 服务端 409，message 直接可展示。 */
	async createVault(name: string): Promise<string> {
		const res = await this.req("/api/v1/vaults", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name }),
		});
		const body = await res.json();
		if (!res.ok) throw new Error(body.message ?? `HTTP ${res.status}`);
		return body.id as string;
	}

	/** 重命名仓库（只动展示名）。 */
	async renameVault(id: string, name: string): Promise<void> {
		const res = await this.req(`/api/v1/vaults/${encodeURIComponent(id)}`, {
			method: "PATCH",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name }),
		});
		if (!res.ok) {
			const body = await res.json().catch(() => ({}));
			throw new Error(body.message ?? `HTTP ${res.status}`);
		}
	}

	/** 删除仓库：confirmName 必须与仓库名一致；不能删最后一个。 */
	async deleteVault(id: string, confirmName: string): Promise<void> {
		const res = await this.req(`/api/v1/vaults/${encodeURIComponent(id)}`, {
			method: "DELETE",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ confirmName }),
		});
		if (!res.ok) {
			const body = await res.json().catch(() => ({}));
			throw new Error(body.message ?? `HTTP ${res.status}`);
		}
	}

	/**
	 * 重置自己的 API Token（v0.18 / v11 设计 §4.3）。
	 * resetAuth 是解锁 E2EE 时派生的重置凭证；已登记而不提交（或不符）→ 403。
	 * 成功后旧 Token 全线失效、全部设备凭据被撤销；发起会话由服务端保活。
	 */
	async resetToken(resetAuth: string): Promise<{
		token: string;
		revokedDevices: number;
		resetAuthEnforced: boolean;
	}> {
		const res = await this.req("/api/v1/account/token-reset", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ resetAuth }),
		});
		const body = await res.json();
		if (!res.ok) {
			throw new Error(body.code === "RESET_AUTH_MISMATCH"
				? "重置凭证不匹配：请先用正确的 E2EE 密码解锁后再试"
				: (body.message ?? `HTTP ${res.status}`));
		}
		return body;
	}

	/** 登记重置凭证（幂等；已登记不同值时服务端 409，忽略即可）。 */
	async putResetAuth(resetAuth: string): Promise<void> {
		await this.req("/api/v1/vault/reset-auth", {
			method: "PUT",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ resetAuth }),
		}).catch(() => undefined);
	}

	async snapshot(): Promise<{ sequence: number; files: FileEntry[] }> {
		const res = await this.req("/api/v1/snapshot");
		if (!res.ok) throw new Error(`snapshot: HTTP ${res.status}`);
		return res.json();
	}

	/** 增量变更（只用来判断「有没有新东西」；有就重取 snapshot）。游标过旧时 resyncRequired=true。 */
	async changes(since: number, limit = 1): Promise<{ latestSequence: number; resyncRequired?: boolean; hasMore: boolean; changes: { sequence: number }[] }> {
		const res = await this.req(`/api/v1/changes?since=${since}&limit=${limit}`);
		if (!res.ok) throw new Error(`changes: HTTP ${res.status}`);
		return res.json();
	}

	async vaultKey(): Promise<VaultKeyDoc | null> {
		const res = await this.req("/api/v1/vault-key");
		if (res.status === 404) return null;
		if (!res.ok) throw new Error(`vault-key: HTTP ${res.status}`);
		return res.json();
	}

	/**
	 * 下载 HEAD 内容，连同服务器声明的身份一起返回（v0.13.3 / 计划书 §7.5）。
	 *
	 * 只要 bytes 不够：调用方必须能核对「服务器给的是不是我要的那个对象」，
	 * 否则一个被攻陷的服务器可以拿另一份内容冒充这个文件。
	 */
	async fileWithIdentity(path: string): Promise<{ data: ArrayBuffer; fileId: string | null; generation: number | null; revision: number }> {
		const res = await this.req(`/api/v1/file?path=${encodeURIComponent(path)}`);
		if (!res.ok) throw new Error(`file ${path}: HTTP ${res.status}`);
		const gen = res.headers.get("X-Content-Generation");
		return {
			data: await res.arrayBuffer(),
			fileId: res.headers.get("X-File-Id"),
			generation: gen === null || gen === "" ? null : Number(gen),
			revision: Number(res.headers.get("X-Revision") ?? 0),
		};
	}

	async file(path: string): Promise<ArrayBuffer> {
		return (await this.fileWithIdentity(path)).data;
	}

	/** 回收站（v0.20）：仍保留的删除记录。restorable=false 表示删除前的内容已被历史裁剪清掉。 */
	async trash(): Promise<TrashItem[]> {
		const res = await this.req("/api/v1/trash");
		if (!res.ok) throw new Error(`trash: HTTP ${res.status}`);
		const body = (await res.json()) as { items: TrashItem[] };
		return body.items ?? [];
	}

	async history(path: string): Promise<VersionEntry[]> {
		const res = await this.req(`/api/v1/history?path=${encodeURIComponent(path)}`);
		if (!res.ok) throw new Error(`history: HTTP ${res.status}`);
		const body = (await res.json()) as { versions: VersionEntry[] };
		return body.versions ?? [];
	}

	/**
	 * 下载历史版本，连同**版本级** fileId 一起返回（§7.5）。
	 *
	 * 历史版本的 fileId 未必等于当前 HEAD 的 fileId：文件被删除后重建过的话，
	 * 旧版本属于旧对象。用当前身份去解旧版本只会得到「解密失败」这种误导性错误。
	 */
	async versionWithIdentity(
		path: string,
		revision: number,
	): Promise<{ data: ArrayBuffer; fileId: string | null }> {
		const res = await this.req(`/api/v1/version?path=${encodeURIComponent(path)}&revision=${revision}`);
		if (!res.ok) throw new Error(`version: HTTP ${res.status}`);
		return { data: await res.arrayBuffer(), fileId: res.headers.get("X-File-Id") };
	}

	async version(path: string, revision: number): Promise<ArrayBuffer> {
		return (await this.versionWithIdentity(path, revision)).data;
	}

	// ---------- 备份管理（ADMIN capability：需要 admin 会话，见 login(token, true)） ----------

	private async adminReq(path: string, init?: RequestInit): Promise<unknown> {
		return this.adminPath(`/api/v1/admin/backup/${path}`, init);
	}

	/** 管理接口的统一请求：错误消息取服务端给的那一句，而不是裸 HTTP 码。 */
	private async adminPath(path: string, init?: RequestInit): Promise<unknown> {
		const res = await this.req(path, {
			...init,
			headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
		});
		const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
		if (!res.ok && res.status !== 202) {
			throw new Error(typeof body.error === "string" ? body.error : `HTTP ${res.status}`);
		}
		return body;
	}

	backupStatus(): Promise<BackupStatus> {
		return this.adminReq("status") as Promise<BackupStatus>;
	}

	backupConfig(): Promise<BackupConfigView> {
		return this.adminReq("config") as Promise<BackupConfigView>;
	}

	backupSaveConfig(update: Record<string, unknown>): Promise<BackupConfigView> {
		return this.adminReq("config", {
			method: "PUT",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(update),
		}) as Promise<BackupConfigView>;
	}

	backupTest(): Promise<{ ok: boolean; initialized?: boolean; error?: string }> {
		return this.adminReq("test", { method: "POST" }) as Promise<{
			ok: boolean;
			initialized?: boolean;
			error?: string;
		}>;
	}

	backupInit(): Promise<void> {
		return this.adminReq("init", { method: "POST" }).then(() => undefined);
	}

	backupRun(): Promise<void> {
		return this.adminReq("run", { method: "POST" }).then(() => undefined);
	}

	backupCheck(): Promise<void> {
		return this.adminReq("check", { method: "POST" }).then(() => undefined);
	}

	// ---------- 管理 UI（v0.17 / §11.3）：出事那天才用得到的那几件事 ----------

	adminDevices(): Promise<{ devices: AdminDevice[] }> {
		return this.adminPath("/api/v1/admin/devices") as Promise<{ devices: AdminDevice[] }>;
	}

	adminRevokeDevice(id: string): Promise<void> {
		return this.adminPath(`/api/v1/admin/devices/${encodeURIComponent(id)}`, {
			method: "DELETE",
		}).then(() => undefined);
	}

	adminMigrationStatus(): Promise<AdminMigrationStatus> {
		return this.adminPath("/api/v1/admin/migration/status") as Promise<AdminMigrationStatus>;
	}

	adminIntegrityEvents(): Promise<{ events: IntegrityEvent[] }> {
		return this.adminPath("/api/v1/admin/integrity/events") as Promise<{ events: IntegrityEvent[] }>;
	}

	adminShares(): Promise<{ shares: AdminShare[] }> {
		return this.adminPath("/api/v1/admin/shares") as Promise<{ shares: AdminShare[] }>;
	}

	adminRecoverShare(id: string, expiresAt: number): Promise<void> {
		return this.adminPath(`/api/v1/admin/shares/${encodeURIComponent(id)}/recover`, {
			method: "POST",
			body: JSON.stringify({ expiresAt }),
		}).then(() => undefined);
	}

	adminRevokeShare(id: string): Promise<void> {
		return this.adminPath(`/api/v1/admin/shares/${encodeURIComponent(id)}`, {
			method: "DELETE",
		}).then(() => undefined);
	}

	adminRestorePlan(snapshot: string): Promise<RestorePlan> {
		return this.adminPath(
			`/api/v1/admin/backup/restore-plan?snapshot=${encodeURIComponent(snapshot)}`,
		) as Promise<RestorePlan>;
	}

	backupSnapshots(): Promise<{ snapshots: BackupSnapshot[]; initialized: boolean }> {
		return this.adminReq("snapshots") as Promise<{ snapshots: BackupSnapshot[]; initialized: boolean }>;
	}

	// ---------- 多用户管理（v0.18，仅管理员） ----------

	async createInvite(expiresHours: number, serverUrl: string): Promise<AdminInvite & { secret: string; path: string }> {
		const res = await this.req("/api/v1/admin/invites", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ expiresHours, serverUrl }),
		});
		if (!res.ok) throw new Error(`invite: HTTP ${res.status}`);
		return res.json();
	}

	async listInvites(): Promise<AdminInvite[]> {
		const res = await this.req("/api/v1/admin/invites");
		if (!res.ok) throw new Error(`invites: HTTP ${res.status}`);
		return (await res.json()).invites ?? [];
	}

	async revokeInvite(id: string): Promise<void> {
		const res = await this.req(`/api/v1/admin/invites/${encodeURIComponent(id)}`, { method: "DELETE" });
		if (!res.ok) throw new Error(`revoke invite: HTTP ${res.status}`);
	}

	async listUsers(): Promise<AdminUser[]> {
		const res = await this.req("/api/v1/admin/users");
		if (!res.ok) throw new Error(`users: HTTP ${res.status}`);
		return (await res.json()).users ?? [];
	}

	async setUserDisabled(userId: string, disabled: boolean): Promise<void> {
		const res = await this.req(
			`/api/v1/admin/users/${encodeURIComponent(userId)}/${disabled ? "disable" : "enable"}`,
			{ method: "POST" });
		if (!res.ok) {
			const body = await res.json().catch(() => ({} as { message?: string }));
			throw new Error(body.message ?? `HTTP ${res.status}`);
		}
	}

	/** 配额覆盖值：0 = 跟随服务器默认，-1 = 不限，>0 = 指定值（字节 / 个数）。 */
	async setUserQuota(userId: string, bytes: number, vaults: number): Promise<void> {
		const res = await this.req(`/api/v1/admin/users/${encodeURIComponent(userId)}/quota`, {
			method: "PUT",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ bytes, vaults }),
		});
		if (!res.ok) {
			const body = await res.json().catch(() => ({} as { message?: string }));
			throw new Error(body.message ?? `HTTP ${res.status}`);
		}
	}

	async deleteUser(userId: string, confirmName: string): Promise<void> {
		const res = await this.req(`/api/v1/admin/users/${encodeURIComponent(userId)}`, {
			method: "DELETE",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ confirmName }),
		});
		if (!res.ok) {
			const body = await res.json().catch(() => ({} as { message?: string }));
			throw new Error(body.message ?? `HTTP ${res.status}`);
		}
	}
}

/** 邀请（v0.18）：secret 只在创建响应里出现一次。 */
export interface AdminInvite {
	id: string;
	serverUrl: string;
	createdAt: number;
	expiresAt: number;
	usedAt?: number;
	usedBy?: string;
	revoked?: boolean;
}

/** 用户概要（v0.18）：不含任何凭据材料。 */
/** 账号用量与上限（v0.20 配额；limit 0 = 不限；override：0 = 跟随默认，-1 = 不限）。 */
export interface Usage {
	bytesUsed: number;
	bytesLimit: number;
	vaults: number;
	vaultsLimit: number;
	overrideBytes: number;
	overrideVaults: number;
}

export interface AdminUser {
	userId: string;
	name: string;
	isAdmin: boolean;
	disabled: boolean;
	createdAt: number;
	lastSeenAt: number;
	devices: number;
	objects: number;
	bytesUsed: number;
	vaults?: number;
	usage?: Usage;
}

export interface BackupStatus {
	keyAvailable: boolean;
	keyError?: string;
	resticOk: boolean;
	resticVersion?: string;
	enabled: boolean;
	configured: boolean;
	running: boolean;
	runningOp?: string;
	lastStartedAt?: number;
	lastCompletedAt?: number;
	lastDurationMs?: number;
	lastSnapshotId?: string;
	lastError?: string;
	nextRunAt?: number;
	repositorySize?: number;
	snapshotCount?: number;
	budgetBytes?: number;
}

export interface BackupConfigView {
	enabled: boolean;
	provider: string;
	accountId: string;
	bucket: string;
	prefix: string;
	endpoint: string;
	accessKeyConfigured: boolean;
	secretKeyConfigured: boolean;
	resticPasswordConfigured: boolean;
	budgetGb: number;
}

export interface BackupSnapshot {
	id: string;
	short_id: string;
	time: string;
	paths?: string[];
	tags?: string[];
}

// ---------- 管理 UI 的数据形状（§11.3） ----------

export interface AdminDevice {
	id: string;
	name: string;
	scopes: string[];
	createdAt: number;
	lastSeenAt: number;
	revoked: boolean;
	hasSigningKey: boolean;
	/** 最后一次上报的插件版本（§15 第 3 步）；未上报过为空串 */
	clientVersion: string;
	/** 最后一次上报的平台 token（windows/macos/linux/ios/android/…）；未上报过为空串 */
	platform: string;
	/** 最近来源 IP（可信代理后取 XFF 真实端）；未记录过为空串 */
	lastIp: string;
}

export interface AdminMigrationStatus {
	meta: Record<string, unknown>;
	needsBlobIdMigration: boolean;
	pendingRewrapEpoch: number;
}

export interface IntegrityEvent {
	blobId: string;
	kind: string;
	detail: string;
	detectedAt: number;
	serving: boolean;
	resolved: boolean;
	affectedRefs: number;
}

export interface AdminShare {
	id: string;
	size: number;
	createdAt: number;
	expiresAt: number;
	revoked: boolean;
	expired: boolean;
	/** 密文是否还在盘上；false 表示已被回收，延长有效期也救不回来 */
	recoverable: boolean;
}

export interface RestorePlan {
	snapshot: string;
	currentSequence: number;
	activeDevices: number;
	command: string;
	consequences: string[];
	whyNotAButton: string;
}

// ---------------------------------------------------------------- v0.20 公开化（/auth、/api/v2）

/** 服务端返回的结构化错误（按 code 分支，永不解析 message）。 */
export class ApiCodeError extends Error {
	constructor(
		readonly status: number,
		readonly code: string,
		message: string,
		readonly retryable = false,
	) {
		super(message);
		this.name = "ApiCodeError";
	}
}

export interface AuthConfig {
	oidc: boolean;
	legacyTokenLogin: boolean;
	registrationMode: "closed" | "invite" | "open";
	accountConsoleUrl?: string;
}

export interface Me {
	account: { id: string; displayName: string; email: string; emailVerified: boolean };
	role: "admin" | "user";
	permissions: string[];
	vaultCount: number;
	onboarding: { state: "needs_first_vault" | "ready" };
	identity: { linked: boolean };
	session: { kind: "oidc" | "token" | "device"; legacyLogin: boolean };
	features: { oidc: boolean; registrationMode: string; webEditing?: boolean };
	accountConsoleUrl?: string;
	usage?: Usage;
}

export interface VaultCard {
	id: string;
	name: string;
	createdAt: number;
	fileCount: number;
	bytesUsed: number;
	updatedAt: number;
	encryptionState: string;
	initState: "pending_encryption" | "initializing" | "ready";
	vaultIdentity: string;
	current: boolean;
}

export interface InitStatus {
	vaultId: string;
	vaultIdentity: string;
	initState: "pending_encryption" | "initializing" | "ready";
	initVersion: number;
	leaseActive: boolean;
	keyDocPresent: boolean;
	cryptoProfile: { protocolVersion: number; keyDocVersion: number; writeEnvelope: string };
	created?: boolean;
	replayed?: boolean;
}

export interface PairingGrantResp {
	grantId: string;
	enrollmentSecret: string;
	expiresAt: number;
	vault: { vaultId: string; vaultIdentity: string; displayName: string };
	accountLabel: string;
	protocolVersion: number;
	requiredCapabilities: string[];
	trust: { mode: string; repoEpoch: string; headSequence: number };
}

export interface AccountDevice {
	id: string;
	name: string;
	platform: string;
	vaultId: string;
	vaultName: string;
	createdAt: number;
	lastSeenAt: number;
	revoked: boolean;
	clientVersion: string;
}

/** 公开的登录配置（不需要会话）。 */
export async function authConfig(): Promise<AuthConfig> {
	const res = await fetch("/auth/config");
	if (!res.ok) return { oidc: false, legacyTokenLogin: true, registrationMode: "closed" };
	return res.json();
}

/**
 * /api/v2 请求：只有 401 视为「需要登录」（AuthError）；其余错误带着 code 抛出，
 * 由调用方按 code 给出准确提示——不把 403 EMAIL_NOT_VERIFIED 之类误当成掉线。
 */
export async function v2<T>(method: string, path: string, body?: unknown, vaultId = ""): Promise<T> {
	const headers: Record<string, string> = {};
	if (body !== undefined) headers["Content-Type"] = "application/json";
	if (vaultId) headers["X-Vault-ID"] = vaultId;
	const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
	if (res.status === 401) throw new AuthError();
	const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
	if (!res.ok) {
		throw new ApiCodeError(res.status, String(data.code ?? "HTTP_" + res.status),
			String(data.message ?? data.error ?? `HTTP ${res.status}`), Boolean(data.retryable));
	}
	return data as T;
}

export const accountApi = {
	me: () => v2<Me>("GET", "/api/v2/me"),
	vaults: async (): Promise<VaultCard[]> => (await v2<{ vaults: VaultCard[] }>("GET", "/api/v1/vaults")).vaults ?? [],
	createVault: (name: string, clientRequestId: string) =>
		v2<InitStatus & { name: string }>("POST", "/api/v2/vaults", { name, clientRequestId }),
	initStatus: (id: string) => v2<InitStatus>("GET", `/api/v2/vaults/${encodeURIComponent(id)}/initialization`),
	initClaim: (id: string, opId: string) =>
		v2<InitStatus>("POST", `/api/v2/vaults/${encodeURIComponent(id)}/initialization`, { phase: "claim", opId }),
	initCommit: (id: string, body: Record<string, unknown>) =>
		v2<InitStatus>("POST", `/api/v2/vaults/${encodeURIComponent(id)}/initialization`, { phase: "commit", ...body }),
	renameVault: (id: string, name: string) => v2<unknown>("PATCH", `/api/v1/vaults/${encodeURIComponent(id)}`, { name }),
	deleteVault: (id: string, confirmName: string) =>
		v2<unknown>("DELETE", `/api/v1/vaults/${encodeURIComponent(id)}`, { confirmName }),
	pairingGrant: (id: string) => v2<PairingGrantResp>("POST", `/api/v2/vaults/${encodeURIComponent(id)}/pairing-grants`),
	uploadPairing: (vaultId: string, grantId: string, ciphertext: string) =>
		v2<{ pairId: string; expiresAt: number }>("POST", "/api/v2/pairings", { grantId, ciphertext, vaultId }, vaultId),
	deletePairing: (vaultId: string, pairId: string) =>
		v2<unknown>("DELETE", `/api/v2/pairings/${encodeURIComponent(pairId)}`, undefined, vaultId),
	pairingAlive: async (pairId: string): Promise<boolean> =>
		(await fetch(`/api/v2/pairings/${encodeURIComponent(pairId)}/envelope`)).ok,
	devices: async (): Promise<AccountDevice[]> => (await v2<{ devices: AccountDevice[] }>("GET", "/api/v2/devices")).devices ?? [],
	revokeDevice: (id: string) => v2<unknown>("DELETE", `/api/v2/devices/${encodeURIComponent(id)}`),
	logout: () => v2<unknown>("POST", "/auth/logout"),
	logoutAll: () => v2<{ revokedDevices: number; endSessionUrl?: string }>("POST", "/api/v2/account/logout-all"),
};
