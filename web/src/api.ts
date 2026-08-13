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

export async function logout(): Promise<void> {
	await fetch("/web/session", { method: "DELETE" }).catch(() => undefined);
}

export class Api {
	private async req(path: string, init?: RequestInit): Promise<Response> {
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
	}> {
		const res = await this.req("/api/v1/info");
		if (!res.ok) throw new Error(`HTTP ${res.status}`);
		return res.json();
	}

	async snapshot(): Promise<{ sequence: number; files: FileEntry[] }> {
		const res = await this.req("/api/v1/snapshot");
		if (!res.ok) throw new Error(`snapshot: HTTP ${res.status}`);
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
	async fileWithIdentity(path: string): Promise<{ data: ArrayBuffer; fileId: string | null; generation: number | null }> {
		const res = await this.req(`/api/v1/file?path=${encodeURIComponent(path)}`);
		if (!res.ok) throw new Error(`file ${path}: HTTP ${res.status}`);
		const gen = res.headers.get("X-Content-Generation");
		return {
			data: await res.arrayBuffer(),
			fileId: res.headers.get("X-File-Id"),
			generation: gen === null || gen === "" ? null : Number(gen),
		};
	}

	async file(path: string): Promise<ArrayBuffer> {
		return (await this.fileWithIdentity(path)).data;
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
