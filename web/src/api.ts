import { VaultKeyDoc } from "./crypto";

export interface FileEntry {
	path: string;
	revision: number;
	hash: string;
	size: number;
	mtime: number;
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
		return res;
	}

	async info(): Promise<{ version: string; latestSequence: number }> {
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

	async file(path: string): Promise<ArrayBuffer> {
		const res = await this.req(`/api/v1/file?path=${encodeURIComponent(path)}`);
		if (!res.ok) throw new Error(`file ${path}: HTTP ${res.status}`);
		return res.arrayBuffer();
	}

	async history(path: string): Promise<VersionEntry[]> {
		const res = await this.req(`/api/v1/history?path=${encodeURIComponent(path)}`);
		if (!res.ok) throw new Error(`history: HTTP ${res.status}`);
		const body = (await res.json()) as { versions: VersionEntry[] };
		return body.versions ?? [];
	}

	async version(path: string, revision: number): Promise<ArrayBuffer> {
		const res = await this.req(`/api/v1/version?path=${encodeURIComponent(path)}&revision=${revision}`);
		if (!res.ok) throw new Error(`version: HTTP ${res.status}`);
		return res.arrayBuffer();
	}

	// ---------- 备份管理（ADMIN capability：需要 admin 会话，见 login(token, true)） ----------

	private async adminReq(path: string, init?: RequestInit): Promise<unknown> {
		const res = await this.req(`/api/v1/admin/backup/${path}`, init);
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
