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
 */
export async function login(token: string): Promise<boolean> {
	const res = await fetch("/web/session", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ token }),
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
}
