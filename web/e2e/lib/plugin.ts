/**
 * 「另一台设备」= 插件原样的源码（ApiClient / uploadFromPlain / downloadPlain / unlockVaultKey），
 * 由 run.mjs 从 LITESYNC_PLUGIN_DIR 打包进来。网页写的东西必须能被插件解开，反之亦然（ED-01）。
 */
import { ApiClient } from "@plugin/api/client";
import { unlockVaultKey } from "@plugin/crypto/crypto";
import { downloadPlain, uploadFromPlain } from "@plugin/sync/transfer";
import { api, E2E } from "./harness";

/* eslint-disable @typescript-eslint/no-explicit-any */
export class PluginDevice {
	private tracked = new Map<string, any>();
	vmk!: CryptoKey;
	info: any;
	constructor(readonly vaultId: string, readonly deviceId = "e2e-plugin") {}

	/** 取仓库信息与 keyDoc，用仓库密码解开 VMK（与插件接入时相同的路径）。 */
	async unlock(password: string): Promise<boolean> {
		this.info = (await api("/api/v1/info", { vaultId: this.vaultId })).body;
		const doc = (await api("/api/v1/vault-key", { vaultId: this.vaultId })).body;
		const k = await unlockVaultKey(doc, password);
		if (k) this.vmk = k;
		return !!k;
	}

	ctx(): any {
		const client = new ApiClient(() => ({
			serverUrl: E2E.base, apiToken: E2E.token, deviceId: this.deviceId, vaultChoice: this.vaultId,
			formatEpoch: this.info.formatEpoch ?? 1, repoEpoch: this.info.repoEpoch ?? "", keyEpoch: this.info.keyEpoch,
		}));
		return {
			client,
			store: { get: (p: string) => this.tracked.get(p), state: { bootstrap: { remoteVaultId: this.info.vaultId, keyEpoch: this.info.keyEpoch, metaState: "plain" } }, save: async () => undefined },
			queue: { getOp: () => undefined, rememberIdentity: () => undefined },
			e2ee: { enabled: true, unlocked: true, requireKey: () => this.vmk },
			gate: { markIntegrityError: (m: string) => { throw new Error("integrity: " + m); } },
			padsSize: () => false,
			reportedMtime: (m: number) => m,
		};
	}

	forget(path: string): void {
		this.tracked.delete(path);
	}

	/** 插件侧读：插件自己的下载 + 解密 + 世代不回退校验。 */
	async read(path: string): Promise<{ text: string; plain: ArrayBuffer; fileId?: string; generation?: number; revision: number }> {
		const d = await downloadPlain(this.ctx(), path);
		this.tracked.set(path, { fileId: d.fileId, generation: d.generation, revision: d.revision });
		return { ...d, text: new TextDecoder().decode(d.plain) };
	}

	/** 插件侧写（以已见世代为下限）；没读过就先读一次拿到 base。 */
	async write(path: string, text: string): Promise<{ revision: number; generation?: number; fileId?: string }> {
		if (!this.tracked.has(path)) await this.read(path);
		const t = this.tracked.get(path);
		const out = await uploadFromPlain(this.ctx(), path, new TextEncoder().encode(text).buffer as ArrayBuffer, t.revision, Date.now(), "upsert", { generationFloor: t.generation });
		this.tracked.set(path, { fileId: out.fileId, generation: out.generation, revision: out.revision });
		return out;
	}

	/** 插件侧新建（字节原样）。 */
	async create(path: string, bytes: Uint8Array): Promise<{ revision: number; fileId?: string; generation?: number }> {
		const out = await uploadFromPlain(this.ctx(), path, bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer, 0, Date.now(), "upsert");
		this.tracked.set(path, { fileId: out.fileId, generation: out.generation, revision: out.revision });
		return out;
	}

	async history(path: string): Promise<any[]> {
		return this.ctx().client.history(path);
	}

	/** 插件侧删除（产生墓碑；以已见 revision 做 CAS）。 */
	async remove(path: string): Promise<{ revision: number }> {
		if (!this.tracked.has(path)) await this.read(path);
		const out = await this.ctx().client.remove(path, this.tracked.get(path).revision);
		this.tracked.delete(path);
		return out;
	}
}

/** 服务器 HEAD 的一致性：响应头声明的内容世代必须等于信封里的世代（W4：不允许「旧密文 + 新世代」）。 */
export async function headConsistency(vaultId: string, serverPath: string): Promise<{ live: boolean; headerGen: number; envelopeGen: number | null; consistent: boolean }> {
	const r = await fetch(`${E2E.base}/api/v1/file?path=${encodeURIComponent(serverPath)}`, { headers: { Authorization: "Bearer " + E2E.token, "X-Vault-ID": vaultId } });
	if (r.status !== 200) return { live: false, headerGen: 0, envelopeGen: null, consistent: true };
	const buf = new Uint8Array(await r.arrayBuffer());
	const magic = new TextDecoder().decode(buf.slice(0, 4));
	const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	const envelopeGen = magic === "LSE3" ? Number(dv.getBigUint64(8)) : magic === "LSE4" ? Number(dv.getBigUint64(9)) : null;
	const headerGen = Number(r.headers.get("X-Content-Generation") ?? 0);
	return { live: true, headerGen, envelopeGen, consistent: envelopeGen === null || envelopeGen === headerGen };
}

/** 服务器上的原始字节前 4 个字节（LSE3 / LSE4 / 明文）。 */
export async function rawMagic(vaultId: string, path: string): Promise<string> {
	const r = await fetch(`${E2E.base}/api/v1/file?path=${encodeURIComponent(path)}`, { headers: { Authorization: "Bearer " + E2E.token, "X-Vault-ID": vaultId } });
	return new TextDecoder().decode(new Uint8Array(await r.arrayBuffer()).slice(0, 4));
}

export async function snapshotPaths(vaultId: string): Promise<{ path: string; fileId: string; revision: number; metaEnc?: string }[]> {
	return (await api("/api/v1/snapshot", { vaultId })).body.files;
}
