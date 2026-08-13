/** 浏览器端 E2EE：与插件同一套格式（LSE1/LSE2 文件 / LSS1 分享）。解密全部在本地完成。 */

export interface VaultKeyDoc {
	version: number;
	kdf: string;
	iterations: number;
	salt: string;
	iv: string;
	wrappedKey: string;
	enabled: boolean;
}

const LSE_MAGIC = [0x4c, 0x53, 0x45, 0x31]; // "LSE1"
const LSE2_MAGIC = [0x4c, 0x53, 0x45, 0x32]; // "LSE2"（v9.2：AAD 绑定 vaultId+keyEpoch+path）
const LSE3_MAGIC = [0x4c, 0x53, 0x45, 0x33]; // "LSE3"（v9.3：AAD 绑定 vaultId+keyEpoch+fileId+generation）
const LSE4_MAGIC = [0x4c, 0x53, 0x45, 0x34]; // "LSE4"（v0.17 §11.1：LSE3 + flags 字节 + 明文定长帧）
const LSS_MAGIC = [0x4c, 0x53, 0x53, 0x31]; // "LSS1"
const IV_LEN = 12;
const EPOCH_LEN = 4;
const GEN_LEN = 8;
/** LSE4：flags 字节长度与明文帧头（真实长度 u64 BE）长度。 */
const FLAGS_LEN = 1;
const FRAME_HEADER_LEN = 8;
/** 与插件 padding.ts 的 MAX_PADDED_LENGTH 一致（1TiB）。 */
const MAX_PADDED_LENGTH = 2 ** 40;

/** LSE2 的 AAD 绑定材料（来自 /api/v1/info）。 */
export interface FileKeyBinding {
	vaultId: string;
	keyEpoch: number;
}

const VMK_AAD = new TextEncoder().encode("litesync/v1/vault-key");
const SHARE_AAD = new TextEncoder().encode("litesync/v1/share");

export function b64decode(s: string): Uint8Array {
	const bin = atob(s);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

export function b64encode(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
}

export function b64urlDecode(s: string): Uint8Array {
	return b64decode(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
}

export function subtleAvailable(): boolean {
	return typeof crypto !== "undefined" && !!crypto.subtle;
}

function hasMagic(data: ArrayBuffer, magic: number[]): boolean {
	if (data.byteLength < magic.length + IV_LEN + 16) return false;
	const head = new Uint8Array(data, 0, magic.length);
	return magic.every((b, i) => head[i] === b);
}

export function isEncryptedFile(data: ArrayBuffer): boolean {
	return (
		hasMagic(data, LSE_MAGIC) ||
		hasMagic(data, LSE2_MAGIC) ||
		hasMagic(data, LSE3_MAGIC) ||
		hasMagic(data, LSE4_MAGIC)
	);
}

export function isEncryptedShare(data: ArrayBuffer): boolean {
	return hasMagic(data, LSS_MAGIC);
}

export async function unlockVaultKey(doc: VaultKeyDoc, password: string): Promise<Uint8Array | null> {
	try {
		const material = await crypto.subtle.importKey(
			"raw",
			new TextEncoder().encode(password),
			"PBKDF2",
			false,
			["deriveKey"],
		);
		const kek = await crypto.subtle.deriveKey(
			{ name: "PBKDF2", hash: "SHA-256", salt: b64decode(doc.salt) as BufferSource, iterations: doc.iterations },
			material,
			{ name: "AES-GCM", length: 256 },
			false,
			["decrypt"],
		);
		const raw = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: b64decode(doc.iv) as BufferSource, additionalData: VMK_AAD as BufferSource },
			kek,
			b64decode(doc.wrappedKey) as BufferSource,
		);
		return new Uint8Array(raw);
	} catch {
		return null;
	}
}

export async function importVmk(raw: Uint8Array): Promise<CryptoKey> {
	return crypto.subtle.importKey("raw", raw as BufferSource, { name: "AES-GCM" }, false, ["decrypt"]);
}

/** LSE3/LSE4 信封头里的世代信息（解密前即可读；GCM 会在解密时认证它们）。 */
export function lse3Header(payload: ArrayBuffer): { keyEpoch: number; generation: number } | null {
	if (hasMagic(payload, LSE3_MAGIC)) {
		const view = new DataView(payload);
		return {
			keyEpoch: view.getUint32(4, false),
			generation: Number(view.getBigUint64(4 + EPOCH_LEN, false)),
		};
	}
	if (hasMagic(payload, LSE4_MAGIC)) {
		const view = new DataView(payload);
		return {
			keyEpoch: view.getUint32(4 + FLAGS_LEN, false),
			generation: Number(view.getBigUint64(4 + FLAGS_LEN + EPOCH_LEN, false)),
		};
	}
	return null;
}

/**
 * LSE4 的明文定长帧：`trueLength(u64 BE) | content | 零填充`（§11.1）。
 * 帧头经 GCM 认证，长度对不上只可能是数据损坏 → null 走「读不出来」分支。
 */
function unframePadded(framed: ArrayBuffer): ArrayBuffer | null {
	if (framed.byteLength < FRAME_HEADER_LEN) return null;
	const len = new DataView(framed).getBigUint64(0, false);
	if (len > BigInt(MAX_PADDED_LENGTH)) return null;
	const n = Number(len);
	if (FRAME_HEADER_LEN + n > framed.byteLength) return null;
	return framed.slice(FRAME_HEADER_LEN, FRAME_HEADER_LEN + n);
}

/**
 * 解密 LSE1/LSE2/LSE3/LSE4 文件；失败返回 null。
 * LSE2 需要 binding（vaultId 来自 /info）；LSE3/LSE4 还需要 fileId（snapshot 提供）。
 */
export async function decryptFile(
	vmk: CryptoKey,
	path: string,
	payload: ArrayBuffer,
	binding?: FileKeyBinding,
	fileId?: string,
): Promise<ArrayBuffer | null> {
	if (hasMagic(payload, LSE4_MAGIC)) {
		// LSE4（v0.17 §11.1）：magic | flags(u8) | keyEpoch(u32) | generation(u64) | iv | ct。
		// flags 参与 AAD（抹掉 padded 位会认证失败）；明文是定长帧，解密后去填充
		if (!binding?.vaultId || !fileId) return null;
		try {
			const view = new DataView(payload);
			const flags = view.getUint8(4);
			const envelopeEpoch = view.getUint32(4 + FLAGS_LEN, false);
			const generation = view.getBigUint64(4 + FLAGS_LEN + EPOCH_LEN, false);
			const head = 4 + FLAGS_LEN + EPOCH_LEN + GEN_LEN;
			const iv = new Uint8Array(payload, head, IV_LEN);
			const ct = new Uint8Array(payload, head + IV_LEN);
			const aad = new TextEncoder().encode(
				`litesync/v4/file:${binding.vaultId}:${envelopeEpoch}:${fileId}:${generation}:${flags}`,
			);
			const framed = await crypto.subtle.decrypt(
				{ name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource },
				vmk,
				ct,
			);
			return unframePadded(framed);
		} catch {
			return null;
		}
	}
	if (hasMagic(payload, LSE3_MAGIC)) {
		if (!binding?.vaultId || !fileId) return null;
		try {
			const view = new DataView(payload);
			const envelopeEpoch = view.getUint32(4, false);
			const generation = view.getBigUint64(4 + EPOCH_LEN, false);
			const head = 4 + EPOCH_LEN + GEN_LEN;
			const iv = new Uint8Array(payload, head, IV_LEN);
			const ct = new Uint8Array(payload, head + IV_LEN);
			const aad = new TextEncoder().encode(
				`litesync/v3/file:${binding.vaultId}:${envelopeEpoch}:${fileId}:${generation}`,
			);
			return await crypto.subtle.decrypt(
				{ name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource },
				vmk,
				ct,
			);
		} catch {
			return null;
		}
	}
	if (hasMagic(payload, LSE2_MAGIC)) {
		if (!binding?.vaultId) return null;
		try {
			const envelopeEpoch = new DataView(payload).getUint32(4, false);
			const iv = new Uint8Array(payload, 4 + EPOCH_LEN, IV_LEN);
			const ct = new Uint8Array(payload, 4 + EPOCH_LEN + IV_LEN);
			const aad = new TextEncoder().encode(`litesync/v2/file:${binding.vaultId}:${envelopeEpoch}:${path}`);
			return await crypto.subtle.decrypt(
				{ name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource },
				vmk,
				ct,
			);
		} catch {
			return null;
		}
	}
	if (!hasMagic(payload, LSE_MAGIC)) return null;
	try {
		const iv = new Uint8Array(payload, 4, IV_LEN);
		const ct = new Uint8Array(payload, 4 + IV_LEN);
		const aad = new TextEncoder().encode(`litesync/v1/file:${path}`);
		return await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource },
			vmk,
			ct,
		);
	} catch {
		return null;
	}
}

// ---------- 元数据加密（v9.3 三期：LSM1） ----------

const LSM_MAGIC = [0x4c, 0x53, 0x4d, 0x31]; // "LSM1"

export interface MetaKeys {
	enc: CryptoKey;
}

/** HKDF 从 VMK 原始字节派生元数据解密密钥（与插件同源参数）。 */
export async function deriveMetaKeys(vmkRaw: Uint8Array): Promise<MetaKeys> {
	const master = await crypto.subtle.importKey("raw", vmkRaw as BufferSource, "HKDF", false, ["deriveKey"]);
	const enc = await crypto.subtle.deriveKey(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt: new Uint8Array(32) as BufferSource,
			info: new TextEncoder().encode("litesync/v5/meta-enc") as BufferSource,
		},
		master,
		{ name: "AES-GCM", length: 256 },
		false,
		["decrypt"],
	);
	return { enc };
}

/** LSM1 解密：返回 { path, metaGeneration }；失败返回 null。 */
export async function decryptMeta(
	keys: MetaKeys,
	payloadB64: string,
	vaultId: string,
	fileId: string,
): Promise<{ path: string; metaGeneration: number } | null> {
	let raw: Uint8Array;
	try {
		raw = b64decode(payloadB64);
	} catch {
		return null;
	}
	const head = 4 + EPOCH_LEN + GEN_LEN;
	if (raw.byteLength < head + IV_LEN + 16 || !LSM_MAGIC.every((b, i) => raw[i] === b)) return null;
	const view = new DataView(raw.buffer, raw.byteOffset);
	const keyEpoch = view.getUint32(4, false);
	const metaGeneration = Number(view.getBigUint64(4 + EPOCH_LEN, false));
	try {
		const iv = raw.subarray(head, head + IV_LEN);
		const ct = raw.subarray(head + IV_LEN);
		const aad = new TextEncoder().encode(`litesync/v5/meta:${vaultId}:${keyEpoch}:${fileId}:${metaGeneration}`);
		const plain = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource },
			keys.enc,
			ct as BufferSource,
		);
		const meta = JSON.parse(new TextDecoder().decode(plain)) as { path?: string };
		if (typeof meta.path !== "string" || meta.path === "") return null;
		return { path: meta.path, metaGeneration };
	} catch {
		return null;
	}
}

/**
 * 分享内容的命名帧（v0.13.3 / 计划书 §7.4）：
 *
 *   "LSN1" | nameLen(2, BE) | name(UTF-8) | content
 *
 * 显示名在**加密之前**就打进了帧里，因此服务器既看不到也改不了它。
 * 没有这个帧的是 v0.13.2 及更早创建的旧分享——那时真实路径是通过
 * `X-Share-Name` 明文交给服务器的，这里按「无名字」处理即可。
 */
const SHARE_NAME_MAGIC = [0x4c, 0x53, 0x4e, 0x31];

export function unframeShareContent(plain: ArrayBuffer): { name: string | null; content: ArrayBuffer } {
	if (plain.byteLength < 6) return { name: null, content: plain };
	const view = new Uint8Array(plain);
	if (!SHARE_NAME_MAGIC.every((b, i) => view[i] === b)) return { name: null, content: plain };
	const nameLen = (view[4] << 8) | view[5];
	if (6 + nameLen > plain.byteLength) return { name: null, content: plain };
	const name = new TextDecoder().decode(plain.slice(6, 6 + nameLen));
	return { name, content: plain.slice(6 + nameLen) };
}

/**
 * 多条目分享帧（0.17.0-rc.3，验收 T2.4）：
 *
 *   "LSN2" | nameLen(2,BE) | name | count(2,BE) |
 *     count × ( pathLen(2,BE) | path | dataLen(4,BE) | data ) | content
 *
 * 主文档仍在帧尾（与 LSN1 同构）；内嵌图片作为 (vault 相对路径, 字节) 列表
 * 随行加密。与插件 src/crypto/crypto.ts 的 frameShareBundle 字节级对应。
 */
const SHARE_BUNDLE_MAGIC = [0x4c, 0x53, 0x4e, 0x32];

export interface ShareAttachment {
	path: string;
	data: ArrayBuffer;
}

/** 拆解分享帧（LSN2 / LSN1 / 裸内容三代兼容）；解析失败退化为「整段是内容」。 */
export function unbundleShare(plain: ArrayBuffer): {
	name: string | null;
	content: ArrayBuffer;
	attachments: ShareAttachment[];
} {
	const view = new Uint8Array(plain);
	if (plain.byteLength < 8 || !SHARE_BUNDLE_MAGIC.every((b, i) => view[i] === b)) {
		const framed = unframeShareContent(plain);
		return { name: framed.name, content: framed.content, attachments: [] };
	}
	try {
		const dv = new DataView(plain);
		const dec = new TextDecoder();
		let off = 4;
		const nameLen = dv.getUint16(off, false);
		off += 2;
		if (off + nameLen > plain.byteLength) throw new Error("truncated");
		const name = dec.decode(plain.slice(off, off + nameLen));
		off += nameLen;
		const count = dv.getUint16(off, false);
		off += 2;
		const attachments: ShareAttachment[] = [];
		for (let i = 0; i < count; i++) {
			const pathLen = dv.getUint16(off, false);
			off += 2;
			if (off + pathLen > plain.byteLength) throw new Error("truncated");
			const path = dec.decode(plain.slice(off, off + pathLen));
			off += pathLen;
			const dataLen = dv.getUint32(off, false);
			off += 4;
			if (off + dataLen > plain.byteLength) throw new Error("truncated");
			attachments.push({ path, data: plain.slice(off, off + dataLen) });
			off += dataLen;
		}
		return { name, content: plain.slice(off), attachments };
	} catch {
		return { name: null, content: plain, attachments: [] };
	}
}

/** 解密 LSS1 分享（独立 Share Key）；失败返回 null。 */
export async function decryptShare(keyRaw: Uint8Array, payload: ArrayBuffer): Promise<ArrayBuffer | null> {
	if (!isEncryptedShare(payload)) return null;
	try {
		const key = await crypto.subtle.importKey("raw", keyRaw as BufferSource, { name: "AES-GCM" }, false, [
			"decrypt",
		]);
		const iv = new Uint8Array(payload, 4, IV_LEN);
		const ct = new Uint8Array(payload, 4 + IV_LEN);
		return await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: iv as BufferSource, additionalData: SHARE_AAD as BufferSource },
			key,
			ct,
		);
	} catch {
		return null;
	}
}
