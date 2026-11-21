/**
 * E2EE 密码学原语（计划书 Phase 12；v9.2 增加 LSE2 信封）。
 *
 * 全部基于 WebCrypto 的成熟 authenticated-encryption 实现，禁止自造算法：
 * - 密码 → PBKDF2-SHA256（600k 迭代）→ KEK
 * - 随机 32 字节 Vault Master Key（VMK），用 KEK 以 AES-256-GCM 包裹后存服务器
 * - 文件加密：AES-256-GCM，每次随机 12 字节 IV
 *
 * 加密文件格式：
 *   LSE1（v1，读取兼容）："LSE1"(4B) | iv(12B) | ct+tag，AAD 只绑定 path
 *   LSE2（v9.2，写入默认）："LSE2"(4B) | keyEpoch(u32 BE) | iv(12B) | ct+tag，
 *     AAD 绑定 vaultId + keyEpoch + path——恶意服务器无法用其他 vault /
 *     其他密钥世代的密文对同一路径做替换重放（同 vault 同 epoch 的
 *     历史版本重放仍需签名 manifest 才能防住，见三阶段计划）
 */

import {
	GENERATION_MAX,
	isFileId,
	isKeyEpoch,
	requireFileId,
	requireGeneration,
	requireKeyEpoch,
} from "../utils/validate";
import { frame, unframe } from "./padding";

export const KDF_ITERATIONS = 600_000;

const MAGIC = new Uint8Array([0x4c, 0x53, 0x45, 0x31]); // "LSE1"
const MAGIC2 = new Uint8Array([0x4c, 0x53, 0x45, 0x32]); // "LSE2"
const MAGIC3 = new Uint8Array([0x4c, 0x53, 0x45, 0x33]); // "LSE3"
const MAGIC4 = new Uint8Array([0x4c, 0x53, 0x45, 0x34]); // "LSE4"
const FLAGS_LEN = 1;
/** LSE4 flags 位 0：明文已填充到桶边界（§11.1）。 */
export const LSE4_FLAG_PADDED = 0x01;
const IV_LEN = 12;
const EPOCH_LEN = 4;
const GEN_LEN = 8;

/** LSE2 的 AAD 绑定材料（vaultId 来自 bootstrap，keyEpoch 来自服务器状态机）。 */
export interface FileKeyBinding {
	vaultId: string;
	keyEpoch: number;
}

/**
 * LSE3（v9.3）的 AAD 绑定材料：路径不再入 AAD——改绑稳定 fileId
 *（E2EE 下改名不再需要重新加密内容），并绑定单调递增的 contentGeneration
 *（恶意服务器无法把同一文件的旧版本密文当 HEAD 重放，客户端按已见 generation 拒绝回退）。
 */
export interface FileKeyBinding3 {
	vaultId: string;
	keyEpoch: number;
	fileId: string;
	generation: number;
}

function fileAadV3(b: FileKeyBinding3): Uint8Array {
	return new TextEncoder().encode(`litesync/v3/file:${b.vaultId}:${b.keyEpoch}:${b.fileId}:${b.generation}`);
}

/**
 * LSE4 的 AAD：在 v3 的基础上把 flags 也绑进去。
 *
 * 前缀是 v4 而不是 v3：两个版本的 AAD 空间必须不相交，
 * 否则一个 LSE3 密文可以被改头换面成 LSE4（或反之）而认证仍然通过。
 */
function fileAadV4(b: FileKeyBinding3, flags: number): Uint8Array {
	return new TextEncoder().encode(
		`litesync/v4/file:${b.vaultId}:${b.keyEpoch}:${b.fileId}:${b.generation}:${flags}`,
	);
}

/** 生成客户端侧的稳定文件身份（16B hex；新文件在加密前就需要确定 id）。 */
export function newFileId(): string {
	const raw = randomBytes(16);
	let out = "";
	for (const b of raw) out += b.toString(16).padStart(2, "0");
	return out;
}

// ---------- 元数据加密（v9.3 三期：LSM1 信封 + canonical HMAC） ----------

const META_MAGIC = new Uint8Array([0x4c, 0x53, 0x4d, 0x31]); // "LSM1"

/** 从 VMK 派生的元数据密钥对：enc 加密路径等元数据，mac 计算同名判定 HMAC。 */
export interface MetaKeys {
	enc: CryptoKey;
	mac: CryptoKey;
}

/**
 * HKDF 从 VMK 原始字节派生元数据密钥（与内容密钥域分离）。
 * 派生是确定性的：任何解锁了 VMK 的设备得到同一组 metaKeys。
 */
/**
 * 从 VMK 派生重置凭证（v0.18 / v11 设计 §3.1，与 Web 端同源参数）。
 *
 * 服务端存 SHA-256(该值)；「重置 API Token」必须提交原值——只持有 Token 的
 * 攻击者派生不出它，抢不走重置权。HKDF 单向：服务端拿到它也推不回 VMK。
 */
export async function deriveResetAuth(vmkRaw: Uint8Array): Promise<string> {
	const master = await crypto.subtle.importKey("raw", vmkRaw as BufferSource, "HKDF", false, ["deriveBits"]);
	const bits = await crypto.subtle.deriveBits(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt: new Uint8Array(32) as BufferSource,
			info: new TextEncoder().encode("litesync/v1/token-reset-auth") as BufferSource,
		},
		master,
		256,
	);
	return Array.from(new Uint8Array(bits))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

export async function deriveMetaKeys(vmkRaw: Uint8Array): Promise<MetaKeys> {
	const master = await crypto.subtle.importKey("raw", vmkRaw as BufferSource, "HKDF", false, ["deriveKey"]);
	const hkdf = (info: string, algo: AesKeyGenParams | HmacKeyGenParams, usages: KeyUsage[]) =>
		crypto.subtle.deriveKey(
			{
				name: "HKDF",
				hash: "SHA-256",
				salt: new Uint8Array(32) as BufferSource,
				info: new TextEncoder().encode(info) as BufferSource,
			},
			master,
			algo,
			false,
			usages,
		);
	const [enc, mac] = await Promise.all([
		hkdf("litesync/v5/meta-enc", { name: "AES-GCM", length: 256 }, ["encrypt", "decrypt"]),
		hkdf("litesync/v5/meta-mac", { name: "HMAC", hash: "SHA-256", length: 256 }, ["sign"]),
	]);
	return { enc, mac };
}

/** 文件元数据明文（LSM1 内容；未来可扩展更多字段）。 */
export interface FileMeta {
	path: string;
}

function metaAad(vaultId: string, keyEpoch: number, fileId: string, metaGeneration: number): Uint8Array {
	return new TextEncoder().encode(`litesync/v5/meta:${vaultId}:${keyEpoch}:${fileId}:${metaGeneration}`);
}

/** LSM1 加密：magic | keyEpoch(u32) | metaGeneration(u64) | iv | ct+tag → base64。 */
export async function encryptMeta(
	keys: MetaKeys,
	binding: { vaultId: string; keyEpoch: number; fileId: string; metaGeneration: number },
	meta: FileMeta,
): Promise<string> {
	// 集中校验（LS-121-C03）：非法 keyEpoch/fileId/metaGeneration 一旦被静默截断，
	// 写出的密文 AAD 与将来重建的 AAD 不一致 → 元数据永久不可解
	requireKeyEpoch(binding.keyEpoch, "encryptMeta");
	requireFileId(binding.fileId, "encryptMeta");
	requireGeneration(binding.metaGeneration, "encryptMeta.metaGeneration");
	const iv = randomBytes(IV_LEN);
	const plain = new TextEncoder().encode(JSON.stringify(meta));
	const ct = new Uint8Array(
		await crypto.subtle.encrypt(
			{
				name: "AES-GCM",
				iv: iv as BufferSource,
				additionalData: metaAad(binding.vaultId, binding.keyEpoch, binding.fileId, binding.metaGeneration) as BufferSource,
			},
			keys.enc,
			plain,
		),
	);
	const head = META_MAGIC.length + EPOCH_LEN + GEN_LEN;
	const out = new Uint8Array(head + IV_LEN + ct.length);
	out.set(META_MAGIC, 0);
	const view = new DataView(out.buffer);
	view.setUint32(META_MAGIC.length, binding.keyEpoch, false);
	view.setBigUint64(META_MAGIC.length + EPOCH_LEN, BigInt(binding.metaGeneration), false);
	out.set(iv, head);
	out.set(ct, head + IV_LEN);
	return b64encode(out);
}

/** LSM1 解密（AAD 由 vaultId + 信封头 + fileId 重建）；失败返回 null。 */
export async function decryptMeta(
	keys: MetaKeys,
	payloadB64: string,
	vaultId: string,
	fileId: string,
): Promise<{ meta: FileMeta; metaGeneration: number; keyEpoch: number } | null> {
	let raw: Uint8Array;
	try {
		raw = b64decode(payloadB64);
	} catch {
		return null;
	}
	const head = META_MAGIC.length + EPOCH_LEN + GEN_LEN;
	if (raw.byteLength < head + IV_LEN + 16) return null;
	for (let i = 0; i < META_MAGIC.length; i++) {
		if (raw[i] !== META_MAGIC[i]) return null;
	}
	const view = new DataView(raw.buffer, raw.byteOffset);
	const keyEpoch = view.getUint32(META_MAGIC.length, false);
	const genRaw = view.getBigUint64(META_MAGIC.length + EPOCH_LEN, false);
	// 信封头是明文字段：非法区间（keyEpoch=0 / generation 超出可精确比较范围）
	// 一律按「不可信封套」拒绝——绝不让抗回退比较建立在被截断的数值上
	if (!isKeyEpoch(keyEpoch) || genRaw > BigInt(GENERATION_MAX)) return null;
	const metaGeneration = Number(genRaw);
	if (!isFileId(fileId)) return null;
	try {
		const iv = raw.subarray(head, head + IV_LEN);
		const ct = raw.subarray(head + IV_LEN);
		const plain = await crypto.subtle.decrypt(
			{
				name: "AES-GCM",
				iv: iv as BufferSource,
				additionalData: metaAad(vaultId, keyEpoch, fileId, metaGeneration) as BufferSource,
			},
			keys.enc,
			ct as BufferSource,
		);
		const meta = JSON.parse(new TextDecoder().decode(plain)) as FileMeta;
		if (typeof meta.path !== "string" || meta.path === "") return null;
		return { meta, metaGeneration, keyEpoch };
	} catch {
		return null;
	}
}

/** canonical 同名判定 HMAC（服务器只见 HMAC，学不到路径内容）。 */
export async function canonicalPathHmac(keys: MetaKeys, path: string): Promise<string> {
	const canonical = path.normalize("NFC").toLowerCase();
	const sig = new Uint8Array(
		await crypto.subtle.sign("HMAC", keys.mac, new TextEncoder().encode(canonical)),
	);
	let out = "";
	for (const b of sig) out += b.toString(16).padStart(2, "0");
	return out;
}

/** 存服务器 / 本地缓存的 vault key 文档（不含任何明文密钥材料）。 */
export interface VaultKeyDoc {
	version: 1;
	kdf: "pbkdf2-sha256";
	iterations: number;
	salt: string; // base64
	iv: string; // base64（包裹 VMK 用的 IV）
	wrappedKey: string; // base64（AES-GCM 加密的 VMK）
	enabled: boolean;
	createdAt: number;
}

const VMK_AAD = new TextEncoder().encode("litesync/v1/vault-key");

function fileAad(path: string): Uint8Array {
	return new TextEncoder().encode(`litesync/v1/file:${path}`);
}

function fileAadV2(binding: FileKeyBinding, path: string): Uint8Array {
	return new TextEncoder().encode(`litesync/v2/file:${binding.vaultId}:${binding.keyEpoch}:${path}`);
}

export function randomBytes(n: number): Uint8Array {
	const b = new Uint8Array(n);
	crypto.getRandomValues(b);
	return b;
}

export function b64encode(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
}

export function b64decode(s: string): Uint8Array {
	const bin = atob(s);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

async function deriveKek(password: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
	const material = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(password),
		"PBKDF2",
		false,
		["deriveKey"],
	);
	return crypto.subtle.deriveKey(
		{ name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
		material,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"],
	);
}

export async function importVmk(raw: Uint8Array): Promise<CryptoKey> {
	// extractable：Trusted Device 需要在解锁状态下导出 VMK 做设备包装
	return crypto.subtle.importKey("raw", raw as BufferSource, { name: "AES-GCM" }, true, [
		"encrypt",
		"decrypt",
	]);
}

/** 导出 VMK 原始字节（仅用于 Trusted Device 包装，用完必须清零）。 */
export async function exportVmkRaw(key: CryptoKey): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

/** 首次启用：生成随机 VMK 并用密码派生的 KEK 包裹。 */
export async function createVaultKeyDoc(
	password: string,
): Promise<{ doc: VaultKeyDoc; vmk: CryptoKey }> {
	const salt = randomBytes(16);
	const iv = randomBytes(IV_LEN);
	const vmkRaw = randomBytes(32);
	const kek = await deriveKek(password, salt, KDF_ITERATIONS);
	const wrapped = new Uint8Array(
		await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv: iv as BufferSource, additionalData: VMK_AAD as BufferSource },
			kek,
			vmkRaw as BufferSource,
		),
	);
	const vmk = await importVmk(vmkRaw);
	vmkRaw.fill(0);
	return {
		doc: {
			version: 1,
			kdf: "pbkdf2-sha256",
			iterations: KDF_ITERATIONS,
			salt: b64encode(salt),
			iv: b64encode(iv),
			wrappedKey: b64encode(wrapped),
			enabled: false,
			createdAt: Date.now(),
		},
		vmk,
	};
}

/**
 * 用新密码重新包装**已有的** VMK（v0.20 / ADR-013 分支 b：忘记密码时的受控重包装）。
 *
 * 与 {@link createVaultKeyDoc} 唯一的区别是 VMK 不重新生成：盐与 IV 全新、
 * 迭代次数取当前常量、AAD 不变，其余字段（version / enabled / createdAt）沿用 base。
 * 生成新随机 VMK 覆盖旧文档会让服务器上已有的全部密文永久不可读——那正是
 * 这个函数存在要防止的事。调用方负责在上传后用新密码试解、确认得到同一把 VMK，
 * 并在用完后清零 vmkRaw。
 */
export async function wrapVmkIntoKeyDoc(
	password: string,
	vmkRaw: Uint8Array,
	base: VaultKeyDoc,
): Promise<VaultKeyDoc> {
	if (vmkRaw.length !== 32) throw new Error("VMK 必须是 32 字节");
	const salt = randomBytes(16);
	const iv = randomBytes(IV_LEN);
	const kek = await deriveKek(password, salt, KDF_ITERATIONS);
	const wrapped = new Uint8Array(
		await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv: iv as BufferSource, additionalData: VMK_AAD as BufferSource },
			kek,
			vmkRaw as BufferSource,
		),
	);
	return {
		...base,
		kdf: "pbkdf2-sha256",
		iterations: KDF_ITERATIONS,
		salt: b64encode(salt),
		iv: b64encode(iv),
		wrappedKey: b64encode(wrapped),
	};
}

/** 用密码解锁 VMK；密码错误或数据被篡改（GCM 认证失败）返回 null。 */
export async function unlockVaultKey(doc: VaultKeyDoc, password: string): Promise<CryptoKey | null> {
	try {
		const kek = await deriveKek(password, b64decode(doc.salt), doc.iterations);
		const vmkRaw = new Uint8Array(
			await crypto.subtle.decrypt(
				{
					name: "AES-GCM",
					iv: b64decode(doc.iv) as BufferSource,
					additionalData: VMK_AAD as BufferSource,
				},
				kek,
				b64decode(doc.wrappedKey) as BufferSource,
			),
		);
		const key = await importVmk(vmkRaw);
		vmkRaw.fill(0);
		return key;
	} catch {
		return null;
	}
}

// ---------- 分享加密（Phase 17：独立 Share Key，与 Vault Master Key 无关） ----------

const SHARE_MAGIC = new Uint8Array([0x4c, 0x53, 0x53, 0x31]); // "LSS1"
const SHARE_AAD = new TextEncoder().encode("litesync/v1/share");

/** 用独立 Share Key（随机 32B）加密分享内容，格式 "LSS1" | iv | ct+tag。 */
/**
 * 分享内容的命名帧（v0.13.3 / 计划书 §7.4）。
 *
 *   "LSN1" | nameLen(2, BE) | name(UTF-8) | content
 *
 * 帧在**加密之前**构造，因此显示名与内容一起受 GCM 保护：服务器既看不到
 * 真实文件名，也改不了它。以前真实路径是通过 `X-Share-Name` 明文交给服务器的
 * ——那等于把「用户分享了哪个文件」直接写进了服务端日志与数据库。
 *
 * 旧分享（没有这个帧）由 {@link unframeShareContent} 兼容处理。
 */
const SHARE_NAME_MAGIC = new Uint8Array([0x4c, 0x53, 0x4e, 0x31]); // "LSN1"

/** 把显示名与内容打成命名帧。 */
export function frameShareContent(name: string, content: ArrayBuffer): ArrayBuffer {
	const nameBytes = new TextEncoder().encode(name);
	if (nameBytes.length > 0xffff) throw new Error("分享显示名过长");
	const out = new Uint8Array(SHARE_NAME_MAGIC.length + 2 + nameBytes.length + content.byteLength);
	out.set(SHARE_NAME_MAGIC, 0);
	out[4] = (nameBytes.length >> 8) & 0xff;
	out[5] = nameBytes.length & 0xff;
	out.set(nameBytes, 6);
	out.set(new Uint8Array(content), 6 + nameBytes.length);
	return out.buffer;
}

/**
 * 拆解命名帧；不是帧则按旧格式处理（整段都是内容，没有名字）。
 * 解析失败一律退化为「无名字」，绝不因为帧头看着像就丢掉内容。
 */
export function unframeShareContent(plain: ArrayBuffer): { name: string | null; content: ArrayBuffer } {
	if (plain.byteLength < 6) return { name: null, content: plain };
	const head = new Uint8Array(plain, 0, 4);
	if (!SHARE_NAME_MAGIC.every((b, i) => head[i] === b)) return { name: null, content: plain };
	const view = new Uint8Array(plain);
	const nameLen = (view[4] << 8) | view[5];
	if (6 + nameLen > plain.byteLength) return { name: null, content: plain };
	const name = new TextDecoder().decode(plain.slice(6, 6 + nameLen));
	return { name, content: plain.slice(6 + nameLen) };
}

/**
 * 多条目分享帧（0.17.0-rc.3，验收 T2.4）：
 *
 *   "LSN2" | nameLen(2,BE) | name(UTF-8) | count(2,BE) |
 *     count × ( pathLen(2,BE) | path(UTF-8) | dataLen(4,BE) | data ) | content
 *
 * 主文档仍在帧尾（与 LSN1 同构）；内嵌图片等附件作为 (vault 相对路径, 字节)
 * 列表随行加密——查看端据此在本地渲染 `![[img]]` 与 `![](img.png)`，
 * 服务器仍然只见一个密文 blob，看不到附件的数量、名字与内容。
 * 没有附件时继续用 LSN1（旧查看端可读）。
 */
const SHARE_BUNDLE_MAGIC = new Uint8Array([0x4c, 0x53, 0x4e, 0x32]); // "LSN2"

export interface ShareAttachment {
	/** Vault 相对路径（查看端按整路径与 basename 两级解析） */
	path: string;
	data: ArrayBuffer;
}

/** 把显示名、附件与内容打成多条目帧。 */
export function frameShareBundle(name: string, content: ArrayBuffer, attachments: ShareAttachment[]): ArrayBuffer {
	if (attachments.length === 0) return frameShareContent(name, content);
	if (attachments.length > 0xffff) throw new Error("分享附件过多");
	const enc = new TextEncoder();
	const nameBytes = enc.encode(name);
	if (nameBytes.length > 0xffff) throw new Error("分享显示名过长");
	const entries = attachments.map((a) => {
		const pathBytes = enc.encode(a.path);
		if (pathBytes.length > 0xffff) throw new Error(`附件路径过长：${a.path}`);
		return { pathBytes, data: new Uint8Array(a.data) };
	});
	let size = 4 + 2 + nameBytes.length + 2 + content.byteLength;
	for (const e of entries) size += 2 + e.pathBytes.length + 4 + e.data.length;
	const out = new Uint8Array(size);
	const dv = new DataView(out.buffer);
	let off = 0;
	out.set(SHARE_BUNDLE_MAGIC, off);
	off += 4;
	dv.setUint16(off, nameBytes.length, false);
	off += 2;
	out.set(nameBytes, off);
	off += nameBytes.length;
	dv.setUint16(off, entries.length, false);
	off += 2;
	for (const e of entries) {
		dv.setUint16(off, e.pathBytes.length, false);
		off += 2;
		out.set(e.pathBytes, off);
		off += e.pathBytes.length;
		dv.setUint32(off, e.data.length, false);
		off += 4;
		out.set(e.data, off);
		off += e.data.length;
	}
	out.set(new Uint8Array(content), off);
	return out.buffer;
}

/**
 * 拆解分享帧（LSN2 / LSN1 / 裸内容三代兼容）。
 * 任何解析失败都退化为「整段是内容」，绝不因为帧头像就丢内容。
 */
export function unframeShareBundle(plain: ArrayBuffer): {
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

export async function encryptShare(keyRaw: Uint8Array, plaintext: ArrayBuffer): Promise<ArrayBuffer> {
	const key = await crypto.subtle.importKey("raw", keyRaw as BufferSource, { name: "AES-GCM" }, false, [
		"encrypt",
	]);
	const iv = randomBytes(IV_LEN);
	const ct = new Uint8Array(
		await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv: iv as BufferSource, additionalData: SHARE_AAD as BufferSource },
			key,
			plaintext,
		),
	);
	const out = new Uint8Array(SHARE_MAGIC.length + IV_LEN + ct.length);
	out.set(SHARE_MAGIC, 0);
	out.set(iv, SHARE_MAGIC.length);
	out.set(ct, SHARE_MAGIC.length + IV_LEN);
	return out.buffer;
}

/** 解密分享内容（Web 查看页同款算法，测试用）；失败返回 null。 */
export async function decryptShare(keyRaw: Uint8Array, payload: ArrayBuffer): Promise<ArrayBuffer | null> {
	const head = new Uint8Array(payload, 0, Math.min(4, payload.byteLength));
	if (payload.byteLength < 4 + IV_LEN + 16 || !SHARE_MAGIC.every((b, i) => head[i] === b)) return null;
	try {
		const key = await crypto.subtle.importKey("raw", keyRaw as BufferSource, { name: "AES-GCM" }, false, [
			"decrypt",
		]);
		const iv = new Uint8Array(payload, SHARE_MAGIC.length, IV_LEN);
		const ct = new Uint8Array(payload, SHARE_MAGIC.length + IV_LEN);
		return await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: iv as BufferSource, additionalData: SHARE_AAD as BufferSource },
			key,
			ct,
		);
	} catch {
		return null;
	}
}

/** base64url（分享链接 fragment 用）。 */
export function b64urlEncode(bytes: Uint8Array): string {
	return b64encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function hasMagic(data: ArrayBuffer, magic: Uint8Array, minTail: number): boolean {
	if (data.byteLength < magic.length + minTail) return false;
	const head = new Uint8Array(data, 0, magic.length);
	for (let i = 0; i < magic.length; i++) {
		if (head[i] !== magic[i]) return false;
	}
	return true;
}

/** 判断字节流是否为 LiteSync 加密格式（LSE1/LSE2/LSE3）。 */
export function isEncryptedPayload(data: ArrayBuffer): boolean {
	return (
		hasMagic(data, MAGIC, IV_LEN + 16) ||
		hasMagic(data, MAGIC2, EPOCH_LEN + IV_LEN + 16) ||
		hasMagic(data, MAGIC3, EPOCH_LEN + GEN_LEN + IV_LEN + 16)
	);
}

/** 是否为旧版信封（LSE1/LSE2，「升级加密信封」命令用；LSE3 为当前格式）。 */
export function isLegacyEnvelope(data: ArrayBuffer): boolean {
	return hasMagic(data, MAGIC, IV_LEN + 16) || hasMagic(data, MAGIC2, EPOCH_LEN + IV_LEN + 16);
}

/** 是否为 LSE3 信封。 */
export function isLse3Envelope(data: ArrayBuffer): boolean {
	return hasMagic(data, MAGIC3, EPOCH_LEN + GEN_LEN + IV_LEN + 16);
}

/** 读取 LSE3 信封头（明文字段；真实性由解密时的 AAD 校验保证）。 */
export function parseLse3Header(data: ArrayBuffer): { keyEpoch: number; generation: number } | null {
	if (!isLse3Envelope(data)) return null;
	const view = new DataView(data);
	const keyEpoch = view.getUint32(MAGIC3.length, false);
	const genRaw = view.getBigUint64(MAGIC3.length + EPOCH_LEN, false);
	// 非法区间的信封头视为无效信封（LS-121-C03）：抗回退比较不接受被截断的值
	if (!isKeyEpoch(keyEpoch) || genRaw > BigInt(GENERATION_MAX)) return null;
	return { keyEpoch, generation: Number(genRaw) };
}

/** LSE3 加密：magic | keyEpoch(u32) | generation(u64) | iv | ct+tag。 */
export async function encryptFileV3(
	vmk: CryptoKey,
	binding: FileKeyBinding3,
	plaintext: ArrayBuffer,
): Promise<ArrayBuffer> {
	// 集中校验（LS-121-C03）：AAD 输入被截断 = 密文永久不可解 / 抗回退失效
	requireKeyEpoch(binding.keyEpoch, "encryptFileV3");
	requireFileId(binding.fileId, "encryptFileV3");
	requireGeneration(binding.generation, "encryptFileV3.generation");
	const iv = randomBytes(IV_LEN);
	const ct = new Uint8Array(
		await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv: iv as BufferSource, additionalData: fileAadV3(binding) as BufferSource },
			vmk,
			plaintext,
		),
	);
	const head = MAGIC3.length + EPOCH_LEN + GEN_LEN;
	const out = new Uint8Array(head + IV_LEN + ct.length);
	out.set(MAGIC3, 0);
	const view = new DataView(out.buffer);
	view.setUint32(MAGIC3.length, binding.keyEpoch, false);
	view.setBigUint64(MAGIC3.length + EPOCH_LEN, BigInt(binding.generation), false);
	out.set(iv, head);
	out.set(ct, head + IV_LEN);
	return out.buffer;
}

/**
 * LSE3 解密。AAD 由 vaultId + 信封头 keyEpoch/generation + 服务器提供的 fileId
 * 重建——fileId 造假会直接导致 GCM 认证失败，无需额外信任服务器。
 * expectedKeyEpoch > 0 时校验信封世代一致（拒绝跨密钥世代重放）。
 * 成功返回 { plain, generation }（generation 已经过 AAD 认证，调用方据此做回退检查）。
 */
export async function decryptFileV3(
	vmk: CryptoKey,
	payload: ArrayBuffer,
	vaultId: string,
	fileId: string,
	expectedKeyEpoch: number,
): Promise<{ plain: ArrayBuffer; generation: number } | null> {
	const header = parseLse3Header(payload);
	if (header === null || !vaultId || !isFileId(fileId)) return null;
	if (expectedKeyEpoch > 0 && header.keyEpoch !== expectedKeyEpoch) return null;
	try {
		const head = MAGIC3.length + EPOCH_LEN + GEN_LEN;
		const iv = new Uint8Array(payload, head, IV_LEN);
		const ct = new Uint8Array(payload, head + IV_LEN);
		const plain = await crypto.subtle.decrypt(
			{
				name: "AES-GCM",
				iv: iv as BufferSource,
				additionalData: fileAadV3({
					vaultId,
					keyEpoch: header.keyEpoch,
					fileId,
					generation: header.generation,
				}) as BufferSource,
			},
			vmk,
			ct,
		);
		return { plain, generation: header.generation };
	} catch {
		return null;
	}
}

/**
 * 加密文件内容（每次随机 IV）。
 * 提供 binding 时输出 LSE2（AAD 绑定 vaultId+keyEpoch+path）；
 * 不提供时输出兼容的 LSE1（仅路径绑定；用于 binding 尚不可知的过渡场景）。
 */
export async function encryptFile(
	vmk: CryptoKey,
	path: string,
	plaintext: ArrayBuffer,
	binding?: FileKeyBinding,
): Promise<ArrayBuffer> {
	const iv = randomBytes(IV_LEN);
	if (!binding) {
		const ct = new Uint8Array(
			await crypto.subtle.encrypt(
				{ name: "AES-GCM", iv: iv as BufferSource, additionalData: fileAad(path) as BufferSource },
				vmk,
				plaintext,
			),
		);
		const out = new Uint8Array(MAGIC.length + IV_LEN + ct.length);
		out.set(MAGIC, 0);
		out.set(iv, MAGIC.length);
		out.set(ct, MAGIC.length + IV_LEN);
		return out.buffer;
	}
	const ct = new Uint8Array(
		await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv: iv as BufferSource, additionalData: fileAadV2(binding, path) as BufferSource },
			vmk,
			plaintext,
		),
	);
	const out = new Uint8Array(MAGIC2.length + EPOCH_LEN + IV_LEN + ct.length);
	out.set(MAGIC2, 0);
	new DataView(out.buffer).setUint32(MAGIC2.length, requireKeyEpoch(binding.keyEpoch, "encryptFile/LSE2"), false);
	out.set(iv, MAGIC2.length + EPOCH_LEN);
	out.set(ct, MAGIC2.length + EPOCH_LEN + IV_LEN);
	return out.buffer;
}

/**
 * 解密文件内容；密钥不符 / 数据被篡改 / AAD 不匹配返回 null。
 * LSE2 要求 binding（vaultId 必需；binding.keyEpoch > 0 时还校验信封内的
 * epoch 与之一致，拒绝其他密钥世代的密文重放）。
 */
export async function decryptFile(
	vmk: CryptoKey,
	path: string,
	payload: ArrayBuffer,
	binding?: FileKeyBinding,
): Promise<ArrayBuffer | null> {
	if (hasMagic(payload, MAGIC2, EPOCH_LEN + IV_LEN + 16)) {
		if (!binding?.vaultId) return null; // 无法建立 AAD → 拒绝
		const envelopeEpoch = new DataView(payload).getUint32(MAGIC2.length, false);
		if (!isKeyEpoch(envelopeEpoch)) return null; // 非法信封头（LS-121-C03）
		if (binding.keyEpoch > 0 && envelopeEpoch !== binding.keyEpoch) return null;
		try {
			const iv = new Uint8Array(payload, MAGIC2.length + EPOCH_LEN, IV_LEN);
			const ct = new Uint8Array(payload, MAGIC2.length + EPOCH_LEN + IV_LEN);
			return await crypto.subtle.decrypt(
				{
					name: "AES-GCM",
					iv: iv as BufferSource,
					additionalData: fileAadV2({ vaultId: binding.vaultId, keyEpoch: envelopeEpoch }, path) as BufferSource,
				},
				vmk,
				ct,
			);
		} catch {
			return null;
		}
	}
	if (!hasMagic(payload, MAGIC, IV_LEN + 16)) return null;
	try {
		const iv = new Uint8Array(payload, MAGIC.length, IV_LEN);
		const ct = new Uint8Array(payload, MAGIC.length + IV_LEN);
		return await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: iv as BufferSource, additionalData: fileAad(path) as BufferSource },
			vmk,
			ct,
		);
	} catch {
		return null;
	}
}

/**
 * LSE4（v0.17 / 计划书 §11.1）：`magic | flags(u8) | keyEpoch(u32) | generation(u64) | iv | ct+tag`。
 *
 * 与 LSE3 的唯一区别是多一个 flags 字节，且**明文内部**是一个定长帧
 *（真实长度 + 内容 + 填充）。填充放在密文里面，服务器因此只看得到桶大小。
 *
 * # 为什么要新开一个信封版本
 *
 * 更省事的做法是继续用 LSE3，只在明文前面塞一个长度前缀。但那样解密时
 * 无法区分「这是填充帧」和「这个文件恰好以那几个字节开头」——
 * 一个二进制附件迟早会撞上，然后被当成帧读，静默损坏用户数据。
 *
 * 版本号 4 大于现有的仓库下限 3，因此**不需要迁移**：存量 LSE3 继续可读，
 * 新内容按用户设置决定用哪个。
 */
export async function encryptFileV4(
	vmk: CryptoKey,
	binding: FileKeyBinding3,
	plaintext: ArrayBuffer,
	padded: boolean,
): Promise<ArrayBuffer> {
	requireKeyEpoch(binding.keyEpoch, "encryptFileV4");
	requireFileId(binding.fileId, "encryptFileV4");
	requireGeneration(binding.generation, "encryptFileV4.generation");
	const flags = padded ? LSE4_FLAG_PADDED : 0;
	const framed = frame(plaintext, padded);
	const iv = randomBytes(IV_LEN);
	const ct = new Uint8Array(
		await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv: iv as BufferSource, additionalData: fileAadV4(binding, flags) as BufferSource },
			vmk,
			framed,
		),
	);
	const head = MAGIC4.length + FLAGS_LEN + EPOCH_LEN + GEN_LEN;
	const out = new Uint8Array(head + IV_LEN + ct.length);
	out.set(MAGIC4, 0);
	out[MAGIC4.length] = flags;
	const view = new DataView(out.buffer);
	view.setUint32(MAGIC4.length + FLAGS_LEN, binding.keyEpoch, false);
	view.setBigUint64(MAGIC4.length + FLAGS_LEN + EPOCH_LEN, BigInt(binding.generation), false);
	out.set(iv, head);
	out.set(ct, head + IV_LEN);
	return out.buffer;
}

/** 是否为 LSE4 信封。 */
export function isLse4Envelope(data: ArrayBuffer): boolean {
	return hasMagic(data, MAGIC4, FLAGS_LEN + EPOCH_LEN + GEN_LEN + IV_LEN + 16);
}

/** 读取 LSE4 信封头（明文字段；真实性由解密时的 AAD 校验保证）。 */
export function parseLse4Header(
	data: ArrayBuffer,
): { flags: number; keyEpoch: number; generation: number } | null {
	if (!isLse4Envelope(data)) return null;
	const view = new DataView(data);
	const flags = view.getUint8(MAGIC4.length);
	const keyEpoch = view.getUint32(MAGIC4.length + FLAGS_LEN, false);
	const genRaw = view.getBigUint64(MAGIC4.length + FLAGS_LEN + EPOCH_LEN, false);
	if (!isKeyEpoch(keyEpoch) || genRaw > BigInt(GENERATION_MAX)) return null;
	return { flags, keyEpoch, generation: Number(genRaw) };
}

/**
 * LSE4 解密。flags 参与 AAD，因此「把 padded 位抹掉」会导致认证失败——
 * 服务器改不了这一位来诱使客户端把填充当内容。
 */
export async function decryptFileV4(
	vmk: CryptoKey,
	payload: ArrayBuffer,
	vaultId: string,
	fileId: string,
	expectedKeyEpoch: number,
): Promise<{ plain: ArrayBuffer; generation: number } | null> {
	const header = parseLse4Header(payload);
	if (header === null || !vaultId || !isFileId(fileId)) return null;
	if (expectedKeyEpoch > 0 && header.keyEpoch !== expectedKeyEpoch) return null;
	try {
		const head = MAGIC4.length + FLAGS_LEN + EPOCH_LEN + GEN_LEN;
		const iv = new Uint8Array(payload, head, IV_LEN);
		const ct = new Uint8Array(payload, head + IV_LEN);
		const framed = await crypto.subtle.decrypt(
			{
				name: "AES-GCM",
				iv: iv as BufferSource,
				additionalData: fileAadV4(
					{ vaultId, keyEpoch: header.keyEpoch, fileId, generation: header.generation },
					header.flags,
				) as BufferSource,
			},
			vmk,
			ct,
		);
		const plain = unframe(framed);
		if (plain === null) return null;
		return { plain, generation: header.generation };
	} catch {
		return null;
	}
}
