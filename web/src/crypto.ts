/** 浏览器端 E2EE：与插件同一套格式（LSE1 文件 / LSS1 分享）。解密全部在本地完成。 */

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
const LSS_MAGIC = [0x4c, 0x53, 0x53, 0x31]; // "LSS1"
const IV_LEN = 12;

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
	return hasMagic(data, LSE_MAGIC);
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

/** 解密 LSE1 文件（路径绑定 AAD）；失败返回 null。 */
export async function decryptFile(vmk: CryptoKey, path: string, payload: ArrayBuffer): Promise<ArrayBuffer | null> {
	if (!isEncryptedFile(payload)) return null;
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
