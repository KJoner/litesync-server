/**
 * 协议值集中校验（v0.12.1 / LS-121-C03）。
 *
 * 红线：keyEpoch、fileId、generation 是加密信封 AAD 与抗回退判断的输入。
 * 任何来源（服务器响应、Header、本地状态文件、迁移流程）的非法值都必须
 * **立即失败**，绝不允许用 `>>> 0`、`Number(x) || 0`、`parseInt` 之类的
 * 方式静默截断——被截断的 keyEpoch 会让密文用错误的 AAD 加密并永久不可读，
 * 被截断的 generation 会让抗回退检查失效。
 *
 * 本模块是唯一的校验实现，业务代码禁止各自再写一份格式判断。
 */

/** 协议字段非法：调用方必须让当前操作硬失败（不得吞掉继续同步）。 */
export class ProtocolValueError extends Error {
	constructor(
		public field: string,
		public got: unknown,
		public where: string,
	) {
		super(
			`协议字段非法：${field}=${describe(got)}${where ? `（${where}）` : ""}——` +
				`已停止本次操作，绝不使用被截断或伪造的值`,
		);
		this.name = "ProtocolValueError";
	}
}

function describe(v: unknown): string {
	if (typeof v === "string") return v.length > 48 ? `"${v.slice(0, 48)}…"` : `"${v}"`;
	if (typeof v === "number" || typeof v === "boolean" || typeof v === "bigint") return String(v);
	if (v === undefined) return "undefined";
	if (v === null) return "null";
	return `<${typeof v}>`; // 对象/函数只报类型，避免把内容（可能含路径）写进错误信息
}

/** fileId / 伪名：小写 32 位十六进制（16 字节随机身份）。 */
const FILE_ID_RE = /^[0-9a-f]{32}$/;
/** canonical path HMAC：小写 64 位十六进制（SHA-256）。 */
const CANONICAL_HASH_RE = /^[0-9a-f]{64}$/;

/** keyEpoch 合法区间 [1, 2^32)：信封头是 u32 BE，0 表示「未知」不可用于加密。 */
export const KEY_EPOCH_MIN = 1;
export const KEY_EPOCH_MAX_EXCLUSIVE = 0x1_0000_0000;

/**
 * generation 上界：信封头是 u64，但 JS number 只能精确表示到 2^53-1。
 * 超出即无法可靠比较大小 → 抗回退检查会失效，必须拒绝。
 */
export const GENERATION_MAX = Number.MAX_SAFE_INTEGER;

export function isFileId(v: unknown): v is string {
	return typeof v === "string" && FILE_ID_RE.test(v);
}

export function isCanonicalHash(v: unknown): v is string {
	return typeof v === "string" && CANONICAL_HASH_RE.test(v);
}

export function isKeyEpoch(v: unknown): v is number {
	return typeof v === "number" && Number.isInteger(v) && v >= KEY_EPOCH_MIN && v < KEY_EPOCH_MAX_EXCLUSIVE;
}

export function isGeneration(v: unknown): v is number {
	return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= GENERATION_MAX;
}

export function requireFileId(v: unknown, where: string): string {
	if (!isFileId(v)) throw new ProtocolValueError("fileId", v, where);
	return v;
}

export function requireCanonicalHash(v: unknown, where: string): string {
	if (!isCanonicalHash(v)) throw new ProtocolValueError("canonicalHash", v, where);
	return v;
}

export function requireKeyEpoch(v: unknown, where: string): number {
	if (!isKeyEpoch(v)) throw new ProtocolValueError("keyEpoch", v, where);
	return v;
}

export function requireGeneration(v: unknown, where: string): number {
	if (!isGeneration(v)) throw new ProtocolValueError("generation", v, where);
	return v;
}

/** 可选字段：缺失（undefined/空串）放行；出现即必须合法。 */
export function optionalFileId(v: unknown, where: string): string | undefined {
	if (v === undefined || v === null || v === "") return undefined;
	return requireFileId(v, where);
}

/** 可选 generation：缺失放行；出现即必须合法（0 是合法值，不能当缺失处理）。 */
export function optionalGeneration(v: unknown, where: string): number | undefined {
	if (v === undefined || v === null) return undefined;
	return requireGeneration(v, where);
}
