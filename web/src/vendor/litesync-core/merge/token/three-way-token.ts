/**
 * token 级三方合并（v0.8.1 智能合并第三层）。
 *
 * 行级 diff3 判为冲突的区域，在 token 粒度上再试一次：
 * Local 与 Remote 的修改若在 token 级不重叠（例如一边改句中词、
 * 一边在句尾加标签），可以确定性地自动合并；仍重叠则维持冲突。
 */
import { DiffTooLargeError } from "../diff";
import { mergePieces } from "../three-way";
import { tokenize } from "./tokenize";

/** 单块冲突文本的 token 合并上限：过大区域退回人工，避免性能与误配风险。 */
const MAX_TOKEN_TEXT = 20_000;

/** token 级三方合并；clean 时返回合并文本，仍有冲突或超限返回 null。 */
export function tokenThreeWayMerge(base: string, local: string, remote: string): string | null {
	if (base.length > MAX_TOKEN_TEXT || local.length > MAX_TOKEN_TEXT || remote.length > MAX_TOKEN_TEXT) {
		return null;
	}
	try {
		const pieces = mergePieces(tokenize(base), tokenize(local), tokenize(remote));
		const out: string[] = [];
		for (const p of pieces) {
			if (p.kind === "conflict") return null;
			out.push(...p.lines);
		}
		return out.join("");
	} catch (e) {
		if (e instanceof DiffTooLargeError) return null;
		throw e;
	}
}
