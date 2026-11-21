/**
 * 三方合并（diff3）：以 Base 为公共祖先，合并 Local 与 Remote 的行级修改。
 *
 * 规则：
 * - 只有一侧修改的区域 → 采用该侧；
 * - 两侧修改相同 → 采用其一；
 * - 两侧修改不同且区域重叠（含同一位置的插入）→ 结构化冲突对象；
 * - 绝不输出 <<<<<<< conflict marker 到用户文件。
 */
import { DiffHunk, diffHunks, splitLines } from "./diff";
import { MergeConflict, MergeInput, MergeResult, MergeSegment } from "./model";

interface SideHunk extends DiffHunk {
	side: "local" | "remote";
}

/** 内部分段：以行数组表示，避免空串与空行的歧义（token 级合并复用同一结构）。 */
export type Piece =
	| { kind: "lines"; lines: string[] }
	| {
			kind: "conflict";
			baseStart: number;
			baseEnd: number;
			baseLines: string[];
			localLines: string[];
			remoteLines: string[];
	  };

export function threeWayMerge(input: MergeInput): MergeResult {
	const base = splitLines(input.base);
	const local = splitLines(input.local);
	const remote = splitLines(input.remote);
	return piecesToResult(mergePieces(base, local, remote));
}

/**
 * 三方序列合并核心：对任意字符串序列（行或 token）做 diff3 分段。
 * smartThreeWayMerge 的 section 级与 token 级合并都复用这里。
 */
export function mergePieces(base: string[], local: string[], remote: string[]): Piece[] {
	const hunks: SideHunk[] = [
		...diffHunks(base, local).map((h) => ({ ...h, side: "local" as const })),
		...diffHunks(base, remote).map((h) => ({ ...h, side: "remote" as const })),
	].sort((a, b) => a.aStart - b.aStart || a.aEnd - b.aEnd);

	const pieces: Piece[] = [];
	let cursor = 0;

	let i = 0;
	while (i < hunks.length) {
		// 组建一个重叠区域（region）：真正重叠的修改，或同一位置的插入
		let regionStart = hunks[i].aStart;
		let regionEnd = hunks[i].aEnd;
		const group: SideHunk[] = [hunks[i]];
		let j = i + 1;
		while (j < hunks.length) {
			const h = hunks[j];
			const strictOverlap = h.aStart < regionEnd;
			// 插入点落在区域边界，或区域本身是插入点且下一个 hunk 从同一位置开始
			const boundaryInsert = h.aStart === regionEnd && (h.aStart === h.aEnd || regionStart === regionEnd);
			if (strictOverlap || boundaryInsert) {
				group.push(h);
				regionEnd = Math.max(regionEnd, h.aEnd);
				j++;
			} else {
				break;
			}
		}
		i = j;

		// 区域前的稳定文本
		if (cursor < regionStart) {
			pieces.push({ kind: "lines", lines: base.slice(cursor, regionStart) });
		}

		const localHunks = group.filter((h) => h.side === "local");
		const remoteHunks = group.filter((h) => h.side === "remote");
		const localLines = applySide(base, regionStart, regionEnd, localHunks, local);
		const remoteLines = applySide(base, regionStart, regionEnd, remoteHunks, remote);

		if (localHunks.length === 0) {
			pieces.push({ kind: "lines", lines: remoteLines });
		} else if (remoteHunks.length === 0) {
			pieces.push({ kind: "lines", lines: localLines });
		} else if (sameLines(localLines, remoteLines)) {
			// 两侧做了相同修改
			pieces.push({ kind: "lines", lines: localLines });
		} else {
			pieces.push({
				kind: "conflict",
				baseStart: regionStart,
				baseEnd: regionEnd,
				baseLines: base.slice(regionStart, regionEnd),
				localLines,
				remoteLines,
			});
		}
		cursor = regionEnd;
	}
	if (cursor < base.length) {
		pieces.push({ kind: "lines", lines: base.slice(cursor) });
	}
	return pieces;
}

/** 把内部分段转成公开的 MergeResult 结构（行域）。 */
export function piecesToResult(pieces: Piece[]): MergeResult {
	const segments: MergeSegment[] = [];
	const conflicts: MergeConflict[] = [];
	const mergedLines: string[] = [];
	let seq = 0;
	for (const p of pieces) {
		if (p.kind === "lines") {
			if (p.lines.length > 0) {
				segments.push({ type: "text", text: p.lines.join("\n") });
				mergedLines.push(...p.lines);
			}
		} else {
			const conflict: MergeConflict = {
				id: `c${++seq}`,
				baseStart: p.baseStart,
				baseEnd: p.baseEnd,
				baseText: p.baseLines.join("\n"),
				localText: p.localLines.join("\n"),
				remoteText: p.remoteLines.join("\n"),
			};
			conflicts.push(conflict);
			segments.push({ type: "conflict", conflict });
			// 预览文本对冲突段取 local（绝不自动写入 Vault）
			mergedLines.push(...p.localLines);
		}
	}

	return {
		clean: conflicts.length === 0,
		mergedText: mergedLines.join("\n"),
		conflicts,
		segments,
	};
}

/**
 * 由“选择每个冲突段用哪几行”重建最终文本。
 * choices[conflict.id] 为该冲突段最终采用的文本（可能是 local/remote/both/用户编辑）。
 */
export function assembleResolution(segments: MergeSegment[], choices: Record<string, string>): string {
	const out: string[] = [];
	for (const s of segments) {
		if (s.type === "text") {
			out.push(...s.text.split("\n"));
		} else {
			const chosen = choices[s.conflict.id];
			if (chosen === undefined) throw new Error(`conflict ${s.conflict.id} unresolved`);
			if (chosen !== "") out.push(...chosen.split("\n"));
			// chosen === "" 表示该段整体删除，不输出任何行
		}
	}
	return out.join("\n");
}

/** 把某一侧的 hunk 应用到 base 的 [regionStart, regionEnd) 区间，得到该侧的区域文本。 */
function applySide(
	base: string[],
	regionStart: number,
	regionEnd: number,
	sideHunks: SideHunk[],
	sideLines: string[],
): string[] {
	const out: string[] = [];
	let pos = regionStart;
	for (const h of sideHunks) {
		for (; pos < h.aStart; pos++) out.push(base[pos]);
		for (let bi = h.bStart; bi < h.bEnd; bi++) out.push(sideLines[bi]);
		pos = h.aEnd;
	}
	for (; pos < regionEnd; pos++) out.push(base[pos]);
	return out;
}

function sameLines(a: string[], b: string[]): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) {
		if (a[i] !== b[i]) return false;
	}
	return true;
}
