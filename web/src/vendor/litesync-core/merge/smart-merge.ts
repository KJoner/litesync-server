/**
 * 智能三方合并入口（v0.8.1）。
 *
 * 分层策略——尽可能自动解决**确定不会丢信息**的冲突，不确定的绝不自作主张：
 *
 *   ① Frontmatter 字段级合并（同 key 双方改不同才算冲突）
 *   ② Section 保守切分（三方结构一致时逐段独立 diff3，防跨段错配）
 *   ③ 行级 diff3（原有引擎）
 *   ④ 冲突块内：列表 item 集合合并 → token 级 diff3
 *   ⑤ 仍无法确定 → 结构化冲突（一侧删除一侧修改时附带建议，供 Resolver 采纳）
 *
 * 全程确定性、本地完成、无 AI、绝不把笔记发给第三方。
 * 与 threeWayMerge 同签名同返回类型：调用方可直接替换。
 */
import { splitLines } from "./diff";
import { mergeFrontmatter, splitFrontmatter } from "./markdown/frontmatter";
import { alignSections } from "./markdown/sections";
import { tryMergeListBlock } from "./markdown/lists";
import { MergeConflict, MergeInput, MergeResult, MergeSegment } from "./model";
import { mergePieces, Piece } from "./three-way";
import { tokenThreeWayMerge } from "./token/three-way-token";

export function smartThreeWayMerge(input: MergeInput): MergeResult {
	let { base, local, remote } = input;

	// ① Frontmatter 预合并：字段级合并成功后，把三方的 frontmatter 统一为
	// 合并结果，使 frontmatter 差异从后续行级 diff 中彻底消失。
	// 合并不确定时保持原文（frontmatter 冲突交给行级引擎正常呈现）。
	const fb = splitFrontmatter(base);
	const fl = splitFrontmatter(local);
	const fr = splitFrontmatter(remote);
	if (fb.fm !== null || fl.fm !== null || fr.fm !== null) {
		const mergedFm = mergeFrontmatter(fb.fm ?? "", fl.fm ?? "", fr.fm ?? "");
		if (mergedFm !== null) {
			const prefix = mergedFm === "" ? "" : `---\n${mergedFm}---\n`;
			base = prefix + fb.body;
			local = prefix + fl.body;
			remote = prefix + fr.body;
		}
	}

	const baseLines = splitLines(base);
	const localLines = splitLines(local);
	const remoteLines = splitLines(remote);

	// ② Section 保守切分：结构一致时逐段合并（行号偏移随段累加）
	const aligned = alignSections(baseLines, localLines, remoteLines);
	const pieces: Piece[] = [];
	if (aligned) {
		for (const seg of aligned) {
			const segPieces = mergePieces(
				baseLines.slice(seg.base.start, seg.base.end),
				localLines.slice(seg.local.start, seg.local.end),
				remoteLines.slice(seg.remote.start, seg.remote.end),
			);
			for (const p of segPieces) {
				if (p.kind === "conflict") {
					pieces.push({ ...p, baseStart: p.baseStart + seg.base.start, baseEnd: p.baseEnd + seg.base.start });
				} else {
					pieces.push(p);
				}
			}
		}
	} else {
		pieces.push(...mergePieces(baseLines, localLines, remoteLines));
	}

	// ③/④ 冲突块后处理：列表合并 → token 合并 → 建议标注
	let autoResolved = 0;
	const processed: Array<Piece | { kind: "smart-conflict"; conflict: Omit<MergeConflict, "id"> }> = [];
	for (const p of pieces) {
		if (p.kind !== "conflict") {
			processed.push(p);
			continue;
		}
		const resolved = resolveConflictPiece(p);
		if (resolved.lines !== null) {
			autoResolved++;
			processed.push({ kind: "lines", lines: resolved.lines });
		} else {
			processed.push({ kind: "smart-conflict", conflict: resolved.conflict! });
		}
	}

	// ⑤ 组装结果（与行级引擎一致的公开结构 + 建议信息）
	const segments: MergeSegment[] = [];
	const conflicts: MergeConflict[] = [];
	const mergedLines: string[] = [];
	let seq = 0;
	for (const p of processed) {
		if (p.kind === "lines") {
			if (p.lines.length > 0) {
				appendText(segments, mergedLines, p.lines);
			}
		} else if (p.kind === "smart-conflict") {
			const conflict: MergeConflict = { id: `c${++seq}`, ...p.conflict };
			conflicts.push(conflict);
			segments.push({ type: "conflict", conflict });
			// 预览文本对冲突段取 local（绝不自动写入 Vault）
			if (conflict.localText !== "") mergedLines.push(...conflict.localText.split("\n"));
		}
	}

	return {
		clean: conflicts.length === 0,
		mergedText: mergedLines.join("\n"),
		conflicts,
		segments,
		stats: { autoResolved },
	};
}

/** 相邻文本段合并进同一个 segment，保持与行级引擎相同的紧凑结构。 */
function appendText(segments: MergeSegment[], mergedLines: string[], lines: string[]): void {
	mergedLines.push(...lines);
	const last = segments[segments.length - 1];
	if (last && last.type === "text") {
		last.text = last.text === "" ? lines.join("\n") : `${last.text}\n${lines.join("\n")}`;
	} else {
		segments.push({ type: "text", text: lines.join("\n") });
	}
}

interface ResolveOutcome {
	lines: string[] | null;
	conflict?: Omit<MergeConflict, "id">;
}

/** 对一个行级冲突块做智能后处理。 */
function resolveConflictPiece(p: Extract<Piece, { kind: "conflict" }>): ResolveOutcome {
	// ③ 列表 item 集合合并（双方新增不同项 → union，绝不该打扰用户）
	const listMerged = tryMergeListBlock(p.baseLines, p.localLines, p.remoteLines);
	if (listMerged !== null) return { lines: listMerged };

	// ④ token 级三方合并（同一行内不重叠的修改 → 确定性合并）
	const tokenMerged = tokenThreeWayMerge(
		p.baseLines.join("\n"),
		p.localLines.join("\n"),
		p.remoteLines.join("\n"),
	);
	if (tokenMerged !== null) return { lines: tokenMerged === "" ? [] : tokenMerged.split("\n") };

	// ⑤ 无法自动解决：构造带建议的结构化冲突
	const conflict: Omit<MergeConflict, "id"> = {
		baseStart: p.baseStart,
		baseEnd: p.baseEnd,
		baseText: p.baseLines.join("\n"),
		localText: p.localLines.join("\n"),
		remoteText: p.remoteLines.join("\n"),
		kind: "text",
	};
	// 一侧删除、另一侧修改：不自动裁决，但给出「保留修改」的建议
	if (p.localLines.length === 0 && p.remoteLines.length > 0 && p.baseLines.length > 0) {
		conflict.kind = "delete-edit";
		conflict.suggestedText = conflict.remoteText;
		conflict.confidence = "medium";
		conflict.reason = "本地删除了此段，远端修改了此段——建议保留远端修改（信息不丢）";
	} else if (p.remoteLines.length === 0 && p.localLines.length > 0 && p.baseLines.length > 0) {
		conflict.kind = "delete-edit";
		conflict.suggestedText = conflict.localText;
		conflict.confidence = "medium";
		conflict.reason = "远端删除了此段，本地修改了此段——建议保留本地修改（信息不丢）";
	}
	return { lines: null, conflict };
}
