/** 三方合并的输入/输出模型（计划书 Phase 14）。 */

export interface MergeInput {
	base: string;
	local: string;
	remote: string;
}

/** 冲突类别（v0.8.1 智能合并）。 */
export type ConflictKind = "text" | "list-item" | "delete-edit" | "frontmatter-value" | "code";

export interface MergeConflict {
	id: string;

	/** base 行区间 [baseStart, baseEnd)，纯插入时二者相等 */
	baseStart: number;
	baseEnd: number;

	baseText: string;
	localText: string;
	remoteText: string;

	// ---- v0.8.1 智能合并附加信息（可选，行级引擎不填） ----
	kind?: ConflictKind;
	/** 引擎给出的建议结果（只建议，绝不自动写入；由用户在 Resolver 里采纳） */
	suggestedText?: string;
	confidence?: "high" | "medium" | "low";
	/** 建议理由（展示给用户） */
	reason?: string;
}

/** 合并结果的分段表示：稳定文本段与冲突段交替出现，供 Resolver UI 使用。 */
export type MergeSegment =
	| { type: "text"; text: string }
	| { type: "conflict"; conflict: MergeConflict };

export interface MergeResult {
	clean: boolean;
	/**
	 * clean 时为最终合并文本；
	 * 有冲突时为“冲突处取 local”的预览文本（绝不自动写入 Vault，
	 * 也绝不输出 <<<<<<< 之类的 conflict marker）。
	 */
	mergedText: string;
	conflicts: MergeConflict[];
	segments: MergeSegment[];
	/** 智能合并统计（v0.8.1）：行级引擎判冲突、但被智能层自动解决的数量 */
	stats?: { autoResolved: number };
}
