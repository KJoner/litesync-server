/**
 * Section 级切分（v0.8.1 智能合并第二层，保守版）。
 *
 * 按 heading path 把文档切成段（fenced code block 内的 # 不算 heading）。
 * 只有当三方的 section 结构（path 序列）完全一致时才按段独立合并——
 * 结构本身有增删/重排时退回整体行级 diff3，绝不冒错配风险。
 * 收益：段内独立 diff 更稳，不会把不同 section 里的相似行错误配对。
 */

export interface Section {
	/** heading 祖先链拼接（如 "Project / Todo"）；首个 heading 前的内容 path 为 "" */
	path: string;
	/** 行区间 [start, end) */
	start: number;
	end: number;
}

const HEADING = /^(#{1,6})\s+(.*)$/;
const FENCE = /^(```|~~~)/;

/** 把行数组切成 section 列表（覆盖全部行，顺序连续）。 */
export function splitSections(lines: string[]): Section[] {
	const sections: Section[] = [];
	const ancestry: { level: number; title: string }[] = [];
	let inFence = false;
	let fenceMarker = "";
	let start = 0;
	let currentPath = "";

	const flush = (end: number): void => {
		if (end > start) sections.push({ path: currentPath, start, end });
	};

	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		if (inFence) {
			if (line.startsWith(fenceMarker)) inFence = false;
			continue;
		}
		const fence = FENCE.exec(line);
		if (fence) {
			inFence = true;
			fenceMarker = fence[1];
			continue;
		}
		const h = HEADING.exec(line);
		if (h) {
			flush(i);
			const level = h[1].length;
			while (ancestry.length > 0 && ancestry[ancestry.length - 1].level >= level) ancestry.pop();
			ancestry.push({ level, title: h[2].trim() });
			currentPath = ancestry.map((a) => a.title).join(" / ");
			start = i;
		}
	}
	flush(lines.length);
	return sections;
}

/**
 * 三方 section 对齐：结构（path 序列）完全一致时返回逐段的三方行区间；
 * 否则返回 null（调用方退回整体行级合并）。
 */
export function alignSections(
	base: string[],
	local: string[],
	remote: string[],
): Array<{ base: Section; local: Section; remote: Section }> | null {
	const sb = splitSections(base);
	const sl = splitSections(local);
	const sr = splitSections(remote);
	if (sb.length < 2) return null; // 单段没有切分收益
	if (sb.length !== sl.length || sb.length !== sr.length) return null;
	for (let i = 0; i < sb.length; i++) {
		if (sb[i].path !== sl[i].path || sb[i].path !== sr[i].path) return null;
	}
	return sb.map((b, i) => ({ base: b, local: sl[i], remote: sr[i] }));
}
