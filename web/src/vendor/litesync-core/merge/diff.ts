/**
 * 行级 Myers diff。
 * 输出 base→side 的变更块（hunk）列表，供三方合并与版本对比视图使用。
 */

/** a 的 [aStart,aEnd) 被替换为 b 的 [bStart,bEnd)；纯插入时 aStart==aEnd。 */
export interface DiffHunk {
	aStart: number;
	aEnd: number;
	bStart: number;
	bEnd: number;
}

/** 差异过大（行数或编辑距离超限）时抛出，调用方应回退到安全策略。 */
export class DiffTooLargeError extends Error {
	constructor() {
		super("diff too large");
		this.name = "DiffTooLargeError";
	}
}

const MAX_LINES = 200_000;
const MAX_EDIT_DISTANCE = 2000;

export function splitLines(text: string): string[] {
	return text.split("\n");
}

export function joinLines(lines: string[]): string {
	return lines.join("\n");
}

/** 计算 a→b 的变更块（按行）。 */
export function diffHunks(a: string[], b: string[]): DiffHunk[] {
	if (a.length + b.length > MAX_LINES) throw new DiffTooLargeError();

	// 公共前后缀裁剪，缩小 Myers 输入
	let start = 0;
	while (start < a.length && start < b.length && a[start] === b[start]) start++;
	let endA = a.length;
	let endB = b.length;
	while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
		endA--;
		endB--;
	}
	const midA = a.slice(start, endA);
	const midB = b.slice(start, endB);
	if (midA.length === 0 && midB.length === 0) return [];
	if (midA.length === 0) return [{ aStart: start, aEnd: start, bStart: start, bEnd: start + midB.length }];
	if (midB.length === 0) return [{ aStart: start, aEnd: start + midA.length, bStart: start, bEnd: start }];

	const ops = myers(midA, midB);
	// 由操作序列构建 hunk 列表
	const hunks: DiffHunk[] = [];
	let ca = start;
	let cb = start;
	let cur: DiffHunk | null = null;
	for (const op of ops) {
		if (op === "same") {
			if (cur) {
				hunks.push(cur);
				cur = null;
			}
			ca++;
			cb++;
		} else if (op === "del") {
			cur ??= { aStart: ca, aEnd: ca, bStart: cb, bEnd: cb };
			cur.aEnd = ++ca;
		} else {
			cur ??= { aStart: ca, aEnd: ca, bStart: cb, bEnd: cb };
			cur.bEnd = ++cb;
		}
	}
	if (cur) hunks.push(cur);
	return hunks;
}

type Op = "same" | "del" | "ins";

/** 经典 Myers O(ND)：编辑距离超过 MAX_EDIT_DISTANCE 时抛 DiffTooLargeError。 */
function myers(a: string[], b: string[]): Op[] {
	const n = a.length;
	const m = b.length;
	const maxD = Math.min(n + m, MAX_EDIT_DISTANCE);
	const offset = maxD;
	const width = 2 * maxD + 1;
	let v = new Int32Array(width);
	const trace: Int32Array[] = [];

	let found = false;
	for (let d = 0; d <= maxD; d++) {
		trace.push(v.slice());
		for (let k = -d; k <= d; k += 2) {
			let x: number;
			if (k === -d || (k !== d && v[offset + k - 1] < v[offset + k + 1])) {
				x = v[offset + k + 1];
			} else {
				x = v[offset + k - 1] + 1;
			}
			let y = x - k;
			while (x < n && y < m && a[x] === b[y]) {
				x++;
				y++;
			}
			v[offset + k] = x;
			if (x >= n && y >= m) {
				found = true;
				break;
			}
		}
		if (found) break;
	}
	if (!found) throw new DiffTooLargeError();

	// 回溯构建操作序列
	const ops: Op[] = [];
	let x = n;
	let y = m;
	for (let d = trace.length - 1; d >= 0; d--) {
		const vd = trace[d];
		const k = x - y;
		let prevK: number;
		if (k === -d || (k !== d && vd[offset + k - 1] < vd[offset + k + 1])) {
			prevK = k + 1;
		} else {
			prevK = k - 1;
		}
		const prevX = vd[offset + prevK];
		const prevY = prevX - prevK;
		while (x > prevX && y > prevY) {
			ops.push("same");
			x--;
			y--;
		}
		if (d > 0) {
			if (x === prevX) {
				ops.push("ins");
				y--;
			} else {
				ops.push("del");
				x--;
			}
		}
		x = prevX;
		y = prevY;
	}
	return ops.reverse();
}

/** 版本对比视图用的逐行差异。 */
export interface DiffLine {
	type: "same" | "add" | "del";
	text: string;
}

export function diffLinesView(aText: string, bText: string): DiffLine[] {
	const a = splitLines(aText);
	const b = splitLines(bText);
	const hunks = diffHunks(a, b);
	const out: DiffLine[] = [];
	let ca = 0;
	let cb = 0;
	for (const h of hunks) {
		while (ca < h.aStart) {
			out.push({ type: "same", text: a[ca] });
			ca++;
			cb++;
		}
		for (; ca < h.aEnd; ca++) out.push({ type: "del", text: a[ca] });
		for (; cb < h.bEnd; cb++) out.push({ type: "add", text: b[cb] });
	}
	while (ca < a.length) {
		out.push({ type: "same", text: a[ca] });
		ca++;
		cb++;
	}
	return out;
}
