/**
 * 编辑器的纯状态逻辑（W6 / RC-2）：只依赖 @codemirror/state，不碰 DOM——Node 测试直接跑。
 *
 * 位置语义：一律用 CodeMirror 文档 position（`state.doc`）。编辑器**不再**配置
 * `EditorState.lineSeparator`：文档内部按 \r\n / \r / \n 切行，一个换行恒为 1 个 position；
 * 原文的换行风格只在**序列化**时体现（{@link Baseline.serialize}）。旧实现给纯 CRLF 文件配
 * lineSeparator("\r\n")，再用序列化后的 CRLF 字符串长度去算 position——多行选区加粗时选区越界
 * （「Selection points outside of document」），插入多行文本时 "\n" 不被当作换行、写出混用换行。
 *
 * 原文保真：没有真实编辑（当前文档与基准文档逐字相同，包括编辑后又撤销回去）时，
 * 序列化**原样返回基准原文**——混用换行、BOM、末尾换行一个字节都不动。
 */
import { EditorSelection, EditorState, Text, TransactionSpec } from "@codemirror/state";

export type Eol = "\n" | "\r\n";

/** 全文一致为 CRLF（没有单独的 \n 或 \r）才按 CRLF 序列化；其余（LF、混用、没有换行）一律 LF。 */
export function detectEol(text: string): Eol {
	return /\r\n/.test(text) && !/(^|[^\r])\n/.test(text) && !/\r(?!\n)/.test(text) ? "\r\n" : "\n";
}

/** 是否混用了不止一种换行（编辑并保存后会统一，界面要事先说明）。 */
export function hasMixedEol(text: string): boolean {
	const crlf = /\r\n/.test(text);
	const lf = /(^|[^\r])\n/.test(text);
	const cr = /\r(?!\n)/.test(text);
	return [crlf, lf, cr].filter(Boolean).length > 1;
}

/** 基准原文（打开时 / 载入远端新版本时的字节）与它对应的文档。 */
export class Baseline {
	readonly eol: Eol;
	constructor(readonly text: string, readonly doc: Text) {
		this.eol = detectEol(text);
	}

	static of(state: EditorState, text: string): Baseline {
		return new Baseline(text, state.doc);
	}

	/** 文档 → 要保存的文本。与基准文档相同 → 原样返回原文（不改任何字节）。 */
	serialize(doc: Text): string {
		return doc.eq(this.doc) ? this.text : doc.sliceString(0, doc.length, this.eol);
	}
}

/** 一段文本插入文档后占多少个 position（换行按 1 计；与 state.toText 的切行规则一致）。 */
export function docLength(state: EditorState, text: string): number {
	return state.toText(text).length;
}

/** 加粗 / 斜体 / 链接 / 代码：包住选区（空选区用占位文字），选中被包住的内容。 */
export function wrapSpec(state: EditorState, before: string, after: string, placeholderText: string): TransactionSpec {
	const r = state.selection.main;
	const sel = state.doc.sliceString(r.from, r.to) || placeholderText; // 文档空间（换行 = "\n"）
	const head = r.from + docLength(state, before);
	return {
		changes: { from: r.from, to: r.to, insert: before + sel + after },
		selection: EditorSelection.range(head, head + docLength(state, sel)),
		userEvent: "input.format",
	};
}

/** 标题 / 列表 / 任务：给选区覆盖的每一行加前缀（已有则不重复加）。 */
export function prefixSpec(state: EditorState, prefix: string): TransactionSpec {
	const r = state.selection.main;
	const first = state.doc.lineAt(r.from).number;
	const last = state.doc.lineAt(r.to).number;
	const changes = [];
	for (let n = first; n <= last; n++) {
		const line = state.doc.line(n);
		if (!line.text.startsWith(prefix)) changes.push({ from: line.from, insert: prefix });
	}
	return { changes, userEvent: "input.format" };
}

/** 在光标处插入（附件引用等），光标落在插入内容之后。 */
export function insertSpec(state: EditorState, text: string): TransactionSpec {
	const r = state.selection.main;
	return { changes: { from: r.from, to: r.to, insert: text }, selection: { anchor: r.from + docLength(state, text) }, userEvent: "input" };
}

const isHigh = (c: number) => c >= 0xd800 && c <= 0xdbff;
const isLow = (c: number) => c >= 0xdc00 && c <= 0xdfff;

/**
 * 把文档改成 next（合并结果 / 草稿）所需的**最小**修改：公共前后缀不动，只替换中间不同的一段
 * ——光标在别处时不被打乱，撤销栈里也只是一次修改。不拆开代理对（emoji）。相同返回 null。
 */
export function diffSpec(state: EditorState, next: string, userEvent = "input.merge"): TransactionSpec | null {
	const a = state.doc.toString();
	const b = state.toText(next).toString();
	if (a === b) return null;
	const max = Math.min(a.length, b.length);
	let p = 0;
	while (p < max && a.charCodeAt(p) === b.charCodeAt(p)) p++;
	if (p > 0 && p < a.length && isHigh(a.charCodeAt(p - 1)) && isLow(a.charCodeAt(p))) p--;
	let s = 0;
	while (s < max - p && a.charCodeAt(a.length - 1 - s) === b.charCodeAt(b.length - 1 - s)) s++;
	if (s > 0 && a.length - s > p && isLow(a.charCodeAt(a.length - s)) && isHigh(a.charCodeAt(a.length - s - 1))) s--;
	return { changes: { from: p, to: a.length - s, insert: b.slice(p, b.length - s) }, userEvent };
}
