/**
 * 无损 token 化（v0.8.1 智能合并第三层）。
 *
 * 不做 NLP 分词，只保证三个性质：
 * - tokens.join("") === 原文（绝对无损，合并结果由 token 原样拼回）
 * - Latin/数字连续段是一个 token（英文按词合并）
 * - CJK 逐字符、标点/Markdown 语法符号逐字符（中文与语法符号按最小单元对齐）
 */

const LATIN = /[A-Za-z0-9_]/;

export function tokenize(text: string): string[] {
	const tokens: string[] = [];
	let i = 0;
	const n = text.length;
	while (i < n) {
		const c = text[i];
		if (c === "\n") {
			tokens.push("\n");
			i++;
			continue;
		}
		if (c === " " || c === "\t" || c === "\r") {
			let j = i + 1;
			while (j < n && (text[j] === " " || text[j] === "\t" || text[j] === "\r")) j++;
			tokens.push(text.slice(i, j));
			i = j;
			continue;
		}
		if (LATIN.test(c)) {
			let j = i + 1;
			while (j < n && LATIN.test(text[j])) j++;
			tokens.push(text.slice(i, j));
			i = j;
			continue;
		}
		// CJK 与其余字符（标点、Markdown 语法、emoji 等）逐字符；
		// codePointAt 保证代理对（emoji 等）不被拆开
		const ch = String.fromCodePoint(text.codePointAt(i)!);
		tokens.push(ch);
		i += ch.length;
	}
	return tokens;
}
