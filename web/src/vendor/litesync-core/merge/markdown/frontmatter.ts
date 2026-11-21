/**
 * Frontmatter 字段级三方合并（v0.8.1 智能合并第一层，投入产出比最高）。
 *
 * 不引入 YAML 解析库：把 frontmatter 按「顶层 key 的原始行块」切分，
 * 以块文本相等与否判定修改，按 key 做三方合并；数组块（全部为 `- item` 行）
 * 在双方都是新增/删除 item 时做集合合并。任何解析不确定（重复 key、
 * 非 key 开头的行、缩进异常）→ 返回 null，整体退回行级 diff3，绝不猜。
 */

/** 顶层 key 块：key + 归属它的原始行（含 key 行本身）。 */
interface FmBlock {
	key: string;
	lines: string[];
}

const KEY_LINE = /^([A-Za-z0-9_][A-Za-z0-9_ ./-]*):(?:\s|$)/;
const LIST_ITEM = /^\s+-\s+(.*)$/;

/** 拆出文首 frontmatter（--- 包围）；无 frontmatter 返回 fm=null。 */
export function splitFrontmatter(text: string): { fm: string | null; body: string } {
	if (!text.startsWith("---\n") && text !== "---") return { fm: null, body: text };
	const end = text.indexOf("\n---", 3);
	if (end < 0) return { fm: null, body: text };
	const after = end + 4; // 跳过 "\n---"
	if (after < text.length && text[after] !== "\n") return { fm: null, body: text };
	return {
		fm: text.slice(4, end + 1), // 含结尾换行，不含围栏
		body: text.slice(after < text.length ? after + 1 : after),
	};
}

/** 把 frontmatter 文本解析为顶层 key 块序列；不可靠时返回 null。 */
export function parseFmBlocks(fm: string): FmBlock[] | null {
	const blocks: FmBlock[] = [];
	const seen = new Set<string>();
	let current: FmBlock | null = null;
	const lines = fm.split("\n");
	// 末尾的空字符串来自结尾换行，不参与解析
	if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();

	for (const line of lines) {
		const m = KEY_LINE.exec(line);
		if (m) {
			const key = m[1].trim();
			if (seen.has(key)) return null; // 重复 key：不可靠
			seen.add(key);
			current = { key, lines: [line] };
			blocks.push(current);
		} else if (line.trim() === "" || /^\s/.test(line)) {
			// 缩进行（数组/嵌套对象/多行值）与空行归属当前 key
			if (!current) {
				if (line.trim() === "") continue; // 开头空行忽略
				return null;
			}
			current.lines.push(line);
		} else {
			return null; // 顶层出现非 key 行（如 YAML 文档流语法）：不可靠
		}
	}
	return blocks;
}

function blockText(b: FmBlock): string {
	return b.lines.join("\n");
}

/** 块是否为纯数组（key: 行后全部是 `- item`），返回 item 列表；否则 null。 */
function listItems(b: FmBlock): string[] | null {
	if (b.lines.length < 2) return null;
	if (b.lines[0].trim() !== `${b.key}:`) return null;
	const items: string[] = [];
	for (const line of b.lines.slice(1)) {
		const m = LIST_ITEM.exec(line);
		if (!m) return null;
		items.push(m[1].trim());
	}
	return items;
}

/** 数组块三方合并：双方新增/删除 union；一边删一边留按删除方；重复 item 不可靠。 */
function mergeListBlocks(key: string, base: FmBlock | null, local: FmBlock, remote: FmBlock): FmBlock | null {
	const baseItems = base ? listItems(base) : [];
	const localItems = listItems(local);
	const remoteItems = listItems(remote);
	if (baseItems === null || localItems === null || remoteItems === null) return null;
	for (const arr of [baseItems, localItems, remoteItems]) {
		if (new Set(arr).size !== arr.length) return null; // 重复 item：不可靠
	}
	const localSet = new Set(localItems);
	const remoteSet = new Set(remoteItems);
	const baseSet = new Set(baseItems);

	const out: string[] = [];
	// base 顺序：双方都保留的留下（任一方删除即删除——删除是明确意图）
	for (const item of baseItems) {
		if (localSet.has(item) && remoteSet.has(item)) out.push(item);
	}
	// local 新增（保持 local 顺序），再 remote 新增
	for (const item of localItems) {
		if (!baseSet.has(item) && !out.includes(item)) out.push(item);
	}
	for (const item of remoteItems) {
		if (!baseSet.has(item) && !out.includes(item)) out.push(item);
	}
	return { key, lines: [`${key}:`, ...out.map((it) => `  - ${it}`)] };
}

/**
 * frontmatter 三方字段合并。
 * 成功返回合并后的 frontmatter 文本（含结尾换行；空结果返回 ""）；
 * 任何不确定（解析失败 / 同 key 双方改成不同标量）返回 null。
 */
export function mergeFrontmatter(baseFm: string, localFm: string, remoteFm: string): string | null {
	const baseBlocks = parseFmBlocks(baseFm);
	const localBlocks = parseFmBlocks(localFm);
	const remoteBlocks = parseFmBlocks(remoteFm);
	if (baseBlocks === null || localBlocks === null || remoteBlocks === null) return null;

	const baseMap = new Map(baseBlocks.map((b) => [b.key, b]));
	const localMap = new Map(localBlocks.map((b) => [b.key, b]));
	const remoteMap = new Map(remoteBlocks.map((b) => [b.key, b]));

	const merged: FmBlock[] = [];
	const emitted = new Set<string>();

	const mergeKey = (key: string): FmBlock | null | "conflict" => {
		const b = baseMap.get(key) ?? null;
		const l = localMap.get(key) ?? null;
		const r = remoteMap.get(key) ?? null;
		const bt = b ? blockText(b) : null;
		const lt = l ? blockText(l) : null;
		const rt = r ? blockText(r) : null;

		if (lt === rt) return l; // 双方一致（含双方都删除 → null）
		if (lt === bt) return r; // local 未动 → 用 remote（含 remote 删除）
		if (rt === bt) return l; // remote 未动 → 用 local
		// 双方都改且不同：数组块尝试集合合并；否则冲突
		if (l && r) {
			const lm = mergeListBlocks(key, b, l, r);
			if (lm) return lm;
		}
		return "conflict"; // 含一边删除一边修改的情况：不猜
	};

	// 输出顺序：base 顺序 → local 新增 → remote 新增
	const orderedKeys: string[] = [];
	for (const b of baseBlocks) orderedKeys.push(b.key);
	for (const b of localBlocks) if (!baseMap.has(b.key)) orderedKeys.push(b.key);
	for (const b of remoteBlocks) if (!baseMap.has(b.key) && !localMap.has(b.key)) orderedKeys.push(b.key);

	for (const key of orderedKeys) {
		if (emitted.has(key)) continue;
		emitted.add(key);
		const result = mergeKey(key);
		if (result === "conflict") return null;
		if (result !== null) merged.push(result);
	}

	if (merged.length === 0) return "";
	return merged.map(blockText).join("\n") + "\n";
}
