/**
 * List / Task 冲突块合并（v0.8.1 智能合并第二层）。
 *
 * 行级 diff3 判为冲突的区域，如果三方都是「顶层列表项」，按 item 集合合并：
 * - 双方新增不同 item → union（信息不丢）
 * - 一方删除、另一方未动 → 删除
 * - task 勾选：一方改勾选另一方未动 → 采用改动方
 * - 一方删除另一方修改 / 同一 item 双方改成不同 → 放弃（维持冲突）
 * 任何歧义（嵌套、缩进、重复 item、非列表行）一律返回 null，绝不猜。
 */

/** 顶层列表项：- / * / + / 1. / 1)，可带 task 勾选框。 */
const ITEM = /^([-*+]|\d+[.)])\s+(\[[ xX]\]\s+)?(.*)$/;

interface Item {
	/** 身份：去掉勾选状态后的内容文本（勾选变化视为对同一 item 的修改） */
	id: string;
	line: string;
	isTask: boolean;
	checked: boolean;
}

function parseItems(lines: string[]): Item[] | null {
	const items: Item[] = [];
	const seen = new Set<string>();
	for (const line of lines) {
		if (/^\s/.test(line)) return null; // 缩进（嵌套列表/续行）：保守放弃
		const m = ITEM.exec(line);
		if (!m) return null;
		const isTask = m[2] !== undefined;
		const checked = isTask && /x/i.test(m[2]);
		const id = `${m[1]} ${m[3]}`;
		if (seen.has(id)) return null; // 重复 item：身份不可靠
		seen.add(id);
		items.push({ id, line, isTask, checked });
	}
	return items;
}

function renderItem(it: Item, checked: boolean): string {
	if (!it.isTask) return it.line;
	return it.line.replace(/\[[ xX]\]/, checked ? "[x]" : "[ ]");
}

/**
 * 尝试把冲突块按列表 item 三方合并；成功返回合并后的行，失败返回 null。
 */
export function tryMergeListBlock(
	baseLines: string[],
	localLines: string[],
	remoteLines: string[],
): string[] | null {
	const base = parseItems(baseLines);
	const local = parseItems(localLines);
	const remote = parseItems(remoteLines);
	if (base === null || local === null || remote === null) return null;

	const baseMap = new Map(base.map((it) => [it.id, it]));
	const remoteMap = new Map(remote.map((it) => [it.id, it]));

	const out: string[] = [];
	const emitted = new Set<string>();

	// 以 local 顺序为骨架（保留其新增位置），对每个 item 做三方判定
	for (const it of local) {
		const b = baseMap.get(it.id);
		const r = remoteMap.get(it.id);
		if (b && !r) {
			// remote 删除了它；local 是否修改过（勾选变化）？
			if (it.line === b.line) continue; // local 未动 → 跟随删除
			return null; // 删除 vs 修改：交给用户
		}
		emitted.add(it.id);
		if (!b) {
			// local 新增（r 若也有同 id 新增则内容一致，直接输出）
			out.push(it.line);
			continue;
		}
		// 三方都有：合并勾选状态（内容 id 相同，差异只可能在勾选）
		const localChanged = it.line !== b.line;
		const remoteChanged = r!.line !== b.line;
		if (localChanged && remoteChanged && it.line !== r!.line) return null; // 双方改成不同
		out.push(localChanged ? renderItem(it, it.checked) : renderItem(r!, r!.checked));
	}

	// remote 侧：处理 remote 新增 + local 删除的判定
	for (const it of remote) {
		if (emitted.has(it.id)) continue;
		const b = baseMap.get(it.id);
		if (!b) {
			out.push(it.line); // remote 新增 → 追加
			continue;
		}
		// base 有、local 没有（local 删除）：remote 是否修改过？
		if (it.line !== b.line) return null; // 删除 vs 修改：交给用户
		// remote 未动 → 跟随 local 删除
	}

	return out;
}
