// W6（RC-2）：CodeMirror 操作用文档 position 语义；没有真实编辑前保留原始字节。
// 覆盖 LF / CRLF / 混合换行 / 末尾换行 / BOM / emoji / 中文多行，以及加粗、插入、撤销。
// 这是 @codemirror/state 层面的测试（不含 DOM 与输入法），真实浏览器的同类场景在 e2e/suites/w6-bytes.ts。
import assert from "node:assert/strict";
import { test } from "node:test";
import { history, undo } from "@codemirror/commands";
import { EditorSelection, EditorState, TransactionSpec } from "@codemirror/state";
import { Baseline, detectEol, diffSpec, hasMixedEol, insertSpec, prefixSpec, wrapSpec } from "../src/editor-core";

/** 与 editor.ts 相同的配置：**不**设 lineSeparator；带 history 以便测撤销。 */
function open(text: string, sel?: { anchor: number; head?: number }) {
	let state = EditorState.create({ doc: text, selection: sel, extensions: [history()] });
	const base = Baseline.of(state, text);
	const apply = (spec: TransactionSpec | null) => {
		if (spec) state = state.update(spec).state;
	};
	return {
		get state() {
			return state;
		},
		apply,
		select: (anchor: number, head = anchor) => apply({ selection: EditorSelection.range(anchor, head) }),
		undo: () => undo({ state, dispatch: (tr) => (state = tr.state) }),
		bytes: () => base.serialize(state.doc),
	};
}

test("审查反例：纯 CRLF 多行全选加粗不再越界，且按 CRLF 写回", () => {
	const text = "a\r\nb\r\nc\r\nd";
	const ed = open(text);
	assert.equal(ed.state.doc.length, 7, "文档内部一个换行 = 1 个 position");
	ed.select(0, ed.state.doc.length);
	assert.doesNotThrow(() => ed.apply(wrapSpec(ed.state, "**", "**", "粗体")));
	assert.equal(ed.bytes(), "**a\r\nb\r\nc\r\nd**");
	const r = ed.state.selection.main;
	assert.equal(ed.state.sliceDoc(r.from, r.to), "a\nb\nc\nd", "选中的正是被包住的内容");
	ed.undo();
	assert.equal(ed.bytes(), text, "撤销后逐字节回到原文");
});

test("没有真实编辑：LF / CRLF / 混合 / 末尾换行 / BOM 原样返回原文字节", () => {
	for (const text of ["第一行\n第二行\n", "a\r\nb\r\nc\r\n", "a\r\nb\nc", "第一行\r\n第二行\n第三行\r\n", "末尾无换行", "两个换行\n\n", "﻿# 标题\r\n正文\r\n", "😀 表情\r\n中文第二行 🎉\r\n第三行", "\r\n", ""]) {
		const ed = open(text);
		assert.equal(ed.bytes(), text, JSON.stringify(text));
	}
	assert.equal(hasMixedEol("a\r\nb\nc"), true);
	assert.equal(hasMixedEol("a\r\nb\r\n"), false);
	assert.equal(detectEol("a\r\nb\r\n"), "\r\n");
	assert.equal(detectEol("a\r\nb\nc"), "\n", "混用换行编辑后统一为 LF（界面事先说明）");
});

test("审查反例：混合换行文档进入编辑但不输入，序列化结果不变（不会被认作已修改）", () => {
	const mixed = "a\r\nb\nc";
	const ed = open(mixed);
	assert.equal(ed.bytes(), mixed);
	ed.apply(insertSpec(ed.state, "x"));
	assert.equal(ed.bytes(), "xa\nb\nc", "真实编辑后才统一换行");
	ed.undo();
	assert.equal(ed.bytes(), mixed, "撤销回原样：原始字节（含混合换行）完整回来");
});

test("插入多行文本：CRLF 文档按 CRLF 写回，光标落在插入内容之后（文档 position）", () => {
	const text = "第一行\r\n第二行\r\n";
	const ed = open(text, { anchor: 3 });
	ed.apply(insertSpec(ed.state, "![[a.png]]\n![[b.png]]"));
	assert.equal(ed.bytes(), "第一行![[a.png]]\r\n![[b.png]]\r\n第二行\r\n");
	assert.equal(ed.state.selection.main.head, 3 + "![[a.png]]\n![[b.png]]".length);
	const ed2 = open(text, { anchor: 3 });
	ed2.apply(insertSpec(ed2.state, "x\r\ny"));
	assert.equal(ed2.bytes(), "第一行x\r\ny\r\n第二行\r\n", "插入内容里自带的 CRLF 也只算一个换行");
	assert.equal(ed2.state.selection.main.head, 3 + 3);
});

test("BOM + CRLF：局部编辑后 BOM 与其余字节都在", () => {
	const text = "﻿# 标题\r\n正文\r\n";
	const ed = open(text);
	ed.apply({ changes: { from: ed.state.doc.length, insert: "追加" } });
	assert.equal(ed.bytes(), "﻿# 标题\r\n正文\r\n追加");
});

test("emoji / 中文多行选区加粗：代理对不被拆开，CRLF 保持", () => {
	const text = "😀 表情\r\n中文第二行 🎉\r\n第三行";
	const ed = open(text);
	const line2 = ed.state.doc.line(2);
	ed.select(0, line2.to);
	ed.apply(wrapSpec(ed.state, "**", "**", "粗体"));
	assert.equal(ed.bytes(), "**😀 表情\r\n中文第二行 🎉**\r\n第三行");
	ed.undo();
	assert.equal(ed.bytes(), text);
});

test("空选区加粗插入占位文字并选中它；前缀按行加、不重复", () => {
	const ed = open("abc\ndef", { anchor: 3 });
	ed.apply(wrapSpec(ed.state, "**", "**", "粗体"));
	assert.equal(ed.bytes(), "abc**粗体**\ndef");
	const r = ed.state.selection.main;
	assert.equal(ed.state.sliceDoc(r.from, r.to), "粗体");
	const ed2 = open("a\r\nb\r\n- c", { anchor: 0, head: 7 }); // 文档长度 7（两个换行各占 1）
	ed2.apply(prefixSpec(ed2.state, "- "));
	assert.equal(ed2.bytes(), "- a\r\n- b\r\n- c");
});

test("diffSpec：只替换差异部分（光标在别处不被打乱）；不拆代理对；CRLF 文档按文档空间计算", () => {
	const ed = open("first\r\n\r\nmiddle\r\n\r\nlast\r\n", { anchor: 2 });
	ed.apply(diffSpec(ed.state, "first\r\n\r\nMIDDLE REMOTE\r\n\r\nlast\r\n"));
	assert.equal(ed.bytes(), "first\r\n\r\nMIDDLE REMOTE\r\n\r\nlast\r\n");
	assert.equal(ed.state.selection.main.head, 2, "修改在光标之后：光标不动");
	const em = open("a😀b");
	const spec = diffSpec(em.state, "a😃b")!;
	const ch = spec.changes as { from: number; to: number; insert: string };
	assert.equal(em.state.sliceDoc(ch.from, ch.to), "😀", "替换范围包含完整的代理对");
	em.apply(spec);
	assert.equal(em.bytes(), "a😃b");
	assert.equal(diffSpec(em.state, "a😃b"), null, "相同内容没有修改");
});
