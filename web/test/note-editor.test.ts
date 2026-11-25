// W1 / W2（RC-1）：编辑控制器在「上传 / 取远端 / 草稿加密」边界被注入延迟与逆序、用户每个阶段都在
// 继续输入时，所有输入都保存在当前文档、冲突副本或已验证（能解开）的草稿里。
//
// 证据边界：这是 **Node 下的控制器状态** 测试——真实的 NoteEditor 源码、真实的 WebCrypto 加密、
// 真实的草稿存储（内存后端，语义与 IndexedDB 后端相同）、真实的 @codemirror/state 文档模型；
// DOM 与网络是替身（假 DOM、可扣住的 fetch / fetchRemote、手动推进的计时器）。真实 Chromium 下的
// 同类场景见 e2e/suites/w1-merge.ts、w2-drafts.ts。审查反例 web-state-repro.cjs 的两个 W1/W2 场景
// 在这里改写成了正确行为的断言（「LAST LATE 消失」→ 必须保留；「草稿被删」→ 必须还在）。
import assert from "node:assert/strict";
import { test } from "node:test";
import { history } from "@codemirror/commands";
import { EditorState, TransactionSpec } from "@codemirror/state";
import { Baseline, diffSpec, insertSpec, prefixSpec, wrapSpec } from "../src/editor-core";
import type { EditorHandle, NoteEditorHost } from "../src/note-editor";
import { NoteEditor } from "../src/note-editor";
import * as core from "../src/vendor/litesync-core/crypto/crypto";
import { deriveDraftKey, DraftStore, memoryBackend, RepoBinding, TrackedFile } from "../src/write";

/* eslint-disable @typescript-eslint/no-explicit-any */

// ---------------------------------------------------------------- 假 DOM（只覆盖 NoteEditor 用到的部分）
class FakeEl {
	children: any[] = [];
	dataset: Record<string, string> = {};
	attrs: Record<string, string> = {};
	className = "";
	textContent = "";
	hidden = false;
	title = "";
	type = "";
	multiple = false;
	value = "";
	onclick: (() => void) | null = null;
	onchange: (() => void) | null = null;
	constructor(public tag: string) {}
	set innerHTML(_v: string) {
		this.children = [];
		this.textContent = "";
	}
	get innerHTML(): string {
		return "";
	}
	append(...n: any[]) {
		this.children.push(...n);
	}
	setAttribute(k: string, v: string) {
		this.attrs[k] = v;
	}
	hasChildNodes() {
		return this.children.length > 0;
	}
	click() {}
	remove() {}
	querySelectorAll(sel: string) {
		const out: FakeEl[] = [];
		const walk = (e: FakeEl) => {
			for (const c of e.children) {
				if (c instanceof FakeEl) {
					if (sel === ".seg button" && c.tag === "button" && c.dataset.mode) out.push(c);
					walk(c);
				}
			}
		};
		walk(this);
		return out;
	}
	text(): string {
		return this.textContent + this.children.map((c) => (typeof c === "string" ? c : c instanceof FakeEl ? c.text() : c.data ?? "")).join("");
	}
	find(label: string): FakeEl | null {
		for (const c of this.children) {
			if (c instanceof FakeEl) {
				if (c.tag === "button" && c.textContent === label) return c;
				const f = c.find(label);
				if (f) return f;
			}
		}
		return null;
	}
}
const g = globalThis as any;
g.window = globalThis;
g.document = {
	createElement: (t: string) => new FakeEl(t),
	// 格式栏的图标（icons.ts 的内联 SVG）
	createElementNS: (_ns: string, t: string) => new FakeEl(t),
	createTextNode: (d: string) => ({ data: d }),
	head: { append() {} },
	body: { append() {} },
};

// ---------------------------------------------------------------- 假编辑器：真实的 CodeMirror 文档模型（无 DOM）
class FakeEditor implements EditorHandle {
	state: EditorState;
	base: Baseline;
	ver = 0;
	composing = false;
	readOnly = false;
	private waiters: (() => void)[] = [];
	private composeFrom = -1;
	constructor(text: string, private onChange: (t: string) => void) {
		this.state = EditorState.create({ doc: text, extensions: [history()] });
		this.base = Baseline.of(this.state, text);
	}
	private dispatch(spec: TransactionSpec | null) {
		if (!spec) return;
		const tr = this.state.update(spec);
		this.state = tr.state;
		if (tr.docChanged) {
			this.ver++;
			this.onChange(this.getText());
		}
	}
	getText() {
		return this.base.serialize(this.state.doc);
	}
	version() {
		return this.ver;
	}
	load(t: string) {
		this.base = new Baseline(t, this.state.toText(t));
		this.dispatch(diffSpec(this.state, t, "input.load"));
	}
	applyText(t: string) {
		this.dispatch(diffSpec(this.state, t));
	}
	focus() {}
	destroy() {}
	isComposing() {
		return this.composing;
	}
	whenNotComposing() {
		return this.composing ? new Promise<void>((r) => this.waiters.push(r)) : Promise.resolve();
	}
	setReadOnly(ro: boolean) {
		this.readOnly = ro;
	}
	wrap(b: string, a: string, ph: string) {
		this.dispatch(wrapSpec(this.state, b, a, ph));
	}
	prefixLines(p: string) {
		this.dispatch(prefixSpec(this.state, p));
	}
	insert(t: string) {
		this.dispatch(insertSpec(this.state, t));
	}
	/** 模拟用户输入：只读时输入被拒绝（返回 false），不会被吞掉。 */
	type(t: string): boolean {
		if (this.readOnly) return false;
		this.dispatch({ changes: { from: this.state.doc.length, insert: t } });
		return true;
	}
	replaceLine(n: number, t: string): boolean {
		if (this.readOnly) return false;
		const line = this.state.doc.line(n);
		this.dispatch({ changes: { from: line.from, to: line.to, insert: t } });
		return true;
	}
	/** 输入法组合：拼音先进文档，组合结束时替换成最终文字（与浏览器里的 DOM 行为一致）。 */
	compose(t: string) {
		this.composing = true;
		this.composeFrom = this.state.doc.length;
		this.dispatch({ changes: { from: this.composeFrom, insert: t } });
	}
	commit(final: string) {
		this.dispatch({ changes: { from: this.composeFrom, to: this.state.doc.length, insert: final } });
		this.composing = false;
		for (const w of this.waiters.splice(0)) w();
	}
}
let lastEditor: FakeEditor | null = null;
g.LiteSyncEditor = {
	createEditor: (_p: unknown, text: string, opts: { onChange(t: string): void }) => (lastEditor = new FakeEditor(text, opts.onChange)),
};

// ---------------------------------------------------------------- 假服务器：可扣住的 PUT；真实解密核对上传内容
interface Deferred<T> {
	promise: Promise<T>;
	resolve: (v: T) => void;
}
function deferred<T = void>(): Deferred<T> {
	let resolve!: (v: T) => void;
	const promise = new Promise<T>((r) => (resolve = r));
	return { promise, resolve };
}
const flush = async (n = 30) => {
	for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
};
/** 按墙钟时间等条件成立（Date 没有被 mock；机器繁忙时 WebCrypto 线程池可能很慢，不能按轮数算）。 */
async function until(cond: () => boolean, ms = 15000): Promise<void> {
	const end = Date.now() + ms;
	while (!cond()) {
		if (Date.now() > end) assert.fail(`条件在 ${ms} ms 内没有成立`);
		await new Promise((r) => setImmediate(r));
	}
}

const vaultIdentity = "0123456789abcdef0123456789abcdef";
const binding: RepoBinding = { vaultId: "v-1", vaultIdentity, keyEpoch: 1, repoEpoch: "ab".repeat(16), formatEpoch: 1, minimumEnvelopeVersion: 3, encrypted: true, metaMode: false };
const raw = core.randomBytes(32);
const vmkP = crypto.subtle.importKey("raw", raw as BufferSource, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

class FakeServer {
	revision = 1;
	generation = 1;
	deleted = false;
	copies = new Map<string, string>();
	puts = 0;
	private holds: Deferred<void>[] = [];
	holdNextPut = false;
	putArrived = deferred();
	constructor(public fileId: string, public text: string) {}
	/** 下一个 PUT 被扣住，直到 release() */
	hold(): () => void {
		this.holdNextPut = true;
		this.putArrived = deferred();
		const d = deferred();
		this.holds.push(d);
		return () => d.resolve();
	}
	async fetch(url: string, init: RequestInit): Promise<Response> {
		const h = init.headers as Record<string, string>;
		assert.equal(url, "/api/v1/file");
		assert.equal(init.method, "PUT");
		this.puts++;
		if (this.holdNextPut) {
			this.holdNextPut = false;
			this.putArrived.resolve();
			await this.holds.shift()!.promise;
		}
		const vmk = await vmkP;
		const id = h["X-File-Id"];
		const body = init.body as Uint8Array;
		const dec = await core.decryptFileV3(vmk, body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer, vaultIdentity, id, 1);
		assert.ok(dec, "上传的必须是能解开的 LSE3");
		const text = new TextDecoder().decode(dec!.plain);
		const json = (status: number, b: unknown) => new Response(JSON.stringify(b), { status });
		if (id !== this.fileId) {
			this.copies.set(decodeURIComponent(h["X-File-Path"]), text); // 冲突副本：新对象
			return json(200, { revision: 1, hash: h["X-Content-Hash"], fileId: id, contentGeneration: dec!.generation });
		}
		if (this.deleted) return json(409, { code: "CONFLICT", revision: this.revision + 1, hash: "", deleted: true, fileId: id });
		if (Number(h["X-Base-Revision"]) !== this.revision) return json(409, { code: "CONFLICT", revision: this.revision, hash: "", deleted: false, fileId: id });
		this.text = text;
		this.revision++;
		this.generation = dec!.generation;
		return json(200, { revision: this.revision, hash: h["X-Content-Hash"], fileId: id, contentGeneration: this.generation });
	}
	/** 别的设备写了一版 */
	remoteWrite(text: string) {
		this.text = text;
		this.revision++;
		this.generation++;
	}
}

interface Rig {
	ed: NoteEditor;
	cm: FakeEditor;
	server: FakeServer;
	ds: DraftStore;
	host: NoteEditorHost & { aliveFlag: boolean; volatile: boolean; fetchHold: Deferred<void> | null; fetchArrived: Deferred<void>; authClaims: string[] };
	notice: () => string;
	click: (label: string) => Promise<void>;
}

async function rig(text: string, shared?: { ds: DraftStore; server: FakeServer }): Promise<Rig> {
	const vmk = await vmkP;
	const fileId = shared?.server.fileId ?? core.newFileId();
	const server = shared?.server ?? new FakeServer(fileId, text);
	const ds = shared?.ds ?? new DraftStore(memoryBackend(), "o|acct|v-1", await deriveDraftKey(raw), `${vaultIdentity}|1`);
	g.fetch = (url: string, init: RequestInit) => server.fetch(url, init);
	const host = {
		aliveFlag: true,
		volatile: false,
		fetchHold: null as Deferred<void> | null,
		fetchArrived: deferred(),
		authClaims: [] as string[],
		binding: () => binding,
		keys: () => ({ vmk }),
		drafts: () => ds,
		draftsVolatile: () => host.volatile,
		alive: () => host.aliveFlag,
		renderPreview: () => undefined,
		fetchRemote: async () => {
			host.fetchArrived.resolve();
			if (host.fetchHold) await host.fetchHold.promise;
			return server.deleted ? null : { text: server.text, revision: server.revision, generation: server.generation, fileId };
		},
		onSaved: () => undefined,
		onAuthExpired: (c: string) => void host.authClaims.push(c),
		uploadAttachment: async () => "",
		showCompare: () => undefined,
	};
	const root = new FakeEl("div");
	const file: TrackedFile = { path: "测试/笔记.md", serverPath: "测试/笔记.md", fileId, revision: server.revision, generation: server.generation, envelope: "LSE3", padded: false, metaGeneration: 0 };
	const ed = new NoteEditor(root as any, host, file, server.text, false);
	await ed.setMode("edit");
	const noticeEl = () => (ed as any).noticeEl as FakeEl;
	await flush();
	return {
		ed, cm: lastEditor!, server, ds, host,
		notice: () => noticeEl().text(),
		click: async (label) => {
			// offerDraft 等异步提示：先等按钮出现
			await until(() => noticeEl().find(label) !== null).catch(() => assert.fail(`通知里没有「${label}」按钮：${noticeEl().text()}`));
			noticeEl().find(label)!.onclick!();
		},
	};
}

const base = "first\n\nmiddle\n\nlast\n";

test("W1 干净合并：上传期间与取远端期间的输入、首次修改、远端修改全部保留，并最终上传", async (t) => {
	t.mock.timers.enable({ apis: ["setTimeout"] });
	const r = await rig(base);
	r.cm.replaceLine(1, "FIRST");
	const release = r.server.hold();
	const saving = r.ed.saveNow();
	await r.server.putArrived.promise;
	r.server.remoteWrite("first\n\nMIDDLE REMOTE\n\nlast\n");
	r.cm.replaceLine(5, "LAST LATE"); // 上传期间的输入
	r.host.fetchHold = deferred();
	release();
	await r.host.fetchArrived.promise;
	r.cm.type("\nC during GET"); // 取远端期间的输入
	r.host.fetchHold.resolve();
	await saving;
	const text = r.cm.getText();
	for (const s of ["FIRST", "MIDDLE REMOTE", "LAST LATE", "C during GET"]) assert.ok(text.includes(s), `编辑器丢了「${s}」：${JSON.stringify(text)}`);
	t.mock.timers.tick(400); // 合并后立即上传合并结果
	await until(() => r.server.text.includes("C during GET"));
	for (const s of ["FIRST", "MIDDLE REMOTE", "LAST LATE", "C during GET"]) assert.ok(r.server.text.includes(s), `服务器正文缺「${s}」`);
	assert.equal(r.server.copies.size, 0, "干净合并不产生冲突副本");
});

test("W1 同段冲突：冲突副本是冲突那一刻的全文；上传副本期间编辑器只读（输入被拒绝而不是被吞掉）；原笔记保留远端版本", async (t) => {
	t.mock.timers.enable({ apis: ["setTimeout"] });
	const r = await rig("alpha\n\nbeta\n\ngamma\n");
	r.cm.replaceLine(1, "alpha 网页");
	const release = r.server.hold();
	const saving = r.ed.saveNow();
	await r.server.putArrived.promise;
	r.server.remoteWrite("alpha 插件\n\nbeta\n\ngamma\n");
	r.cm.replaceLine(5, "gamma 上传期间输入");
	r.host.fetchHold = deferred();
	release();
	await r.host.fetchArrived.promise;
	r.cm.type("\n取远端期间输入");
	const releaseCopy = r.server.hold(); // 扣住冲突副本的上传
	r.host.fetchHold.resolve();
	await r.server.putArrived.promise;
	assert.equal(r.cm.readOnly, true, "上传冲突副本期间编辑器只读");
	assert.equal(r.cm.type("被拒绝的输入"), false);
	releaseCopy();
	await saving;
	const copy = [...r.server.copies.values()][0];
	assert.ok(copy, "应当产生冲突副本");
	for (const s of ["alpha 网页", "gamma 上传期间输入", "取远端期间输入"]) assert.ok(copy.includes(s), `冲突副本缺「${s}」：${JSON.stringify(copy)}`);
	assert.equal(r.server.text, "alpha 插件\n\nbeta\n\ngamma\n", "原笔记没有被网页覆盖");
	assert.equal(r.cm.getText(), "alpha 插件\n\nbeta\n\ngamma\n", "编辑器载入远端版本");
	assert.equal(r.cm.readOnly, false, "完成后恢复可编辑");
	assert.match(r.notice(), /冲突副本/);
});

test("W1 远端删除：「另存为新笔记」保存的是点按钮那一刻的全文（含上传期间与提示之后的输入）", async (t) => {
	t.mock.timers.enable({ apis: ["setTimeout"] });
	const r = await rig("one\n");
	r.cm.replaceLine(1, "one 网页");
	const release = r.server.hold();
	const saving = r.ed.saveNow();
	await r.server.putArrived.promise;
	r.server.deleted = true;
	r.cm.type("two 上传期间输入\n");
	release();
	await saving;
	assert.match(r.notice(), /别处被删除/);
	r.cm.type("three 提示之后输入");
	await r.click("另存为新笔记");
	await until(() => r.server.copies.size === 1);
	const copy = [...r.server.copies.values()][0];
	for (const s of ["one 网页", "two 上传期间输入", "three 提示之后输入"]) assert.ok(copy.includes(s), `新笔记缺「${s}」：${JSON.stringify(copy)}`);
});

test("W1 输入法：组合进行中合并结果到达时不替换文档；组合结束后以当时的全文合并，组合文字与远端修改都在", async (t) => {
	t.mock.timers.enable({ apis: ["setTimeout"] });
	const r = await rig("x1\n\nx2\n\nx3\n");
	r.cm.replaceLine(1, "x1 网页");
	const release = r.server.hold();
	const saving = r.ed.saveNow();
	await r.server.putArrived.promise;
	r.server.remoteWrite("x1\n\nX2 远端\n\nx3\n");
	r.cm.compose("zhong");
	release();
	await flush(200);
	assert.equal(r.cm.getText(), "x1 网页\n\nx2\n\nx3\nzhong", "组合进行中：文档不被程序化替换");
	r.cm.commit("中文");
	await saving;
	const text = r.cm.getText();
	assert.ok(text.includes("中文") && text.includes("X2 远端") && text.includes("x1 网页") && !text.includes("zhong"), JSON.stringify(text));
});

test("W2 旧上传成功晚到：较新的草稿不删除，而是以新的 base 重写；随后「强制结束」重开能完整恢复", async (t) => {
	t.mock.timers.enable({ apis: ["setTimeout"] });
	const r = await rig("草稿基线\n");
	r.cm.type("A 随上传发出\n");
	const release = r.server.hold();
	const saving = r.ed.saveNow();
	await r.server.putArrived.promise;
	r.cm.type("B 上传期间输入");
	t.mock.timers.tick(900); // 草稿防抖：B 加密落盘
	await until(() => (r.ed as any).drafted?.version === r.cm.version());
	release();
	await saving;
	const drafts = await r.ds.loadAll(r.server.fileId);
	assert.equal(drafts.length, 1, "B 的草稿必须还在（审查反例：这里曾被无条件删除）");
	assert.ok(drafts[0].text.includes("B 上传期间输入"));
	assert.equal(drafts[0].baseRevision, r.server.revision, "草稿已经改以刚确认的版本为 base");
	assert.equal(drafts[0].baseText, "草稿基线\nA 随上传发出\n");
	// 强制结束：不经过 lock / leave，直接丢掉这个编辑器；新实例只看得到服务器与本机草稿
	const again = await rig(r.server.text, { ds: r.ds, server: r.server });
	await until(() => /草稿/.test(again.notice()));
	await again.click("恢复草稿");
	await until(() => again.cm.getText().includes("B 上传期间输入"));
	assert.equal(again.cm.getText(), "草稿基线\nA 随上传发出\nB 上传期间输入");
	await until(() => (again.ed as any).drafted !== null);
	await flush();
	const after = await r.ds.loadAll(r.server.fileId);
	assert.deepEqual(after.map((d) => d.draftId), [again.ed.draftId], "被接管的旧草稿在新实例的草稿落盘后才删除");
});

test("W2 上传进行中锁定（会话失效）：迟到的成功结果被丢弃、草稿不删；解锁后以「随上传发出的那一版」为 base 干净合并", async (t) => {
	t.mock.timers.enable({ apis: ["setTimeout"] });
	const r = await rig("锁定基线\n");
	r.cm.type("锁定前上传的\n");
	const release = r.server.hold();
	const saving = r.ed.saveNow();
	await r.server.putArrived.promise;
	r.cm.type("锁定前最后输入的");
	t.mock.timers.tick(900);
	await until(() => (r.ed as any).drafted?.version === r.cm.version());
	const outcome = await r.ed.lock();
	assert.deepEqual(outcome, { unsynced: true, persisted: true, volatile: false });
	r.host.aliveFlag = false; // lockNow 让会话代次前进：旧会话的一切异步结果作废
	release(); // 被扣住的上传其实到了服务器
	await saving;
	assert.equal(r.server.text, "锁定基线\n锁定前上传的\n", "服务器收下了随上传发出的那一版");
	const drafts = await r.ds.loadAll(r.server.fileId);
	assert.equal(drafts.length, 1, "迟到的成功不得删除草稿");
	assert.equal(drafts[0].inflightText, "锁定基线\n锁定前上传的\n", "草稿记下了在途上传的那一版");
	const again = await rig(r.server.text, { ds: r.ds, server: r.server });
	await again.click("恢复草稿");
	await until(() => again.cm.getText().includes("锁定前最后输入的"));
	assert.equal(again.cm.getText(), "锁定基线\n锁定前上传的\n锁定前最后输入的", "以在途那一版为 base：干净合并，不需要冲突副本");
	assert.equal(again.server.copies.size, 0);
});

test("W2 草稿加密逆序完成：较早开始、较晚完成的那次写入不能覆盖较新的草稿", async (t) => {
	t.mock.timers.enable({ apis: ["setTimeout"] });
	const r = await rig("逆序基线\n");
	const subtle = crypto.subtle as any;
	const orig = subtle.encrypt.bind(subtle);
	const gate = deferred();
	let n = 0;
	let firstDone = false;
	subtle.encrypt = async (alg: any, key: CryptoKey, data: BufferSource) => {
		const res = await orig(alg, key, data);
		const aad = alg?.additionalData ? new TextDecoder().decode(alg.additionalData) : "";
		if (aad.startsWith("litesync/web-draft/") && ++n === 1) {
			await gate.promise; // 第一次草稿加密被拖住
			firstDone = true;
		}
		return res;
	};
	try {
		r.cm.type("第一版（较早开始）");
		t.mock.timers.tick(900); // 第一次草稿写入开始（卡在加密）
		await flush();
		r.cm.type("\n第二版（较晚开始、先完成）");
		t.mock.timers.tick(900); // 第二次草稿写入完成
		await until(() => (r.ed as any).drafted?.version === r.cm.version());
		gate.resolve(); // 第一次随后才完成
		await until(() => firstDone);
		await flush(200); // 让第一次写入的条件写也走完（它必须被拒绝）
		const drafts = await r.ds.loadAll(r.server.fileId);
		assert.equal(drafts.length, 1);
		assert.ok(drafts[0].text.includes("第二版"), `较早的写入覆盖了较新的草稿：${JSON.stringify(drafts[0].text)}`);
	} finally {
		subtle.encrypt = orig;
	}
});

test("文案如实：草稿只在内存 / 写入失败 / 停在旧版本时，不说「已加密保存在本机，不会丢」", async (t) => {
	t.mock.timers.enable({ apis: ["setTimeout"] });
	const r = await rig("文案基线\n");
	r.cm.type("改动");
	assert.match(r.ed.draftClaim(), /还没有写入本机草稿/);
	t.mock.timers.tick(900);
	await until(() => (r.ed as any).drafted !== null);
	assert.match(r.ed.draftClaim(), /已加密保存在本机/);
	r.cm.type("更多");
	assert.match(r.ed.draftClaim(), /之后的输入还没有写入本机/);
	r.host.volatile = true;
	assert.match(r.ed.draftClaim(), /只在这个页面的内存里/);
	assert.doesNotMatch(r.ed.draftClaim(), /不会丢/);
	r.host.volatile = false;
	const ds = r.ds as any;
	const save = ds.save.bind(ds);
	ds.save = async () => {
		throw new DOMException("模拟：存储配额已满", "QuotaExceededError");
	};
	try {
		t.mock.timers.tick(900);
		await until(() => (r.ed as any).draftFailed === true);
		assert.match(r.ed.draftClaim(), /本机草稿保存失败/);
	} finally {
		ds.save = save;
	}
	// 永久配额超限的提示按实际草稿状态说明
	const txt = (r.ed as any).rejectText("QUOTA_EXCEEDED", "", { limit: 100, used: 90 });
	assert.match(txt, /上限/);
	assert.match(txt, /本机草稿保存失败|已加密保存在本机|还没有写入/);
});

test("W1 回归（审查反例 web-state-repro 场景一）：旧快照合并不再覆盖期间的输入", async (t) => {
	t.mock.timers.enable({ apis: ["setTimeout"] });
	const r = await rig(base);
	r.cm.replaceLine(1, "FIRST");
	const release = r.server.hold();
	const saving = r.ed.saveNow();
	await r.server.putArrived.promise;
	r.server.remoteWrite("first\n\nMIDDLE REMOTE\n\nlast\n");
	r.cm.replaceLine(5, "LAST LATE");
	release();
	await saving;
	assert.equal(r.cm.getText(), "FIRST\n\nMIDDLE REMOTE\n\nLAST LATE\n", "反例里这里得到 FIRST/MIDDLE REMOTE/last——LAST LATE 被覆盖");
});
