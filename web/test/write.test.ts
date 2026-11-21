// 网页写端协议层（ADR-015）：信封不降级、世代单调、meta 模式、幂等重试、CAS 冲突、三方合并、加密草稿隔离。
import assert from "node:assert/strict";
import { test } from "node:test";
import * as core from "../src/vendor/litesync-core/crypto/crypto";
import {
	attachmentLink,
	attachmentPath,
	conflictCopyPath,
	deleteFile,
	deriveDraftKey,
	DraftStore,
	memoryBackend,
	mergeTexts,
	newTrackedFile,
	prepareUpload,
	RepoBinding,
	restoreTombstone,
	sanitizeFileName,
	TrackedFile,
	uploadPrepared,
} from "../src/write";

const enc = new TextEncoder();
const dec = new TextDecoder();
const binding: RepoBinding = {
	vaultId: "v-test", vaultIdentity: "0123456789abcdef0123456789abcdef", keyEpoch: 1,
	repoEpoch: "ab".repeat(16), formatEpoch: 1, minimumEnvelopeVersion: 3, encrypted: true, metaMode: false,
};
const raw = core.randomBytes(32);
const vmkP = crypto.subtle.importKey("raw", raw as BufferSource, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

function file(over: Partial<TrackedFile> = {}): TrackedFile {
	return { path: "日记/今天.md", serverPath: "日记/今天.md", fileId: core.newFileId(), revision: 3, generation: 5, envelope: "LSE3", padded: false, metaGeneration: 0, ...over };
}

test("prepareUpload：LSE3、世代 +1、AAD 绑定仓库身份与 fileId", async () => {
	const vmk = await vmkP;
	const f = file();
	const p = await prepareUpload(binding, { vmk }, f, enc.encode("# 标题\n正文"));
	assert.equal(p.generation, 6);
	assert.ok(core.isLse3Envelope(p.payload.buffer.slice(0) as ArrayBuffer));
	const out = await core.decryptFileV3(vmk, p.payload.buffer.slice(0) as ArrayBuffer, binding.vaultIdentity, f.fileId, 1);
	assert.ok(out);
	assert.equal(out.generation, 6);
	assert.equal(dec.decode(out.plain), "# 标题\n正文");
	assert.equal(await core.decryptFileV3(vmk, p.payload.buffer.slice(0) as ArrayBuffer, "ffffffffffffffffffffffffffffffff", f.fileId, 1), null);
});

test("prepareUpload：LSE4 对象不降级，保持填充标记（INV-07）", async () => {
	const vmk = await vmkP;
	const f = file({ envelope: "LSE4", padded: true });
	const p = await prepareUpload(binding, { vmk }, f, enc.encode("x"));
	const buf = p.payload.buffer.slice(0) as ArrayBuffer;
	assert.ok(core.isLse4Envelope(buf));
	assert.ok(p.payload.length >= 4096, "填充对象应落在桶边界");
	const out = await core.decryptFileV4(vmk, buf, binding.vaultIdentity, f.fileId, 1);
	assert.equal(out && dec.decode(out.plain), "x");
});

test("prepareUpload：路径加密仓库的新文件附带 LSM1 元数据（服务器只见 fileId）", async () => {
	const vmk = await vmkP;
	const meta = await core.deriveMetaKeys(raw);
	const b = { ...binding, metaMode: true, formatEpoch: 2 };
	const f = newTrackedFile("私密/计划.md", b);
	assert.equal(f.serverPath, f.fileId);
	const p = await prepareUpload(b, { vmk, meta }, f, enc.encode("内容"));
	assert.ok(p.meta);
	const m = await core.decryptMeta(meta, p.meta.metaEnc, b.vaultIdentity, f.fileId);
	assert.equal(m?.meta.path, "私密/计划.md");
	assert.equal(p.meta.canonicalHash, await core.canonicalPathHmac(meta, "私密/计划.md"));
});

test("uploadPrepared：重试复用同一 operationId 与同一份密文；冲突与身份不符被识别", async () => {
	const vmk = await vmkP;
	const f = file();
	const p = await prepareUpload(binding, { vmk }, f, enc.encode("v2"));
	const seen: { op: string; hash: string; body: string }[] = [];
	let mode: "drop" | "ok" | "conflict" | "mismatch" = "drop";
	const fakeFetch = async (_url: string, init?: RequestInit) => {
		const h = init!.headers as Record<string, string>;
		seen.push({ op: h["X-Operation-Id"], hash: h["X-Content-Hash"], body: Buffer.from(init!.body as Uint8Array).toString("base64") });
		assert.equal(h["X-Base-Revision"], "3");
		assert.equal(h["X-File-Id"], f.fileId);
		assert.equal(h["X-Vault-ID"], "v-test");
		if (mode === "drop") throw new TypeError("network down");
		if (mode === "conflict") return new Response(JSON.stringify({ code: "CONFLICT", revision: 9, hash: "h", deleted: false }), { status: 409 });
		if (mode === "mismatch") return new Response(JSON.stringify({ revision: 4, hash: p.cipherHash, fileId: "00".repeat(16) }), { status: 200 });
		return new Response(JSON.stringify({ revision: 4, hash: p.cipherHash, fileId: f.fileId, contentGeneration: 6 }), { status: 200 });
	};
	assert.equal((await uploadPrepared(binding, f, p, fakeFetch)).kind, "offline");
	mode = "ok";
	const ok = await uploadPrepared(binding, f, p, fakeFetch);
	assert.deepEqual(ok, { kind: "saved", revision: 4, generation: 6, fileId: f.fileId, hash: p.cipherHash });
	assert.equal(seen[0].op, seen[1].op, "重试必须复用同一个 operationId");
	assert.equal(seen[0].body, seen[1].body, "重试必须复用同一份密文（同 ID 换载荷是协议禁止的）");
	mode = "conflict";
	const c = await uploadPrepared(binding, f, p, fakeFetch);
	assert.equal(c.kind, "conflict");
	assert.equal(c.kind === "conflict" && c.revision, 9);
	mode = "mismatch";
	assert.equal((await uploadPrepared(binding, f, p, fakeFetch)).kind, "rejected");
});

test("mergeTexts：不同段落干净合并；同一行冲突与无 base 都不假装能合并", () => {
	const base = "# 标题\n\n第一段\n\n第二段\n";
	const local = "# 标题\n\n第一段（网页改）\n\n第二段\n";
	const remote = "# 标题\n\n第一段\n\n第二段（插件改）\n";
	const m = mergeTexts(base, local, remote);
	assert.ok(m.clean);
	assert.equal(m.clean && m.text, "# 标题\n\n第一段（网页改）\n\n第二段（插件改）\n");
	assert.equal(mergeTexts(base, base.replace("第一段", "A"), base.replace("第一段", "B")).clean, false);
	assert.equal(mergeTexts(null, "a", "b").clean, false);
	assert.match(conflictCopyPath("笔记/计划.md", new Date(2026, 10, 21, 9, 5)), /^笔记\/计划（网页冲突副本 2026-11-21 0905）\.md$/);
});

test("加密草稿：只存密文；换账号/换密钥/篡改都读不出；命名空间隔离", async () => {
	const backend = memoryBackend();
	const key = await deriveDraftKey(raw);
	const alice = new DraftStore(backend, "https://sync.example|u-alice|v-1", key, "identity|1");
	const f = file();
	await alice.save(f.fileId, "ed1", 1, { text: "秘密草稿", baseText: "旧", baseRevision: 3, path: f.path, file: f });
	for (const rec of backend.dump().values()) {
		assert.ok(!JSON.stringify(rec).includes("秘密草稿") && !JSON.stringify(rec).includes("今天"), "草稿记录里不能出现明文正文或路径");
	}
	assert.equal((await alice.loadAll(f.fileId))[0]?.text, "秘密草稿");
	const bob = new DraftStore(backend, "https://sync.example|u-bob|v-1", key, "identity|1");
	assert.deepEqual(await bob.loadAll(f.fileId), [], "另一个账号的命名空间里没有这份草稿");
	assert.deepEqual(await bob.listFiles(), []);
	const other = new DraftStore(backend, "https://sync.example|u-alice|v-1", await deriveDraftKey(core.randomBytes(32)), "identity|1");
	assert.deepEqual(await other.loadAll(f.fileId), [], "别的仓库密钥解不开");
	const rotated = new DraftStore(backend, "https://sync.example|u-alice|v-1", key, "identity|2");
	assert.deepEqual(await rotated.loadAll(f.fileId), [], "密钥世代变化后旧草稿不再自动重放");
	const k = [...backend.dump().keys()][0];
	const rec = backend.dump().get(k)!;
	const ct = core.b64decode(rec.ct);
	ct[3] ^= 1;
	backend.dump().set(k, { ...rec, ct: core.b64encode(ct) });
	assert.deepEqual(await alice.loadAll(f.fileId), [], "被篡改的草稿解不开");
	backend.dump().set(k, { ...rec, v: 99 });
	assert.deepEqual(await alice.loadAll(f.fileId), [], "版本号绑进 AAD：改记录里的 v 同样解不开");
});

// W2（RC-1）：草稿条件写 / compare-and-delete / 按编辑器实例分开
test("加密草稿：逆序完成的旧写入不覆盖新草稿；旧上传成功只删它确认的版本；两个编辑器实例互不删除", async () => {
	const backend = memoryBackend();
	const ds = new DraftStore(backend, "o|u|v", await deriveDraftKey(raw), "id|1");
	const f = file();
	const c = (text: string) => ({ text, baseText: "base", baseRevision: 3, path: f.path, file: f });
	assert.equal((await ds.save(f.fileId, "tabA", 5, c("第五版"))).stored, true);
	assert.equal((await ds.save(f.fileId, "tabA", 4, c("第四版（较早开始、较晚完成）"))).stored, false, "较早的版本晚到：不得覆盖");
	assert.equal((await ds.loadAll(f.fileId))[0].text, "第五版");
	assert.equal(await ds.removeIfAtMost(f.fileId, "tabA", 4), false, "旧上传只确认到第 4 版：第 5 版的草稿必须留着");
	assert.equal((await ds.loadAll(f.fileId)).length, 1);
	await ds.save(f.fileId, "tabB", 1, c("另一个标签页的输入"));
	assert.equal((await ds.loadAll(f.fileId)).length, 2, "同一篇笔记两个编辑器实例各有一份草稿");
	assert.equal(await ds.removeIfAtMost(f.fileId, "tabA", 5), true);
	const left = await ds.loadAll(f.fileId);
	assert.deepEqual(left.map((d) => [d.draftId, d.text]), [["tabB", "另一个标签页的输入"]], "标签一保存成功不删标签二的草稿");
	assert.equal((await ds.listFiles())[0].count, 1);
});

test("加密草稿：0.20.0 的单草稿格式（wd1）仍可读、可删", async () => {
	const backend = memoryBackend();
	const key = await deriveDraftKey(raw);
	const ns = "o|u|v";
	const f = file();
	const iv = core.randomBytes(12);
	const aad = new TextEncoder().encode(`litesync/web-draft/wd1|${ns}|${f.fileId}|id|1`);
	const body = new TextEncoder().encode(JSON.stringify({ text: "旧格式草稿", baseText: "b", baseRevision: 1, path: f.path, file: f }));
	const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource }, key, body as BufferSource));
	await backend.putIfNotOlder(`${ns}|${f.fileId}`, { format: "wd1", iv: core.b64encode(iv), ct: core.b64encode(ct), savedAt: 1 });
	const ds = new DraftStore(backend, ns, key, "id|1");
	const all = await ds.loadAll(f.fileId);
	assert.equal(all.length, 1);
	assert.equal(all[0].draftId, "legacy");
	assert.equal(all[0].text, "旧格式草稿");
	await ds.remove(f.fileId, "legacy");
	assert.equal((await ds.loadAll(f.fileId)).length, 0);
});

test("deleteFile：与插件 ApiClient.remove 同形——JSON {path, baseRevision}，CAS 冲突被识别", async () => {
	const f = file({ revision: 7 });
	let seen: { method?: string; body?: unknown; ct?: string } = {};
	let conflict = false;
	const fakeFetch = async (_url: string, init?: RequestInit) => {
		seen = { method: init!.method, body: JSON.parse(String(init!.body)), ct: (init!.headers as Record<string, string>)["Content-Type"] };
		if (conflict) return new Response(JSON.stringify({ code: "CONFLICT", revision: 8, hash: "h", deleted: false }), { status: 409 });
		return new Response(JSON.stringify({ revision: 8, sequence: 3 }), { status: 200 });
	};
	const ok = await deleteFile(binding, f, fakeFetch);
	assert.equal(ok.kind, "saved");
	assert.deepEqual(seen, { method: "DELETE", body: { path: "日记/今天.md", baseRevision: 7 }, ct: "application/json" });
	conflict = true;
	assert.equal((await deleteFile(binding, f, fakeFetch)).kind, "conflict");
});

test("附件命名：去掉 Obsidian 不允许的字符；截图改名；同名（大小写/Unicode 归一）追加序号；放在笔记所在文件夹", () => {
	assert.equal(sanitizeFileName('a/b\\c:d*e?f"g<h>i|j#k^l[m]n\u0001.png'), "a-b-c-d-e-f-g-h-i-j-k-l-m-n-.png");
	assert.equal(sanitizeFileName("...隐藏.png"), "隐藏.png");
	assert.equal(sanitizeFileName("   "), "附件");
	const taken = new Set(["笔记/图.png", "笔记/图 1.png"]);
	assert.equal(attachmentPath("笔记/日记.md", "图.png", (c) => taken.has(c)), "笔记/图 2.png");
	assert.equal(attachmentPath("笔记/日记.md", "Report.PDF", (c) => c === "笔记/report.pdf"), "笔记/Report 1.PDF");
	assert.equal(attachmentPath("根目录笔记.md", "x.txt", () => false), "x.txt");
	assert.equal(attachmentPath("a/b.md", "image.png", () => false, new Date(2026, 10, 21, 9, 5, 7)), "a/Pasted image 20261121090507.png");
	assert.equal(attachmentLink("a/图.png", true), "![[图.png]]");
	assert.equal(attachmentLink("a/图.png", false), "![[a/图.png]]");
	assert.equal(attachmentLink("a/表格.xlsx", true), "[[表格.xlsx]]");
});

test("restoreTombstone：与插件 ApiClient.restore 同形，带幂等键；服务器换对象即拒绝", async () => {
	let seen: { url?: string; body?: unknown; op?: string } = {};
	let respondId = "f".repeat(32);
	const fakeFetch = async (url: string, init?: RequestInit) => {
		seen = { url, body: JSON.parse(String(init!.body)), op: (init!.headers as Record<string, string>)["X-Operation-Id"] };
		return new Response(JSON.stringify({ fileId: respondId, path: "a.md", revision: 5, metaGeneration: 2, restored: true }), { status: 200 });
	};
	const r = await restoreTombstone(binding, "f".repeat(32), { expectedTombstoneRevision: 4, contentGeneration: 3, pseudonym: "a.md" }, "web_op1", fakeFetch);
	assert.deepEqual(r, { ok: true, fileId: "f".repeat(32), path: "a.md", revision: 5, metaGeneration: 2 });
	assert.equal(seen.url, `/api/v1/files/${"f".repeat(32)}/restore`);
	assert.deepEqual(seen.body, { metaEnc: "", canonicalHash: "", expectedTombstoneRevision: 4, contentGeneration: 3, pseudonym: "a.md" });
	assert.equal(seen.op, "web_op1");
	respondId = "e".repeat(32);
	const bad = await restoreTombstone(binding, "f".repeat(32), { expectedTombstoneRevision: 4, contentGeneration: 3, pseudonym: "a.md" }, "web_op2", fakeFetch);
	assert.equal(bad.ok, false);
});

// W5 前置（路径加密仓库）：新建后服务器记账的元数据世代是 1——客户端必须采纳，
// 否则第一次改名拿 0 做 CAS 被服务器 412 拒绝（v0.20.0 网页在路径加密仓库里的实际行为）
test("uploadPrepared：采纳服务器回报的 metaGeneration（之后改名的 CAS 以它为准）", async () => {
	const vmk = await vmkP;
	const meta = await core.deriveMetaKeys(raw);
	const b = { ...binding, metaMode: true, formatEpoch: 2 };
	const f = newTrackedFile("私密/新建.md", b);
	const p = await prepareUpload(b, { vmk, meta }, f, enc.encode("x"));
	const fakeFetch = async () => new Response(JSON.stringify({ revision: 1, hash: p.cipherHash, fileId: f.fileId, contentGeneration: 1, metaGeneration: 1 }), { status: 200 });
	const out = await uploadPrepared(b, f, p, fakeFetch);
	assert.equal(out.kind === "saved" && out.metaGeneration, 1);
});
