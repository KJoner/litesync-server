// W4 / W5（RC-3）网页端的原子恢复请求：一次 PUT 带期望的墓碑 revision / 世代与固定的 operationId；
// 新世代严格大于墓碑世代与删除前内容的世代；信封不降级；路径加密仓库附 LSM1（世代 = 墓碑 + 1）；
// 断网重试复用同一份密文；各种拒绝映射成明确的结局（不把失败说成「已恢复」）。
import assert from "node:assert/strict";
import { test } from "node:test";
import * as core from "../src/vendor/litesync-core/crypto/crypto";
import { prepareRestore, RepoBinding, uploadRestore } from "../src/write";

const binding: RepoBinding = {
	vaultId: "v-1", vaultIdentity: "0123456789abcdef0123456789abcdef", keyEpoch: 1,
	repoEpoch: "ab".repeat(16), formatEpoch: 1, minimumEnvelopeVersion: 3, encrypted: true, metaMode: false,
};
const raw = core.randomBytes(32);
const vmkP = crypto.subtle.importKey("raw", raw as BufferSource, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
const it = { fileId: "c".repeat(32), deletionRevision: 7, contentGeneration: 5, metaGeneration: 2 };
const body = (b: unknown) => new Uint8Array(b as ArrayBuffer);

test("prepareRestore：新世代 = max(墓碑世代, 删除前内容世代) + 1；LSE3 AAD 绑定 fileId 与新世代", async () => {
	const vmk = await vmkP;
	const p = await prepareRestore(binding, { vmk }, it, "回收/a.md", new TextEncoder().encode("删除前的内容"), { envelope: "LSE3", padded: false, generation: 5 });
	assert.equal(p.generation, 6);
	assert.equal(p.pseudonym, "回收/a.md");
	const out = await core.decryptFileV3(vmk, p.payload.buffer.slice(0) as ArrayBuffer, binding.vaultIdentity, it.fileId, 1);
	assert.equal(out?.generation, 6);
	assert.equal(new TextDecoder().decode(out!.plain), "删除前的内容");
	const q = await prepareRestore(binding, { vmk }, it, "回收/a.md", new Uint8Array([1]), { envelope: "LSE3", padded: false, generation: 9 });
	assert.equal(q.generation, 10, "删除前内容的世代更高时以它为下限");
});

test("prepareRestore：LSE4 对象保持 LSE4 与填充标记（不降级）", async () => {
	const vmk = await vmkP;
	const p = await prepareRestore(binding, { vmk }, it, "a.md", new TextEncoder().encode("x"), { envelope: "LSE4", padded: true, generation: 5 });
	assert.equal(p.envelope, "LSE4");
	assert.ok(core.isLse4Envelope(p.payload.buffer.slice(0) as ArrayBuffer));
	assert.ok(p.payload.length >= 4096, "填充对象落在桶边界");
});

test("prepareRestore：路径加密仓库附 LSM1（metaGeneration = 墓碑 + 1、寻址名 = fileId、canonical HMAC）", async () => {
	const vmk = await vmkP;
	const meta = await core.deriveMetaKeys(raw);
	const b = { ...binding, metaMode: true, formatEpoch: 2 };
	const p = await prepareRestore(b, { vmk, meta }, it, "私密/改名后.md", new TextEncoder().encode("c"), { envelope: "LSE3", padded: false, generation: 5 });
	assert.equal(p.pseudonym, it.fileId);
	assert.equal(p.meta?.metaGeneration, 3);
	const dec = await core.decryptMeta(meta, p.meta!.metaEnc, b.vaultIdentity, it.fileId);
	assert.equal(dec?.meta.path, "私密/改名后.md");
	assert.equal(dec?.metaGeneration, 3);
	assert.equal(p.meta?.canonicalHash, await core.canonicalPathHmac(meta, "私密/改名后.md"));
	await assert.rejects(prepareRestore(b, { vmk }, it, "x.md", new Uint8Array([1]), { envelope: "LSE3", padded: false, generation: 1 }), /元数据密钥/);
});

test("uploadRestore：一次 PUT、头部齐全；断网重试复用同一 operationId 与同一份密文；拒绝映射成明确结局", async () => {
	const vmk = await vmkP;
	const p = await prepareRestore(binding, { vmk }, it, "回收/a.md", new TextEncoder().encode("v"), { envelope: "LSE3", padded: false, generation: 5 });
	const seen: { url: string; method?: string; h: Record<string, string>; body: string }[] = [];
	let respond: () => Response | Promise<Response> = () => {
		throw new TypeError("network down");
	};
	const fakeFetch = async (url: string, init?: RequestInit) => {
		seen.push({ url, method: init?.method, h: init!.headers as Record<string, string>, body: Buffer.from(body(init!.body)).toString("base64") });
		return respond();
	};
	assert.equal((await uploadRestore(binding, p, fakeFetch)).kind, "offline");
	respond = () => new Response(JSON.stringify({ fileId: it.fileId, path: "回收/a.md", revision: 8, contentGeneration: 6, metaGeneration: 3, replayed: true }), { status: 200 });
	const ok = await uploadRestore(binding, p, fakeFetch);
	assert.deepEqual(ok, { kind: "restored", fileId: it.fileId, path: "回收/a.md", revision: 8, generation: 6, metaGeneration: 3, replayed: true });
	assert.equal(seen[0].url, `/api/v1/files/${it.fileId}/restore`);
	assert.equal(seen[0].method, "PUT");
	assert.equal(seen[0].h["X-Expected-Tombstone-Revision"], "7");
	assert.equal(seen[0].h["X-Expected-Tombstone-Generation"], "5");
	assert.equal(seen[0].h["X-File-Path"], encodeURIComponent("回收/a.md"));
	assert.equal(seen[0].h["X-Content-Hash"], p.cipherHash);
	assert.equal(seen[0].h["X-Operation-Id"], seen[1].h["X-Operation-Id"], "重试必须复用同一个 operationId");
	assert.equal(seen[0].body, seen[1].body, "重试必须复用同一份密文");
	const cases: [number, Record<string, unknown>, string][] = [
		[401, { code: "UNAUTHORIZED" }, "auth"],
		[429, { code: "RATE_LIMITED" }, "offline"],
		[503, { code: "INTERNAL" }, "offline"],
		[412, { code: "STALE_REVISION" }, "changed"],
		[409, { code: "CONFLICT", deleted: false }, "changed"],
		[409, { code: "TOMBSTONE_PURGED" }, "changed"],
		[422, { code: "CANONICAL_COLLISION", existing: "回收/A.md" }, "collision"],
		[413, { code: "QUOTA_EXCEEDED", details: { limit: 10 } }, "rejected"],
	];
	for (const [status, b, kind] of cases) {
		respond = () => new Response(JSON.stringify(b), { status });
		const out = await uploadRestore(binding, p, fakeFetch);
		assert.equal(out.kind, kind, `${status} ${JSON.stringify(b)}`);
		if (out.kind === "collision") assert.equal(out.existing, "回收/A.md");
		if (out.kind === "rejected") assert.equal(out.code, "QUOTA_EXCEEDED");
	}
	respond = () => new Response(JSON.stringify({ fileId: "d".repeat(32), path: "x", revision: 1 }), { status: 200 });
	const bad = await uploadRestore(binding, p, fakeFetch);
	assert.equal(bad.kind === "rejected" && bad.code, "FILE_ID_MISMATCH", "服务器恢复的不是请求的对象：拒绝采纳");
});
