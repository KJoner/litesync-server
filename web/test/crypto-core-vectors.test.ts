// crypto-core 冻结向量（ADR-015）：Web 端用 vendor 进来的插件源码跑插件生成的同一份向量，
// 并核对 Web 旧有的只读解密实现（src/crypto.ts）与之一致——网页建库/写入产出的密文
// 插件解得开、插件产出的密文网页解得开，靠的就是这一组断言。
import assert from "node:assert/strict";
import { test } from "node:test";
import vectorsJson from "../src/vendor/litesync-core/test-vectors/crypto-core-v1.json";
import * as core from "../src/vendor/litesync-core/crypto/crypto";
import * as webCrypto from "../src/crypto";

const V = vectorsJson as unknown as {
	password: string;
	vmkHex: string;
	keyDoc: core.VaultKeyDoc;
	binding: { vaultIdentity: string; keyEpoch: number; fileId: string };
	files: { label: string; envelope: string; generation: number; plaintextB64: string; ciphertextB64: string }[];
	meta: { fileId: string; path: string; lsm1B64: string }[];
	resetAuthHex: string;
};

const hex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const ab = (b64: string) => {
	const u = core.b64decode(b64);
	return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
};

test("vendor 核心：冻结 keyDoc 解出同一把 VMK；Web 旧实现结果一致", async () => {
	const vmk = await core.unlockVaultKey(V.keyDoc, V.password);
	assert.ok(vmk);
	assert.equal(hex(await core.exportVmkRaw(vmk)), V.vmkHex);
	const raw = await webCrypto.unlockVaultKey(V.keyDoc, V.password);
	assert.ok(raw);
	assert.equal(hex(raw), V.vmkHex);
	assert.equal(await webCrypto.unlockVaultKey(V.keyDoc, "wrong password"), null);
});

test("vendor 核心与 Web 旧实现：LSE3/LSE4 解密结果一致", async () => {
	const vmk = await core.unlockVaultKey(V.keyDoc, V.password);
	assert.ok(vmk);
	const webVmk = await webCrypto.importVmk((await webCrypto.unlockVaultKey(V.keyDoc, V.password))!);
	const { vaultIdentity, keyEpoch, fileId } = V.binding;
	for (const f of V.files) {
		const ct = ab(f.ciphertextB64);
		const viaCore = f.envelope === "LSE3"
			? await core.decryptFileV3(vmk, ct, vaultIdentity, fileId, keyEpoch)
			: await core.decryptFileV4(vmk, ct, vaultIdentity, fileId, keyEpoch);
		assert.ok(viaCore, f.label);
		const viaWeb = await webCrypto.decryptFile(webVmk, "ignored.md", ct, { vaultId: vaultIdentity, keyEpoch }, fileId);
		assert.ok(viaWeb, f.label);
		assert.equal(Buffer.from(viaCore.plain).toString("base64"), f.plaintextB64);
		assert.equal(Buffer.from(viaWeb).toString("base64"), f.plaintextB64);
		assert.deepEqual(webCrypto.lse3Header(ct), { keyEpoch, generation: f.generation });
	}
});

test("vendor 核心与 Web 旧实现：LSM1 路径与重置凭证一致", async () => {
	const raw = (await webCrypto.unlockVaultKey(V.keyDoc, V.password))!;
	const webKeys = await webCrypto.deriveMetaKeys(raw);
	const coreKeys = await core.deriveMetaKeys(raw);
	for (const m of V.meta) {
		assert.equal((await webCrypto.decryptMeta(webKeys, m.lsm1B64, V.binding.vaultIdentity, m.fileId))?.path, m.path);
		assert.equal((await core.decryptMeta(coreKeys, m.lsm1B64, V.binding.vaultIdentity, m.fileId))?.meta.path, m.path);
	}
	assert.equal(await webCrypto.deriveResetAuth(raw), V.resetAuthHex);
	assert.equal(await core.deriveResetAuth(raw), V.resetAuthHex);
});

test("Web 建库：vendor 核心新生成的 keyDoc 形状满足服务端校验，且双实现都能解锁", async () => {
	const pw = "另一个仓库密码 · 2026";
	const { doc, vmk } = await core.createVaultKeyDoc(pw);
	const committed = { ...doc, enabled: true };
	// 与服务端 sync.ValidateKeyDoc 的规则逐条对应
	assert.equal(committed.version, 1);
	assert.equal(committed.kdf, "pbkdf2-sha256");
	assert.ok(committed.iterations >= 600_000 && committed.iterations <= 10_000_000);
	assert.ok(core.b64decode(committed.salt).length >= 16);
	assert.equal(core.b64decode(committed.iv).length, 12);
	assert.equal(core.b64decode(committed.wrappedKey).length, 48);
	assert.equal(typeof committed.createdAt, "number");
	const a = await core.exportVmkRaw(vmk);
	const b = await webCrypto.unlockVaultKey(committed, pw);
	assert.ok(b);
	assert.equal(hex(a), hex(b));
	// 每次建库都是全新的随机 VMK 与盐：两次建库绝不共享密钥
	const second = await core.createVaultKeyDoc(pw);
	assert.notEqual(second.doc.salt, doc.salt);
	assert.notEqual(hex(await core.exportVmkRaw(second.vmk)), hex(a));
});
