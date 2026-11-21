// RC-1（审查 §7「必须补测」第 1 项）：IndexedDB 草稿后端只在事务**提交完成**（oncomplete）后报告成功；
// 事务中止（提交时配额已满）、请求回调里同步抛出的 QuotaExceededError 一律报告失败，不误报「已落盘」。
//
// Node 没有 IndexedDB：这里用一个按规范事件顺序建模的最小替身（请求成功在微任务里触发、
// 全部请求结束后才提交、回调里抛异常 → 事务中止、可注入「提交时中止」）。真实 Chromium 下的
// 同类故障注入（put 直接抛 QuotaExceededError）在 e2e/suites/edit.ts 的 8b。
import assert from "node:assert/strict";
import { test } from "node:test";
import { DraftRecord, indexedDbBackend } from "../src/write";

interface FakeOpts {
	/** put() 同步抛 QuotaExceededError（浏览器在写入时即发现配额不足） */
	failPut: boolean;
	/** 请求都成功，但提交时事务中止（error = QuotaExceededError） */
	abortAtCommit: boolean;
}

function installFakeIndexedDB(opts: FakeOpts): Map<string, DraftRecord> {
	const data = new Map<string, DraftRecord>();
	class Req {
		result: unknown;
		error: unknown = null;
		onsuccess: (() => void) | null = null;
		onerror: (() => void) | null = null;
		onupgradeneeded: (() => void) | null = null;
	}
	class Tx {
		oncomplete: (() => void) | null = null;
		onabort: (() => void) | null = null;
		onerror: (() => void) | null = null;
		error: unknown = null;
		private pending = 0;
		private writes: (() => void)[] = [];
		private state: "active" | "done" | "aborted" = "active";
		objectStore() {
			const tx = this; // eslint-disable-line @typescript-eslint/no-this-alias
			return {
				get transaction() {
					return tx;
				},
				get: (k: string) => tx.request(() => data.get(k)),
				getAllKeys: () => tx.request(() => [...data.keys()]),
				put: (v: DraftRecord, k: string) => {
					if (opts.failPut) throw new DOMException("模拟：存储配额已满", "QuotaExceededError");
					return tx.request(() => void tx.writes.push(() => data.set(k, v)));
				},
				delete: (k: string) => tx.request(() => void tx.writes.push(() => data.delete(k))),
			};
		}
		request(fn: () => unknown): Req {
			const r = new Req();
			this.pending++;
			queueMicrotask(() => {
				if (this.state !== "active") return;
				r.result = fn();
				this.pending--;
				try {
					r.onsuccess?.();
				} catch (e) {
					this.fail(e); // 规范：成功事件的处理器抛出异常 → 事务中止
					return;
				}
				this.maybeCommit();
			});
			return r;
		}
		private maybeCommit() {
			if (this.pending > 0 || this.state !== "active") return;
			setTimeout(() => {
				if (this.state !== "active" || this.pending > 0) return;
				if (opts.abortAtCommit && this.writes.length > 0) return this.fail(new DOMException("模拟：提交时配额已满", "QuotaExceededError"));
				this.state = "done";
				for (const w of this.writes) w();
				this.oncomplete?.();
			}, 0);
		}
		abort() {
			this.fail(null);
		}
		private fail(e: unknown) {
			if (this.state !== "active") return;
			this.state = "aborted";
			this.error = e;
			this.onabort?.();
		}
	}
	const db = { transaction: () => new Tx(), createObjectStore: () => undefined };
	(globalThis as unknown as { indexedDB: unknown }).indexedDB = {
		open: () => {
			const r = new Req();
			queueMicrotask(() => {
				r.result = db;
				r.onupgradeneeded?.();
				r.onsuccess?.();
			});
			return r;
		},
	};
	return data;
}

const rec = (v: number): DraftRecord => ({ format: "wd2", iv: "iv", ct: `ct-${v}`, savedAt: v, v });

test("IndexedDB 后端：条件写在事务提交完成后才 resolve；旧版本不覆盖新版本；compare-and-delete", async () => {
	const data = installFakeIndexedDB({ failPut: false, abortAtCommit: false });
	const be = indexedDbBackend("t1");
	const p = be.putIfNotOlder("k", rec(2));
	assert.equal(data.has("k"), false, "提交之前不算落盘");
	assert.equal(await p, true);
	assert.equal(data.get("k")?.v, 2, "resolve 时记录已经提交");
	assert.equal(await be.putIfNotOlder("k", rec(1)), false, "较旧的版本晚到：不写");
	assert.equal(data.get("k")?.v, 2);
	assert.equal(await be.deleteIfAtMost("k", 1), false, "只确认到第 1 版：第 2 版留着");
	assert.equal(data.has("k"), true);
	assert.equal(await be.deleteIfAtMost("k", 2), true);
	assert.equal(data.has("k"), false);
	assert.deepEqual(await be.keys(""), []);
});

test("IndexedDB 后端：提交时事务中止（配额已满）→ reject，记录没有写入", async () => {
	const data = installFakeIndexedDB({ failPut: false, abortAtCommit: true });
	const be = indexedDbBackend("t2");
	await assert.rejects(be.putIfNotOlder("k", rec(1)), (e: unknown) => e instanceof DOMException && e.name === "QuotaExceededError");
	assert.equal(data.has("k"), false);
});

test("IndexedDB 后端：put 在请求回调里同步抛出 QuotaExceededError → 事务中止并 reject（不被吞掉）", async () => {
	const data = installFakeIndexedDB({ failPut: true, abortAtCommit: false });
	const be = indexedDbBackend("t3");
	await assert.rejects(be.putIfNotOlder("k", rec(1)), (e: unknown) => e instanceof DOMException && e.name === "QuotaExceededError");
	assert.equal(data.has("k"), false);
});
