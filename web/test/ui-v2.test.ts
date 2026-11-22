// UI 焕新 v2（v12.0.3 V2）：概览「最近编辑」里的相对时间。只是展示用的纯函数——今天 / 昨天给时分，
// 同一年给月日，跨年只给日期；未来时间（时钟偏差）不写成「昨天」。
import assert from "node:assert/strict";
import { test } from "node:test";
import { fmtRelative } from "../src/ui";

const at = (y: number, mo: number, d: number, h = 0, mi = 0) => new Date(y, mo - 1, d, h, mi).getTime();
const NOW = at(2026, 11, 22, 15, 30);

test("今天、昨天：带时分", () => {
	assert.equal(fmtRelative(at(2026, 11, 22, 10, 24), NOW), "今天 10:24");
	assert.equal(fmtRelative(at(2026, 11, 22, 0, 5), NOW), "今天 00:05");
	assert.equal(fmtRelative(at(2026, 11, 21, 18, 7), NOW), "昨天 18:07");
});

test("同一年更早的日子：月日 + 时分；跨年：只给年月日", () => {
	assert.equal(fmtRelative(at(2026, 11, 20, 20, 36), NOW), "11月20日 20:36");
	assert.equal(fmtRelative(at(2026, 1, 3, 9, 0), NOW), "1月3日 09:00");
	assert.equal(fmtRelative(at(2025, 3, 1, 9, 0), NOW), "2025年3月1日");
});

test("没有时间给空串；未来时间（时钟偏差）不冒充「昨天」", () => {
	assert.equal(fmtRelative(0, NOW), "");
	assert.equal(fmtRelative(at(2026, 11, 23, 8, 0), NOW), "2026年11月23日");
});
