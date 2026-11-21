/**
 * 大小混淆的填充桶（v0.17 / 计划书 §11.1）。
 *
 * # 精确大小本身就是内容
 *
 * E2EE 之后服务器读不到内容，但它一直看得到每个对象的**精确字节数**，
 * 而且看得到它每次修改后的变化。这比直觉上更有信息量：
 *
 *   - 一份公开文档（合同模板、泄露的文件、某本书的某一版）字节数是已知的，
 *     命中即确认；
 *   - 同一个对象的大小序列（1832 → 1847 → 1901）画出的是编辑节奏，
 *     谁在什么时候写了多少；
 *   - 附件的精确大小往往足以在一个候选集合里唯一定位。
 *
 * 把大小对齐到桶边界，上面三件事全部退化成「落在某个区间里」。
 *
 * # 桶怎么选
 *
 * 两个极端都不可取：桶太粗（比如一律 2 的幂）最坏浪费接近 100%；
 * 桶太细则几乎不混淆任何东西。这里取
 *
 *     bucket(n) = 大于等于 n 的最小的 (8+i)/8 × 2^k，i ∈ [0, 7]
 *
 * 也就是每个二进制量级里再切 8 档。最坏开销 1/8 = 12.5%，
 * 而每个桶仍然覆盖一个足够宽的区间（例如 1MB 附近的桶宽 128KB，
 * 意味着 13 万种可能的精确大小被压成同一个观测值）。
 *
 * 另加一条下限：小于 MIN_BUCKET 的一律填到 MIN_BUCKET。
 * 笔记类文件绝大多数都很小，没有这条下限的话，
 * 小文件之间的相对差异反而是最容易辨认的。
 *
 * # 成本（必须说清楚，§11.1 第 3 条）
 *
 *   - 存储与流量：单个对象最坏 +12.5%；小于 4KB 的对象按 4KB 计，
 *     一个 200 字节的笔记会占 4KB。以「几千个小笔记」的典型仓库估算，
 *     整体膨胀主要来自下限而不是桶，量级是几十 MB。
 *   - 去重：填充在密文内部，同一份内容仍然得到同一个密文长度，
 *     Vault 内去重不受影响。
 *   - 增量：本项目本来就是整文件上传，没有块级增量可损失。
 *
 * 因此这是一个**可选**功能：默认关闭，由用户对高敏目录显式开启。
 * 替用户默默多花 12.5% 的空间不是我们该做的决定。
 */

/** 填充下限：低于此值的对象一律填到这么大。 */
export const MIN_BUCKET = 4096;

/** 每个二进制量级切几档（8 档 → 最坏开销 1/8）。 */
const STEPS_PER_OCTAVE = 8;

/**
 * 最大可填充长度。
 *
 * 明文框里用 u64 记真实长度，但 JS 的安全整数是 2^53；
 * 这里定在 2^40（1TiB），远超任何笔记仓库里的单文件，
 * 同时给桶计算留足余量不会溢出。
 */
export const MAX_PADDED_LENGTH = 2 ** 40;

/**
 * 返回不小于 n 的桶大小。
 *
 * n <= 0 时返回 MIN_BUCKET——空文件也要占一个桶，
 * 否则「这个对象是空的」本身就泄露了。
 */
export function bucketSize(n: number): number {
	if (!Number.isFinite(n) || n < 0) throw new RangeError(`bucketSize: 非法长度 ${n}`);
	if (n > MAX_PADDED_LENGTH) throw new RangeError(`bucketSize: 超过可填充上限 ${n}`);
	if (n <= MIN_BUCKET) return MIN_BUCKET;

	// 所在的二进制量级：2^octave <= n < 2^(octave+1)
	const octave = Math.floor(Math.log2(n));
	const step = 2 ** octave / STEPS_PER_OCTAVE;
	const bucket = Math.ceil(n / step) * step;
	// log2 的浮点误差可能让 bucket 落在 n 之下一点点；直接往上补一档
	return bucket < n ? bucket + step : bucket;
}

/** 帧头长度：真实长度用 u64 大端记在明文最前面。 */
export const FRAME_HEADER_LEN = 8;

/**
 * 把内容装进定长帧：`trueLength(u64 BE) | content | 零填充`。
 *
 * padded=false 时不填充（帧仍然存在），用于「这个对象不需要混淆」的场景——
 * 保持单一格式比按情况切换两种明文布局要安全得多。
 */
export function frame(content: ArrayBuffer, padded: boolean): ArrayBuffer {
	const len = content.byteLength;
	if (len > MAX_PADDED_LENGTH) throw new RangeError(`frame: 内容过大 ${len}`);
	const total = padded ? bucketSize(len + FRAME_HEADER_LEN) : len + FRAME_HEADER_LEN;
	const out = new Uint8Array(total);
	new DataView(out.buffer).setBigUint64(0, BigInt(len), false);
	out.set(new Uint8Array(content), FRAME_HEADER_LEN);
	return out.buffer;
}

/**
 * 从帧里取回原始内容；帧不合法返回 null。
 *
 * 这里的校验不是形式主义：帧头已经过 AES-GCM 认证，所以长度对不上
 * 只可能是我们自己写错了。返回 null 而不是抛异常，是为了让调用方
 * 走「这份密文读不出来」的既有分支，而不是让同步整轮崩掉。
 */
export function unframe(framed: ArrayBuffer): ArrayBuffer | null {
	if (framed.byteLength < FRAME_HEADER_LEN) return null;
	const len = new DataView(framed).getBigUint64(0, false);
	if (len > BigInt(MAX_PADDED_LENGTH)) return null;
	const n = Number(len);
	if (FRAME_HEADER_LEN + n > framed.byteLength) return null;
	return framed.slice(FRAME_HEADER_LEN, FRAME_HEADER_LEN + n);
}

/** 估算某个大小在开启填充后的膨胀比例（设置页展示成本用）。 */
export function paddingOverhead(n: number): number {
	if (n <= 0) return Infinity;
	return bucketSize(n + FRAME_HEADER_LEN) / n - 1;
}
