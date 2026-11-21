/**
 * 联调垫片（二进制安全）：其余 Obsidian API 取插件自己的测试替身（tests/mocks/obsidian.ts），
 * requestUrl 换成真实的 fetch——请求体可以是 ArrayBuffer，响应 arrayBuffer 是原始字节
 * （密文下载不能经过文本解码）。run.mjs 把 import "obsidian" 解析到这里。
 */
export * from "@plugin-mocks/obsidian";

export async function requestUrl(p: { url: string; method?: string; headers?: Record<string, string>; body?: string | ArrayBuffer; throw?: boolean }) {
	const r = await fetch(p.url, { method: p.method ?? "GET", headers: p.headers, body: p.body as BodyInit | undefined });
	const buf = await r.arrayBuffer();
	const text = new TextDecoder().decode(buf);
	let json: unknown = null;
	try {
		json = JSON.parse(text);
	} catch {
		/* 不是 JSON */
	}
	const headers: Record<string, string> = {};
	r.headers.forEach((v, k) => (headers[k] = v));
	if (p.throw !== false && r.status >= 400) throw new Error(`HTTP ${r.status}`);
	return { status: r.status, text, json, headers, arrayBuffer: buf };
}
