/** 行级 diff（Myers），供版本对比视图使用。 */

export interface DiffLine {
	type: "same" | "add" | "del";
	text: string;
}

const MAX_D = 2000;

export function diffLines(aText: string, bText: string): DiffLine[] | null {
	const a = aText.split("\n");
	const b = bText.split("\n");

	let start = 0;
	while (start < a.length && start < b.length && a[start] === b[start]) start++;
	let endA = a.length;
	let endB = b.length;
	while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
		endA--;
		endB--;
	}

	const ops = myers(a.slice(start, endA), b.slice(start, endB));
	if (ops === null) return null;

	const out: DiffLine[] = [];
	for (let i = 0; i < start; i++) out.push({ type: "same", text: a[i] });
	let ca = start;
	let cb = start;
	for (const op of ops) {
		if (op === "same") {
			out.push({ type: "same", text: a[ca] });
			ca++;
			cb++;
		} else if (op === "del") {
			out.push({ type: "del", text: a[ca] });
			ca++;
		} else {
			out.push({ type: "add", text: b[cb] });
			cb++;
		}
	}
	for (let i = endA; i < a.length; i++) out.push({ type: "same", text: a[i] });
	return out;
}

type Op = "same" | "del" | "ins";

function myers(a: string[], b: string[]): Op[] | null {
	const n = a.length;
	const m = b.length;
	if (n === 0 && m === 0) return [];
	if (n === 0) return b.map(() => "ins" as Op);
	if (m === 0) return a.map(() => "del" as Op);

	const maxD = Math.min(n + m, MAX_D);
	const offset = maxD;
	const width = 2 * maxD + 1;
	const v = new Int32Array(width);
	const trace: Int32Array[] = [];
	let found = false;
	for (let d = 0; d <= maxD; d++) {
		trace.push(v.slice());
		for (let k = -d; k <= d; k += 2) {
			let x =
				k === -d || (k !== d && v[offset + k - 1] < v[offset + k + 1])
					? v[offset + k + 1]
					: v[offset + k - 1] + 1;
			let y = x - k;
			while (x < n && y < m && a[x] === b[y]) {
				x++;
				y++;
			}
			v[offset + k] = x;
			if (x >= n && y >= m) {
				found = true;
				break;
			}
		}
		if (found) break;
	}
	if (!found) return null;

	const ops: Op[] = [];
	let x = n;
	let y = m;
	for (let d = trace.length - 1; d >= 0; d--) {
		const vd = trace[d];
		const k = x - y;
		const prevK = k === -d || (k !== d && vd[offset + k - 1] < vd[offset + k + 1]) ? k + 1 : k - 1;
		const prevX = vd[offset + prevK];
		const prevY = prevX - prevK;
		while (x > prevX && y > prevY) {
			ops.push("same");
			x--;
			y--;
		}
		if (d > 0) {
			if (x === prevX) {
				ops.push("ins");
				y--;
			} else {
				ops.push("del");
				x--;
			}
		}
		x = prevX;
		y = prevY;
	}
	return ops.reverse();
}
