/**
 * Markdown 源码编辑器（CodeMirror 6；v0.20 公开化 / UI 规格 §3）。
 *
 * 单独打包成 /editor.js，只在用户进入编辑时加载——阅读路径不背这几百 KB。
 * 原则：Markdown 原文是唯一事实来源。
 *   - 不做任何「整篇格式化」：打开、预览、保存都不会重排原文；
 *   - 位置一律用文档 position（W6）：文档内部按任意换行切行、一个换行恒为 1 个 position；
 *     换行风格只在序列化时体现——纯 CRLF 原文按 CRLF 写回，其余按 LF；
 *   - 没有真实编辑（含编辑后撤销回原样）时 getText() 原样返回原文字节（混用换行、BOM 不动）；
 *   - 工具栏动作只改动选区或光标所在行；输入法组合输入期间不执行任何程序化替换
 *     （合并结果等组合结束再套用，见 whenNotComposing）。
 */
import { Compartment, EditorState } from "@codemirror/state";
import { drawSelection, EditorView, highlightActiveLine, keymap, placeholder } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { markdown } from "@codemirror/lang-markdown";
import { defaultHighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { highlightSelectionMatches, search, searchKeymap } from "@codemirror/search";
import { StyleModule } from "style-mod";
import { Baseline, diffSpec, insertSpec, prefixSpec, wrapSpec } from "./editor-core";

/**
 * CSP 兼容：本站 CSP 是 `style-src 'self'`（不允许内联 <style>）。CodeMirror 的主题由
 * style-mod 注入，对 Document 根默认插一个 <style> 标签——会被 CSP 拦掉（实测：基础主题、
 * 自动换行、光标层定位全部失效）。这里不给 CSP 开 'unsafe-inline'，而是让 style-mod 走
 * Constructable Stylesheets（document.adoptedStyleSheets）：样式以 CSSOM 方式安装，
 * 不受 style-src 限制。做法是给它一个「没有 head、转发 adoptedStyleSheets 的根」，
 * 它就会选择自己现成的 adoptedStyleSheets 分支，规则顺序等逻辑完全不变。
 * 不支持的旧浏览器保持原逻辑（样式被拦时，styles.css 里的 .cm-* 兜底规则保证可用）。
 */
function installCspSafeStyles(): void {
	const doc = document as Document & { adoptedStyleSheets?: CSSStyleSheet[] };
	if (!Array.isArray(doc.adoptedStyleSheets) || typeof CSSStyleSheet === "undefined" || !("replaceSync" in CSSStyleSheet.prototype)) return;
	const root = {
		ownerDocument: document,
		get adoptedStyleSheets(): CSSStyleSheet[] {
			return doc.adoptedStyleSheets!;
		},
		set adoptedStyleSheets(v: CSSStyleSheet[]) {
			doc.adoptedStyleSheets = v;
		},
	};
	const mount = StyleModule.mount.bind(StyleModule);
	StyleModule.mount = (r, modules, options) => mount((r === document ? root : r) as unknown as Document, modules, options);
}
installCspSafeStyles();

export interface EditorOptions {
	onChange(text: string): void;
	onSave(): void;
	/** 粘贴 / 拖入文件（附件上传）；不提供时交给浏览器默认行为 */
	onFiles?(files: File[]): void;
}

export interface EditorHandle {
	/** 要保存的文本：没有真实编辑时原样返回基准原文。 */
	getText(): string;
	/** 文档修改计数（每次 docChanged +1，含程序化修改）：异步结果据此判断「期间有没有新输入」。 */
	version(): number;
	/** 载入新的基准原文（远端新版本 / 刚保存的内容），整体替换。 */
	load(text: string): void;
	/** 把文档改成 text（合并结果、恢复的草稿）：只替换差异部分，作为一次可撤销的修改；基准不变。 */
	applyText(text: string): void;
	focus(): void;
	destroy(): void;
	isComposing(): boolean;
	/** 输入法组合结束后 resolve（没有组合时立即 resolve）。 */
	whenNotComposing(): Promise<void>;
	/** 只读（保留双方上传冲突副本期间）：用户输入被拒绝而不是被吞掉。 */
	setReadOnly(readOnly: boolean): void;
	wrap(before: string, after: string, placeholderText: string): void;
	prefixLines(prefix: string): void;
	insert(text: string): void;
}

const theme = EditorView.theme({
	"&": { backgroundColor: "var(--bg)", color: "var(--text)", fontSize: "15px", height: "100%" },
	".cm-content": { fontFamily: "ui-monospace, SFMono-Regular, Consolas, 'Microsoft YaHei', monospace", lineHeight: "1.7", padding: "16px 0", caretColor: "var(--accent)" },
	".cm-line": { padding: "0 4px" },
	"&.cm-focused": { outline: "none" },
	".cm-activeLine": { backgroundColor: "var(--accent-dim)" },
	".cm-selectionBackground, &.cm-focused .cm-selectionBackground": { backgroundColor: "var(--accent-dim) !important" },
	".cm-cursor": { borderLeftColor: "var(--accent)" },
	".cm-panels": { backgroundColor: "var(--bg-panel)", color: "var(--text)" },
	".cm-searchMatch": { backgroundColor: "rgba(232,164,59,0.35)" },
	".cm-scroller": { overflow: "auto" },
});

export function createEditor(parent: HTMLElement, text: string, opts: EditorOptions): EditorHandle {
	let baseline: Baseline;
	let version = 0;
	const readOnly = new Compartment();
	const view = new EditorView({
		parent,
		state: EditorState.create({
			doc: text,
			extensions: [
				readOnly.of([]),
				history(),
				drawSelection(),
				highlightActiveLine(),
				EditorView.lineWrapping,
				markdown(),
				syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
				search({ top: true }),
				highlightSelectionMatches(),
				placeholder("开始写作…"),
				keymap.of([
					{ key: "Mod-s", preventDefault: true, run: () => (opts.onSave(), true) },
					indentWithTab,
					...defaultKeymap,
					...historyKeymap,
					...searchKeymap,
				]),
				EditorView.updateListener.of((u) => {
					if (!u.docChanged) return;
					version++;
					opts.onChange(baseline.serialize(u.state.doc));
				}),
				EditorView.domEventHandlers({
					paste: (e) => {
						const files = Array.from(e.clipboardData?.files ?? []);
						if (files.length === 0 || !opts.onFiles) return false;
						e.preventDefault();
						opts.onFiles(files);
						return true;
					},
					drop: (e, v) => {
						const files = Array.from(e.dataTransfer?.files ?? []);
						if (files.length === 0 || !opts.onFiles) return false;
						e.preventDefault();
						// 光标放到落点，引用插在用户松手的位置
						const pos = v.posAtCoords({ x: e.clientX, y: e.clientY });
						if (pos !== null) v.dispatch({ selection: { anchor: pos } });
						opts.onFiles(files);
						return true;
					},
				}),
				EditorView.contentAttributes.of({ "aria-label": "Markdown 编辑区", spellcheck: "false" }),
				theme,
			],
		}),
	});
	baseline = Baseline.of(view.state, text);

	const guard = () => !view.composing; // 输入法组合期间不做任何程序化替换

	return {
		getText: () => baseline.serialize(view.state.doc),
		version: () => version,
		load: (t) => {
			// 先换基准再派发：updateListener 里序列化出来的就是 t 本身（内容相同的文档 eq 成立）
			baseline = new Baseline(t, view.state.toText(t));
			const spec = diffSpec(view.state, t, "input.load");
			if (spec) view.dispatch(spec);
		},
		applyText: (t) => {
			const spec = diffSpec(view.state, t);
			if (spec) view.dispatch(spec);
		},
		focus: () => view.focus(),
		destroy: () => view.destroy(),
		isComposing: () => view.composing,
		whenNotComposing: () =>
			new Promise<void>((resolve) => {
				const tick = () => (view.composing ? setTimeout(tick, 50) : resolve());
				tick();
			}),
		setReadOnly: (ro) => {
			view.dispatch({ effects: readOnly.reconfigure(ro ? [EditorState.readOnly.of(true), EditorView.editable.of(false)] : []) });
		},
		wrap: (before, after, ph) => {
			if (!guard()) return;
			view.dispatch(wrapSpec(view.state, before, after, ph));
			view.focus();
		},
		prefixLines: (prefix) => {
			if (!guard()) return;
			view.dispatch(prefixSpec(view.state, prefix));
			view.focus();
		},
		insert: (t) => {
			if (!guard()) return;
			view.dispatch(insertSpec(view.state, t));
			view.focus();
		},
	};
}

(globalThis as unknown as { LiteSyncEditor: { createEditor: typeof createEditor } }).LiteSyncEditor = { createEditor };
