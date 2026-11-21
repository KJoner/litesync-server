/**
 * Markdown 源码编辑器（CodeMirror 6；v0.20 公开化 / UI 规格 §3）。
 *
 * 单独打包成 /editor.js，只在用户进入编辑时加载——阅读路径不背这几百 KB。
 * 原则：Markdown 原文是唯一事实来源。
 *   - 不做任何「整篇格式化」：打开、预览、保存都不会重排原文；
 *   - 换行风格按原文保持（CRLF 文件用 CRLF 作为行分隔符，否则 CodeMirror 会统一成 LF）；
 *   - 工具栏动作只改动选区或光标所在行；输入法组合输入期间不执行任何替换。
 */
import { EditorState, Transaction } from "@codemirror/state";
import { drawSelection, EditorView, highlightActiveLine, keymap, placeholder } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { markdown } from "@codemirror/lang-markdown";
import { defaultHighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { highlightSelectionMatches, search, searchKeymap } from "@codemirror/search";
import { StyleModule } from "style-mod";

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
	getText(): string;
	/** 整体替换内容（合并远端后）；作为一次可撤销的修改。 */
	replaceAll(text: string): void;
	focus(): void;
	destroy(): void;
	isComposing(): boolean;
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
	const crlf = /\r\n/.test(text) && !/(^|[^\r])\n/.test(text); // 全文一致为 CRLF 时才按 CRLF 保持
	const view = new EditorView({
		parent,
		state: EditorState.create({
			doc: text,
			extensions: [
				crlf ? EditorState.lineSeparator.of("\r\n") : [],
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
					// sliceDoc 按配置的行分隔符拼接（CRLF 文件保持 CRLF）；doc.toString() 永远用 LF（ED-02 实测抓到）
					if (u.docChanged) opts.onChange(u.state.sliceDoc());
				}),
				EditorView.domEventHandlers({
					paste: (e) => {
						const files = Array.from(e.clipboardData?.files ?? []);
						if (files.length === 0 || !opts.onFiles) return false;
						e.preventDefault();
						opts.onFiles(files);
						return true;
					},
					drop: (e, view) => {
						const files = Array.from(e.dataTransfer?.files ?? []);
						if (files.length === 0 || !opts.onFiles) return false;
						e.preventDefault();
						// 光标放到落点，引用插在用户松手的位置
						const pos = view.posAtCoords({ x: e.clientX, y: e.clientY });
						if (pos !== null) view.dispatch({ selection: { anchor: pos } });
						opts.onFiles(files);
						return true;
					},
				}),
				EditorView.contentAttributes.of({ "aria-label": "Markdown 编辑区", spellcheck: "false" }),
				theme,
			],
		}),
	});

	const guard = () => !view.composing; // 输入法组合期间不做任何程序化替换

	return {
		getText: () => view.state.sliceDoc(),
		replaceAll: (t) => {
			view.dispatch({
				changes: { from: 0, to: view.state.doc.length, insert: t },
				annotations: Transaction.userEvent.of("input.merge"),
			});
		},
		focus: () => view.focus(),
		destroy: () => view.destroy(),
		isComposing: () => view.composing,
		wrap: (before, after, ph) => {
			if (!guard()) return;
			const r = view.state.selection.main;
			const sel = view.state.sliceDoc(r.from, r.to) || ph;
			view.dispatch({
				changes: { from: r.from, to: r.to, insert: before + sel + after },
				selection: { anchor: r.from + before.length, head: r.from + before.length + sel.length },
				userEvent: "input.format",
			});
			view.focus();
		},
		prefixLines: (prefix) => {
			if (!guard()) return;
			const r = view.state.selection.main;
			const first = view.state.doc.lineAt(r.from).number;
			const last = view.state.doc.lineAt(r.to).number;
			const changes = [];
			for (let n = first; n <= last; n++) {
				const line = view.state.doc.line(n);
				if (!line.text.startsWith(prefix)) changes.push({ from: line.from, insert: prefix });
			}
			view.dispatch({ changes, userEvent: "input.format" });
			view.focus();
		},
		insert: (t) => {
			if (!guard()) return;
			const r = view.state.selection.main;
			view.dispatch({ changes: { from: r.from, to: r.to, insert: t }, selection: { anchor: r.from + t.length }, userEvent: "input" });
			view.focus();
		},
	};
}

(globalThis as unknown as { LiteSyncEditor: { createEditor: typeof createEditor } }).LiteSyncEditor = { createEditor };
