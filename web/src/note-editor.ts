/**
 * 笔记编辑控制器（v0.20 公开化 / ADR-015 状态机；v0.20.1 RC-1 修复 W1 / W2）。
 *
 *   未修改 ──输入──▶ 未保存 ──加密写入本机草稿──▶ 已加密保存到本机 ──上传──▶ 正在上传
 *   正在上传 ──服务器确认──▶ 已同步          正在上传 ──网络失败──▶ 离线待同步（同一份密文退避重试）
 *   正在上传 ──CAS 冲突──▶ 三方合并（干净 → 继续保存；不干净/远端已删除 → 冲突，保留双方）
 *   任意 ──401──▶ 登录已过期      任意 ──锁定──▶ 已锁定（正文立即清空，草稿只以密文留在本机）
 *
 * 只有收到服务器确认才显示「已同步」。只打开不修改绝不上传（不会改写任何字节）。
 *
 * 上传期间用户可以继续输入（W1 / W2 的根源）。因此：
 *   - 一次上传捕获 {text, version, baseRevision, baseText}；编辑器每次修改 version +1；
 *   - 旧上传成功只确认**它**那一版：没有新输入才 compare-and-delete 草稿，有新输入就把当前全文
 *     以新的 base 重写成草稿（绝不删除更新的输入）；
 *   - CAS 冲突以**当前全文**合并（读全文 → 合并 → 写回之间没有 await，不可能插进新输入）；
 *     输入法组合期间推迟到组合结束再合并；保留双方时冲突副本是当时的全文，上传副本期间编辑器只读；
 *   - 草稿按编辑器实例（draftId）分开存、带版本号条件写（逆序完成的旧加密不会覆盖新草稿）；
 *   - 锁定 / 切库 / 换号之后到达的任何异步结果一律丢弃（host.alive()），草稿原样留着。
 */
import {
	conflictCopyPath,
	DraftStore,
	LoadedDraft,
	mergeTexts,
	newTrackedFile,
	PreparedUpload,
	prepareUpload,
	RepoBinding,
	SaveOutcome,
	TrackedFile,
	uploadPrepared,
	WriteKeys,
} from "./write";

export interface EditorHandle {
	getText(): string;
	version(): number;
	load(text: string): void;
	applyText(text: string): void;
	focus(): void;
	destroy(): void;
	isComposing(): boolean;
	whenNotComposing(): Promise<void>;
	setReadOnly(readOnly: boolean): void;
	wrap(before: string, after: string, placeholderText: string): void;
	prefixLines(prefix: string): void;
	insert(text: string): void;
}

export interface NoteEditorHost {
	binding(): RepoBinding;
	keys(): WriteKeys | null;
	drafts(): DraftStore | null;
	/** 草稿只在本页内存里（浏览器不允许持久存储）：状态里如实说明 */
	draftsVolatile?(): boolean;
	/** 本编辑器所属的会话是否仍然有效（锁定、切库、换号之后为 false）：每个异步结果回来先问它 */
	alive?(): boolean;
	renderPreview(container: HTMLElement, text: string): void;
	/** 取远端 HEAD 并解密（冲突合并用）；不存在或已删除返回 null。 */
	fetchRemote(f: TrackedFile): Promise<{ text: string; revision: number; generation: number; fileId: string } | null>;
	/** 保存成功：更新文件树/索引里的条目。 */
	onSaved(f: TrackedFile, created: boolean): void;
	/** 登录过期；claim 是「修改现在在哪里」的准确说明（按实际草稿状态生成）。 */
	onAuthExpired(claim: string): void;
	/** 上传一个附件（与笔记同一套加密写入），返回要插入笔记的引用文本。 */
	uploadAttachment(file: File, notePath: string): Promise<string>;
	/** 对照两份文本（保留双方之后的处理界面）。 */
	showCompare(title: string, a: { label: string; text: string }, b: { label: string; text: string }): void;
}

type Mode = "read" | "edit" | "split";
type SaveState = "clean" | "dirty" | "drafted" | "uploading" | "synced" | "offline" | "conflict" | "quota" | "auth" | "locked" | "error";

const LABEL: Record<SaveState, string> = {
	clean: "未修改",
	dirty: "未保存",
	drafted: "已加密保存到本机，等待同步",
	uploading: "正在上传…",
	synced: "已同步",
	offline: "离线，待同步",
	conflict: "有冲突，需要处理",
	quota: "容量不足，未上传",
	auth: "登录已过期，请重新登录",
	locked: "已锁定",
	error: "保存失败",
};

/** 一次上传的快照：它确认的是哪一版、基于哪个版本。 */
interface Snap {
	text: string;
	version: number;
	base: number;
	baseText: string;
}

/** 锁定 / 离开时的草稿结局（锁定提示据此如实说明）。 */
export interface LockOutcome {
	unsynced: boolean;
	persisted: boolean;
	volatile: boolean;
}

let editorLoader: Promise<{
	createEditor: (p: HTMLElement, t: string, o: { onChange(t: string): void; onSave(): void; onFiles?(files: File[]): void }) => EditorHandle;
}> | null = null;

/** 按需加载 /editor.js（CodeMirror）。 */
function loadEditor() {
	editorLoader ??= new Promise((resolve, reject) => {
		const g = globalThis as unknown as { LiteSyncEditor?: unknown };
		if (g.LiteSyncEditor) return resolve(g.LiteSyncEditor as never);
		const s = document.createElement("script");
		s.src = "/editor.js";
		s.onload = () => (g.LiteSyncEditor ? resolve(g.LiteSyncEditor as never) : reject(new Error("编辑器加载失败")));
		s.onerror = () => {
			editorLoader = null;
			reject(new Error("编辑器加载失败（网络）"));
		};
		document.head.append(s);
	});
	return editorLoader;
}

function hhmmss(ts: number): string {
	return new Date(ts).toLocaleTimeString();
}

function randomDraftId(): string {
	const b = new Uint8Array(6);
	crypto.getRandomValues(b);
	return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));

export class NoteEditor {
	private editor: EditorHandle | null = null;
	private mode: Mode = "read";
	private state: SaveState = "clean";
	private synced: string; // 服务器确认过的内容（三方合并的 base）
	private prepared: { text: string; base: number; p: PreparedUpload } | null = null;
	/** 正在上传、尚未确认的那一版（草稿里一并记下，恢复时用作合并 base 的候选） */
	private inflight: Snap | null = null;
	/** 本编辑器实例的草稿身份（同一篇笔记在两个标签页里各有一份） */
	readonly draftId = randomDraftId();
	/** 最近一次**确实落盘**的草稿版本与时间 */
	private drafted: { version: number; at: number } | null = null;
	/** 恢复时接管的别的草稿：本实例自己的草稿落盘（或内容到达服务器）之后再删 */
	private adopted: LoadedDraft[] = [];
	private uploadTimer = 0;
	private draftTimer = 0;
	private retryDelay = 5000;
	private previewTimer = 0;
	private lastSyncedAt = 0;
	private draftFailed = false;
	private busy = false;
	private destroyed = false;
	/** 已离开这篇笔记：只在后台把最后一版上传一次；冲突/失败都留在加密草稿里等下次打开 */
	private detached = false;
	private readonly statusEl: HTMLElement;
	private readonly bodyEl: HTMLElement;
	private readonly previewEl: HTMLElement;
	private readonly editorEl: HTMLElement;
	private readonly toolbarEl: HTMLElement;
	private readonly noticeEl: HTMLElement;
	private readonly saveBtn: HTMLButtonElement;
	/** 丢失风险的完整说明（草稿没落盘、只在本页内存）：单独一行全文显示，不挤在会被截断的状态文字里。 */
	private readonly riskEl: HTMLElement;
	private riskText = "";

	constructor(
		private root: HTMLElement,
		private host: NoteEditorHost,
		public file: TrackedFile,
		original: string,
		private created: boolean,
	) {
		this.synced = original;
		root.innerHTML = "";
		const bar = document.createElement("div");
		bar.className = "edit-bar";
		const modes = document.createElement("div");
		modes.className = "seg";
		modes.setAttribute("role", "group");
		modes.setAttribute("aria-label", "显示方式");
		for (const [m, label] of [["read", "阅读"], ["edit", "编辑"], ["split", "分栏"]] as const) {
			const b = document.createElement("button");
			b.type = "button";
			b.textContent = label;
			b.dataset.mode = m;
			b.onclick = () => void this.setMode(m);
			modes.append(b);
		}
		this.toolbarEl = document.createElement("div");
		this.toolbarEl.className = "fmt-bar";
		for (const [label, title, fn] of [
			["H", "标题", () => this.editor?.prefixLines("## ")],
			["B", "粗体", () => this.editor?.wrap("**", "**", "粗体")],
			["I", "斜体", () => this.editor?.wrap("*", "*", "斜体")],
			["•", "列表", () => this.editor?.prefixLines("- ")],
			["☐", "任务", () => this.editor?.prefixLines("- [ ] ")],
			["🔗", "链接", () => this.editor?.wrap("[", "](https://)", "链接文字")],
			["</>", "代码", () => this.editor?.wrap("`", "`", "代码")],
		] as const) {
			const b = document.createElement("button");
			b.type = "button";
			b.textContent = label;
			b.title = title;
			b.setAttribute("aria-label", title);
			b.onclick = fn;
			this.toolbarEl.append(b);
		}
		// 附件：按钮选择，或直接粘贴 / 拖入编辑区（与笔记同一套加密写入）
		const attachInput = document.createElement("input");
		attachInput.type = "file";
		attachInput.multiple = true;
		attachInput.hidden = true;
		attachInput.onchange = () => {
			const files = Array.from(attachInput.files ?? []);
			attachInput.value = "";
			void this.attach(files);
		};
		const attachBtn = document.createElement("button");
		attachBtn.type = "button";
		attachBtn.textContent = "📎";
		attachBtn.title = "上传附件（也可以直接粘贴或拖入）";
		attachBtn.setAttribute("aria-label", "上传附件");
		attachBtn.onclick = () => attachInput.click();
		this.toolbarEl.append(attachBtn, attachInput);
		const save = document.createElement("button");
		save.type = "button";
		save.className = "primary small-btn";
		save.textContent = "保存";
		save.title = "保存（Ctrl/⌘+S）";
		save.onclick = () => void this.saveNow();
		this.saveBtn = save;
		this.statusEl = document.createElement("span");
		this.statusEl.className = "save-status";
		this.statusEl.setAttribute("role", "status");
		this.statusEl.setAttribute("aria-live", "polite");
		bar.append(modes, this.toolbarEl, this.statusEl, save);
		this.riskEl = document.createElement("div");
		this.riskEl.className = "save-risk";
		this.riskEl.hidden = true;
		this.noticeEl = document.createElement("div");
		this.noticeEl.className = "edit-notice";
		this.bodyEl = document.createElement("div");
		this.bodyEl.className = "edit-body";
		this.editorEl = document.createElement("div");
		this.editorEl.className = "edit-pane";
		this.previewEl = document.createElement("div");
		this.previewEl.className = "markdown-body preview-pane";
		this.bodyEl.append(this.editorEl, this.previewEl);
		root.append(bar, this.riskEl, this.noticeEl, this.bodyEl);
		this.host.renderPreview(this.previewEl, original);
		this.render();
		// 打开时（阅读模式也一样）就检查本机草稿：用户不必先点「编辑」才知道有未同步的修改
		void this.offerDraft();
	}

	get dirty(): boolean {
		return (this.editor?.getText() ?? this.synced) !== this.synced;
	}

	private get version(): number {
		return this.editor?.version() ?? 0;
	}

	/** 会话仍有效、编辑器没被销毁：异步结果才允许落到界面与状态上。 */
	private alive(): boolean {
		return !this.destroyed && (this.host.alive?.() ?? true);
	}

	private fileKey(): string {
		return this.file.fileId;
	}

	/** 当前这一版已经确实落盘为加密草稿。 */
	private draftedCurrent(): boolean {
		return this.drafted !== null && this.drafted.version === this.version;
	}

	/**
	 * 「修改现在在哪里」的准确说明：按实际后端（持久 / 只在内存）与最后一次**确实落盘**的版本生成。
	 * 任何提示都不能笼统地说「已加密保存在本机，不会丢」。
	 */
	draftClaim(): string {
		if (!this.dirty) return "";
		if (this.draftFailed) return "本机草稿保存失败：修改目前只在编辑器里，请不要关闭页面，必要时先导出。";
		if (this.host.draftsVolatile?.()) return "浏览器不允许持久存储：修改只在这个页面的内存里，关闭或刷新页面就会丢失。";
		if (!this.drafted) return "修改还没有写入本机草稿。";
		const when = hhmmss(this.drafted.at);
		return this.draftedCurrent()
			? `修改已加密保存在本机（${when}），刷新或关闭页面不会丢。`
			: `本机草稿停在 ${when} 的版本，之后的输入还没有写入本机。`;
	}

	private render(): void {
		if (this.destroyed) return;
		this.root.dataset.mode = this.mode;
		this.root.querySelectorAll<HTMLButtonElement>(".seg button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.mode === this.mode)));
		this.toolbarEl.hidden = this.mode === "read";
		const volatile = this.host.draftsVolatile?.() === true;
		let text = this.state === "drafted" && volatile ? "已暂存在本页内存，等待同步" : LABEL[this.state];
		if (this.state === "synced" && this.lastSyncedAt) text += " " + hhmmss(this.lastSyncedAt);
		if ((this.state === "drafted" || this.state === "offline" || this.state === "quota") && this.drafted && !volatile) text += `（本机草稿 ${hhmmss(this.drafted.at)}）`;
		if (this.draftFailed) text += " · 本机草稿保存失败";
		else if (volatile && this.state !== "clean" && this.state !== "synced") text += " · 只在本页内存";
		this.statusEl.textContent = text;
		this.statusEl.title = text;
		this.statusEl.dataset.state = this.state;
		// 阅读态没有可保存的内容时（UI 焕新 W05）：不摆「保存」主按钮，也不写「未修改」；
		// 有没同步的修改（切回阅读也算）时照常显示，随时可以保存或重试
		const idle = this.state === "clean" || this.state === "synced";
		this.saveBtn.hidden = this.mode === "read" && idle;
		this.statusEl.hidden = this.mode === "read" && this.state === "clean";
		this.renderRisk(volatile);
	}

	/** 丢失风险全文（W06）：只在文字变化时重写，免得读屏反复播报同一句。 */
	private renderRisk(volatile: boolean): void {
		const dirty = this.dirty;
		const risk = this.draftFailed && dirty
			? "本机草稿保存失败：这些修改目前只在编辑器里，关闭或刷新页面就会丢失。网络和存储恢复后会照常保存；也可以先导出一份。"
			: volatile && dirty
				? "浏览器不允许持久存储（例如隐私模式）：没同步的修改只在这个页面的内存里，关闭或刷新页面就会丢失。"
				: "";
		if (risk === this.riskText) return;
		this.riskText = risk;
		this.riskEl.innerHTML = "";
		this.riskEl.hidden = !risk;
		if (!risk) return;
		this.riskEl.setAttribute("role", this.draftFailed ? "alert" : "status");
		const exp = document.createElement("button");
		exp.type = "button";
		exp.className = "small-btn";
		exp.textContent = "导出为文件";
		exp.onclick = () => this.exportText();
		this.riskEl.append(document.createTextNode(risk), " ", exp);
	}

	private setState(s: SaveState): void {
		this.state = s;
		this.render();
	}

	async setMode(m: Mode): Promise<void> {
		if (m !== "read" && !this.editor) {
			try {
				const lib = await loadEditor();
				if (!this.alive()) return;
				this.editor = lib.createEditor(this.editorEl, this.synced, {
					onChange: (t) => this.onChange(t),
					onSave: () => void this.saveNow(),
					onFiles: (files) => void this.attach(files),
				});
				// 混用两种换行的文件：编辑器内部只能用一种分隔符，修改并保存时会统一——事先说明，不悄悄改字节
				if (/\r\n/.test(this.synced) && /(^|[^\r])\n/.test(this.synced) && !this.noticeEl.hasChildNodes()) {
					this.notice("这篇笔记混用了 CRLF 和 LF 两种换行：只打开不修改不会改动文件；在网页修改并保存时，换行会统一为 LF。", "warn");
				}
			} catch (e) {
				this.notice(`编辑器加载失败：${errText(e)}`, "danger");
				return;
			}
		}
		this.mode = m;
		// 阅读与分栏都要显示**当前**内容
		if (m !== "edit") this.host.renderPreview(this.previewEl, this.editor?.getText() ?? this.synced);
		this.render();
		if (m !== "read") this.editor?.focus();
	}

	private notice(msg: string, kind: "info" | "warn" | "danger" = "info", actions: [string, () => void][] = []): void {
		if (this.destroyed) return;
		this.noticeEl.innerHTML = "";
		if (!msg) return;
		const box = document.createElement("div");
		box.className = "banner " + kind;
		box.setAttribute("role", kind === "danger" ? "alert" : "status");
		box.append(document.createTextNode(msg));
		for (const [label, fn] of actions) {
			const b = document.createElement("button");
			b.type = "button";
			b.className = "small-btn";
			b.textContent = label;
			b.onclick = fn;
			box.append(" ", b);
		}
		this.noticeEl.append(box);
	}

	/** 打开时发现本机有加密草稿：提示恢复（只恢复成功加密落盘、能解开的内容）。 */
	private async offerDraft(): Promise<void> {
		const ds = this.host.drafts();
		if (!ds) return;
		const all = await ds.loadAll(this.fileKey()).catch(() => [] as LoadedDraft[]);
		if (!this.alive()) return;
		const pending: LoadedDraft[] = [];
		for (const d of all) {
			if (d.draftId === this.draftId || this.adopted.some((a) => a.draftId === d.draftId)) continue;
			if (d.text === this.synced) {
				void ds.remove(d.fileKey, d.draftId).catch(() => undefined); // 草稿内容已经在服务器上了
				continue;
			}
			pending.push(d);
		}
		if (pending.length === 0) return;
		const d = pending[0];
		const when = new Date(d.savedAt).toLocaleString();
		const more = pending.length > 1 ? `（另有 ${pending.length - 1} 份较早的草稿，处理完这一份会接着提示）` : "";
		this.notice(`本机有一份 ${when} 加密保存、尚未同步的草稿${more}。`, "warn", [
			["恢复草稿", () => void this.restoreDraft(d).then(() => this.offerDraft())],
			["丢弃草稿", () => {
				this.notice("");
				void ds.remove(d.fileKey, d.draftId).catch(() => undefined).then(() => this.offerDraft());
			}],
		]);
	}

	/**
	 * 恢复一份草稿。草稿之后远端又变了：以草稿的 base 三方合并；那次上传其实已到服务器时
	 * 以「随上传发出的那一版」为 base（W2）；不干净就把草稿另存为冲突副本，编辑器保持远端版本。
	 */
	private async restoreDraft(d: LoadedDraft): Promise<void> {
		await this.setMode(this.mode === "read" ? "edit" : this.mode);
		if (!this.editor || !this.alive()) return;
		await this.editor.whenNotComposing();
		if (!this.editor || !this.alive()) return;
		let text = d.text;
		if (d.baseRevision !== this.file.revision || (d.baseText !== null && d.baseText !== this.synced)) {
			const bases = [d.inflightText, d.baseText].filter((b, i, a): b is string => typeof b === "string" && a.indexOf(b) === i);
			let merged: string | null = null;
			for (const base of bases) {
				const m = mergeTexts(base, d.text, this.synced);
				if (m.clean) {
					merged = m.text;
					break;
				}
			}
			if (merged === null) {
				await this.keepBoth({ msg: "草稿与远端的新版本有冲突：草稿已另存为冲突副本，编辑器里是远端的最新版本。", local: d.text, adoptedDraft: d });
				return;
			}
			text = merged;
		}
		// 点「恢复」之前编辑器里已经有输入：不覆盖它，和草稿再合并一次
		if (this.dirty) {
			const m = mergeTexts(this.synced, this.editor.getText(), text);
			if (!m.clean) {
				await this.keepBoth({ msg: "草稿与你刚输入的内容改了同一处：草稿已另存为冲突副本，编辑器里的输入保持不变。", local: text, adoptedDraft: d });
				return;
			}
			text = m.text;
		}
		this.adopted.push(d);
		this.editor.applyText(text);
		this.notice("");
		await this.saveDraft(); // 以本实例的 draftId 落盘之后，才删除被接管的那份
	}

	/** 本实例的草稿已落盘 / 内容已到服务器：被接管的旧草稿可以删了。 */
	private async releaseAdopted(): Promise<void> {
		const ds = this.host.drafts();
		const list = this.adopted;
		this.adopted = [];
		for (const d of list) await ds?.remove(d.fileKey, d.draftId).catch(() => undefined);
	}

	private onChange(text: string): void {
		if (!this.alive() || this.state === "locked" || this.state === "auth") return;
		const dirty = text !== this.synced;
		this.setState(dirty ? (this.draftedCurrent() ? "drafted" : "dirty") : this.lastSyncedAt ? "synced" : "clean");
		window.clearTimeout(this.draftTimer);
		window.clearTimeout(this.uploadTimer);
		if (!dirty) {
			// 回到了服务器确认的内容：本实例 ≤ 当前版本的草稿不再需要（compare-and-delete）
			const v = this.version;
			this.drafted = null;
			void this.host.drafts()?.removeIfAtMost(this.fileKey(), this.draftId, v).catch(() => undefined);
			return;
		}
		this.draftTimer = window.setTimeout(() => void this.saveDraft(), 800);
		this.uploadTimer = window.setTimeout(() => void this.saveNow(), 4000);
		if (this.mode === "split") {
			// 输入停顿后再刷新预览：逐键重绘会让嵌入的附件反复下载解密
			window.clearTimeout(this.previewTimer);
			this.previewTimer = window.setTimeout(() => {
				if (this.mode === "split" && this.editor && this.alive()) this.host.renderPreview(this.previewEl, this.editor.getText());
			}, 300);
		}
	}

	/**
	 * 把当前全文加密写入本机草稿（条件写：不会被更早开始的写入覆盖）。锁定收尾时也调用它，
	 * 因此这里**不**检查 alive()——只是不更新已经失效的界面。返回当前内容是否已受草稿保护。
	 */
	private async saveDraft(): Promise<boolean> {
		const ds = this.host.drafts();
		if (!ds || !this.editor) return !this.dirty;
		if (!this.dirty) return true;
		const version = this.editor.version();
		const text = this.editor.getText();
		try {
			const { stored, savedAt } = await ds.save(this.fileKey(), this.draftId, version, {
				text, baseText: this.synced, baseRevision: this.file.revision, path: this.file.path, file: this.file,
				inflightText: this.inflight?.text ?? null,
			});
			if (stored && (!this.drafted || version >= this.drafted.version)) this.drafted = { version, at: savedAt };
			this.draftFailed = false;
			await this.releaseAdopted();
			if (this.alive()) {
				if (this.state === "dirty" && this.draftedCurrent()) this.setState("drafted");
				else this.render();
			}
			return true;
		} catch {
			this.draftFailed = true; // 隐私模式 / 配额 / 事务中止：如实显示，不假装已保存
			if (this.alive()) this.render();
			return false;
		}
	}

	/** 立即保存（Ctrl/⌘+S、自动保存、重试）。 */
	async saveNow(): Promise<void> {
		if (!this.editor || this.busy || !this.alive()) return;
		if (this.state === "locked" || this.state === "auth" || this.state === "conflict") return;
		if (!this.dirty) {
			this.setState(this.lastSyncedAt ? "synced" : "clean");
			return;
		}
		this.busy = true;
		window.clearTimeout(this.uploadTimer);
		try {
			const snap: Snap = { text: this.editor.getText(), version: this.editor.version(), base: this.file.revision, baseText: this.synced };
			await this.saveDraft();
			if (!this.alive()) return;
			// 同一内容、同一前置版本 → 复用已加密的字节与 operationId（幂等重试）
			if (!this.prepared || this.prepared.text !== snap.text || this.prepared.base !== snap.base) {
				this.prepared = { text: snap.text, base: snap.base, p: await prepareUpload(this.host.binding(), this.host.keys(), this.file, new TextEncoder().encode(snap.text)) };
				if (!this.alive()) return;
			}
			this.inflight = snap;
			this.setState("uploading");
			const out = await uploadPrepared(this.host.binding(), this.file, this.prepared.p);
			// 锁定 / 切库 / 换号之后才到达的旧结果：丢弃。草稿原样留在本机，下次打开时恢复
			if (!this.alive()) return;
			await this.handle(out, snap);
		} catch (e) {
			if (this.alive()) {
				this.setState("error");
				this.notice(`保存失败：${errText(e)}。${this.draftClaim()}`, "danger");
			}
		} finally {
			this.inflight = null;
			this.busy = false;
		}
	}

	private async handle(out: SaveOutcome, snap: Snap): Promise<void> {
		switch (out.kind) {
			case "saved": {
				const created = this.file.revision === 0;
				this.file = { ...this.file, revision: out.revision, generation: out.generation, fileId: out.fileId, metaGeneration: out.metaGeneration ?? this.file.metaGeneration };
				this.synced = snap.text;
				this.prepared = null;
				this.retryDelay = 5000;
				this.lastSyncedAt = Date.now();
				this.host.onSaved(this.file, created || this.created);
				this.created = false;
				if (!this.dirty) {
					// 确认的就是当前内容：只删本实例 ≤ 当前版本的草稿（compare-and-delete）
					await this.host.drafts()?.removeIfAtMost(this.fileKey(), this.draftId, this.version).catch(() => false);
					this.drafted = null;
					await this.releaseAdopted();
				} else {
					// 上传期间又输入了：这份草稿**不能删**。以新的 base 把当前全文重写成草稿（原子替换旧的）
					this.inflight = null;
					await this.saveDraft();
				}
				if (!this.alive()) return;
				this.setState(this.dirty ? (this.draftedCurrent() ? "drafted" : "dirty") : "synced");
				if (this.dirty && !this.detached) this.uploadTimer = window.setTimeout(() => void this.saveNow(), 2000);
				return;
			}
			case "offline":
				this.setState("offline");
				if (this.detached) return; // 已离开：留在加密草稿里，回到这篇笔记时再同步
				this.uploadTimer = window.setTimeout(() => void this.saveNow(), this.retryDelay);
				this.retryDelay = Math.min(this.retryDelay * 2, 60000);
				return;
			case "auth":
				this.setState("auth");
				this.host.onAuthExpired(this.draftClaim());
				return;
			case "conflict":
				await this.resolveConflict(snap, out.deleted);
				return;
			case "rejected":
				this.setState(out.code === "QUOTA_EXCEEDED" ? "quota" : "error");
				this.notice(this.rejectText(out.code, out.message, out.details), "danger");
				return;
		}
	}

	private rejectText(code: string, message: string, details?: Record<string, unknown>): string {
		const claim = this.draftClaim();
		switch (code) {
			case "QUOTA_EXCEEDED": {
				const size = (v: unknown) => {
					const n = Number(v);
					if (n < 1024) return `${n} B`;
					if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
					if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
					return `${(n / 1024 ** 3).toFixed(2)} GB`;
				};
				const usage = details?.limit ? `（已用 ${size(details.used)}，上限 ${size(details.limit)}，历史版本也计入）` : "";
				return `已达到账号的存储配额${usage}，这次修改没有上传。${claim}删除不需要的文件或清理历史版本后再保存，或联系管理员调整配额。`;
			}
			case "VAULT_NOT_READY":
				return "这个仓库还没有完成加密设置，暂时不能写入。";
			case "KEY_EPOCH_MISMATCH":
			case "FORMAT_EPOCH_MISMATCH":
			case "REPO_EPOCH_MISMATCH":
				return `仓库状态已经变化（密钥轮换、格式升级或从备份恢复）。${claim}请刷新页面重新解锁后再保存。`;
			case "ENVELOPE_TOO_OLD":
			case "PLAINTEXT_REJECTED":
				return "服务器拒绝了这次写入的加密格式（不会降级）。请刷新页面后重试。";
			case "MIGRATION_LOCKED":
				return "路径加密迁移进行中，暂时不能修改这篇笔记。";
			case "FORBIDDEN":
				return "你在这个仓库里只有只读权限，或网页编辑未开启。";
			case "TOO_LARGE":
				return "内容超过服务器允许的单文件大小。";
			default:
				return `保存被服务器拒绝（${code}）：${message}`;
		}
	}

	/**
	 * CAS 冲突：取远端 → 以**当前全文**三方合并（base = 这次上传所基于的版本）。
	 * 不干净 / 远端已删除 → 保留双方。取远端期间的输入、输入法组合中的输入都不会丢。
	 */
	private async resolveConflict(snap: Snap, deleted: boolean): Promise<void> {
		this.prepared = null;
		if (this.detached) {
			// 用户已经不在这篇笔记上：不替他做合并决定。草稿（含 base）已加密落盘，
			// 下次打开时以它为 base 三方合并，不干净就保留双方
			this.setState("conflict");
			return;
		}
		const remote = deleted ? null : await this.host.fetchRemote(this.file).catch(() => null);
		if (!this.alive() || !this.editor) return;
		if (!remote) {
			this.setState("conflict");
			this.notice(`这篇笔记在别处被删除了。你的修改仍在编辑器里。${this.draftClaim()}`, "warn", [
				["另存为新笔记", () => void this.keepBoth({ msg: "已把你的版本另存为新笔记。", onlyLocal: true })],
			]);
			return;
		}
		// 输入法组合期间不做程序化替换：等组合结束，再以那一刻的全文合并
		await this.editor.whenNotComposing();
		if (!this.alive() || !this.editor) return;
		// 读全文 → 合并 → 写回：同步完成，中间没有 await，不可能插进新的输入
		const local = this.editor.getText();
		const m = mergeTexts(snap.baseText, local, remote.text);
		if (m.clean) {
			this.file = { ...this.file, revision: remote.revision, generation: Math.max(this.file.generation, remote.generation), fileId: remote.fileId || this.file.fileId };
			this.synced = remote.text;
			this.editor.applyText(m.text);
			this.notice("远端有新的修改，已与你的修改自动合并。", "info");
			if (m.text === remote.text) {
				this.editor.load(remote.text); // 合并结果就是远端：以它为新的基准原文
				this.setState("synced");
				this.lastSyncedAt = Date.now();
				await this.host.drafts()?.removeIfAtMost(this.fileKey(), this.draftId, this.version).catch(() => false);
				this.drafted = null;
				return;
			}
			this.setState(this.draftedCurrent() ? "drafted" : "dirty");
			window.clearTimeout(this.uploadTimer);
			this.uploadTimer = window.setTimeout(() => void this.saveNow(), 300); // 本轮保存结束后立即上传合并结果
			return;
		}
		await this.keepBoth({
			msg: "远端与你同时改了同一处：你的版本已另存为冲突副本，编辑器里现在是远端版本。两份都在，请对照合并。",
			remote,
		});
	}

	/**
	 * 保留双方：把本地版本另存为新文件（新 fileId），不覆盖任何一边。
	 *   - remote：编辑器随后载入的远端版本（同段冲突）；
	 *   - onlyLocal：远端已删除，编辑器改为跟踪这份新笔记；
	 *   - local：另存的文本（不给时取点按钮 / 冲突那一刻编辑器里的全文）；adoptedDraft：它来自哪份草稿。
	 * 上传冲突副本期间编辑器只读——输入被明确拒绝，而不是在「副本已取走、编辑器即将换成远端」之间被吞掉。
	 * 失败时编辑器内容与合并基准都保持原样：之后的保存会再次冲突，不会把远端的修改覆盖掉。
	 */
	private async keepBoth(o: { msg: string; remote?: { text: string; revision: number; generation: number; fileId: string }; onlyLocal?: boolean; local?: string; adoptedDraft?: LoadedDraft }): Promise<void> {
		if (!this.editor || !this.alive()) return;
		const fromEditor = o.local === undefined;
		if (fromEditor) {
			await this.editor.whenNotComposing();
			if (!this.editor || !this.alive()) return;
		}
		const localText = o.local ?? this.editor.getText();
		const lockEditor = fromEditor;
		if (lockEditor) this.editor.setReadOnly(true);
		this.notice(lockEditor ? "正在把你的版本另存为冲突副本…（完成前编辑器只读）" : "正在把草稿另存为冲突副本…", "info");
		// 新对象、新名字：被删除的原路径上是墓碑，普通新建会被服务器按「删除后复活」拒绝
		const copy = newTrackedFile(conflictCopyPath(this.file.path), this.host.binding());
		try {
			const p = await prepareUpload(this.host.binding(), this.host.keys(), copy, new TextEncoder().encode(localText));
			let out = await uploadPrepared(this.host.binding(), copy, p);
			for (let i = 0; i < 3 && out.kind === "offline" && this.alive(); i++) {
				await new Promise((r) => setTimeout(r, 2000 * (i + 1)));
				out = await uploadPrepared(this.host.binding(), copy, p);
			}
			if (!this.alive()) return;
			if (out.kind !== "saved") throw new Error(out.kind === "rejected" ? out.code : out.kind);
			const saved = { ...copy, revision: out.revision, generation: out.generation, fileId: out.fileId, metaGeneration: out.metaGeneration ?? copy.metaGeneration };
			this.host.onSaved(saved, true);
			if (o.adoptedDraft) await this.host.drafts()?.remove(o.adoptedDraft.fileKey, o.adoptedDraft.draftId).catch(() => undefined);
			if (o.onlyLocal) {
				// 远端已删除：编辑器改为跟踪这份新笔记，之后的修改都保存到它
				const oldKey = this.fileKey();
				this.file = saved;
				this.synced = localText;
				this.editor?.load(localText);
				await this.host.drafts()?.removeIfAtMost(oldKey, this.draftId, this.version).catch(() => false);
				this.drafted = null;
				this.setState("synced");
				this.lastSyncedAt = Date.now();
				this.notice(`${o.msg}（「${saved.path}」）`, "warn");
				return;
			}
			if (o.remote && this.editor) {
				// 冲突副本已在服务器上：编辑器载入远端版本，远端成为新的基准
				this.file = { ...this.file, revision: o.remote.revision, generation: Math.max(this.file.generation, o.remote.generation), fileId: o.remote.fileId || this.file.fileId };
				this.synced = o.remote.text;
				this.editor.load(o.remote.text);
				await this.host.drafts()?.removeIfAtMost(this.fileKey(), this.draftId, this.version).catch(() => false);
				this.drafted = null;
				this.setState("clean");
			}
			const remoteText = this.synced;
			this.notice(o.msg, "warn", [
				["对照两份", () => this.host.showCompare(`对照：${saved.path}`, { label: "编辑器里（远端版本）", text: remoteText }, { label: "冲突副本（你的版本）", text: localText })],
			]);
		} catch (e) {
			if (!this.alive()) return;
			this.setState("conflict");
			this.notice(`保留双方失败（${errText(e)}）：你的修改仍在${fromEditor ? "编辑器里" : "本机草稿里"}。${this.draftClaim()}请稍后重试。`, "danger", [
				["重试", () => void this.keepBoth(o)],
			]);
		} finally {
			if (lockEditor) this.editor?.setReadOnly(false);
		}
	}

	/**
	 * 锁定 / 离开：有限时间内尝试把未保存内容加密落盘（不会为了等它而无限保持解锁），
	 * 然后销毁编辑器、清空正文与预览。返回草稿的真实结局（锁定提示据此如实说明）。
	 */
	async lock(timeoutMs = 1500): Promise<LockOutcome> {
		const unsynced = this.dirty || this.busy;
		let persisted = !this.dirty || this.draftedCurrent();
		if (this.dirty && !persisted) persisted = await Promise.race([this.saveDraft(), new Promise<boolean>((r) => setTimeout(() => r(false), timeoutMs))]);
		const volatile = this.host.draftsVolatile?.() === true;
		this.destroyed = true;
		window.clearTimeout(this.draftTimer);
		window.clearTimeout(this.uploadTimer);
		window.clearTimeout(this.previewTimer);
		this.editor?.destroy();
		this.editor = null;
		this.prepared = null;
		this.synced = "";
		this.previewEl.innerHTML = "";
		this.root.innerHTML = "";
		this.state = "locked";
		return { unsynced, persisted: persisted && !volatile, volatile };
	}

	/** 上传附件并在光标处插入引用。失败如实提示，不插入指向不存在文件的引用。 */
	private async attach(files: File[]): Promise<void> {
		if (!this.editor || files.length === 0) return;
		if (this.state === "locked" || this.state === "auth") return;
		const links: string[] = [];
		for (const f of files) {
			this.notice(`正在加密上传附件「${f.name || "粘贴的内容"}」…`, "info");
			try {
				links.push(await this.host.uploadAttachment(f, this.file.path));
			} catch (e) {
				if (!this.alive()) return;
				if (links.length) this.editor?.insert(links.join("\n"));
				this.notice(`附件「${f.name || "粘贴的内容"}」上传失败：${errText(e)}`, "danger");
				return;
			}
			if (!this.alive()) return;
		}
		this.notice("");
		this.editor?.insert(links.join("\n"));
	}

	/** 把编辑器里的内容导出为文件（切换仓库时本机草稿无法落盘的兜底，需求 §7.3）。 */
	exportText(): void {
		const text = this.editor?.getText() ?? this.synced;
		const url = URL.createObjectURL(new Blob([text], { type: "text/markdown;charset=utf-8" }));
		const a = document.createElement("a");
		a.href = url;
		a.download = this.file.path.slice(this.file.path.lastIndexOf("/") + 1) || "note.md";
		document.body.append(a);
		a.click();
		a.remove();
		setTimeout(() => URL.revokeObjectURL(url), 10_000);
	}

	/** 未落盘的内容先加密保存（改名前、页面隐藏时）。返回当前内容是否已受持久草稿保护。 */
	async flush(): Promise<boolean> {
		if (!this.dirty) return true;
		if (this.draftedCurrent()) return this.host.draftsVolatile?.() !== true;
		return (await this.saveDraft()) && this.host.draftsVolatile?.() !== true;
	}

	/**
	 * 别处更新了这篇笔记（轮询发现）：没有未保存的修改就直接载入新版本；
	 * 有的话不动编辑器，提示保存时会自动合并（CAS → 三方合并 → 合并不了保留双方）。
	 */
	async remoteChanged(): Promise<void> {
		if (!this.alive() || this.busy || this.detached) return;
		if (this.dirty || this.state === "conflict") {
			this.notice("这篇笔记在别处有新版本：保存时会自动与你的修改合并，合并不了就保留双方。", "info");
			return;
		}
		const remote = await this.host.fetchRemote(this.file).catch(() => null);
		if (!remote || !this.alive() || this.dirty || this.busy) return; // 取远端期间用户开始输入了：交给保存时合并
		if (this.editor) {
			await this.editor.whenNotComposing();
			if (!this.alive() || this.dirty) return;
		}
		this.file = { ...this.file, revision: remote.revision, generation: Math.max(this.file.generation, remote.generation), fileId: remote.fileId || this.file.fileId };
		this.synced = remote.text;
		this.prepared = null;
		if (this.editor) this.editor.load(remote.text);
		if (this.mode !== "edit") this.host.renderPreview(this.previewEl, remote.text);
		this.setState("synced");
		this.lastSyncedAt = Date.now();
		this.notice(`已载入别处的更新（${hhmmss(this.lastSyncedAt)}）`, "info");
	}

	/** 别处删除了这篇笔记（轮询发现）。保存时会走「远端已删除」流程，另存为新笔记。 */
	remoteDeleted(): void {
		if (!this.alive() || this.detached) return;
		this.notice("这篇笔记已在别处被删除。如果你有修改，保存时会另存为新笔记；也可以在回收站恢复它。", "warn");
	}

	/** 是否还有服务器没确认的内容（离开页面前的提示用）。 */
	get unsynced(): boolean {
		return !this.destroyed && (this.dirty || this.busy);
	}

	/**
	 * 离开这篇笔记（切换笔记、新建）：未保存的内容先加密落盘，然后在后台上传一次。
	 * 返回 { done }：后台上传的 Promise（没有要上传的内容时为 null；包一层对象，
	 * 免得 async 函数把内层 Promise 展平成「等上传完才返回」）。结束后编辑器自行销毁。
	 */
	async leave(): Promise<{ done: Promise<void> } | null> {
		window.clearTimeout(this.draftTimer);
		window.clearTimeout(this.uploadTimer);
		if (!this.editor || (!this.dirty && !this.busy)) {
			this.dispose();
			return null;
		}
		await this.saveDraft();
		this.detached = true;
		const done = (async () => {
			while (this.busy) await new Promise((r) => setTimeout(r, 100)); // 正在上传的那一轮先结束
			if (this.alive() && this.dirty && this.state !== "conflict" && this.state !== "auth") await this.saveNow();
		})().finally(() => this.dispose());
		return { done };
	}

	private dispose(): void {
		this.destroyed = true;
		window.clearTimeout(this.draftTimer);
		window.clearTimeout(this.uploadTimer);
		window.clearTimeout(this.previewTimer);
		this.editor?.destroy();
		this.editor = null;
		this.prepared = null;
	}
}
