/**
 * 笔记编辑控制器（v0.20 公开化 / ADR-015 状态机）。
 *
 *   未修改 ──输入──▶ 未保存 ──加密写入本机草稿──▶ 已加密保存到本机 ──上传──▶ 正在上传
 *   正在上传 ──服务器确认──▶ 已同步          正在上传 ──网络失败──▶ 离线待同步（同一份密文退避重试）
 *   正在上传 ──CAS 冲突──▶ 三方合并（干净 → 继续保存；不干净/远端已删除 → 冲突，保留双方）
 *   任意 ──401──▶ 登录已过期      任意 ──锁定──▶ 已锁定（正文立即清空，草稿只以密文留在本机）
 *
 * 只有收到服务器确认才显示「已同步」。只打开不修改绝不上传（不会改写任何字节）。
 */
import {
	conflictCopyPath,
	DraftContent,
	DraftStore,
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
	replaceAll(text: string): void;
	focus(): void;
	destroy(): void;
	isComposing(): boolean;
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
	renderPreview(container: HTMLElement, text: string): void;
	/** 取远端 HEAD 并解密（冲突合并用）；不存在或已删除返回 null。 */
	fetchRemote(f: TrackedFile): Promise<{ text: string; revision: number; generation: number; fileId: string } | null>;
	/** 保存成功：更新文件树/索引里的条目。 */
	onSaved(f: TrackedFile, created: boolean): void;
	onAuthExpired(): void;
	/** 上传一个附件（与笔记同一套加密写入），返回要插入笔记的引用文本。 */
	uploadAttachment(file: File, notePath: string): Promise<string>;
	/** 对照两份文本（保留双方之后的处理界面）。 */
	showCompare(title: string, a: { label: string; text: string }, b: { label: string; text: string }): void;
}

type Mode = "read" | "edit" | "split";
type SaveState = "clean" | "dirty" | "drafted" | "uploading" | "synced" | "offline" | "conflict" | "auth" | "locked" | "error";

const LABEL: Record<SaveState, string> = {
	clean: "未修改",
	dirty: "未保存",
	drafted: "已加密保存到本机，等待同步",
	uploading: "正在上传…",
	synced: "已同步",
	offline: "离线，待同步",
	conflict: "有冲突，需要处理",
	auth: "登录已过期，请重新登录",
	locked: "已锁定",
	error: "保存失败",
};

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

export class NoteEditor {
	private editor: EditorHandle | null = null;
	private mode: Mode = "read";
	private state: SaveState = "clean";
	private synced: string; // 服务器确认过的内容（三方合并的 base）
	private prepared: { text: string; base: number; p: PreparedUpload } | null = null;
	private uploadTimer = 0;
	private draftTimer = 0;
	private retryDelay = 5000;
	private previewTimer = 0;
	private lastDraftAt = 0;
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
		this.statusEl = document.createElement("span");
		this.statusEl.className = "save-status";
		this.statusEl.setAttribute("role", "status");
		this.statusEl.setAttribute("aria-live", "polite");
		bar.append(modes, this.toolbarEl, this.statusEl, save);
		this.noticeEl = document.createElement("div");
		this.noticeEl.className = "edit-notice";
		this.bodyEl = document.createElement("div");
		this.bodyEl.className = "edit-body";
		this.editorEl = document.createElement("div");
		this.editorEl.className = "edit-pane";
		this.previewEl = document.createElement("div");
		this.previewEl.className = "markdown-body preview-pane";
		this.bodyEl.append(this.editorEl, this.previewEl);
		root.append(bar, this.noticeEl, this.bodyEl);
		this.host.renderPreview(this.previewEl, original);
		this.render();
		// 打开时（阅读模式也一样）就检查本机草稿：用户不必先点「编辑」才知道有未同步的修改
		void this.offerDraft();
	}

	get dirty(): boolean {
		return (this.editor?.getText() ?? this.synced) !== this.synced;
	}

	private fileKey(): string {
		return this.file.fileId;
	}

	private render(): void {
		this.root.dataset.mode = this.mode;
		this.root.querySelectorAll<HTMLButtonElement>(".seg button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.mode === this.mode)));
		this.toolbarEl.hidden = this.mode === "read";
		let text = LABEL[this.state];
		if (this.state === "synced" && this.lastSyncedAt) text += " " + hhmmss(this.lastSyncedAt);
		if ((this.state === "drafted" || this.state === "offline") && this.lastDraftAt) text += `（本机草稿 ${hhmmss(this.lastDraftAt)}）`;
		if (this.draftFailed) text += " · 本机草稿保存失败";
		else if (this.host.draftsVolatile?.() && this.state !== "clean" && this.state !== "synced") text += " · 浏览器不允许持久存储，本机草稿只在本页有效";
		this.statusEl.textContent = text;
		this.statusEl.dataset.state = this.state;
	}

	private setState(s: SaveState): void {
		this.state = s;
		this.render();
	}

	async setMode(m: Mode): Promise<void> {
		if (m !== "read" && !this.editor) {
			try {
				const lib = await loadEditor();
				if (this.destroyed) return;
				this.editor = lib.createEditor(this.editorEl, this.synced, {
					onChange: (t) => this.onChange(t),
					onSave: () => void this.saveNow(),
					onFiles: (files) => void this.attach(files),
				});
				// 混用两种换行的文件：编辑器内部只能用一种分隔符，保存时会统一——事先说明，不悄悄改字节
				if (/\r\n/.test(this.synced) && /(^|[^\r])\n/.test(this.synced) && !this.noticeEl.hasChildNodes()) {
					this.notice("这篇笔记混用了 CRLF 和 LF 两种换行：只打开不修改不会改动文件；在网页修改并保存时，换行会统一为 LF。", "warn");
				}
			} catch (e) {
				this.notice(`编辑器加载失败：${e instanceof Error ? e.message : String(e)}`, "danger");
				return;
			}
		}
		this.mode = m;
		// 阅读与分栏都要显示**当前**内容（分栏此前沿用打开时的旧预览）
		if (m !== "edit") this.host.renderPreview(this.previewEl, this.editor?.getText() ?? this.synced);
		this.render();
		if (m !== "read") this.editor?.focus();
	}

	private notice(msg: string, kind: "info" | "warn" | "danger" = "info", actions: [string, () => void][] = []): void {
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

	/** 打开时发现本机有更新的加密草稿：提示恢复（只恢复成功加密落盘的内容）。 */
	private async offerDraft(): Promise<void> {
		const ds = this.host.drafts();
		if (!ds) return;
		const d = await ds.load(this.fileKey()).catch(() => null);
		if (!d) return;
		if (d.text === this.synced) {
			void ds.remove(this.fileKey()).catch(() => undefined); // 草稿内容已经在服务器上了
			return;
		}
		const when = new Date(d.savedAt).toLocaleString();
		this.notice(`本机有一份 ${when} 加密保存、尚未同步的草稿。`, "warn", [
			["恢复草稿", () => void this.restoreDraft(d)],
			["丢弃草稿", () => {
				void ds.remove(this.fileKey());
				this.notice("");
			}],
		]);
	}

	private async restoreDraft(d: DraftContent): Promise<void> {
		await this.setMode(this.mode === "read" ? "edit" : this.mode);
		if (!this.editor) return;
		let text = d.text;
		if (d.baseRevision !== this.file.revision) {
			// 草稿之后远端又变了：以草稿的 base 做三方合并，不干净就保留双方
			const m = mergeTexts(d.baseText, d.text, this.synced);
			if (!m.clean) {
				await this.keepBoth(d.text, "草稿与远端的新版本有冲突：草稿已另存为冲突副本，编辑器里是远端的最新版本。");
				return;
			}
			text = m.text;
		}
		this.editor.replaceAll(text);
		this.notice("");
	}

	private onChange(text: string): void {
		if (this.state === "locked" || this.state === "auth") return;
		const dirty = text !== this.synced;
		this.setState(dirty ? "dirty" : "clean");
		window.clearTimeout(this.draftTimer);
		window.clearTimeout(this.uploadTimer);
		if (!dirty) {
			void this.host.drafts()?.remove(this.fileKey()).catch(() => undefined);
			return;
		}
		this.draftTimer = window.setTimeout(() => void this.saveDraft(), 800);
		this.uploadTimer = window.setTimeout(() => void this.saveNow(), 4000);
		if (this.mode === "split") {
			// 输入停顿后再刷新预览：逐键重绘会让嵌入的附件反复下载解密
			window.clearTimeout(this.previewTimer);
			this.previewTimer = window.setTimeout(() => {
				if (this.mode === "split" && this.editor) this.host.renderPreview(this.previewEl, this.editor.getText());
			}, 300);
		}
	}

	private async saveDraft(): Promise<boolean> {
		const ds = this.host.drafts();
		if (!ds || !this.editor || !this.dirty) return !this.dirty;
		try {
			this.lastDraftAt = await ds.save(this.fileKey(), {
				text: this.editor.getText(), baseText: this.synced, baseRevision: this.file.revision, path: this.file.path, file: this.file,
			});
			this.draftFailed = false;
			if (this.state === "dirty") this.setState("drafted");
			else this.render();
			return true;
		} catch {
			this.draftFailed = true; // 隐私模式 / 配额：如实显示，不假装已保存
			this.render();
			return false;
		}
	}

	/** 立即保存（Ctrl/⌘+S、自动保存、重试）。 */
	async saveNow(): Promise<void> {
		if (!this.editor || this.busy || this.destroyed) return;
		if (this.state === "locked" || this.state === "auth" || this.state === "conflict") return;
		if (!this.dirty) {
			this.setState(this.lastSyncedAt ? "synced" : "clean");
			return;
		}
		this.busy = true;
		window.clearTimeout(this.uploadTimer);
		try {
			const text = this.editor.getText();
			await this.saveDraft();
			// 同一内容、同一前置版本 → 复用已加密的字节与 operationId（幂等重试）
			if (!this.prepared || this.prepared.text !== text || this.prepared.base !== this.file.revision) {
				this.prepared = { text, base: this.file.revision, p: await prepareUpload(this.host.binding(), this.host.keys(), this.file, new TextEncoder().encode(text)) };
			}
			this.setState("uploading");
			const out = await uploadPrepared(this.host.binding(), this.file, this.prepared.p);
			await this.handle(out, text);
		} catch (e) {
			this.setState("error");
			this.notice(`保存失败：${e instanceof Error ? e.message : String(e)}`, "danger");
		} finally {
			this.busy = false;
		}
	}

	private async handle(out: SaveOutcome, text: string): Promise<void> {
		switch (out.kind) {
			case "saved": {
				const created = this.file.revision === 0;
				this.file = { ...this.file, revision: out.revision, generation: out.generation, fileId: out.fileId };
				this.synced = text;
				this.prepared = null;
				this.retryDelay = 5000;
				this.lastSyncedAt = Date.now();
				await this.host.drafts()?.remove(this.fileKey()).catch(() => undefined);
				this.host.onSaved(this.file, created || this.created);
				this.created = false;
				// 保存期间用户又输入了：继续下一轮
				this.setState(this.dirty ? "dirty" : "synced");
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
				this.host.onAuthExpired();
				return;
			case "conflict":
				await this.resolveConflict(text, out.deleted);
				return;
			case "rejected":
				this.setState("error");
				this.notice(this.rejectText(out.code, out.message, out.details), "danger");
				return;
		}
	}

	private rejectText(code: string, message: string, details?: Record<string, unknown>): string {
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
				return `已达到账号的存储配额${usage}。这次修改已加密保存在本机，不会丢；删除不需要的文件或清理历史版本后再保存，或联系管理员调整配额。`;
			}
			case "VAULT_NOT_READY":
				return "这个仓库还没有完成加密设置，暂时不能写入。";
			case "KEY_EPOCH_MISMATCH":
			case "FORMAT_EPOCH_MISMATCH":
			case "REPO_EPOCH_MISMATCH":
				return "仓库状态已经变化（密钥轮换、格式升级或从备份恢复）。草稿已加密保存在本机；请刷新页面重新解锁后再保存。";
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

	/** CAS 冲突：取远端 → 本地三方合并；不干净 / 远端已删除 → 保留双方。 */
	private async resolveConflict(text: string, deleted: boolean): Promise<void> {
		this.prepared = null;
		if (this.detached) {
			// 用户已经不在这篇笔记上：不替他做合并决定。草稿（含打开时的 base）已加密落盘，
			// 下次打开时以它为 base 三方合并，不干净就保留双方
			this.setState("conflict");
			return;
		}
		const remote = deleted ? null : await this.host.fetchRemote(this.file).catch(() => null);
		if (!remote) {
			this.setState("conflict");
			this.notice("这篇笔记在别处被删除了。你的修改仍在编辑器里，并已加密保存在本机。", "warn", [
				["另存为新笔记", () => void this.keepBoth(text, "已把你的版本另存为新笔记。", true)],
			]);
			return;
		}
		const m = mergeTexts(this.synced, text, remote.text);
		// 远端成为新的 base
		this.file = { ...this.file, revision: remote.revision, generation: Math.max(this.file.generation, remote.generation), fileId: remote.fileId || this.file.fileId };
		this.synced = remote.text;
		if (m.clean) {
			this.editor!.replaceAll(m.text);
			this.notice("远端有新的修改，已与你的修改自动合并。", "info");
			this.setState(m.text === remote.text ? "synced" : "dirty");
			if (m.text !== remote.text) void this.saveNow();
			return;
		}
		await this.keepBoth(text, "远端与你同时改了同一处：你的版本已另存为冲突副本，编辑器里现在是远端版本。两份都在，请对照合并。");
	}

	/** 保留双方：把本地文本另存为新文件（新 fileId），编辑器载入远端版本。 */
	private async keepBoth(localText: string, msg: string, onlyLocal = false): Promise<void> {
		// 新对象、新名字：被删除的原路径上是墓碑，普通新建会被服务器按「删除后复活」拒绝
		const copy = newTrackedFile(conflictCopyPath(this.file.path), this.host.binding());
		try {
			const p = await prepareUpload(this.host.binding(), this.host.keys(), copy, new TextEncoder().encode(localText));
			let out = await uploadPrepared(this.host.binding(), copy, p);
			for (let i = 0; i < 3 && out.kind === "offline"; i++) {
				await new Promise((r) => setTimeout(r, 2000 * (i + 1)));
				out = await uploadPrepared(this.host.binding(), copy, p);
			}
			if (out.kind !== "saved") throw new Error(out.kind === "rejected" ? out.code : out.kind);
			const saved = { ...copy, revision: out.revision, generation: out.generation, fileId: out.fileId };
			const oldKey = this.fileKey();
			this.host.onSaved(saved, true);
			await this.host.drafts()?.remove(oldKey).catch(() => undefined);
			if (onlyLocal) {
				// 远端已删除：编辑器改为跟踪这份新笔记，之后的修改都保存到它
				this.file = saved;
				this.synced = localText;
				this.setState("synced");
				this.notice(`${msg}（「${saved.path}」）`, "warn");
				return;
			}
			const remoteText = this.synced;
			this.editor!.replaceAll(remoteText);
			this.setState("clean");
			this.notice(msg, "warn", [
				["对照两份", () => this.host.showCompare(`对照：${saved.path}`, { label: "编辑器里（远端版本）", text: remoteText }, { label: "冲突副本（你的版本）", text: localText })],
			]);
		} catch (e) {
			this.setState("conflict");
			this.notice(`保留双方失败（${e instanceof Error ? e.message : String(e)}）：你的修改仍在编辑器里并已加密保存在本机，请稍后重试。`, "danger", [
				["重试", () => void this.keepBoth(localText, msg, onlyLocal)],
			]);
		}
	}

	/**
	 * 锁定 / 离开：有限时间内尝试把未保存内容加密落盘（不会为了等它而无限保持解锁），
	 * 然后销毁编辑器、清空正文与预览。返回草稿是否已落盘。
	 */
	async lock(timeoutMs = 1500): Promise<boolean> {
		let ok = !this.dirty;
		if (this.dirty) ok = await Promise.race([this.saveDraft(), new Promise<boolean>((r) => setTimeout(() => r(false), timeoutMs))]);
		this.destroyed = true;
		window.clearTimeout(this.draftTimer);
		window.clearTimeout(this.uploadTimer);
		this.editor?.destroy();
		this.editor = null;
		this.prepared = null;
		this.synced = "";
		this.previewEl.innerHTML = "";
		this.root.innerHTML = "";
		this.state = "locked";
		return ok;
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
				if (links.length) this.editor.insert(links.join("\n"));
				this.notice(`附件「${f.name || "粘贴的内容"}」上传失败：${e instanceof Error ? e.message : String(e)}`, "danger");
				return;
			}
		}
		this.notice("");
		this.editor.insert(links.join("\n"));
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

	/** 未落盘的内容先加密保存（改名前、页面隐藏时）。 */
	async flush(): Promise<boolean> {
		if (!this.dirty) return true;
		return this.saveDraft();
	}

	/**
	 * 别处更新了这篇笔记（轮询发现）：没有未保存的修改就直接载入新版本；
	 * 有的话不动编辑器，提示保存时会自动合并（CAS → 三方合并 → 合并不了保留双方）。
	 */
	async remoteChanged(): Promise<void> {
		if (this.destroyed || this.busy || this.detached) return;
		if (this.dirty || this.state === "conflict") {
			this.notice("这篇笔记在别处有新版本：保存时会自动与你的修改合并，合并不了就保留双方。", "info");
			return;
		}
		const remote = await this.host.fetchRemote(this.file).catch(() => null);
		if (!remote || this.destroyed || this.dirty) return; // 取远端期间用户开始输入了：交给保存时合并
		this.file = { ...this.file, revision: remote.revision, generation: Math.max(this.file.generation, remote.generation), fileId: remote.fileId || this.file.fileId };
		this.synced = remote.text;
		this.prepared = null;
		if (this.editor) this.editor.replaceAll(remote.text);
		if (this.mode !== "edit") this.host.renderPreview(this.previewEl, remote.text);
		this.setState("synced");
		this.lastSyncedAt = Date.now();
		this.notice(`已载入别处的更新（${hhmmss(this.lastSyncedAt)}）`, "info");
	}

	/** 别处删除了这篇笔记（轮询发现）。保存时会走「远端已删除」流程，另存为新笔记。 */
	remoteDeleted(): void {
		if (this.destroyed || this.detached) return;
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
			if (this.dirty && this.state !== "conflict" && this.state !== "auth") await this.saveNow();
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
