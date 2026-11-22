import { openDialog } from "./portal";

/**
 * 笔记的新建 / 重命名 / 移动到 / 删除（UI 焕新 U4，审查 03）：产品内的对话框代替浏览器原生
 * prompt / confirm / alert。标题和位置分开填，不要求用户手写完整路径；错误留在表单里，
 * 已填的内容不丢；Esc / 取消不提交；完成后焦点回到触发按钮（openDialog 负责）。
 */
function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string): HTMLElementTagNameMap[K] {
	const n = document.createElement(tag);
	if (cls) n.className = cls;
	if (text !== undefined) n.textContent = text;
	return n;
}

let seq = 0;
const uid = (p: string) => `${p}-${++seq}`;

/** 仓库里已有的文件夹（取自文件路径），根目录用 ""。 */
export function foldersOf(paths: readonly string[]): string[] {
	const set = new Set<string>();
	for (const p of paths) {
		const segs = p.split("/");
		for (let i = 1; i < segs.length; i++) set.add(segs.slice(0, i).join("/"));
	}
	return ["", ...[...set].sort((a, b) => a.localeCompare(b, "zh-Hans-CN"))];
}

export const folderOf = (path: string) => (path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "");
export const titleOf = (path: string) => (path.split("/").pop() ?? path).replace(/\.md$/i, "");

const NEW_FOLDER = "\u0000new";

export interface NoteLocationOptions {
	title: string;
	okLabel: string;
	/** 初始标题（不含 .md）。 */
	name?: string;
	/** 初始位置（文件夹，"" = 根目录）。 */
	folder?: string;
	folders: readonly string[];
	/** 重命名只改标题，移动只改位置。 */
	askName: boolean;
	askFolder: boolean;
	/** 用户输入 → 规范化后的路径；不合法返回 null。 */
	normalize(input: string): string | null;
	/** 提交前的本地检查（撞名等）；返回要显示的错误。 */
	check?(path: string): string | null;
	/** 真正执行；返回错误文字（表单保持打开、内容保留），成功返回 null。 */
	submit(path: string): Promise<string | null>;
}

export function noteLocationDialog(o: NoteLocationOptions): void {
	const dlg = openDialog(o.title);
	const form = el("form", "note-form");
	form.noValidate = true;
	const errId = uid("note-err");

	const nameInput = el("input");
	nameInput.type = "text";
	nameInput.value = o.name ?? "";
	nameInput.autocomplete = "off";
	nameInput.spellcheck = false;
	nameInput.setAttribute("aria-describedby", errId);
	if (o.askName) {
		const f = el("label", "field");
		f.append(el("span", "", "标题"), nameInput);
		form.append(f);
	}

	const select = el("select");
	const newFolder = el("input");
	newFolder.type = "text";
	newFolder.placeholder = "例如：工作/周记";
	newFolder.autocomplete = "off";
	const newFolderField = el("label", "field");
	newFolderField.append(el("span", "", "新文件夹名称"), newFolder);
	newFolderField.hidden = true;
	if (o.askFolder) {
		for (const f of o.folders) {
			const opt = el("option", "", f === "" ? "仓库根目录" : f);
			opt.value = f;
			select.append(opt);
		}
		const add = el("option", "", "新建文件夹…");
		add.value = NEW_FOLDER;
		select.append(add);
		select.value = o.folders.includes(o.folder ?? "") ? (o.folder ?? "") : "";
		const f = el("label", "field");
		f.append(el("span", "", "位置"), select);
		form.append(f, newFolderField);
		select.onchange = () => {
			newFolderField.hidden = select.value !== NEW_FOLDER;
			if (!newFolderField.hidden) newFolder.focus();
			update();
		};
	}

	const preview = el("p", "muted small note-form-preview");
	const error = el("p", "error small note-form-error");
	error.id = errId;
	error.setAttribute("role", "alert");
	const actions = el("div", "dialog-actions");
	const cancel = el("button", "ghost", "取消");
	cancel.type = "button";
	cancel.onclick = () => dlg.close();
	const ok = el("button", "primary", o.okLabel);
	ok.type = "submit";
	actions.append(cancel, ok);
	form.append(preview, error, actions);
	dlg.body.append(form);

	const folder = () => (!o.askFolder ? (o.folder ?? "") : select.value === NEW_FOLDER ? newFolder.value.trim().replace(/^\/+|\/+$/g, "") : select.value);
	const name = () => (o.askName ? nameInput.value : (o.name ?? ""));
	const candidate = () => {
		const n = name().trim();
		if (!n) return null;
		return o.normalize(folder() ? `${folder()}/${n}` : n);
	};
	const update = () => {
		const p = candidate();
		preview.textContent = p ? `保存为：${p}` : "";
	};
	nameInput.oninput = update;
	newFolder.oninput = update;
	update();

	form.onsubmit = async (e) => {
		e.preventDefault();
		error.textContent = "";
		if (o.askName && !nameInput.value.trim()) {
			error.textContent = "请填写标题。";
			nameInput.focus();
			return;
		}
		const p = candidate();
		if (!p) {
			error.textContent = "名称或位置不能用：不能为空、不能以「.」开头，也不能包含「..」。";
			(o.askName ? nameInput : newFolderField.hidden ? select : newFolder).focus();
			return;
		}
		const local = o.check?.(p) ?? null;
		if (local) {
			error.textContent = local;
			(o.askName ? nameInput : select).focus();
			return;
		}
		ok.disabled = true;
		cancel.disabled = true;
		try {
			const failed = await o.submit(p);
			if (failed) {
				error.textContent = failed;
				(o.askName ? nameInput : select).focus();
				return;
			}
			dlg.close(true);
		} finally {
			ok.disabled = false;
			cancel.disabled = false;
		}
	};
	// The title field gets the focus, with the text selected (rename: type to replace).
	setTimeout(() => {
		if (o.askName) {
			nameInput.focus();
			nameInput.select();
		} else select.focus();
	}, 0);
}

export interface ConfirmOptions {
	title: string;
	message: string;
	okLabel: string;
	danger?: boolean;
	/** 返回错误文字时对话框保持打开并显示它。 */
	confirm(): Promise<string | null>;
}

export function confirmDialog(o: ConfirmOptions): void {
	const dlg = openDialog(o.title);
	const msg = el("p", "", o.message);
	msg.style.whiteSpace = "pre-line";
	const error = el("p", "error small");
	error.setAttribute("role", "alert");
	const actions = el("div", "dialog-actions");
	const cancel = el("button", "ghost", "取消");
	cancel.type = "button";
	cancel.onclick = () => dlg.close();
	const ok = el("button", o.danger ? "danger-solid" : "primary", o.okLabel);
	ok.type = "button";
	ok.onclick = async () => {
		error.textContent = "";
		ok.disabled = true;
		cancel.disabled = true;
		try {
			const failed = await o.confirm();
			if (failed) {
				error.textContent = failed;
				return;
			}
			dlg.close(true);
		} finally {
			ok.disabled = false;
			cancel.disabled = false;
		}
	};
	actions.append(cancel, ok);
	dlg.body.append(msg, error, actions);
	// Destructive actions do not start focused on the destructive button.
	setTimeout(() => (o.danger ? cancel : ok).focus(), 0);
}

/** 只是告知（代替 alert）：一句话 + 「知道了」。 */
export function noticeDialog(title: string, message: string): void {
	const dlg = openDialog(title);
	const msg = el("p", "", message);
	msg.style.whiteSpace = "pre-line";
	const actions = el("div", "dialog-actions");
	const ok = el("button", "primary", "知道了");
	ok.type = "button";
	ok.onclick = () => dlg.close();
	actions.append(ok);
	dlg.body.append(msg, actions);
}
