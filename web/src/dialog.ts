/**
 * 产品内的对话框与抽屉（UI 规格 §6「焦点」，UI 焕新 U4 / U4b）：
 * 打开时焦点进入，Tab 不离开，Esc 或点遮罩关闭，关闭后焦点回到触发它的按钮。
 */
import { icon } from "./icons";

function h<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string): HTMLElementTagNameMap[K] {
	const n = document.createElement(tag);
	if (cls) n.className = cls;
	if (text !== undefined) n.textContent = text;
	return n;
}

const FOCUSABLE = "button,input,select,textarea,a[href],[tabindex]:not([tabindex='-1'])";

/** 简单的焦点陷阱：Tab / Shift+Tab 在容器内循环。 */
function trapTab(box: HTMLElement, e: KeyboardEvent): void {
	const f = Array.from(box.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((n) => !n.hasAttribute("disabled") && !n.closest("[hidden]"));
	if (f.length === 0) return;
	const first = f[0], last = f[f.length - 1];
	if (e.shiftKey && (document.activeElement === first || !box.contains(document.activeElement))) {
		last.focus();
		e.preventDefault();
	} else if (!e.shiftKey && (document.activeElement === last || !box.contains(document.activeElement))) {
		first.focus();
		e.preventDefault();
	}
}

/** 模态对话框：焦点进入、Esc 关闭并把焦点还给触发按钮。 */
export function openDialog(title: string, onClose?: () => void): { body: HTMLElement; close: (silent?: boolean) => void; setTitle: (t: string) => void } {
	const opener = document.activeElement as HTMLElement | null;
	const backdrop = h("div", "dialog-backdrop");
	const dlg = h("div", "dialog");
	dlg.setAttribute("role", "dialog");
	dlg.setAttribute("aria-modal", "true");
	const head = h("div", "dialog-head");
	const t = h("h2", "dialog-title", title);
	t.id = "dlg-" + Math.random().toString(36).slice(2);
	dlg.setAttribute("aria-labelledby", t.id);
	const x = h("button", "icon-btn dialog-close");
	x.append(icon("close"));
	x.type = "button";
	x.onclick = () => close();
	x.setAttribute("aria-label", "关闭");
	head.append(t, x);
	const body = h("div", "dialog-body");
	dlg.append(head, body);
	backdrop.append(dlg);
	document.body.append(backdrop);
	let closed = false;
	const onKey = (e: KeyboardEvent) => {
		// 叠在上面的对话框先处理（例如在抽屉里打开的确认框）
		if (backdrop.nextElementSibling?.classList.contains("dialog-backdrop")) return;
		if (e.key === "Escape") close();
		if (e.key === "Tab") trapTab(dlg, e);
	};
	document.addEventListener("keydown", onKey);
	/** silent：只关窗，不触发 onClose（例如关窗后立刻切到别的页面，不能再回头重绘列表）。 */
	const close = (silent = false) => {
		if (closed) return;
		closed = true;
		document.removeEventListener("keydown", onKey);
		backdrop.remove();
		if (silent) return;
		onClose?.();
		opener?.focus?.();
	};
	setTimeout(() => (dlg.querySelector<HTMLElement>("input,button.primary,button") ?? x).focus(), 0);
	return { body, close, setTitle: (s) => (t.textContent = s) };
}

export interface DrawerHandle {
	body: HTMLElement;
	panel: HTMLElement;
	close: (silent?: boolean) => void;
}

/**
 * 侧边抽屉（历史版本等，W08）：带遮罩的模态面板。打开时焦点进入面板标题，Tab 不出抽屉，
 * Esc / 遮罩 / 「关闭」都能关，关闭后焦点回到触发按钮，触发按钮的 aria-expanded 随之更新。
 */
export function openDrawer(o: { id: string; title: string; opener?: HTMLElement | null; onClose?: () => void }): DrawerHandle {
	const opener = o.opener ?? (document.activeElement as HTMLElement | null);
	const backdrop = h("div", "drawer-backdrop");
	const panel = h("aside", "drawer");
	panel.id = o.id;
	panel.setAttribute("role", "dialog");
	panel.setAttribute("aria-modal", "true");
	const head = h("div", "drawer-head");
	const t = h("h2", "drawer-title", o.title);
	t.id = `${o.id}-title`;
	t.tabIndex = -1;
	panel.setAttribute("aria-labelledby", t.id);
	const x = h("button", "btn ghost small-btn", "关闭");
	x.type = "button";
	x.onclick = () => close();
	head.append(t, x);
	const body = h("div", "drawer-body");
	panel.append(head, body);
	backdrop.onclick = () => close();
	document.body.append(backdrop, panel);
	opener?.setAttribute("aria-expanded", "true");
	let closed = false;
	const onKey = (e: KeyboardEvent) => {
		if (document.querySelector(".dialog-backdrop")) return; // 抽屉上面还有对话框：交给它
		if (e.key === "Escape") {
			e.preventDefault();
			close();
		}
		if (e.key === "Tab") trapTab(panel, e);
	};
	document.addEventListener("keydown", onKey);
	const close = (silent = false) => {
		if (closed) return;
		closed = true;
		document.removeEventListener("keydown", onKey);
		backdrop.remove();
		panel.remove();
		opener?.setAttribute("aria-expanded", "false");
		o.onClose?.();
		if (!silent && opener?.isConnected) opener.focus();
	};
	setTimeout(() => t.focus(), 0);
	return { body, panel, close };
}
