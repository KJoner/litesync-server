/**
 * 账号页与工作台共用的小部件（UI 焕新 v2 / v12.0.3）：主题按钮、图标按钮、相对时间。
 * 只管展示；登录、密钥、同步与权限的判断都留在原来的模块里。
 */
import { icon, IconName } from "./icons";
import { currentTheme } from "./theme";

export function h<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string): HTMLElementTagNameMap[K] {
	const n = document.createElement(tag);
	if (cls) n.className = cls;
	if (text !== undefined) n.textContent = text;
	return n;
}

/** 只有图标的按钮：一定带可读名称（aria-label + title）。 */
export function iconButton(name: IconName, label: string, cls = "icon-btn", onClick?: () => void): HTMLButtonElement {
	const b = h("button", cls);
	b.type = "button";
	b.append(icon(name));
	b.setAttribute("aria-label", label);
	b.title = label;
	if (onClick) b.onclick = onClick;
	return b;
}

/** 图标 + 文字的按钮。 */
export function labelButton(name: IconName | null, text: string, cls: string, onClick?: () => void, after = false): HTMLButtonElement {
	const b = h("button", cls);
	b.type = "button";
	const t = h("span", "", text);
	if (!name) b.append(t);
	else if (after) b.append(t, icon(name));
	else b.append(icon(name), t);
	if (onClick) b.onclick = onClick;
	return b;
}

function syncThemeButton(b: HTMLElement): void {
	const dark = currentTheme() === "dark";
	const label = dark ? "切换到浅色主题" : "切换到深色主题";
	b.replaceChildren(icon(dark ? "sun" : "moon"));
	if (b.dataset.themeText) b.append(h("span", "", "切换主题"));
	b.setAttribute("aria-label", label);
	b.title = label;
}

/** 页面上所有主题按钮的图标与名称跟随当前主题（切换后、系统主题变化后）。 */
export function refreshThemeButtons(): void {
	document.querySelectorAll<HTMLElement>("[data-theme-toggle]").forEach(syncThemeButton);
}

if (typeof matchMedia === "function") {
	matchMedia("(prefers-color-scheme: light)").addEventListener?.("change", () => setTimeout(refreshThemeButtons, 0));
}

/** 主题按钮：沿用既有的主题选择（theme.ts：没选过跟随系统，点过就记住）。withText：抽屉里带文字的一行。 */
export function themeButton(toggle: () => void, cls = "icon-btn theme-control", withText = false): HTMLButtonElement {
	const b = h("button", cls);
	b.type = "button";
	b.dataset.themeToggle = "";
	if (withText) b.dataset.themeText = "1";
	syncThemeButton(b);
	b.onclick = () => {
		toggle();
		refreshThemeButtons();
	};
	return b;
}

/** LiteSync 字标（图标 + 文字）。href 为空时是不可点的文字。 */
export function brand(href?: string, label = "LiteSync"): HTMLElement {
	const n = href ? h("a", "brand-mark") : h("div", "brand-mark");
	if (href) {
		(n as HTMLAnchorElement).href = href;
		n.setAttribute("aria-label", label);
	}
	n.append(icon("logo"), h("span", "wordmark", "LiteSync"));
	return n;
}

const pad = (n: number) => String(n).padStart(2, "0");

/** 「今天 10:24」「昨天 18:07」「11月20日 20:36」「2025年3月1日」：列表里的相对时间。 */
export function fmtRelative(ms: number, now = Date.now()): string {
	if (!ms) return "";
	const d = new Date(ms);
	const today = new Date(now);
	today.setHours(0, 0, 0, 0);
	const day = new Date(d);
	day.setHours(0, 0, 0, 0);
	const diffDays = Math.round((today.getTime() - day.getTime()) / 86_400_000);
	const hm = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
	if (diffDays === 0) return `今天 ${hm}`;
	if (diffDays === 1) return `昨天 ${hm}`;
	if (d.getFullYear() === new Date(now).getFullYear() && diffDays > 0) return `${d.getMonth() + 1}月${d.getDate()}日 ${hm}`;
	return `${d.getFullYear()}年${d.getMonth() + 1}月${d.getDate()}日`;
}
