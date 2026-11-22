/**
 * 深浅主题（UI 焕新 U4）：没有选过就跟随系统，并随系统切换；点过「切换主题」就记住那一次的选择。
 * 网页、分享页、加入页共用这一份，避免三处各自默认深色。
 */
export const THEME_KEY = "litesync-theme";

function stored(): "light" | "dark" | null {
	try {
		const v = localStorage.getItem(THEME_KEY);
		return v === "light" || v === "dark" ? v : null;
	} catch {
		return null;
	}
}

const systemLight = () => typeof matchMedia === "function" && matchMedia("(prefers-color-scheme: light)").matches;

export function currentTheme(): "light" | "dark" {
	return stored() ?? (systemLight() ? "light" : "dark");
}

export function applyTheme(): void {
	document.documentElement.dataset.theme = currentTheme();
}

/** 跟随系统：只在没有手动选择时生效。 */
export function followSystemTheme(): void {
	applyTheme();
	if (typeof matchMedia !== "function") return;
	matchMedia("(prefers-color-scheme: light)").addEventListener?.("change", () => {
		if (!stored()) applyTheme();
	});
}

export function toggleTheme(): void {
	try {
		localStorage.setItem(THEME_KEY, currentTheme() === "dark" ? "light" : "dark");
	} catch {
		/* storage disabled: this page only */
		document.documentElement.dataset.theme = currentTheme() === "dark" ? "light" : "dark";
		return;
	}
	applyTheme();
}
