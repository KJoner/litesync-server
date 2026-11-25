/**
 * 网页端统一的线性图标（UI 焕新 v2 / v12.0.3）：一套本地内联 SVG，代替各处的 emoji 与 Unicode 符号
 * （它们在不同系统上字形、大小、颜色都不一样）。图标只做装饰：一律 aria-hidden，
 * 按钮的可读名称由文字或 aria-label 提供。路径是静态字符串，不拼接任何外部内容。
 */
const PATHS = {
	logo: '<path d="m12 2 10 10-10 10L2 12Z"/><path d="m12 7 5 5-5 5-5-5Z"/>',
	folder: '<path d="M3 6a2 2 0 0 1 2-2h5l2 3h7a2 2 0 0 1 2 2v10H3Z"/>',
	file: '<path d="M6 3h8l4 4v14H6Z"/><path d="M14 3v5h4M9 12h6M9 16h6"/>',
	attachment: '<path d="m20.5 11.5-8.2 8.2a5 5 0 0 1-7-7l8.6-8.6a3.3 3.3 0 0 1 4.7 4.7l-8.6 8.6a1.7 1.7 0 0 1-2.4-2.4l7.9-7.9"/>',
	image: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="2"/><path d="m21 16-5-5-9 9"/>',
	chevron: '<path d="m9 5 7 7-7 7"/>',
	down: '<path d="m6 9 6 6 6-6"/>',
	arrow: '<path d="M4 12h15m-6-6 6 6-6 6"/>',
	back: '<path d="M20 12H5m6-6-6 6 6 6"/>',
	check: '<path d="m5 12 4 4L19 6"/>',
	search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
	home: '<path d="m3 10 9-7 9 7M5 9v11h5v-7h4v7h5V9"/>',
	lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
	unlock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 7-2"/>',
	sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/>',
	moon: '<path d="M20 15a8 8 0 0 1-11-11 9 9 0 1 0 11 11Z"/>',
	plus: '<path d="M12 5v14M5 12h14"/>',
	settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z"/>',
	trash: '<path d="M4 6h16M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7m4-7v7"/>',
	menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
	close: '<path d="m5 5 14 14M19 5 5 19"/>',
	monitor: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 21h8M12 16v5"/>',
	phone: '<rect x="6" y="2" width="12" height="20" rx="3"/><path d="M10 5h4M11 19h2"/>',
	shield: '<path d="m12 2 9 4v6c0 5-9 10-9 10S3 17 3 12V6Z"/><path d="m8 12 3 3 5-6"/>',
	cloud: '<path d="M7 18h11a4 4 0 0 0 1-8 7 7 0 0 0-13-2 5 5 0 0 0 1 10Z"/>',
	copy: '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
	eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
	eyeOff: '<path d="M3 3l18 18M10.6 5.1A10 10 0 0 1 12 5c6 0 10 7 10 7a17 17 0 0 1-3.2 4M6.6 6.6A17 17 0 0 0 2 12s4 7 10 7a9.7 9.7 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
	external: '<path d="M14 3h7v7M21 3l-11 11M11 5H4v15h15v-7"/>',
	clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
	history: '<path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1L3.5 8.5"/><path d="M3.5 3.5v5h5M12 7.5V12l3 2"/>',
	info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7v.01"/>',
	warn: '<path d="M12 3 2 20h20Z"/><path d="M12 10v4M12 17v.01"/>',
	more: '<circle cx="5" cy="12" r="1.2"/><circle cx="12" cy="12" r="1.2"/><circle cx="19" cy="12" r="1.2"/>',
	user: '<circle cx="12" cy="8" r="4"/><path d="M4 21v-1a8 8 0 0 1 16 0v1"/>',
	users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0M16 4.6a3.5 3.5 0 0 1 0 6.8M18 20h3.5a6.5 6.5 0 0 0-4-6"/>',
	tools: '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2.4-.6-.6-2.4Z"/>',
	database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
	refresh: '<path d="M20 11a8 8 0 0 0-14.9-4M4 4v4h4M4 13a8 8 0 0 0 14.9 4M20 20v-4h-4"/>',
	logout: '<path d="M10 4H5v16h5m4-12 4 4-4 4m-6-4h10"/>',
	box: '<path d="m3 7 9-5 9 5v11l-9 5-9-5ZM3 7l9 5 9-5M12 12v11"/>',
	link: '<path d="M10 14a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1"/><path d="M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>',
	checksquare: '<rect x="3" y="3" width="18" height="18" rx="3"/><path d="m7 12 3 3 7-7"/>',
	// 编辑器格式栏（用户决定：emoji 换成图标；只换外观，按钮的动作与快捷行为不变）
	heading: '<path d="M6 4v16M17 4v16M6 12h11"/>',
	bold: '<path d="M7 4h6a4 4 0 0 1 0 8H7Z"/><path d="M7 12h7.5a4 4 0 0 1 0 8H7Z"/>',
	italic: '<path d="M10 4h8M6 20h8M14.5 4l-5 16"/>',
	list: '<path d="M10 6h10M10 12h10M10 18h10"/><circle cx="5" cy="6" r="1"/><circle cx="5" cy="12" r="1"/><circle cx="5" cy="18" r="1"/>',
	task: '<rect x="3" y="4" width="7" height="7" rx="1.5"/><path d="m4.5 17 1.8 1.8L9.5 15.5M14 7.5h7M14 17h7"/>',
	code: '<path d="m8 7-5 5 5 5M16 7l5 5-5 5"/>',
} as const;

export type IconName = keyof typeof PATHS;

const SVG_NS = "http://www.w3.org/2000/svg";

export function icon(name: IconName, cls = ""): SVGSVGElement {
	const svg = document.createElementNS(SVG_NS, "svg");
	svg.setAttribute("viewBox", "0 0 24 24");
	svg.setAttribute("aria-hidden", "true");
	svg.setAttribute("focusable", "false");
	svg.setAttribute("class", cls ? `icon ${cls}` : "icon");
	svg.innerHTML = PATHS[name];
	return svg;
}

/** 文字 + 图标：图标在前（after=true 时在后，例如「打开仓库 →」）。 */
export function withIcon<T extends HTMLElement>(node: T, name: IconName, text: string, after = false): T {
	const label = document.createElement("span");
	label.textContent = text;
	if (after) node.append(label, icon(name));
	else node.append(icon(name), label);
	return node;
}
