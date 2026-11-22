/**
 * 账号级页面（v0.20 公开化）：统一登录、我的仓库、网页建库（浏览器端 E2EE 初始化）、
 * 连接 Obsidian（指定仓库配对 v2）、账号与设备。
 *
 * 安全约定（ADR-012 / ADR-014 / ADR-015）：
 *   - 仓库密码、KEK、明文 VMK 只在本页内存里存在，从不写入任何浏览器存储、从不上传；
 *     服务端只收到与插件逐字段一致的、用仓库密码包装过的 keyDoc（vendor 进来的插件源码生成）。
 *   - sessionStorage 里只放**非秘密**的幂等键（clientRequestId / opId），用于刷新后续接，
 *     保证「重复点击、网络中断、刷新重试」不会建出两个仓库或换掉密钥。
 *   - 配对链接只含一次性 enrollment 与本地加密的配置包，密钥在 #fragment 里。
 *
 * UI 焕新 v2（v12.0.3 V1/V2）：欢迎页两栏构图、仓库门户与账号页按定稿原型重排。只改展示——
 * 登录入口仍是 /auth/login（带 invite / returnTo / intent），注册按真实的开放状态显示，
 * Token 登录只在服务器开放时出现；建库、配对、撤销的流程与文字承诺不变。
 */
import qrcode from "qrcode-generator";
import { icon, IconName, withIcon } from "./icons";
import { brand, labelButton, themeButton } from "./ui";
import {
	accountApi,
	announceAccount,
	ApiCodeError,
	AuthConfig,
	AuthError,
	login,
	Me,
	PairingGrantResp,
	PeerDelivery,
	RevocationView,
	Usage,
	VaultCard,
} from "./api";
import {
	b64encode,
	b64urlEncode,
	createVaultKeyDoc,
	deriveResetAuth,
	exportVmkRaw,
	randomBytes,
	unlockVaultKey,
	VaultKeyDoc,
} from "./vendor/litesync-core/crypto/crypto";
import { openDialog } from "./dialog";
import { confirmDialog, fieldsDialog, noticeDialog, typedConfirmDialog } from "./forms";

export interface PortalHost {
	root: HTMLElement;
	/** 进入某个仓库的笔记工作台（preset：刚建库时手里已有的密钥，免得立刻再输一次密码）。 */
	openVault(vaultId: string, preset?: { doc: VaultKeyDoc; vmk: CryptoKey }): void;
	toggleTheme(): void;
	/** 这个浏览器上次打开的仓库（W03：从工作台离开后回来，一眼找到继续的入口）。 */
	lastVault?(): string;
}

// ---------------------------------------------------------------- 小工具

function h<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string): HTMLElementTagNameMap[K] {
	const n = document.createElement(tag);
	if (cls) n.className = cls;
	if (text !== undefined) n.textContent = text;
	return n;
}

function button(text: string, cls: string, onClick: () => void): HTMLButtonElement {
	const b = h("button", cls, text);
	b.type = "button";
	b.onclick = onClick;
	return b;
}

function fmtBytes(n: number): string {
	if (n < 1024) return `${n} B`;
	if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
	if (n < 1024 ** 3) return `${(n / 1024 / 1024).toFixed(1)} MB`;
	return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

function fmtWhen(unixSec: number): string {
	if (!unixSec) return "尚无内容";
	const d = Date.now() / 1000 - unixSec;
	if (d < 60) return "刚刚更新";
	if (d < 3600) return `${Math.floor(d / 60)} 分钟前更新`;
	if (d < 86400) return `${Math.floor(d / 3600)} 小时前更新`;
	return `更新于 ${new Date(unixSec * 1000).toLocaleDateString()}`;
}

function errText(e: unknown): string {
	if (e instanceof ApiCodeError) {
		switch (e.code) {
			case "EMAIL_NOT_VERIFIED":
				return "请先验证邮箱，再创建仓库或连接设备。";
			case "CONFLICT":
				return e.message;
			case "VAULT_NOT_READY":
				return "这个仓库还没有完成加密设置。";
			case "INIT_IN_PROGRESS":
				return "另一个窗口正在设置这个仓库的加密，请稍候再试（最多 10 分钟）。";
			case "REAUTH_REQUIRED":
				return "为了安全，请重新登录后再连接新设备。";
			case "RATE_LIMITED":
				return "操作太频繁，请稍后再试。";
			default:
				return e.message || `请求失败（${e.code}）`;
		}
	}
	if (e instanceof TypeError) return "网络连接失败，请检查网络后重试。";
	return e instanceof Error ? e.message : String(e);
}

const store = {
	get(k: string): string | null {
		try {
			return sessionStorage.getItem(k);
		} catch {
			return null;
		}
	},
	set(k: string, v: string): void {
		try {
			sessionStorage.setItem(k, v);
		} catch {
			/* 隐私模式：幂等键只在内存里，刷新后重新开始（服务端仍保证不会重复建库） */
		}
	},
	del(k: string): void {
		try {
			sessionStorage.removeItem(k);
		} catch {
			/* ignore */
		}
	},
};

function newId(prefix: string): string {
	return prefix + "_" + Array.from(randomBytes(12)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export { openDialog };

// ---------------------------------------------------------------- 外框

type Section = "vaults" | "me";

/**
 * 账号级页面的页头：品牌、我的仓库、账号与设备、主题。顶栏不显示用户名、昵称或邮箱
 * （身份资料只在「账号与设备」里）。解锁页也用这一条页头。
 */
export function portalHeader(host: Pick<PortalHost, "toggleTheme">, active: Section | ""): HTMLElement {
	const top = h("header", "portal-header");
	top.append(brand("#/vaults", "LiteSync 我的仓库"));
	const nav = h("nav", "portal-nav");
	nav.setAttribute("aria-label", "主导航");
	for (const [key, label, hash] of [
		["vaults", "我的仓库", "#/vaults"],
		["me", "账号与设备", "#/me"],
	] as const) {
		const a = h("a", "portal-nav-item" + (active === key ? " active" : ""), label);
		a.href = hash;
		if (active === key) a.setAttribute("aria-current", "page");
		nav.append(a);
	}
	nav.append(themeButton(() => host.toggleTheme()));
	top.append(nav);
	return top;
}

function shell(host: PortalHost, active: Section): HTMLElement {
	host.root.innerHTML = "";
	const page = h("div", "portal");
	const main = h("main", "portal-content");
	page.append(portalHeader(host, active), main);
	host.root.append(page);
	return main;
}

/** 页面标题区：小标题、标题、一行说明，右侧一个动作（可选）。 */
function headline(eyebrow: string, title: string, lead: string, action?: HTMLElement | null): HTMLElement {
	const head = h("div", "headline");
	const text = h("div", "headline-text");
	text.append(h("p", "eyebrow", eyebrow), h("h1", "", title), h("p", "lead", lead));
	head.append(text);
	if (action) head.append(action);
	return head;
}

function pill(tone: "" | "ok" | "warn" | "danger", name: IconName, text: string): HTMLElement {
	const p = h("span", "pill" + (tone ? " " + tone : ""));
	p.append(icon(name), h("span", "", text));
	return p;
}

// ---------------------------------------------------------------- 登录

/** 欢迎页左侧的小窗口：纯装饰（aria-hidden），只有通用的示例文字，不含任何真实笔记或账号。 */
function miniWindow(): HTMLElement {
	const w = h("div", "mini-window");
	w.setAttribute("aria-hidden", "true");
	const top = h("div", "mini-top");
	const a = h("span");
	a.append(icon("folder"), "工作笔记");
	const b = h("span");
	b.append(icon("lock"), "本次会话已解锁");
	top.append(a, b);
	const body = h("div", "mini-body");
	const side = h("div", "mini-sidebar");
	for (const t of ["概览", "项目笔记", "灵感收集", "资料"]) side.append(h("span", "", t));
	const doc = h("div", "mini-doc");
	doc.append(h("strong", "", "把想法，写成下一步。"), h("span", "mini-line"), h("span", "mini-line"), h("span", "mini-line"));
	const note = h("span", "mini-note");
	note.append(icon("lock"), "每个仓库，用独立密码保护");
	doc.append(note);
	body.append(side, doc);
	w.append(top, body);
	return w;
}

/**
 * LiteSync 自己的欢迎页（V1 / L1）：左侧品牌与说明，右侧入口。账号密码只在账号中心填写——这里只有
 * 「登录账号」（既有的 /auth/login，带 invite / returnTo）和按真实开放状态显示的「创建账号」；
 * Token 登录只在服务器开放时出现（同时开了统一登录时折叠在「自托管与管理员连接」里）。
 */
export function renderLoginPage(host: PortalHost, cfg: AuthConfig, error?: string): void {
	host.root.innerHTML = "";
	const page = h("main", "welcome");

	const art = h("section", "welcome-art");
	art.setAttribute("aria-label", "LiteSync 简介");
	art.append(brand());
	const story = h("div", "welcome-story");
	const headline = h("p", "welcome-headline");
	headline.append("你的笔记，", h("br"), "始终与你同在。");
	const sub = h("p", "welcome-sub");
	sub.append("在电脑上开始，在手机上继续。", h("br"), "让每一个值得保留的想法，都有自己的位置。");
	story.append(h("p", "eyebrow", "A quiet place for your thoughts"), headline, sub, miniWindow());
	art.append(story);
	const foot = h("ul", "welcome-foot");
	for (const [name, text] of [["folder", "多个仓库"], ["cloud", "设备同步"], ["shield", "独立仓库密码"]] as const) {
		const li = h("li");
		li.append(icon(name), h("span", "", text));
		foot.append(li);
	}
	art.append(foot);

	const right = h("section", "welcome-right");
	const util = h("div", "utility-top");
	util.append(h("span", "lang-label", "简体中文"), themeButton(() => host.toggleTheme()));
	right.append(util);
	const card = h("div", "welcome-form login-card");
	const invite = new URLSearchParams(location.search).get("invite") ?? "";
	const errEl = h("p", "error welcome-error", error ?? "");
	errEl.setAttribute("role", "alert");
	const title = h("h1", "welcome-title");
	title.append("从这里，", h("br"), "继续你的想法。");
	card.append(h("p", "eyebrow", "Welcome to LiteSync"), title);

	if (cfg.oidc) {
		// 注册按真实的开放状态说清楚，不摆一个点了也注册不成的按钮（只改展示，登录流程不变）
		const intro = h("p", "intro");
		intro.append("一个账号，连接 LiteSync 与 Nexus。", h("br"), "登录后，即可打开你的笔记仓库。");
		card.append(intro);
		const q = new URLSearchParams({ returnTo: "/#/vaults" });
		if (invite) q.set("invite", invite);
		const signIn = h("a", "btn primary wide");
		signIn.href = "/auth/login?" + q.toString();
		withIcon(signIn, "arrow", "登录账号", true);
		card.append(signIn);
		const rq = new URLSearchParams(q);
		rq.set("intent", "register");
		if (cfg.registrationMode === "open" || (cfg.registrationMode === "invite" && invite)) {
			const reg = h("a", "btn wide", invite ? "用邀请创建账号" : "创建账号");
			reg.href = "/auth/login?" + rq.toString();
			card.append(reg);
			if (invite) card.append(h("p", "welcome-note", "你收到了邀请：用这个页面创建账号，之后就能新建仓库、连接 Obsidian。"));
		} else if (cfg.registrationMode === "invite") {
			card.append(h("p", "welcome-note", "LiteSync 目前只接受邀请注册：请用收到的邀请链接打开这个页面。已经有账号的，直接登录。"));
		} else {
			card.append(h("p", "welcome-note", "LiteSync 暂未开放注册。已经有账号的，直接登录。"));
		}
		// 页面上只留一条短提示；细节放进可展开的帮助
		const tip = h("p", "security-copy");
		tip.append(icon("shield"), h("span", "", "登录账号后，打开仓库还需输入独立的仓库密码。"));
		const help = h("details", "welcome-help");
		const hs = h("summary");
		hs.append(h("span", "", "账号密码和仓库密码有什么不同？"), icon("down"));
		help.append(hs, h("p", "", "登录与注册在账号中心完成，LiteSync 看不到你的账号密码。仓库密码只在你的设备上用来解密笔记，服务器和邮件都无法找回它；重设账号密码也不会改变仓库密码。"));
		card.append(tip, help);
	} else if (cfg.legacyTokenLogin) {
		card.append(h("p", "intro", "端到端加密的笔记同步。每个仓库都用你自己设置的仓库密码在本机加密；这台服务器用 API Token 登录。"));
	} else {
		card.append(h("p", "intro", "端到端加密的笔记同步。每个仓库都用你自己设置的仓库密码在本机加密。"));
	}
	if (cfg.legacyTokenLogin) {
		const box = cfg.oidc ? h("details", "self-hosted") : h("div", "self-hosted token-only");
		if (cfg.oidc) {
			const s = h("summary");
			s.append(h("span", "", "自托管与管理员连接"), icon("down"));
			box.append(s);
		}
		const label = h("label", "field");
		label.append(h("span", "", "API Token"));
		const input = h("input");
		input.type = "password";
		input.autocomplete = "off";
		input.placeholder = "输入服务器提供的 Token";
		label.append(input, h("small", "", "Token 只用于换取网页会话（HttpOnly Cookie），不会保存在浏览器中。"));
		const go = h("button", cfg.oidc ? "btn wide" : "btn primary wide", "使用 Token 登录");
		go.type = "button";
		const submit = async () => {
			go.disabled = true;
			go.textContent = "登录中…";
			try {
				if (!(await login(input.value.trim()))) throw new Error("unauthorized");
				location.hash = "#/vaults";
				location.reload();
			} catch {
				errEl.textContent = "登录失败：Token 不正确，或服务器暂时不可达。";
				go.disabled = false;
				go.textContent = "使用 Token 登录";
			}
		};
		go.onclick = () => void submit();
		input.onkeydown = (e) => {
			if (e.key === "Enter") void submit();
		};
		box.append(label, go);
		card.append(box);
	}
	if (!cfg.oidc && !cfg.legacyTokenLogin) card.append(h("p", "welcome-note", "此服务器没有开放网页登录。"));
	card.append(errEl);
	right.append(card, h("p", "legal-foot", "你的笔记由仓库密码在本机加密保护"));
	page.append(art, right);
	host.root.append(page);
}

// ---------------------------------------------------------------- 我的仓库

export async function renderVaultCenter(host: PortalHost, me: Me): Promise<void> {
	const main = shell(host, "vaults");
	const canCreate = me.permissions.includes("vault:create");
	const create = labelButton("plus", "新建仓库", "btn primary", () => openCreateVaultDialog(host, me));
	create.disabled = !canCreate;
	const head = headline("Your space for every idea", "我的仓库", "为工作与生活，留出各自的空间。", create);
	main.append(head);
	if (!me.account.emailVerified) {
		main.append(h("div", "banner warn", "邮箱尚未验证：验证之前可以浏览，但不能创建仓库或连接新设备。请到邮箱中点击验证链接。"));
	}
	const grid = h("div", "vault-grid");
	grid.append(h("p", "muted", "正在加载…"));
	main.append(grid);
	let vaults: VaultCard[];
	try {
		vaults = await accountApi.vaults();
	} catch (e) {
		if (e instanceof AuthError) return location.reload();
		grid.innerHTML = "";
		grid.append(h("div", "banner danger", "加载仓库失败：" + errText(e)), button("重试", "btn", () => void renderVaultCenter(host, me)));
		return;
	}
	grid.innerHTML = "";
	if (vaults.length === 0) {
		// 没有仓库：主任务只有一个——创建第一个仓库（标题区不再重复放同一个按钮）
		create.remove();
		grid.replaceWith(emptyVaults(host, me, canCreate));
		main.append(portalTip());
		return;
	}
	for (const v of vaults) grid.append(vaultCard(host, me, v));
	main.append(portalTip());
}

function emptyVaults(host: PortalHost, me: Me, canCreate: boolean): HTMLElement {
	const box = h("section", "vault-empty");
	box.setAttribute("aria-labelledby", "vault-empty-title");
	const glyph = h("span", "vault-glyph");
	glyph.append(icon("folder"));
	const title = h("h2", "", "创建第一个仓库");
	title.id = "vault-empty-title";
	box.append(glyph, title, h("p", "muted", "创建第一个仓库，开始保存你的笔记。"));
	const steps = h("ol", "empty-steps");
	for (const [t, d] of [
		["创建仓库", "给它起一个名字"],
		["设置仓库密码", "只在你的设备上用来加密"],
		["连接 Obsidian", "或者直接在网页里写"],
	]) {
		const li = h("li");
		li.append(h("strong", "", t), h("span", "", d));
		steps.append(li);
	}
	const b = labelButton("plus", "创建第一个仓库", "btn primary", () => openCreateVaultDialog(host, me));
	b.disabled = !canCreate;
	box.append(steps, b, h("p", "muted small", "已经在用 Obsidian？先在这里新建一个空仓库，再在 Obsidian 里用「连接链接」接入；本机已有的笔记可以在接入时加密上传。"));
	return box;
}

function portalTip(): HTMLElement {
	const tip = h("aside", "portal-tip");
	const text = h("div");
	text.append(h("strong", "", "每个仓库，都有自己的密码。"), h("span", "", "登录账号后仍需单独解锁仓库。仓库密码不会随账号密码重置，切换仓库时需要重新输入。"));
	tip.append(icon("shield"), text);
	return tip;
}

/** 仓库的真实状态：待完成加密设置 / 已锁定（这一页不持有任何仓库的钥匙）/ 迁移中 / 旧的未加密仓库。 */
function statePill(v: VaultCard): HTMLElement {
	if (v.initState !== "ready") return pill("warn", "warn", "待完成加密设置");
	if (v.encryptionState === "encrypted") return pill("", "lock", "已锁定");
	if (v.encryptionState === "migrating") return pill("warn", "refresh", "加密迁移中");
	return pill("", "info", "未加密（旧仓库）");
}

function vaultCard(host: PortalHost, me: Me, v: VaultCard): HTMLElement {
	const card = h("article", "vault-card");
	const top = h("div", "vault-card-top");
	const glyph = h("span", "vault-glyph");
	glyph.append(icon("folder"));
	const marks = h("div", "vault-marks");
	if (v.initState === "ready" && host.lastVault?.() === v.id) marks.append(h("span", "chip", "上次打开"));
	marks.append(statePill(v));
	top.append(glyph, marks);
	card.append(top);
	const name = h("h2", "vault-name", v.name || "默认仓库");
	card.append(name);
	const stats = h("p", "vault-stats");
	if (v.initState === "ready") {
		for (const t of [`${v.fileCount} 个文件`, fmtBytes(v.bytesUsed), fmtWhen(v.updatedAt)]) stats.append(h("span", "", t));
	} else {
		stats.append(h("span", "", "这个仓库还没有设置仓库密码，完成之前不能写入任何内容。"));
	}
	card.append(stats);
	const bottom = h("div", "vault-card-bottom");
	const actions = h("div", "vault-actions");
	if (v.initState === "ready") {
		bottom.append(h("span", "vault-foot muted small", v.encryptionState === "encrypted" ? "独立仓库密码" : "未设置仓库密码"));
		const connect = labelButton(null, "连接 Obsidian", "btn ghost", () => void openConnectDialog(me, v));
		connect.disabled = !me.permissions.includes("vault:create");
		actions.append(connect, labelButton("arrow", "打开仓库", "btn open-vault", () => host.openVault(v.id), true));
	} else {
		bottom.append(h("span", "vault-foot muted small", "还差一步"));
		actions.append(labelButton(null, "完成加密设置", "btn primary", () => openCreateVaultDialog(host, me, v)));
	}
	const more = h("details", "vault-more");
	const summary = h("summary");
	summary.title = "更多操作";
	summary.append(icon("more"), h("span", "sr-only", "更多操作"));
	more.append(summary);
	const menu = h("div", "vault-menu");
	// 低频操作也用产品内的表单（UI 焕新 U4b / W04）：错误留在表单里，Esc / 取消不提交
	menu.append(
		button("重命名…", "ghost", () => {
			more.open = false;
			fieldsDialog({
				title: "重命名仓库",
				message: "只改显示名，不影响同步与加密。",
				fields: [{ label: "仓库名称", value: v.name, hint: "1–64 个字符" }],
				okLabel: "重命名",
				validate: ([name]) => (!name ? "请填写仓库名称。" : [...name].length > 64 ? "仓库名称最多 64 个字符。" : null),
				submit: async ([name]) => {
					if (name === v.name) return null;
					try {
						await accountApi.renameVault(v.id, name);
					} catch (e) {
						return errText(e);
					}
					void renderVaultCenter(host, me);
					return null;
				},
			});
		}),
		button("删除仓库…", "ghost danger-text", () => {
			more.open = false;
			if (!v.name) {
				noticeDialog("先给这个仓库起个名字", "删除需要输入仓库名称确认，这个仓库还没有名字。请先用「重命名…」起一个名字。");
				return;
			}
			typedConfirmDialog({
				title: `删除仓库「${v.name}」？`,
				message: "会清除服务器上这个仓库的全部密文、历史版本、分享与设备授权，不能恢复。\n已经同步到设备上的本地文件不受影响。",
				expect: v.name,
				label: `输入仓库名称「${v.name}」确认`,
				okLabel: "删除仓库",
				confirm: async (typed) => {
					try {
						await accountApi.deleteVault(v.id, typed);
					} catch (e) {
						return errText(e);
					}
					void renderVaultCenter(host, me);
					return null;
				},
			});
		}),
	);
	more.append(menu);
	actions.append(more);
	bottom.append(actions);
	card.append(bottom);
	return card;
}

// ---------------------------------------------------------------- 新建仓库（浏览器端加密初始化）

const MIN_PASSWORD = 8;

/** existing：继续完成一个已建但未初始化的仓库。 */
export function openCreateVaultDialog(host: PortalHost, me: Me, existing?: VaultCard): void {
	const dlg = openDialog(existing ? `完成「${existing.name}」的加密设置` : "新建仓库", () => void renderVaultCenter(host, me));
	let name = existing?.name ?? "";

	const stepName = () => {
		dlg.body.innerHTML = "";
		dlg.body.append(h("p", "step-label", "第 1 步，共 3 步 · 仓库名称"));
		const label = h("label", "field");
		label.append(h("span", "", "仓库名称"));
		const input = h("input");
		input.maxLength = 64;
		input.value = name;
		input.placeholder = "例如：个人笔记";
		label.append(input);
		const err = h("p", "error");
		const next = button("下一步", "primary", () => {
			const v = input.value.trim();
			if (!v || v.length > 64) {
				err.textContent = "仓库名需为 1–64 个字符。";
				return;
			}
			name = v;
			stepPassword();
		});
		input.onkeydown = (e) => {
			if (e.key === "Enter") next.click();
		};
		dlg.body.append(label, h("p", "muted small", "仓库名称会以明文保存在服务器上，用于在列表里区分仓库；不要在名称里写敏感信息。"), err, h("div", "dialog-actions"));
		dlg.body.lastElementChild!.append(button("取消", "", () => dlg.close()), next);
		setTimeout(() => input.focus(), 0);
	};

	const stepPassword = () => {
		dlg.body.innerHTML = "";
		dlg.body.append(h("p", "step-label", "第 2 步，共 3 步 · 设置仓库密码"));
		const warn = h("div", "banner warn");
		warn.append(
			h("strong", "", "仓库密码 ≠ 账号登录密码。"),
			document.createTextNode(" 仓库密码只在你的设备上用来解密这个仓库。服务器和邮件都无法找回它：忘记仓库密码，这个仓库里的内容将无法解密。重置账号登录密码也不会改变它。"),
		);
		const p1 = h("label", "field");
		p1.append(h("span", "", `仓库密码（至少 ${MIN_PASSWORD} 个字符）`));
		const in1 = h("input");
		in1.type = "password";
		in1.autocomplete = "new-password";
		p1.append(in1);
		const p2 = h("label", "field");
		p2.append(h("span", "", "再输入一次"));
		const in2 = h("input");
		in2.type = "password";
		in2.autocomplete = "new-password";
		p2.append(in2);
		const ack = h("label", "check");
		const box = h("input");
		box.type = "checkbox";
		ack.append(box, document.createTextNode(" 我已记下这个仓库密码，并理解它无法找回"));
		const err = h("p", "error");
		err.setAttribute("role", "alert");
		const go = button("创建并加密", "primary", () => {
			if (in1.value.length < MIN_PASSWORD) return void (err.textContent = `仓库密码至少 ${MIN_PASSWORD} 个字符。`);
			if (in1.value !== in2.value) return void (err.textContent = "两次输入的仓库密码不一致。");
			if (!box.checked) return void (err.textContent = "请确认你已记下仓库密码。");
			const pw = in1.value;
			in1.value = "";
			in2.value = "";
			void stepRun(pw);
		});
		dlg.body.append(warn, p1, p2, ack, err, h("div", "dialog-actions"));
		dlg.body.lastElementChild!.append(button(existing ? "取消" : "上一步", "", () => (existing ? dlg.close() : stepName())), go);
		setTimeout(() => in1.focus(), 0);
	};

	const stepRun = async (password: string) => {
		dlg.body.innerHTML = "";
		dlg.body.append(h("p", "step-label", "第 3 步，共 3 步 · 在本机加密初始化"));
		const steps = ["建立仓库", "在本机生成并包装仓库密钥", "提交加密的密钥文档", "完成"];
		const list = h("ol", "progress-steps");
		const items = steps.map((s) => {
			const li = h("li", "", s);
			list.append(li);
			return li;
		});
		const err = h("div");
		err.setAttribute("role", "alert");
		dlg.body.append(list, h("p", "muted small", "密钥在浏览器里生成，仓库密码与明文密钥不会发送到服务器。"), err);
		const mark = (i: number, cls: string) => {
			items.forEach((li, k) => (li.className = k < i ? "done" : k === i ? cls : ""));
		};

		let vaultId = existing?.id ?? "";
		let doc: VaultKeyDoc | null = null;
		let vmk: CryptoKey | null = null;
		const fail = (stage: number, e: unknown) => {
			mark(stage, "failed");
			err.innerHTML = "";
			err.append(h("p", "error", `「${steps[stage]}」失败：${errText(e)}`));
			const actions = h("div", "dialog-actions");
			actions.append(button("关闭", "", () => dlg.close()), button("重新输入仓库密码并重试", "primary", () => stepPassword()));
			err.append(actions);
		};
		try {
			// 1. 建立仓库（同名重试复用同一个 clientRequestId → 服务端返回同一个仓库）
			mark(0, "active");
			if (!vaultId) {
				const reqKey = "ls.create." + name;
				let reqId = store.get(reqKey);
				if (!reqId) {
					reqId = newId("req");
					store.set(reqKey, reqId);
				}
				const created = await accountApi.createVault(name, reqId);
				vaultId = created.vaultId;
			}
		} catch (e) {
			return fail(0, e);
		}
		try {
			// 2. 认领初始化（同一浏览器会话复用 opId：刷新后续接自己的租约）
			mark(1, "active");
			const opKey = "ls.init." + vaultId;
			let opId = store.get(opKey);
			if (!opId) {
				opId = newId("op");
				store.set(opKey, opId);
			}
			const status = await accountApi.initStatus(vaultId);
			if (status.initState === "ready") {
				// 早就完成了（另一个窗口，或上一次提交成功但响应丢了）：不重新生成密钥
				return void (await adoptExisting(vaultId, password));
			}
			const claimed = await accountApi.initClaim(vaultId, opId);
			const created = await createVaultKeyDoc(password);
			doc = { ...created.doc, enabled: true };
			vmk = created.vmk;
			const raw = await exportVmkRaw(vmk);
			let resetAuth = "";
			try {
				resetAuth = await deriveResetAuth(raw);
			} finally {
				raw.fill(0);
			}
			// 3. 原子提交
			mark(2, "active");
			try {
				await accountApi.initCommit(vaultId, {
					opId, expectedInitVersion: claimed.initVersion, keyDoc: doc, resetAuth,
					cryptoProfile: claimed.cryptoProfile,
				});
			} catch (e) {
				if (e instanceof ApiCodeError) throw e;
				// 网络错误：提交可能已经成功——先查状态，绝不重新生成密钥
				const again = await accountApi.initStatus(vaultId);
				if (again.initState !== "ready") throw e;
				return void (await adoptExisting(vaultId, password, vmk));
			}
			store.del(opKey);
			store.del("ls.create." + name);
			mark(4, "done");
			done(vaultId, doc, vmk);
		} catch (e) {
			return fail(doc ? 2 : 1, e);
		}
	};

	/** 仓库已就绪：用刚输入的密码解开服务器上的 keyDoc；若有本地 VMK 还要核对是同一把。 */
	const adoptExisting = async (vaultId: string, password: string, mine?: CryptoKey) => {
		const res = await fetch("/api/v1/vault-key", { headers: { "X-Vault-ID": vaultId } });
		if (!res.ok) throw new Error("读取仓库密钥文档失败");
		const serverDoc = (await res.json()) as VaultKeyDoc;
		const vmk = await unlockVaultKey(serverDoc, password);
		if (!vmk) throw new Error("这个仓库已在另一个窗口完成设置，用的不是刚才输入的仓库密码。请用当时设置的密码在「我的仓库」里解锁。");
		if (mine) {
			const a = await exportVmkRaw(mine), b = await exportVmkRaw(vmk);
			const same = a.length === b.length && a.every((x, i) => x === b[i]);
			a.fill(0);
			b.fill(0);
			if (!same) throw new Error("这个仓库已在另一个窗口完成设置。请用当时设置的仓库密码解锁。");
		}
		done(vaultId, serverDoc, vmk);
	};

	const done = (vaultId: string, doc: VaultKeyDoc, vmk: CryptoKey) => {
		dlg.setTitle("仓库已创建");
		dlg.body.innerHTML = "";
		dlg.body.append(
			h("p", "", `仓库「${name}」已创建并完成加密设置。`),
			h("p", "muted small", "接下来可以直接在网页打开它，或者把它连接到你的 Obsidian。仓库密码只在你的设备上使用，请妥善保管。"),
		);
		const actions = h("div", "dialog-actions");
		actions.append(
			button("稍后再说", "", () => dlg.close()),
			button("连接 Obsidian", "", () => {
				dlg.close();
				void openConnectDialog(me, { id: vaultId, name } as VaultCard);
			}),
			button("在网页打开", "primary", () => {
				// 先关窗（不重绘仓库列表，免得和正在进入的工作台抢页面），再进入仓库
				dlg.close(true);
				host.openVault(vaultId, { doc, vmk });
			}),
		);
		dlg.body.append(actions);
	};

	if (existing) stepPassword();
	else stepName();
}

// ---------------------------------------------------------------- 连接 Obsidian（配对 v2）

const PAIRING_AAD = new TextEncoder().encode("litesync/v1/pairing");

/** 与插件 src/pairing/pairing.ts 的 encryptPairingConfig 同格式：base64(iv | ct+tag)，AAD 固定。 */
export async function encryptPairingPackage(secret: Uint8Array, config: object): Promise<string> {
	const key = await crypto.subtle.importKey("raw", secret as BufferSource, { name: "AES-GCM" }, false, ["encrypt"]);
	const iv = randomBytes(12);
	const ct = new Uint8Array(await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv: iv as BufferSource, additionalData: PAIRING_AAD as BufferSource },
		key, new TextEncoder().encode(JSON.stringify(config)) as BufferSource));
	const out = new Uint8Array(iv.length + ct.length);
	out.set(iv, 0);
	out.set(ct, iv.length);
	return b64encode(out);
}

function scopeLabels(): string {
	return "同步笔记与附件、创建分享链接、管理加密密钥、为本仓库添加新设备";
}

/**
 * 连接 Obsidian（配对 v2，ADR-014）。UI 焕新 U4b / W10：同设备直接「在 Obsidian 中打开」，跨设备扫码或复制；
 * 复制失败时选中链接让人手动复制；过期后原位「重新生成」（调用同一个创建接口）。
 * 链接的语义一律不变：5 分钟、只能用一次、关闭窗口即作废尚未使用的链接——这里只是把规则写在动作旁边。
 */
export async function openConnectDialog(me: Me, vault: Pick<VaultCard, "id" | "name">): Promise<void> {
	const vaultName = vault.name || "默认仓库";
	let pairId = "";
	let alive = true;
	let timer = 0;
	const revoke = (id: string) => void accountApi.deletePairing(vault.id, id).catch(() => undefined);
	const dlg = openDialog(`连接到「${vaultName}」`, () => {
		alive = false;
		window.clearInterval(timer);
		// 关闭窗口即撤销尚未兑换的链接（与插件「添加新设备」一致）
		if (pairId) revoke(pairId);
	});
	// 手机 / 平板（粗指针）：多半就是要在这台设备上打开；电脑上多半是给手机扫码
	const touch = window.matchMedia?.("(pointer: coarse)").matches ?? false;

	const generate = async (): Promise<void> => {
		window.clearInterval(timer);
		if (pairId) {
			revoke(pairId); // 重新生成：上一条（过期 / 用过）作废，与关窗同一规则
			pairId = "";
		}
		dlg.body.innerHTML = "";
		dlg.body.append(h("p", "muted", "正在生成一次性连接链接…"));
		let grant: PairingGrantResp;
		let url = "";
		let deep = "";
		try {
			grant = await accountApi.pairingGrant(vault.id);
			const secret = randomBytes(32);
			const config = {
				v: 2,
				serverUrl: location.origin,
				enrollmentSecret: grant.enrollmentSecret,
				selectedVault: grant.vault,
				accountLabel: grant.accountLabel,
				protocolVersion: grant.protocolVersion,
				requiredCapabilities: grant.requiredCapabilities,
				trust: grant.trust,
			};
			const ciphertext = await encryptPairingPackage(secret, config);
			const up = await accountApi.uploadPairing(vault.id, grant.grantId, ciphertext);
			const s64 = b64urlEncode(secret);
			secret.fill(0);
			if (!alive) {
				revoke(up.pairId); // 生成期间窗口已经关了：这条链接没人看见，按「关窗即作废」立刻撤销
				return;
			}
			pairId = up.pairId;
			url = `${location.origin}/p/${pairId}#secret=${s64}`;
			// 与扫码落地页（/p/…）交给 Obsidian 的深链完全相同，只是省掉落地页这一步
			deep = "obsidian://litesync-import?server=" + encodeURIComponent(location.origin) + "&id=" + encodeURIComponent(pairId) + "&secret=" + encodeURIComponent(s64);
		} catch (e) {
			if (!alive) return;
			dlg.body.innerHTML = "";
			dlg.body.append(h("div", "banner danger", "生成连接链接失败：" + errText(e)));
			const retry = h("div", "dialog-actions");
			retry.append(button("重试", "primary", () => void generate()));
			dlg.body.append(retry);
			return;
		}
		dlg.body.innerHTML = "";
		const facts = h("dl", "facts connect-facts");
		for (const [k, v] of [
			["服务器", location.host],
			["账号", grant.accountLabel || me.account.email],
			["仓库", grant.vault.displayName || vaultName],
			["新设备将获得", scopeLabels()],
		]) {
			facts.append(h("dt", "", k), h("dd", "", v));
		}
		const qrWrap = h("div", "qr-wrap");
		qrWrap.append(qrCanvas(url));
		const link = h("input", "link-input");
		link.readOnly = true;
		link.value = url;
		link.setAttribute("aria-label", "连接链接");
		link.onclick = () => link.select();
		const copyNote = h("p", "muted small copy-note");
		copyNote.setAttribute("aria-live", "polite");
		const manualCopy = (why: string) => {
			link.focus();
			link.select();
			copyNote.className = "warn-text small copy-note";
			copyNote.textContent = `${why}链接已经选中，请按 Ctrl+C（Mac 上 ⌘+C；手机上长按选择「拷贝」）。`;
		};
		const copy = labelButton("copy", "复制链接", touch ? "btn" : "btn primary", () => {
			if (!navigator.clipboard?.writeText) return manualCopy("这个浏览器不能直接复制：");
			void navigator.clipboard.writeText(url).then(() => {
				copy.replaceChildren(icon("check"), h("span", "", "已复制"));
				copyNote.className = "muted small copy-note";
				copyNote.textContent = "已复制。把它发到新设备上打开，或者粘贴到那台设备的 LiteSync 插件里。";
			}, () => manualCopy("浏览器没有允许复制："));
		});
		const open = h("a", touch ? "btn primary" : "btn");
		withIcon(open, "external", "在 Obsidian 中打开");
		open.href = deep;
		open.title = "这台设备装了 Obsidian 与 LiteSync 插件时，直接在这里接入";
		// 规则紧挨着复制按钮：关窗即作废尚未使用的链接；有效时间按服务端返回的到期时间倒数
		const code = h("div", "pair-code");
		code.append(link, copy);
		const warning = h("div", "pair-warning");
		const warnText = h("div");
		const status = h("p", "muted small pair-status");
		status.setAttribute("aria-live", "polite");
		warnText.append(h("strong", "", "新设备完成接入之前，请保持这个窗口打开。"),
			h("span", "", "关闭窗口会立即作废还没用过的链接。链接只能使用一次。"), status);
		warning.append(icon("info"), warnText);
		const trustNote = grant.trust.mode === "new_vault_genesis"
			? "这是一个新仓库：新设备会从空白状态开始，不需要继承任何历史信任。"
			: "首次信任：新设备会信任服务器当前提供的历史起点（与在插件里手动连接时相同）。如需从已信任的设备转移信任，请在那台设备的插件里「添加新设备」。";
		const actions = h("div", "dialog-actions connect-actions");
		actions.append(open);
		const grid = h("div", "connect-grid");
		grid.append(qrWrap, facts);
		dlg.body.append(
			h("p", "connect-intro", touch
				? "在这台设备上：点「在 Obsidian 中打开」。要连接另一台设备：用那台设备扫码，或者把链接发过去打开。之后输入这个仓库的仓库密码即可开始同步。"
				: "连接另一台设备：用它的相机扫码，或者复制链接发过去打开。这台电脑上装了 Obsidian：直接点「在 Obsidian 中打开」。之后输入这个仓库的仓库密码即可开始同步。"),
			grid, code, copyNote, warning, actions,
			h("p", "muted small", "链接里不包含你的账号密码、仓库密码或任何长期凭据。需要 LiteSync 插件 0.20 或更高版本。"),
			h("p", "muted small", trustNote),
		);
		/** 链接不能再用（过期 / 已被使用）：收起复制与打开，给出下一步。 */
		const finished = (msg: string, again: string) => {
			window.clearInterval(timer);
			status.className = "warn-text small pair-status";
			status.textContent = msg;
			qrWrap.classList.add("expired");
			qrWrap.setAttribute("aria-hidden", "true");
			link.disabled = true;
			copy.remove();
			open.removeAttribute("href");
			open.setAttribute("aria-disabled", "true");
			copyNote.textContent = "";
			actions.innerHTML = "";
			const regen = labelButton("refresh", again, "btn primary", () => void generate());
			actions.append(button("完成", "btn ghost", () => dlg.close()), regen);
			regen.focus();
		};
		const tick = async () => {
			if (!alive) return;
			const left = Math.max(0, grant.expiresAt - Math.floor(Date.now() / 1000));
			if (left === 0) {
				finished("链接已过期：为了安全，连接链接只有 5 分钟有效。", "重新生成");
				return;
			}
			if (left % 5 === 0 && !(await accountApi.pairingAlive(pairId).catch(() => true))) {
				pairId = "";
				finished("链接已被使用（或已失效）。新设备接入后会出现在「账号与设备」里。", "再连接一台设备");
				return;
			}
			status.className = "muted small pair-status";
			status.textContent = `剩余有效时间 ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
		};
		void tick();
		timer = window.setInterval(() => void tick(), 1000);
	};
	await generate();
}

function qrCanvas(text: string): HTMLCanvasElement {
	const qr = qrcode(0, "M");
	qr.addData(text);
	qr.make();
	const n = qr.getModuleCount();
	const scale = 4, margin = 16;
	const size = n * scale + margin * 2;
	const canvas = h("canvas", "qr");
	canvas.width = size;
	canvas.height = size;
	canvas.setAttribute("role", "img");
	canvas.setAttribute("aria-label", "连接链接的二维码");
	const g = canvas.getContext("2d");
	if (g) {
		g.fillStyle = "#ffffff";
		g.fillRect(0, 0, size, size);
		g.fillStyle = "#000000";
		for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) g.fillRect(margin + c * scale, margin + r * scale, scale, scale);
	}
	return canvas;
}

// ---------------------------------------------------------------- 账号与设备

/** 头像里的一个字：昵称的第一个字符；没有昵称时用通用图标（不拿邮箱凑）。 */
function avatar(displayName: string): HTMLElement {
	const a = h("div", "avatar");
	a.setAttribute("aria-hidden", "true");
	const first = Array.from(displayName.trim())[0];
	if (first) a.textContent = first.toUpperCase();
	else a.append(icon("user"));
	return a;
}

/** 存储与仓库数（需求 §12：额度在用尽之前就看得到；历史版本计入存储）。只显示服务器返回的真实数值。 */
function usagePanel(u: Usage): HTMLElement {
	const p = h("section", "panel usage-panel");
	p.append(h("h2", "", "仓库用量"));
	const head = h("div", "capacity-head");
	head.append(h("strong", "", fmtBytes(u.bytesUsed)), h("span", "", u.bytesLimit > 0 ? `/ ${fmtBytes(u.bytesLimit)}` : "/ 不限"));
	p.append(head);
	if (u.bytesLimit > 0) {
		const bar = h("div", "capacity-bar");
		bar.setAttribute("aria-hidden", "true");
		const fill = h("span");
		const ratio = Math.min(1, u.bytesUsed / u.bytesLimit);
		fill.style.width = `${Math.max(ratio > 0 ? 2 : 0, Math.round(ratio * 100))}%`;
		if (ratio >= 0.9) fill.className = "near-full";
		bar.append(fill);
		p.append(bar);
	}
	const facts = h("dl", "facts usage-facts");
	facts.append(h("dt", "", "存储"), h("dd", "", `${fmtBytes(u.bytesUsed)} / ${u.bytesLimit > 0 ? fmtBytes(u.bytesLimit) : "不限"}（含历史版本）`));
	facts.append(h("dt", "", "仓库"), h("dd", "", `${u.vaults} / ${u.vaultsLimit > 0 ? u.vaultsLimit : "不限"}`));
	p.append(facts);
	if (u.bytesLimit > 0 && u.bytesUsed >= u.bytesLimit * 0.9) {
		p.append(h("p", "banner warn", "存储快用完了：超出后新的修改无法保存到服务器（已有内容仍可查看和导出）。可以删除不需要的文件、清理历史版本，或联系管理员调整配额。"));
	}
	const link = h("a", "btn text");
	link.href = "#/vaults";
	withIcon(link, "arrow", "管理仓库", true);
	p.append(link);
	return p;
}

export async function renderAccountCenter(host: PortalHost, me: Me, cfg: AuthConfig): Promise<void> {
	const main = shell(host, "me");
	const toVaults = h("a", "btn");
	toVaults.href = "#/vaults";
	withIcon(toVaults, "folder", "我的仓库");
	main.append(headline("Your LiteSync account", "账号与设备", "管理 LiteSync 的仓库用量和已连接设备。", toVaults));
	const grid = h("div", "account-grid");
	const col = h("div", "account-main");
	const side = h("aside", "account-side");
	side.setAttribute("aria-label", "用量与账号中心");
	grid.append(col, side);
	main.append(grid);

	// 个人资料：昵称（显示名）、邮箱与验证状态；登录用户名只在服务器给出时显示（不从昵称或邮箱推）
	const acct = h("section", "panel profile-panel");
	acct.setAttribute("aria-labelledby", "profile-title");
	const label = h("p", "panel-eyebrow", "个人资料");
	label.id = "profile-title";
	const row = h("div", "profile-row");
	const who = h("div", "profile-who");
	who.append(h("h2", "", me.account.displayName || "我的账号"), h("p", "", me.account.email || "没有登记邮箱"));
	row.append(avatar(me.account.displayName), who);
	acct.append(label, row);
	const facts = h("dl", "profile-grid");
	const fact = (k: string, v: string) => {
		const d = h("div");
		d.append(h("dt", "", k), h("dd", "", v));
		facts.append(d);
	};
	if (me.account.username) fact("登录用户名", me.account.username);
	if (me.account.email) fact("邮箱状态", me.account.emailVerified ? "已验证" : "未验证");
	fact("角色", me.role === "admin" ? "实例管理员" : "普通用户");
	acct.append(facts);
	if (cfg.oidc && !me.identity.linked) {
		acct.append(h("p", "muted small", "当前用 API Token 登录。绑定统一账号后，可以用邮箱和登录密码进入 LiteSync 与 Nexus Portal；原有仓库、设备与历史全部保留。"));
		const link = h("a", "btn primary", "绑定统一账号");
		link.href = "/auth/link/start?returnTo=" + encodeURIComponent("/#/me");
		acct.append(link);
	}
	if (me.accountConsoleUrl) {
		const action = h("div", "profile-action");
		const a = h("a", "btn");
		withIcon(a, "external", "管理账号资料", true);
		a.href = me.accountConsoleUrl;
		a.rel = "noopener";
		action.append(h("p", "", "昵称、邮箱、账号密码、两步验证与网页登录在账号中心管理。"), a);
		// 账号中心只管浏览器里的登录：它的「退出所有浏览器」不会断开 Obsidian（预发布真机验收，2026-11-22）
		acct.append(action, h("p", "muted small",
			"账号中心只列出、只退出浏览器里的登录；已连接的 Obsidian 在下面「Obsidian 设备」里，" +
			"要一次断开全部请用「退出所有产品与设备」。重置登录密码只恢复账号访问，不能解密忘记了仓库密码的仓库。"));
	}
	col.append(acct);

	const devs = h("section", "panel");
	const devTitle = h("div", "panel-title");
	const devCount = h("span", "small muted");
	devTitle.append(h("h2", "", "Obsidian 设备"), devCount);
	devs.append(devTitle, h("p", "small muted panel-lead", "撤销后，这台设备下一次联网就不能再同步；已经下载到设备上的笔记不会被远程删除。设备凭据只能访问密文，不是解密密钥。"));
	const list = h("div", "device-list");
	list.append(h("p", "muted", "正在加载…"));
	devs.append(list);
	col.append(devs);

	col.append(revocationSection(me));
	const history = h("section", "panel");
	history.append(h("h2", "", "最近的撤销"));
	const historyList = h("div", "revocation-list");
	historyList.append(h("p", "muted small", "正在加载…"));
	history.append(historyList);
	col.append(history);
	void renderRevocationHistory(historyList);

	if (me.usage) side.append(usagePanel(me.usage));
	if (cfg.oidc) {
		const p = h("section", "panel products-panel");
		const chips = h("div", "connected-products");
		for (const [name, text] of [["logo", "LiteSync"], ["box", "Nexus"]] as const) {
			const c = h("span");
			c.append(icon(name), h("span", "", text));
			chips.append(c);
		}
		p.append(h("h2", "", "一个账号，两种日常"), h("p", "small muted", "登录资料由账号中心管理。仓库密码仍在 LiteSync 中独立使用。"), chips);
		side.append(p);
	}

	try {
		const devices = await accountApi.devices();
		list.innerHTML = "";
		const live = devices.filter((d) => !d.revoked);
		devCount.textContent = live.length ? `${live.length} 台已连接` : "";
		if (live.length === 0) list.append(h("p", "empty-note", "还没有连接设备。在「我的仓库」里点「连接 Obsidian」添加第一台。"));
		for (const d of live) {
			const row = h("div", "device-row");
			const info = h("div", "device-info");
			info.append(h("strong", "", d.name || d.id), h("small", "",
				`${d.platform || "未知平台"} · 仓库「${d.vaultName || d.vaultId}」 · ${d.lastSeenAt ? "最近活动 " + new Date(d.lastSeenAt * 1000).toLocaleString() : "尚未联网"}${d.clientVersion ? " · 插件 " + d.clientVersion : ""}`));
			row.append(icon(/ios|iphone|ipad|android|mobile/i.test(d.platform) ? "phone" : "monitor", "device-icon"));
			const rev = button("撤销…", "btn text danger-text", () => {
				confirmDialog({
					title: `撤销「${d.name || d.id}」？`,
					message: "它下一次联网时就不能再同步，要重新连接才能继续使用。已经下载到它上面的笔记不会被远程删除。",
					okLabel: "撤销设备",
					danger: true,
					confirm: async () => {
						try {
							await accountApi.revokeDevice(d.id);
						} catch (e) {
							return errText(e);
						}
						void renderAccountCenter(host, me, cfg);
						return null;
					},
				});
			});
			row.append(info, rev);
			list.append(row);
		}
	} catch (e) {
		list.innerHTML = "";
		list.append(h("div", "banner danger", "加载设备失败：" + errText(e)));
	}
}

// ---------------------------------------------------------------- 退出与撤销（ADR-019）
//
// 三种动作各是一个按钮，旁边写清影响范围（ADR-019 §2.1）：
//   A 只退出这个浏览器      POST /auth/logout（统一登录）/ DELETE /web/session（Token 登录）
//   B 退出 LiteSync 的全部设备  POST /api/v2/account/logout-devices
//   C 退出所有产品与设备      POST /api/v2/account/logout-all：逐项展示本产品 / 身份中心 / 另一个产品的
//                             真实状态，pending / failed 看得到、能「重新发送」（R-5）
// B / C 之后本产品的会话都已失效；C 的结果页凭响应里的一次性 statusToken（30 分钟）继续查看与重发。

const IDENTITY_ERRORS: Record<string, string> = {
	"no-user-token": "当前登录方式没有可用的身份中心令牌（例如用 API Token 登录）",
	"session-expired": "身份中心那边的登录已经过期，或已在别处退出",
	"identity-unreachable": "暂时连不上身份中心",
	forbidden: "身份中心拒绝了请求（服务器的身份中心配置缺少 manage-account 授权）",
	unauthorized: "身份中心不接受这个令牌",
	"not-supported": "身份中心不支持「结束全部会话」",
	"identity-error": "身份中心返回了意外的结果",
};

function peerErrorText(err?: string): string {
	if (!err) return "";
	if (err.startsWith("expired:")) return "7 天内一直没能送达（最后一次：" + peerErrorText(err.slice(8)) + "）";
	if (err.startsWith("rejected:http-")) return `对方拒绝了这个事件（HTTP ${err.slice(14)}），需要管理员检查两边的地址与版本后重新发送`;
	if (err.startsWith("http-")) return `对方暂时不可用（HTTP ${err.slice(5)}）`;
	switch (err) {
		case "network":
			return "网络不通";
		case "timeout":
			return "请求超时";
		case "redirect-refused":
			return "对方返回了重定向（地址可能配置错了），不会跟随，稍后重试";
		case "signature-rejected":
			return "对方拒绝了签名：两边的共享密钥不一致，或对方没有配置跨产品撤销；需要管理员修正后重新发送";
		default:
			return err;
	}
}

function productName(p: string): string {
	return p === "nexus" ? "Nexus Portal" : p;
}

function fmtIso(iso?: string): string {
	if (!iso) return "";
	const d = new Date(iso);
	return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function revocationTitle(r: RevocationView): string {
	if (r.reason.startsWith("peer:")) return `${productName(r.origin)} 发起的「退出所有产品与设备」`;
	switch (r.reason) {
		case "admin-disable":
			return "管理员停用了账号";
		case "central-disabled":
			return "身份中心停用了账号";
		case "account-deleted":
			return "身份中心删除了账号";
		case "token-reset":
			return "重置 API Token";
		default:
			return r.scope === "all-products-all-devices" ? "退出所有产品与设备" : "退出 LiteSync 的全部设备";
	}
}

/** 一个跨产品投递的展示：[状态文字, chip 样式, 说明]。 */
function peerView(p: PeerDelivery): [string, string, string] {
	switch (p.state) {
		case "delivered":
			return ["已送达", "ok", p.result === "unknown-identity" ? "对方没有这个账号，无需撤销" : "对方已撤销这个账号的全部网页登录、设备与扩展授权"];
		case "pending":
			return ["等待送达", "warn", `已尝试 ${p.attempts ?? 0} 次${p.error ? "（" + peerErrorText(p.error) + "）" : ""}；` +
				`下次重试约在 ${fmtIso(p.nextAttemptAt)}，后台会持续重试，最长 7 天`];
		case "failed":
			return ["发送失败", "danger", peerErrorText(p.error) || "没有送达"];
		default:
			return ["未配置", "warn", "服务器没有配置跨产品撤销，这个产品没有被通知。请到它的账户中心执行「退出全部设备」。"];
	}
}

function scopeBlock(title: string, scope: string, action: HTMLElement): { row: HTMLElement; text: HTMLElement } {
	const row = h("div", "revocation-action");
	const text = h("div", "revocation-scope");
	text.append(h("strong", "", title), h("p", "muted small", scope));
	row.append(text, action);
	return { row, text };
}

function revocationSection(me: Me): HTMLElement {
	const rc = me.features.revocation;
	const out = h("section", "panel");
	out.append(h("h2", "", "退出与安全"));
	out.append(h("p", "muted small", "三种退出的影响范围不同，请按需要选择。任何一种都不会远程删除已经下载到设备上的笔记；设备上还没同步的修改会留在设备上。"));

	// A：只退出这个浏览器
	const a = button("退出此浏览器", "btn", () => {
		a.disabled = true;
		void (me.session.kind === "oidc" ? accountApi.logout() : fetch("/web/session", { method: "DELETE" }))
			.catch(() => undefined).then(() => {
				announceAccount(""); // 同一浏览器的其他标签页随之清掉可见内容
				location.hash = "";
				location.reload();
			});
	});
	out.append(scopeBlock("只退出这个浏览器",
		"结束这个浏览器里的 LiteSync 登录。其他浏览器、已连接的 Obsidian 设备、身份中心的登录和 Nexus Portal 都不受影响。", a).row);

	// B：退出 LiteSync 的全部设备
	const bScope = "结束 LiteSync 在所有浏览器里的登录，撤销你名下全部 Obsidian 设备授权、尚未使用的连接链接和 API Token。" +
		"身份中心的登录和 Nexus Portal 不受影响。之后每台 Obsidian 都需要重新连接。";
	const tokenNote = me.session.kind === "token"
		? "你现在用 API Token 登录：这个 API Token 也会一起作废。之后需要用统一账号登录后重置，或由管理员在服务器上运行 obsync token reset。"
		: "";
	const b = button("退出 LiteSync 的全部设备…", "btn danger", () => {
		confirmDialog({
			title: "退出 LiteSync 的全部设备？",
			message: bScope + (tokenNote ? "\n\n" + tokenNote : ""),
			okLabel: "全部退出",
			danger: true,
			confirm: async () => {
				let r: Awaited<ReturnType<typeof accountApi.logoutDevices>>;
				try {
					r = await accountApi.logoutDevices();
				} catch (e) {
					return errText(e);
				}
				noticeDialog("已退出 LiteSync 的全部设备",
					`撤销了 ${r.local.revokedDevices} 台设备、${r.local.revokedGrants} 个尚未使用的连接链接；所有浏览器里的 LiteSync 登录已结束。`,
					() => {
						announceAccount("");
						location.hash = "";
						location.reload();
					});
				return null;
			},
		});
	});
	const bBlock = scopeBlock("退出 LiteSync 的全部设备", bScope, b);
	if (tokenNote) bBlock.text.append(h("p", "banner warn", tokenNote));
	out.append(bBlock.row);

	// C：退出所有产品与设备
	const linked = me.identity.linked && me.features.oidc;
	const cScope = "包括上一项的全部，并且：结束你在身份中心所有浏览器里的登录；通知 Nexus Portal 撤销它那边的全部网页登录、设备与扩展授权。" +
		"每一步的结果都会如实显示，没送达的可以重新发送。";
	const c = button("退出所有产品与设备…", "btn danger", () => {
		confirmDialog({
			title: "退出所有产品与设备？",
			message: cScope,
			okLabel: "全部退出",
			danger: true,
			confirm: async () => {
				let r: RevocationView;
				try {
					r = await accountApi.logoutAll();
				} catch (e) {
					return errText(e);
				}
				openRevocationResult(r);
				return null;
			},
		});
	});
	const cBlock = scopeBlock("退出所有产品与设备", cScope, c);
	if (!linked) {
		c.disabled = true;
		cBlock.text.append(h("p", "muted small", "当前账号没有绑定统一账号：「退出所有产品」不适用，请使用上一项。"));
	} else if (rc && !rc.peerRevocation) {
		cBlock.text.append(h("p", "banner warn", "服务器没有配置跨产品撤销：执行后 Nexus Portal 不会收到通知，结果里会显示「未配置」。请另外到 Nexus Portal 的账户中心退出。"));
	}
	out.append(cBlock.row);

	if (me.session.kind === "token") {
		const adv = h("a", "btn ghost", "API Token（高级）");
		adv.href = "#/account";
		out.append(adv);
	}
	// 管理员：如实提示部署缺口（ADR-019 §2.4 / §2.5「启动日志与管理员页面写明」）
	if (me.role === "admin" && rc && rc.identityCenter) {
		if (!rc.peerRevocation) {
			out.append(h("p", "banner warn", "管理员：跨产品撤销未配置（OBSYNC_PEER_REVOCATION_URL / OBSYNC_PEER_REVOCATION_SECRET）。用户执行「退出所有产品与设备」时，另一个产品不会被通知。"));
		}
		if (!rc.centralStatusCheck) {
			out.append(h("p", "banner warn", "管理员：中心状态检查未配置（OBSYNC_OIDC_STATUS_CLIENT_ID / OBSYNC_OIDC_STATUS_CLIENT_SECRET）。在身份中心停用或删除用户后，只有网页登录会在复核时结束，已连接的设备不会自动失效；开放公众注册前必须配置。"));
		}
	}
	return out;
}

function stepRow(list: HTMLElement, label: string, chipText: string, chipCls: string, detail: string, extra?: HTMLElement[]): void {
	const dd = h("dd");
	dd.append(h("span", "chip " + chipCls, chipText), document.createTextNode(" " + detail));
	for (const x of extra ?? []) dd.append(x);
	list.append(h("dt", "", label), dd);
}

/** 动作 C 的结果页：逐项展示真实状态；有 pending 时定时刷新；pending / failed 可以重新发送。 */
function openRevocationResult(first: RevocationView): void {
	let current = first;
	const token = first.statusToken ?? "";
	let timer = 0;
	const dlg = openDialog("退出所有产品与设备：结果", () => {
		window.clearInterval(timer);
		announceAccount("");
		location.hash = "";
		location.reload();
	});
	const render = () => {
		dlg.body.innerHTML = "";
		dlg.body.append(h("p", current.ok ? "banner" : "banner warn",
			current.ok ? "三步都已完成。" : "还有没完成的步骤：请看下面每一项的状态。"));
		const list = h("dl", "facts revocation-result");
		stepRow(list, "LiteSync（本产品）", "已完成", "ok",
			`撤销 ${current.local.revokedDevices} 台设备、${current.local.revokedGrants} 个尚未使用的连接链接；所有浏览器里的 LiteSync 登录已结束。`);
		const ic = current.identityCenter;
		if (ic) {
			if (ic.state === "done") {
				stepRow(list, "身份中心", "已完成", "ok", "已结束你在所有浏览器里的登录。");
			} else if (ic.state === "not-applicable") {
				stepRow(list, "身份中心", "不适用", "", "这个账号没有绑定统一账号。");
			} else {
				const extra: HTMLElement[] = [];
				if (ic.accountConsoleUrl) {
					const link = h("a", "button small-btn", "打开账号中心");
					link.href = ic.accountConsoleUrl;
					link.rel = "noopener";
					extra.push(link);
				}
				if (current.endSessionUrl) {
					const here = h("a", "button ghost small-btn", "至少退出此浏览器的身份中心登录");
					here.href = current.endSessionUrl;
					extra.push(here);
				}
				stepRow(list, "身份中心", ic.state === "pending" ? "进行中" : "没有完成", ic.state === "pending" ? "warn" : "danger",
					`${IDENTITY_ERRORS[ic.error ?? ""] ?? "没有完成"}。请打开账号中心，在「网页登录」（Keycloak 原名「设备活动」）里手动退出其他浏览器的登录。`, extra);
			}
		}
		const peers = current.peers ?? [];
		let pending = false;
		for (const p of peers) {
			const [text, cls, detail] = peerView(p);
			const extra: HTMLElement[] = [];
			if ((p.state === "pending" || p.state === "failed") && token) {
				pending = pending || p.state === "pending";
				const failed = h("span", "error small");
				failed.setAttribute("role", "alert");
				const resend = button("重新发送", "small-btn", () => {
					resend.disabled = true;
					failed.textContent = "";
					void accountApi.resendRevocation(current.eventId, token).then((r) => {
						current = r;
						render();
					}, (e) => {
						resend.disabled = false;
						failed.textContent = " " + errText(e);
					});
				});
				extra.push(resend, failed);
			}
			stepRow(list, productName(p.product), text, cls, detail, extra);
		}
		dlg.body.append(list);
		dlg.body.append(h("p", "muted small", "这个结果页 30 分钟内有效；之后重新登录，可以在「账号与设备 → 最近的撤销」查看最新状态或重新发送。"));
		const actions = h("div", "dialog-actions");
		actions.append(button("完成", "primary", () => dlg.close()));
		dlg.body.append(actions);
		window.clearInterval(timer);
		if (pending && token) {
			timer = window.setInterval(() => {
				void accountApi.revocationStatus(current.eventId, token).then((r) => {
					const was = JSON.stringify(current.peers);
					current = r;
					if (JSON.stringify(r.peers) !== was) render();
				}, () => window.clearInterval(timer));
			}, 5000);
		}
	};
	render();
}

/** 「最近的撤销」：时间、动作、每一步的真实状态；没送达的可以重新发送。 */
async function renderRevocationHistory(list: HTMLElement): Promise<void> {
	let data: { revocations: RevocationView[] };
	try {
		data = await accountApi.revocations();
	} catch (e) {
		list.innerHTML = "";
		list.append(h("div", "banner danger", "加载撤销记录失败：" + errText(e)));
		return;
	}
	list.innerHTML = "";
	if (data.revocations.length === 0) {
		list.append(h("p", "muted small", "还没有撤销记录。"));
		return;
	}
	for (const r of data.revocations) {
		const row = h("div", "revocation-row");
		row.append(h("strong", "", revocationTitle(r)), h("span", "muted small", " · " + fmtIso(r.createdAt)));
		const facts = h("dl", "facts");
		stepRow(facts, "LiteSync", "已完成", "ok", `撤销 ${r.local.revokedDevices} 台设备、${r.local.revokedGrants} 个尚未使用的连接链接`);
		if (r.identityCenter && r.origin === "litesync") {
			const ic = r.identityCenter;
			stepRow(facts, "身份中心", ic.state === "done" ? "已完成" : ic.state === "not-applicable" ? "不适用" : "没有完成",
				ic.state === "done" ? "ok" : ic.state === "not-applicable" ? "" : "danger",
				ic.state === "failed" ? (IDENTITY_ERRORS[ic.error ?? ""] ?? "") : "");
		}
		for (const p of r.peers ?? []) {
			const [text, cls, detail] = peerView(p);
			const extra: HTMLElement[] = [];
			if (p.state === "pending" || p.state === "failed") {
				const failed = h("span", "error small");
				failed.setAttribute("role", "alert");
				const retry = button("重新发送", "small-btn", () => {
					retry.disabled = true;
					failed.textContent = "";
					void accountApi.retryRevocation(r.eventId).then(() => renderRevocationHistory(list), (e) => {
						retry.disabled = false;
						failed.textContent = " " + errText(e);
					});
				});
				extra.push(retry, failed);
			}
			stepRow(facts, productName(p.product), text, cls, detail, extra);
		}
		row.append(facts);
		list.append(row);
	}
}
