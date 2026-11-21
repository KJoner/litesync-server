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
 */
import qrcode from "qrcode-generator";
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

export interface PortalHost {
	root: HTMLElement;
	/** 进入某个仓库的笔记工作台（preset：刚建库时手里已有的密钥，免得立刻再输一次密码）。 */
	openVault(vaultId: string, preset?: { doc: VaultKeyDoc; vmk: CryptoKey }): void;
	toggleTheme(): void;
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

/** 模态对话框：焦点进入、Esc 关闭并把焦点还给触发按钮（UI 规格 §6「焦点」）。 */
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
	const x = button("✕", "icon-btn dialog-close", () => close());
	x.setAttribute("aria-label", "关闭");
	head.append(t, x);
	const body = h("div", "dialog-body");
	dlg.append(head, body);
	backdrop.append(dlg);
	document.body.append(backdrop);
	let closed = false;
	const onKey = (e: KeyboardEvent) => {
		if (e.key === "Escape") close();
		if (e.key === "Tab") {
			// 简单的焦点陷阱：Tab 不离开对话框
			const f = Array.from(dlg.querySelectorAll<HTMLElement>("button,input,select,textarea,a[href]")).filter((n) => !n.hasAttribute("disabled"));
			if (f.length === 0) return;
			const first = f[0], last = f[f.length - 1];
			if (e.shiftKey && document.activeElement === first) {
				last.focus();
				e.preventDefault();
			} else if (!e.shiftKey && document.activeElement === last) {
				first.focus();
				e.preventDefault();
			}
		}
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

// ---------------------------------------------------------------- 外框

type Section = "vaults" | "me";

function shell(host: PortalHost, me: Me, active: Section): HTMLElement {
	host.root.innerHTML = "";
	const page = h("div", "portal");
	const top = h("header", "portal-top");
	const brand = h("a", "portal-brand", "◈ LiteSync");
	brand.href = "#/vaults";
	const spacer = h("div", "spacer");
	const theme = button("切换主题", "ghost small-btn", () => host.toggleTheme());
	const who = h("span", "portal-who", me.account.displayName || me.account.email || "我的账号");
	top.append(brand, spacer, theme, who);

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
	const main = h("main", "portal-main");
	page.append(top, nav, main);
	host.root.append(page);
	return main;
}

// ---------------------------------------------------------------- 登录

export function renderLoginPage(host: PortalHost, cfg: AuthConfig, error?: string): void {
	host.root.innerHTML = "";
	const wrap = h("div", "center-screen");
	const card = h("div", "center-card login-card");
	card.append(h("div", "brand", "◈ LiteSync"));
	card.append(h("p", "muted", "端到端加密的笔记同步。每个仓库都用你自己设置的仓库密码在本机加密。"));
	const invite = new URLSearchParams(location.search).get("invite") ?? "";
	const errEl = h("p", "error", error ?? "");
	errEl.setAttribute("role", "alert");

	if (cfg.oidc) {
		const q = new URLSearchParams({ returnTo: "/#/vaults" });
		if (invite) q.set("invite", invite);
		const signIn = h("a", "button primary block", "登录");
		signIn.href = "/auth/login?" + q.toString();
		card.append(signIn);
		if (cfg.registrationMode !== "closed") {
			const rq = new URLSearchParams(q);
			rq.set("intent", "register");
			const reg = h("a", "button block", cfg.registrationMode === "invite" && !invite ? "使用邀请注册" : "注册新账号");
			reg.href = "/auth/login?" + rq.toString();
			card.append(reg);
		}
		card.append(h("p", "muted small", "登录与注册由账号中心完成；LiteSync 不会看到你的登录密码。登录后仍需输入各仓库的仓库密码才能解密笔记。"));
	}
	if (cfg.legacyTokenLogin) {
		const box = cfg.oidc ? h("details", "legacy-login") : h("div", "legacy-login");
		if (cfg.oidc) box.append(h("summary", "", "管理员 / 自托管：使用 API Token 登录"));
		const label = h("label", "field");
		label.append(h("span", "", "API Token"));
		const input = h("input");
		input.type = "password";
		input.autocomplete = "off";
		label.append(input);
		const go = h("button", "primary", "使用 Token 登录");
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
		box.append(label, go, h("p", "muted small", "Token 只用于换取网页会话（HttpOnly Cookie），不会保存在浏览器中。"));
		card.append(box);
	}
	if (!cfg.oidc && !cfg.legacyTokenLogin) card.append(h("p", "muted", "此服务器没有开放网页登录。"));
	card.append(errEl);
	wrap.append(card);
	host.root.append(wrap);
}

// ---------------------------------------------------------------- 我的仓库

export async function renderVaultCenter(host: PortalHost, me: Me): Promise<void> {
	const main = shell(host, me, "vaults");
	const head = h("div", "portal-head");
	const titles = h("div");
	titles.append(h("h1", "", "我的仓库"), h("p", "muted", "每个仓库都用独立的仓库密码在你的设备上加密，服务器只保存密文。"));
	const canCreate = me.permissions.includes("vault:create");
	const create = button("新建仓库", "primary", () => openCreateVaultDialog(host, me));
	create.disabled = !canCreate;
	head.append(titles, create);
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
		grid.append(h("div", "banner danger", "加载仓库失败：" + errText(e)), button("重试", "", () => void renderVaultCenter(host, me)));
		return;
	}
	grid.innerHTML = "";
	if (vaults.length === 0) {
		const empty = h("div", "empty-state");
		empty.append(
			h("h2", "", "还没有笔记仓库"),
			h("p", "muted", "新建一个仓库，设置它的仓库密码，然后在网页里写笔记，或连接你的 Obsidian。"),
		);
		const b = button("新建第一个仓库", "primary", () => openCreateVaultDialog(host, me));
		b.disabled = !canCreate;
		empty.append(b, h("p", "muted small", "已经在用 Obsidian？先在这里新建一个空仓库，再在 Obsidian 里用「连接链接」接入并选择「用本地初始化」。"));
		grid.append(empty);
		return;
	}
	for (const v of vaults) grid.append(vaultCard(host, me, v));
}

function stateChip(v: VaultCard): HTMLElement {
	if (v.initState !== "ready") return h("span", "chip warn", "⚠ 待完成加密设置");
	if (v.encryptionState === "encrypted") return h("span", "chip ok", "🔒 已加密");
	if (v.encryptionState === "migrating") return h("span", "chip warn", "⟳ 加密迁移中");
	return h("span", "chip", "未加密（旧仓库）");
}

function vaultCard(host: PortalHost, me: Me, v: VaultCard): HTMLElement {
	const card = h("article", "vault-card");
	const top = h("div", "vault-card-top");
	top.append(h("h3", "vault-name", v.name || v.id), stateChip(v));
	card.append(top);
	card.append(h("p", "muted small", v.initState === "ready"
		? `${v.fileCount} 个文件 · ${fmtBytes(v.bytesUsed)} · ${fmtWhen(v.updatedAt)}`
		: "这个仓库还没有设置仓库密码，完成之前不能写入任何内容。"));
	const actions = h("div", "vault-actions");
	if (v.initState === "ready") {
		actions.append(button(v.encryptionState === "encrypted" ? "解锁并打开" : "打开", "primary", () => host.openVault(v.id)));
		const connect = button("连接 Obsidian", "", () => void openConnectDialog(me, v));
		connect.disabled = !me.permissions.includes("vault:create");
		actions.append(connect);
	} else {
		actions.append(button("完成加密设置", "primary", () => openCreateVaultDialog(host, me, v)));
	}
	const more = h("details", "vault-more");
	more.append(h("summary", "", "更多"));
	const menu = h("div", "vault-menu");
	menu.append(
		button("重命名", "ghost", () => {
			const name = prompt("新的仓库名称（1–64 个字符）", v.name);
			if (!name || name.trim() === v.name) return;
			void accountApi.renameVault(v.id, name.trim()).then(() => renderVaultCenter(host, me), (e) => alert(errText(e)));
		}),
		button("删除仓库…", "ghost danger-text", () => {
			const name = prompt(`删除仓库会清除服务器上的全部密文与历史，且不可恢复（设备上的本地文件不受影响）。\n请输入仓库名称「${v.name}」确认：`);
			if (name === null) return;
			void accountApi.deleteVault(v.id, name).then(() => renderVaultCenter(host, me), (e) => alert(errText(e)));
		}),
	);
	more.append(menu);
	actions.append(more);
	card.append(actions);
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

export async function openConnectDialog(me: Me, vault: Pick<VaultCard, "id" | "name">): Promise<void> {
	let pairId = "";
	let alive = true;
	let timer = 0;
	const dlg = openDialog(`连接到「${vault.name}」`, () => {
		alive = false;
		window.clearInterval(timer);
		// 关闭窗口即撤销尚未兑换的链接（与插件「添加新设备」一致）
		if (pairId) void accountApi.deletePairing(vault.id, pairId).catch(() => undefined);
	});
	dlg.body.append(h("p", "muted", "正在生成一次性连接链接…"));
	let grant: PairingGrantResp;
	let url = "";
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
		pairId = up.pairId;
		url = `${location.origin}/p/${pairId}#secret=${b64urlEncode(secret)}`;
		secret.fill(0);
	} catch (e) {
		dlg.body.innerHTML = "";
		dlg.body.append(h("div", "banner danger", "生成连接链接失败：" + errText(e)));
		return;
	}
	if (!alive) return;
	dlg.body.innerHTML = "";
	const facts = h("dl", "facts");
	for (const [k, v] of [
		["服务器", location.host],
		["账号", grant.accountLabel || me.account.email],
		["仓库", grant.vault.displayName || vault.name],
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
	const copy = button("复制链接", "primary", () => {
		void navigator.clipboard.writeText(url).then(() => (copy.textContent = "已复制 ✓"), () => link.select());
	});
	const status = h("p", "muted small");
	status.setAttribute("aria-live", "polite");
	const trustNote = grant.trust.mode === "new_vault_genesis"
		? "这是一个新仓库：新设备会从空白状态开始，不需要继承任何历史信任。"
		: "首次信任：新设备会信任服务器当前提供的历史起点（与在插件里手动连接时相同）。如需从已信任的设备转移信任，请在那台设备的插件里「添加新设备」。";
	dlg.body.append(
		h("p", "", "在新设备上用系统相机扫码（或打开链接），按提示在 Obsidian 中导入；之后输入这个仓库的仓库密码即可开始同步。"),
		facts, qrWrap, link, h("div", "dialog-actions"),
		h("p", "muted small", "链接 5 分钟内有效、只能使用一次，关闭本窗口即作废；链接里不包含你的账号密码、仓库密码或任何长期凭据。需要 LiteSync 插件 0.20 或更高版本。"),
		h("p", "muted small", trustNote), status,
	);
	dlg.body.querySelector(".dialog-actions")!.append(copy);
	const tick = async () => {
		const left = Math.max(0, grant.expiresAt - Math.floor(Date.now() / 1000));
		if (left === 0) {
			status.textContent = "链接已过期。关闭窗口后可以重新生成。";
			window.clearInterval(timer);
			return;
		}
		if (left % 5 === 0 && !(await accountApi.pairingAlive(pairId).catch(() => true))) {
			status.textContent = "链接已被使用（或已失效）。新设备接入后会出现在「账号与设备」里。";
			pairId = "";
			window.clearInterval(timer);
			return;
		}
		status.textContent = `剩余有效时间 ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
	};
	void tick();
	timer = window.setInterval(() => void tick(), 1000);
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

export async function renderAccountCenter(host: PortalHost, me: Me, cfg: AuthConfig): Promise<void> {
	const main = shell(host, me, "me");
	main.append(h("h1", "", "账号与设备"));

	const acct = h("section", "panel");
	acct.append(h("h2", "", "账号"));
	const facts = h("dl", "facts");
	facts.append(h("dt", "", "名称"), h("dd", "", me.account.displayName || "—"));
	facts.append(h("dt", "", "邮箱"), h("dd", "", (me.account.email || "—") + (me.account.email ? (me.account.emailVerified ? "（已验证）" : "（未验证）") : "")));
	facts.append(h("dt", "", "角色"), h("dd", "", me.role === "admin" ? "实例管理员" : "普通用户"));
	// 用量与上限（需求 §12：额度在用尽之前就看得到；历史版本计入存储）
	if (me.usage) {
		const u = me.usage;
		facts.append(h("dt", "", "存储"), h("dd", "", `${fmtBytes(u.bytesUsed)} / ${u.bytesLimit > 0 ? fmtBytes(u.bytesLimit) : "不限"}（含历史版本）`));
		facts.append(h("dt", "", "仓库"), h("dd", "", `${u.vaults} / ${u.vaultsLimit > 0 ? u.vaultsLimit : "不限"}`));
	}
	acct.append(facts);
	if (me.usage && me.usage.bytesLimit > 0 && me.usage.bytesUsed >= me.usage.bytesLimit * 0.9) {
		acct.append(h("p", "banner warn", "存储快用完了：超出后新的修改无法保存到服务器（已有内容仍可查看和导出）。可以删除不需要的文件、清理历史版本，或联系管理员调整配额。"));
	}
	if (cfg.oidc && !me.identity.linked) {
		acct.append(h("p", "muted small", "当前用 API Token 登录。绑定统一账号后，可以用邮箱和登录密码进入 LiteSync 与 Nexus Portal；原有仓库、设备与历史全部保留。"));
		const link = h("a", "button primary", "绑定统一账号");
		link.href = "/auth/link/start?returnTo=" + encodeURIComponent("/#/me");
		acct.append(link);
	}
	if (me.accountConsoleUrl) {
		const a = h("a", "button", "修改登录密码 / 两步验证 / 网页登录");
		a.href = me.accountConsoleUrl;
		a.rel = "noopener";
		// 账号中心只管浏览器里的登录：它的「退出所有浏览器」不会断开 Obsidian（预发布真机验收，2026-11-22）
		acct.append(a, h("p", "muted small",
			"这些设置在账号中心管理。账号中心只列出、只退出浏览器里的登录；已连接的 Obsidian 在下面「已授权的设备」里，" +
			"要一次断开全部请用「退出所有产品与设备」。重置登录密码只恢复账号访问，不能解密忘记了仓库密码的仓库。"));
	}
	main.append(acct);

	const devs = h("section", "panel");
	devs.append(h("h2", "", "已授权的设备"), h("p", "muted small", "设备凭据只授权访问密文，不是解密密钥。撤销后该设备下一次联网即失效；已经下载到设备上的笔记无法远程删除。"));
	const list = h("div", "device-list");
	list.append(h("p", "muted", "正在加载…"));
	devs.append(list);
	main.append(devs);

	main.append(revocationSection(me));
	const history = h("section", "panel");
	history.append(h("h2", "", "最近的撤销"));
	const historyList = h("div", "revocation-list");
	historyList.append(h("p", "muted small", "正在加载…"));
	history.append(historyList);
	main.append(history);
	void renderRevocationHistory(historyList);

	try {
		const devices = await accountApi.devices();
		list.innerHTML = "";
		const live = devices.filter((d) => !d.revoked);
		if (live.length === 0) list.append(h("p", "muted", "还没有设备。在「我的仓库」里点「连接 Obsidian」添加第一台。"));
		for (const d of live) {
			const row = h("div", "device-row");
			const info = h("div");
			info.append(h("strong", "", d.name || d.id), h("div", "muted small",
				`${d.platform || "未知平台"} · 仓库「${d.vaultName || d.vaultId}」 · ${d.lastSeenAt ? "最近活动 " + new Date(d.lastSeenAt * 1000).toLocaleString() : "尚未联网"}${d.clientVersion ? " · 插件 " + d.clientVersion : ""}`));
			const rev = button("撤销", "ghost danger-text", () => {
				if (!confirm(`撤销「${d.name || d.id}」？它下一次联网时将无法再同步。`)) return;
				void accountApi.revokeDevice(d.id).then(() => renderAccountCenter(host, me, cfg), (e) => alert(errText(e)));
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
	out.append(h("h2", "", "退出与撤销"));
	out.append(h("p", "muted small", "三种退出的影响范围不同，请按需要选择。任何一种都不会远程删除已经下载到设备上的笔记；设备上还没同步的修改会留在设备上。"));

	// A：只退出这个浏览器
	const a = button("退出此浏览器", "", () => {
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
	const b = button("退出 LiteSync 的全部设备…", "danger", () => {
		if (!confirm(bScope + (tokenNote ? "\n\n" + tokenNote : "") + "\n\n确定继续？")) return;
		b.disabled = true;
		void accountApi.logoutDevices().then((r) => {
			alert(`已完成：撤销 ${r.local.revokedDevices} 台设备、${r.local.revokedGrants} 个尚未使用的连接链接；所有浏览器里的 LiteSync 登录已结束。`);
			announceAccount("");
			location.hash = "";
			location.reload();
		}, (e) => {
			b.disabled = false;
			alert(errText(e));
		});
	});
	const bBlock = scopeBlock("退出 LiteSync 的全部设备", bScope, b);
	if (tokenNote) bBlock.text.append(h("p", "banner warn", tokenNote));
	out.append(bBlock.row);

	// C：退出所有产品与设备
	const linked = me.identity.linked && me.features.oidc;
	const cScope = "包括上一项的全部，并且：结束你在身份中心所有浏览器里的登录；通知 Nexus Portal 撤销它那边的全部网页登录、设备与扩展授权。" +
		"每一步的结果都会如实显示，没送达的可以重新发送。";
	const c = button("退出所有产品与设备…", "danger", () => {
		if (!confirm(cScope + "\n\n确定继续？")) return;
		c.disabled = true;
		void accountApi.logoutAll().then((r) => openRevocationResult(r), (e) => {
			c.disabled = false;
			alert(errText(e));
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
		const adv = h("a", "button ghost", "API Token（高级）");
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
				const resend = button("重新发送", "small-btn", () => {
					resend.disabled = true;
					void accountApi.resendRevocation(current.eventId, token).then((r) => {
						current = r;
						render();
					}, (e) => {
						resend.disabled = false;
						alert(errText(e));
					});
				});
				extra.push(resend);
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
				const retry = button("重新发送", "small-btn", () => {
					retry.disabled = true;
					void accountApi.retryRevocation(r.eventId).then(() => renderRevocationHistory(list), (e) => {
						retry.disabled = false;
						alert(errText(e));
					});
				});
				extra.push(retry);
			}
			stepRow(facts, productName(p.product), text, cls, detail, extra);
		}
		row.append(facts);
		list.append(row);
	}
}
