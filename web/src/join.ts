/** LiteSync 注册页（v0.18 / v11 设计 §5.5）。
 *
 * 邀请链接 /join/<secret> 的落地页：受邀者输入用户名 → 拿到自己的 API Token
 * 与分步接入教程。面向零上下文的新用户，因此全中文。
 *
 * 安全性质：
 * - secret 即凭证（32 字节随机、一次性、有 TTL）；页面自身不需要任何登录态；
 * - Token 明文只在注册响应里出现一次，页面强制「我已保存」确认；
 * - 本页不触碰任何密钥材料——E2EE 密码在 Obsidian 插件里设置，永不经过浏览器。
 */
import { followSystemTheme } from "./theme";

function el<K extends keyof HTMLElementTagNameMap>(
	tag: K,
	cls?: string,
	text?: string,
): HTMLElementTagNameMap[K] {
	const node = document.createElement(tag);
	if (cls) node.className = cls;
	if (text !== undefined) node.textContent = text;
	return node;
}

const app = document.getElementById("app")!;

function applyTheme(): void {
	followSystemTheme();
}

function centered(children: HTMLElement[]): void {
	app.innerHTML = "";
	const wrap = el("div", "center-screen");
	const card = el("div", "center-card join-card");
	card.append(el("div", "brand", "◈ LiteSync"), ...children);
	wrap.append(card);
	app.append(wrap);
}

function inviteSecret(): string {
	// 路径形如 /join/<secret>
	const parts = location.pathname.split("/").filter(Boolean);
	return parts.length >= 2 && parts[0] === "join" ? parts[1] : "";
}

async function boot(): Promise<void> {
	applyTheme();
	const secret = inviteSecret();
	if (!secret) {
		centered([el("p", "muted", "链接不完整。请向管理员索取新的邀请链接。")]);
		return;
	}
	try {
		const res = await fetch(`/join/${encodeURIComponent(secret)}/info`);
		if (!res.ok) {
			centered([
				el("p", "muted", "邀请链接无效或已过期。"),
				el("p", "muted small", "邀请是一次性的，且有有效期。请向管理员索取新的邀请链接。"),
			]);
			return;
		}
		const info = (await res.json()) as { serverUrl?: string };
		renderForm(secret, info.serverUrl || location.origin);
	} catch {
		centered([el("p", "muted", "无法连接服务器，请稍后重试。")]);
	}
}

function renderForm(secret: string, serverUrl: string): void {
	const sub = el("p", "muted", "你被邀请加入这台 LiteSync 私有同步服务器");
	const desc = el("p", "muted small",
		"注册后你将获得一个完全独立的笔记仓库：内容只属于你，其他用户（包括管理员）都看不到。");
	const input = el("input") as HTMLInputElement;
	input.placeholder = "起一个用户名（1–32 个字符，不含空格）";
	input.maxLength = 32;
	const btn = el("button", "primary", "注册");
	const errEl = el("p", "error", "");
	const submit = async (): Promise<void> => {
		const name = input.value.trim();
		if (!name) {
			errEl.textContent = "请输入用户名";
			return;
		}
		btn.disabled = true;
		btn.textContent = "注册中…";
		try {
			const res = await fetch(`/join/${encodeURIComponent(secret)}/register`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name }),
			});
			const body = (await res.json().catch(() => ({}))) as { token?: string; message?: string };
			if (res.status === 409) {
				errEl.textContent = "该用户名已被使用，请换一个（邀请仍然有效）。";
			} else if (!res.ok || !body.token) {
				errEl.textContent = body.message ?? "注册失败：邀请可能已失效，请向管理员索取新链接。";
			} else {
				renderSuccess(name, body.token, serverUrl);
				return;
			}
		} catch {
			errEl.textContent = "无法连接服务器，请稍后重试。";
		}
		btn.disabled = false;
		btn.textContent = "注册";
	};
	btn.onclick = () => void submit();
	input.onkeydown = (e) => {
		if (e.key === "Enter") void submit();
	};
	centered([sub, desc, input, btn, errEl]);
	input.focus();
}

function copyBtnFor(text: string, label: string): HTMLButtonElement {
	const btn = el("button", "primary", label);
	btn.onclick = () => {
		void navigator.clipboard.writeText(text).then(() => {
			btn.textContent = "已复制 ✓";
			setTimeout(() => (btn.textContent = label), 1500);
		});
	};
	return btn;
}

function renderSuccess(name: string, token: string, serverUrl: string): void {
	app.innerHTML = "";
	const wrap = el("div", "center-screen");
	const card = el("div", "center-card join-card join-wide");
	card.append(el("div", "brand", "◈ LiteSync"));
	card.append(el("h2", "", `欢迎，${name}！`));

	// —— Token：只显示这一次 ——
	card.append(el("p", "", "这是你的 API Token（相当于账号密码）："));
	const tokenEl = el("code", "token-display", token);
	card.append(tokenEl);
	const tokenRow = el("div", "join-row");
	tokenRow.append(copyBtnFor(token, "复制 Token"));
	card.append(tokenRow);
	const warn = el("p", "error",
		"⚠ 明文只显示这一次，服务器上只保存不可逆的指纹。请立刻抄写到密码管理器——" +
		"丢失后无法找回，账号也无法恢复（只能请管理员删除后重新邀请，数据会清空）。");
	card.append(warn);

	card.append(el("p", "", "你的服务器地址（Server URL）："));
	const urlEl = el("code", "token-display", serverUrl);
	card.append(urlEl);
	const urlRow = el("div", "join-row");
	urlRow.append(copyBtnFor(serverUrl, "复制地址"));
	card.append(urlRow);

	// —— 「我已保存」门：教程在确认之后展示，防止用户滚过 Token 就把页面关了 ——
	const gate = el("label", "join-gate");
	const check = el("input") as HTMLInputElement;
	check.type = "checkbox";
	gate.append(check, document.createTextNode(" 我已把 Token 和服务器地址保存到安全的地方"));
	card.append(gate);

	const steps = el("div", "join-steps");
	steps.hidden = true;
	check.onchange = () => {
		steps.hidden = !check.checked;
	};

	steps.append(el("h3", "", "接下来，在你的设备上完成接入："));
	const list = el("ol", "join-list");
	const items: [string, string][] = [
		["安装 Obsidian", "在 obsidian.md 下载并安装（电脑与手机都支持），创建或打开一个笔记库（Vault）。"],
		["安装 LiteSync 插件", "设置 → 第三方插件 → 关闭安全模式 → 社区插件市场搜索「LiteSync」安装并启用。" +
			"（插件尚未上架时，请向管理员索取插件文件，放入笔记库的 .obsidian/plugins/litesync/ 目录后启用。）"],
		["填写连接信息", "打开 LiteSync 插件设置，把上面的 Server URL 和 API Token 粘贴进去。"],
		["测试连接", "点「测试连接」。首次连接会引导你设置端到端加密（E2EE）并开始同步。"],
		["设置端到端加密密码", "新仓库必须启用 E2EE——服务器只见密文，管理员和任何拿到服务器数据的人都读不到你的笔记内容。" +
			"密码只存在你的设备上，忘了没有任何人能帮你找回，请与 Token 一起妥善保存。"],
		["完成", "首轮同步结束后，在其他设备重复以上步骤（或在已接入设备上用「添加新设备」扫码，更快）。"],
	];
	for (const [title, detail] of items) {
		const li = el("li");
		li.append(el("strong", "", title), el("p", "muted small", detail));
		list.append(li);
	}
	steps.append(list);
	steps.append(el("p", "muted small",
		"提示：网页端（也就是本站首页）可以用 API Token 登录，随时在浏览器里查看你的笔记；" +
		"启用 E2EE 后网页端也需要输入加密密码才能解密内容。"));
	card.append(steps);

	wrap.append(card);
	app.append(wrap);
}

void boot();

export {};
