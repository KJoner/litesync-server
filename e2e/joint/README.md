# 联合验收 runner：LiteSync × Nexus × 真实 Keycloak

在一台机器上起一套一次性的完整环境：真实 Keycloak + 真实 LiteSync 服务端 + 真实 Nexus + 本机收信器。然后用浏览器（Playwright）
和插件仓**原样**的配对、加密、上传下载代码跑跨产品场景。这是 CC-NEXT §1.3「联合验收」的可复现入口。

| 文件 | 作用 |
|---|---|
| `env.mjs` | 起停一次性环境：Keycloak 26.8.1 + PostgreSQL 17.10（三库三角色）+ Mailpit 1.33.0 + 本机构建的 LiteSync（PG 模式）与 Nexus |
| `run.mjs` | 用 esbuild 打包一个 runner 再运行：`litesync-plugin/*` 指向插件 checkout，`obsidian` 指向插件的 `scripts/interop/obsidian-shim.ts` |
| `lib.ts` | runner 共用的部分：读环境、记检查项、写结果（三仓 SHA、版本）、脱敏，以及身份中心和两个产品的浏览器操作 |
| `core.ts` | 核心完成场景，**20 项**（`CORE-01`…`CORE-20`）：从 Nexus 注册、SSO 进 LiteSync、两个仓库、插件配对与加密同步、网页编辑、跨账号隔离、重开要重新解锁、Nexus 的 B、旧管理员认领 |
| `revocation.ts` | ADR-019 跨产品撤销矩阵，**31 项**：A / C（两个方向）/ 对方不可达时 pending 后补投 / 中心停用 D 与恢复 / 撤销与兑换并发 |
| `stage-smoke.ts` | 隔离 HTTPS 预发布冒烟，**18 项**。不用 `env.mjs`，直接打已部署好的预发布，见文末「预发布冒烟」 |

## 前置条件

- **Docker**（含 compose v2），能拉取 `quay.io/keycloak/keycloak:26.8.1`、`postgres:17.10-alpine`、`axllent/mailpit:v1.33.0`。
- **Node 22**（runner 用到顶层 await 和内置 fetch），**Go**（版本见 `go.mod`，用来构建 LiteSync），以及 POSIX `sh`（跑 Nexus 的
  `configure.sh`；Windows 上用 Git for Windows 自带的那个）。
- **插件 checkout**（litesync）：在插件目录执行过 `npm ci`。runner 从这里取 `src/` 的原样代码、`scripts/interop/obsidian-shim.ts`，
  以及 `node_modules` 里的 esbuild。
- **Nexus checkout**（nexus-portal）：在 Nexus 目录执行过 `npm ci` 和 `npx playwright install chromium`。从这里取以下内容：
  - `infra/identity`：realm 模板、compose、`configure.sh`
  - `npm run build` 的产物（`up` 会自动构建）
  - Playwright：`@playwright/test` 和它的 Chromium
- **端口**：`--port-base N` 之后依次占用以下端口，默认 N = 28000。
  - N+25：Mailpit 网页
  - N+26：SMTP
  - N+81：LiteSync
  - N+180：Keycloak
  - N+432：PostgreSQL
  - N+787：Nexus

  Windows 上先用 `netsh interface ipv4 show excludedportrange protocol=tcp` 确认这些端口不在保留段。
- 只用合成数据：账号由 runner 在一次性 Keycloak 里新建（`…@example.test`，密码随机），邮件只进本机 Mailpit，不访问任何外部服务。

## 命令

```sh
WORK=/tmp/litesync-joint-1          # 新的临时目录；里面会放密钥，用完删除
PLUGIN=../litesync                  # 插件 checkout
NEXUS=../nexus-portal               # Nexus checkout
OUT=./joint-out                     # 结果与截图

node e2e/joint/env.mjs up --work "$WORK" --nexus "$NEXUS" --port-base 29000 [--project s-joint29]
node e2e/joint/run.mjs core       --env "$WORK/joint-env.json" --plugin "$PLUGIN" --out "$OUT"
node e2e/joint/run.mjs revocation --env "$WORK/joint-env.json" --plugin "$PLUGIN" --out "$OUT"
node e2e/joint/env.mjs down --work "$WORK" --purge
```

- `up` 大约 2～5 分钟（首次要拉镜像，另外要构建 LiteSync 和 Nexus）。结束时写出 `<work>/joint-env.json`，内容是地址、端口、
  密钥文件路径和两个产品的提交。
- 2026-11-21 本机实测：`core` 约 20 秒；`revocation` 约 1.5 分钟，其中约 60 秒在等中心停用检查生效。
- `--project` 是 compose 项目名，也是容器名前缀（`<project>-keycloak-1`、`<project>-mailpit` 等），不传时由 `<work>` 的完整路径
  哈希得到。`down`、`stop-nexus`、`start-nexus` 会从 `joint-env.json` 读出它，不必再传。
- **Nexus 的配对限流**：Nexus 对同一来源 10 分钟内最多允许 10 次扩展配对请求（`pair/start`），同时最多 10 个待确认的配对，
  计数在内存里。`revocation` 每跑一次发起 6 次，其中 5 次在中途重启 Nexus 之前。所以在同一套环境里**多次重跑之前**，尤其是中途
  失败、没走到重启那一步的运行，先重启 Nexus 清零：
  `node e2e/joint/env.mjs stop-nexus --work "$WORK" && node e2e/joint/env.mjs start-nexus --work "$WORK"`。
  `core` 不做 Nexus 扩展配对，不受这个限制。
- 同一套环境里可以重跑 `core`：`CORE-20` 的「旧管理员认领统一账号」只能做一次，重跑时沿用 `<work>/core-state.json` 里第一次
  用的那个合成账号。
- **要测的必须是某个确定的提交**：`up` 构建的是 checkout 的工作区。如果当时有未提交的改动，结果里的 `dirty` 会是 `true`。共享的
  checkout 正在被别人改动（比如合并进行到一半）时，不要在里面 stash 或 checkout，而是另做一个干净副本，把它作为 `--nexus` 传入：
  `git clone --shared --no-checkout <nexus> <副本>`，然后 `git -C <副本> checkout --detach <提交>`，再在副本里 `npm ci --prefer-offline`。
  插件同理。
- Mailpit 以 `MP_SMTP_DISABLE_RDNS=true` 启动。原因是 Docker Desktop 上反向 DNS 会让每个 SMTP 连接多等约 9 秒，Keycloak 发验证
  邮件会因读超时（10 秒）失败。
- 退出码：0 表示全部通过；1 表示有项失败或运行中出错；2 表示用法错误。

## 结果

每个 runner 在 `<out>` 下写出以下文件：

- `<runner>-result.json`：结果，格式见下。
- `<runner>.log`：控制台输出的副本。
- 截图：`core-01`…`core-05-*.png`、`revocation-final.png`。
- 证据 JSON：`core-nexus-logout-all.json`、`c-from-litesync.json`、`c-from-nexus.json`。

打包产物放在 `<work>/bundles`。

```json
{
  "runner": "joint/core",
  "startedAt": "2026-11-21T13:05:06.451Z",
  "finishedAt": "2026-11-21T13:06:30.710Z",
  "env": {
    "versions": { "keycloak": "26.8.1", "postgres": "17.10", "mailpit": "1.33.0", "node": "v22.17.1",
                  "chromium": "<Playwright 启动的 Chromium>", "playwright": "1.64.1", "plugin": "<插件 PLUGIN_VERSION>" },
    "shas":  { "server": "<up 时构建 LiteSync 的提交>", "nexus": "<up 时构建 Nexus 的提交>", "plugin": "<运行时插件 checkout 的提交>" },
    "dirty": { "server": false, "nexus": false, "plugin": false }
  },
  "total": 20, "passed": 20, "failed": 0,
  "error": null,
  "checks": [ { "id": "CORE-01", "name": "准备：旧管理员用 API Token 在默认仓库写入资产", "ok": true, "detail": "PUT /api/v1/file → 200" } ]
}
```

- `dirty` 表示当时该 checkout 有未提交的**已跟踪**改动（未跟踪文件不算）。为 `true` 时，测到的不完全是对应提交里的代码。
- `core` 预先列出了全部 20 项。如果中途某一步抛错，没跑到的项会记为失败「未执行」，`error` 里是脱敏后的错误信息，`total`
  始终是 20，不会因为提前退出而显得「全部通过」。
- `checks[].id` 是稳定编号，可以在交付记录里直接引用。

## 脱敏规则

- **密钥只放在 `<work>` 下的文件里**。这些密钥包括：PostgreSQL 各角色口令、Keycloak 临时管理员口令、两个产品的 OIDC client
  secret、跨产品共享密钥、LiteSync 管理员 API Token、`NEXUS_SECRET`。它们都在 `up` 时随机生成，写进 `secrets.json`、
  `identity/.env`、`nexus-env.json`（权限 600），不打印到终端，也不进日志。runner 自己的临时状态同样只放在 `<work>` 下：
  `core-state.json`（权限 600）存着可重复使用的合成管理员账号；浏览器的 storage state 用完立即删除。
- **结果、日志、证据 JSON 在写出之前都会经过 `lib.ts` 的脱敏，下面这些内容一律替换为 `<已脱敏>`：**
  - `secrets.json` 里的每一个值；
  - 运行中拿到的一次性值：设备凭据、连接链接、Keycloak 验证链接、Nexus 配对 secret、合成账号密码、仓库密码；
  - 任何形如 JWT 的字符串；
  - 键名以 `token` / `secret` / `password` / `credential` / `cookie` 结尾的 JSON 字段，例如 C 响应里的 `statusToken`。
- 放进交付证据时只拷贝 `<out>`，**不要拷贝 `<work>`**。拷贝前再用 `grep -rn "eyJ\|Bearer " <out>` 自查一遍。截图里没有连接链接和
  令牌（runner 不对「连接 Obsidian」对话框截图）。
- 用完执行 `down --purge`，或者手动删除 `<work>`。
- Keycloak 与 PostgreSQL 只绑 127.0.0.1。LiteSync 与 Nexus 监听 0.0.0.0，因为容器里的 Keycloak 要经 `host.docker.internal`
  回调它们的 back-channel logout。所以只在可信网络里运行，测完立即 `down`。

## 预发布冒烟（`stage-smoke.ts`）

这是 RELEASE-GATES G1 的自动化部分，目标是隔离的 HTTPS 预发布：真实域名，Cloudflare → Nginx → 容器。它**不起本机环境**，
直接对已经部署好的预发布运行。18 项检查：

- `G1-1`～`G1-4`：HTTPS、HSTS、CSP；账号中心 issuer 是公网 https 地址；管理控制台与 master realm 不对公网开放。
- `S-1`～`S-3`：跨子域 SSO；两个产品的会话 Cookie 都是 Secure + HttpOnly + host-only。
- `SW-1`、`SW-2`：Service Worker 接管页面之后的退出与再登录。
- `P-1`～`P-3`：网页建库、连接链接、插件原样代码经 HTTPS 兑换，以及 Nexus 扩展配对。
- `C-1`～`C-6`：从 LiteSync 发起 C，结果如实报告；A 在两个产品的设备与另一浏览器的会话失效，再登录必须重新输入密码；B 不受影响。

```sh
node e2e/joint/run.mjs stage-smoke --env <stage-env.json> --plugin <插件目录> --out <输出目录>
```

输入 `stage-env.json` 是**本机文件，不入库**：

```json
{
  "urls": { "accounts": "https://<账号中心域名>", "litesync": "https://<LiteSync 域名>", "nexus": "https://<Nexus 域名>" },
  "users": { "a": { "email": "<合成账号 A>", "password": "<A 的密码>" }, "b": { "email": "<合成账号 B>", "password": "<B 的密码>" } },
  "playwrightFrom": "<nexus-portal>/package.json",
  "shas": { "server": "<预发布上 LiteSync 的提交>", "nexus": "<预发布上 Nexus 的提交>" }
}
```

- 两个账号是预先在预发布 Keycloak 里建好的合成账号（预发布关闭了自助注册）。runner **不需要、也不使用任何管理凭据**：
  不连 Keycloak 管理 API，也不读服务器上的任何密钥。
- **账号密码只放在本机的 `stage-env.json` 里**：只被填进登录表单，不进结果、日志与证据。另外两类一次性凭据也不写出：
  - 连接链接在结果里只记它指向的站点（`<origin>/p/<已脱敏>#secret=<已脱敏>`）；
  - 设备凭据与 statusToken 不写出。C 的证据 `stage-c.json` 只有各部分的状态。
- 输出：
  - `stage-smoke-result.json`：字段为 runner、startedAt、finishedAt、urls、`shas`（`stage-env.json` 里的部署提交，加上 run.mjs
    记下的插件提交）、`versions`（node、chromium）、total、passed、failed、`checks[{id,name,ok,detail}]`；
  - `stage-smoke.log`、`stage-c.json`、`stage-litesync-after-c.png`。
- **有副作用，只能对隔离预发布和合成账号运行，绝不能指向生产**：
  - A 每跑一次会新建一个「预发布-xxxx」仓库、连接一台 Obsidian 和一个扩展，然后执行 C，A 在两个产品的设备与会话全部失效；
  - B 会登录两个产品并连接一个扩展。
  - 每次运行发起 2 次 Nexus 扩展配对。
- S 道按规定不访问预发布和远程地址，只做了打包检查，**没有运行过它**。主线程在真实预发布上的结果是 17/18，唯一失败是脚本时序，
  已修。

## 语义备忘（ADR-019 之后）

- 两个产品的路径不同：

  | 动作 | LiteSync | Nexus |
  |---|---|---|
  | B：退出本产品全部设备 | `POST /api/v2/account/logout-devices` | `POST /api/v2/account/logout-all` |
  | C：退出所有产品与设备 | `POST /api/v2/account/logout-all` | `POST /api/v2/account/revoke-everywhere` |

- `CORE-18`：Nexus 的「退出所有设备」是 B。它只结束 Nexus 自己的网页会话、设备与待领取授权，不碰身份中心，也不会触发
  back-channel，所以 LiteSync 的网页会话**保持**有效。runner 观察 10 秒，并核对身份中心会话仍在。上一轮（ADR-019 之前）这一项的
  期望是「LiteSync 网页会话经 back-channel 结束」，现在已不再成立。
- `CORE-19`：Nexus 的 B 不撤销 LiteSync 的设备凭据，这是设计如此。跨产品撤销设备是 C 的事，由 `revocation.ts` 覆盖。
