# LiteSync Server

**Self-hosted sync server for the [LiteSync Obsidian plugin](https://github.com/KJoner/litesync).**
Single-user, low-resource (runs comfortably on a 1-core / 256MB VPS), E2EE-friendly.

一个使用 Go + SQLite + 内容寻址 Blob 存储实现的单用户、低资源、增量式
Obsidian 私有同步服务器，内嵌 Web 只读客户端与 Restic → Cloudflare R2 异地备份。

> Obsidian 插件仓库：<https://github.com/KJoner/litesync>
> （插件与服务器独立发版，兼容性由 `/api/v1/info` 的 `protocolVersion` 区间判定）

> ⚠️ **Sync is not Backup（同步不等于备份）**
> 同步只保护多设备一致性；灾难恢复请启用内置的 R2 异地备份（见下），
> 或自行定期备份整个 `/data` 目录。

## 架构

```text
一个 Go Binary + 一个 SQLite 文件 + 一个内容寻址 Blob 目录（+ restic 备份旁路）
```

```text
/data
├── sync.db      # 元数据：file_heads（HEAD）/ object_versions（历史）/
│                #   object_changes / tombstones / devices / shares /
│                #   users / vaults / memberships / audit_events
├── blobs/       # 唯一内容存储：不可变、Vault 内跨版本跨文件去重
│   └── _quarantine/   # 被判定损坏的副本（取证用，默认不自动删）
├── shares/      # 分享密文（服务器无解密密钥）
└── vaults/      # 旧版本遗留目录（v0.5 起 HEAD 不再单独落盘，启动时自动收编）
```

- 每个文件独立 revision，上传/删除必须携带 baseRevision，不一致返回 409
- 所有变更写入 changes 表（递增 sequence），客户端按 `since` 增量拉取；
  changes 被裁剪后旧游标客户端收到 `resyncRequired`，自动走 snapshot 全量对账
- 上传流程「锁外收流 + SHA-256 → 锁内校验 → blob 原子入库 → SQLite 事务」，
  断电不产生半文件，慢速大文件不阻塞其他请求
- E2EE 与分享对服务器**零感知**：内容一律按 opaque bytes 处理
- 资源治理任务（启动 + 每 24h）：历史保留扫描（Markdown/附件差异化）、
  历史字节硬预算、孤儿 blob 回收、过期分享清理、changes 裁剪、
  SQLite checkpoint / 按需 VACUUM，并输出资源统计日志；
  0.10.0 起含**完整性 scrub**（SQLite quick_check + 每个 HEAD blob
  存在/尺寸校验 + 随机全量 hash 抽查，位腐坏检出即告警隔离）
- 备份是**服务器旁路能力**（v0.6）：不改动 revision / changes / E2EE / merge
  任何协议；restic 仅在备份任务执行时 fork，无常驻内存开销
- **租户隔离（0.16.0）**：所有按仓库划分的数据（HEAD / 历史 / changes /
  tombstones / repo 状态 / 写锁 / 保留策略）都带 `vault_id`，由类型层
  （`VaultScope`）与源码扫描双重强制；blobID 按 Vault 域化，跨租户去重
  不可能发生。单实例目前仍只服务一个 Vault，隔离先在结构上成立
- **设备可信度（0.15.0）**：服务器转发由**设备**签名的 checkpoint，
  自己不参与签名——它无法给不同设备编造不同的仓库状态而不被发现

## 一键部署 / 更新

```bash
bash <(wget -qO- https://raw.githubusercontent.com/KJoner/litesync-server/master/scripts/litesync-install.sh)
```

首次执行：克隆配置、生成 `.env`（随机 Token，端口被占用时自动改用
8081–8099 中的空闲端口）、拉取 Docker Hub 预构建镜像（multi-arch，
无需本机编译；镜像不可用时自动回退源码构建）、启动并输出配置信息。
再次执行：拉取最新配置与镜像完成升级，`.env` 和 `data/` 保持不变。

## 快速开始（Docker Hub 镜像）

镜像：[`kjoner/litesync-server`](https://hub.docker.com/r/kjoner/litesync-server)
（multi-arch manifest，同时支持 `linux/amd64` / `linux/arm64`）。
正式部署不需要克隆源码，也不需要本机编译：

```bash
mkdir litesync-server && cd litesync-server
wget https://raw.githubusercontent.com/KJoner/litesync-server/master/docker-compose.yml
wget -O .env https://raw.githubusercontent.com/KJoner/litesync-server/master/.env.example
# 编辑 .env，填入 OBSYNC_TOKEN（openssl rand -hex 32 生成）

docker compose pull
docker compose up -d
curl http://127.0.0.1:8080/health
```

只需要持久化 `./data` 目录。compose 已配置日志轮转（10MB × 3）。
如需 R2 备份，另需备份密钥（一键部署脚本自动生成，手动部署可
`mkdir etc-litesync && openssl rand -hex 32 > etc-litesync/backup-config.key`）。

### 版本与升级

Git tag `v0.8.2` 发布后，Docker Hub 会同时存在
`0.8.2`（精确版本）/ `0.8` / `0`（滚动次/主版本）/ `latest`（最新正式版）。

- **`latest`**：始终指向最新正式发布，`docker compose pull` 即可升级，适合个人部署；
- **固定版本**（如 `0.8.2`）：升级完全由你控制，适合谨慎升级的场景，
  在 `.env` 中设置 `LITESYNC_VERSION=0.8.2`，升级时改版本号再 pull。

升级步骤（数据在 `./data` 挂载卷中，升级不受影响）：

```bash
docker compose pull
docker compose up -d
```

数据库结构升级在 `db.Open` 时自动完成、幂等、可续跑，**但不可回滚到旧版**
（重建后的表旧代码读不了）。因此跨大版本升级前请先
`obsync backup create`，或至少完整拷贝一次 `./data`。

**从 0.15 及更早升级到 0.16+ 时的一步手工迁移**：blobID 从裸内容哈希
改为按 Vault 域化（见[租户隔离](#租户隔离0160)），存量 blob 需要改名。
这**不是启动硬门槛**——混合状态读写都正确，服务器只会告警不会拒绝启动，
但在迁移完成前老数据上的隔离尚未成立：

```bash
obsync backup create              # 先备份，下一步不可逆
obsync blobid status              # 还有多少停留在旧格式
obsync blobid migrate             # dry-run，不动任何文件
obsync blobid migrate --confirm   # 真正执行
```

**升级到 0.20 时**：表结构升级自动完成（统一账号映射、仓库初始化状态、配对 v2、邮件 outbox、
配额覆盖值等新表新列），既有仓库一律视为「已就绪」。**默认行为不变**：不配置统一登录仍是 API Token
登录，网页仍是只读，注册仍需邀请。打算开放注册时，先读[公开化（0.20.0）](#公开化0200)：配置统一登录、
`OBSYNC_QUOTA_BYTES_PER_USER`（开放注册时必填）与邮件渠道，再把 `OBSYNC_REGISTRATION_MODE` 改为 `open`。
0.19 插件可以继续连接 0.20 服务端；网页发行的「连接链接 v2」需要插件 0.20 才能在兑换前核对仓库。

**升级到 0.17.x 时**：服务端与插件都要升到 0.17（协议 v6 不变，但 Web 端的
LSE4 解密、设备平台/IP 记录、运维页都在服务端资产里）。如果部署时固定了
镜像标签，记得一并更新——「网页端显示乱码」这类现象多半是 Web 资产还是旧版。

## 配置（全部通过环境变量）

| 变量 | 默认值 | 说明 |
|---|---|---|
| `OBSYNC_TOKEN` | （必填） | API Token，建议 `openssl rand -hex 32` 生成 |
| `OBSYNC_LISTEN` | `127.0.0.1:8080` | 监听地址（防误暴露公网；Docker 镜像内为 `:8080`） |
| `OBSYNC_DATA_DIR` | `./data` | 数据目录（权限 0700，sync.db 0600） |
| `OBSYNC_MAX_FILE_SIZE` | `104857600` | 单文件大小上限（字节，默认 100MB） |
| `OBSYNC_LOG_LEVEL` | `info` | debug / info / warn / error |
| `OBSYNC_HISTORY_ENABLED` | `true` | 版本历史开关 |
| `OBSYNC_HISTORY_DAYS` | `90` | Markdown 历史保留天数（0 = 不限；同时是三方合并的 merge-base） |
| `OBSYNC_HISTORY_MAX_PER_FILE` | `100` | Markdown 每文件版本数（0 = 不限） |
| `OBSYNC_HISTORY_ATTACHMENT_DAYS` | `30` | 附件历史保留天数 |
| `OBSYNC_HISTORY_ATTACHMENT_MAX_PER_FILE` | `10` | 附件每文件版本数 |
| `OBSYNC_HISTORY_MAX_BYTES` | `0` | 非 HEAD 历史总字节硬上限（0 = 不限） |
| `OBSYNC_CHANGES_DAYS` | `90` | changes 保留天数（旧游标自动 snapshot 对账） |
| `OBSYNC_CHANGES_MAX` | `100000` | changes 最大行数 |
| `OBSYNC_MAINTENANCE_HOURS` | `24` | 资源治理任务间隔（0 = 关闭定时；启动时总会执行一次） |
| `OBSYNC_BACKUP_KEY_FILE` | （空 = 备份不可用） | 备份配置加密密钥文件；Docker 镜像内默认 `/etc/litesync/backup-config.key` |
| `OBSYNC_DURABILITY` | `strict` | `strict` = SQLite `synchronous=FULL`（掉电后已确认事务绝不回滚）；`normal` 更快但掉电可能丢最近事务 |
| `OBSYNC_TRUSTED_PROXIES` | `127.0.0.1,::1` | 允许信任其 `X-Forwarded-Proto` 的反向代理（IP/CIDR，逗号分隔）；其余来源的该 Header 一律忽略 |
| `OBSYNC_STRICT_BLOB_VERIFY` | `false` | 去重命中时全量重算现有 blob 的 hash（能抓位腐坏，代价是每次命中都完整读一遍文件） |
| `OBSYNC_QUARANTINE_DAYS` | `0`（永久） | 隔离区保留期。隔离区放的是被判定损坏的副本，属于取证材料，默认不自动删 |
| `OBSYNC_HTTP_READ_TIMEOUT` | `1800`（秒） | 请求读取超时。必须覆盖「慢速链路上传大附件」这种正常场景 |
| `OBSYNC_HTTP_WRITE_TIMEOUT` | `1800`（秒） | 响应写出超时，同上 |
| `OBSYNC_DB` | `sqlite` | 元数据库：`sqlite`（数据目录里的 `sync.db`）或 `postgres`（见「PostgreSQL 元数据库」）。Blob 无论哪种都在数据目录 |
| `OBSYNC_PG_DSN` | （空） | PostgreSQL 连接串，`OBSYNC_DB=postgres` 时必填；**只从环境变量读取，不出现在任何日志与输出里** |
| `OBSYNC_PG_RESTORE_DSN` | （空） | 仅 PG 部署的 `backup restore` 使用：恢复写入的**新的空库**（旧库原样保留作为退路） |
| `OBSYNC_PUBLIC_URL` | （空） | 本服务对外的规范地址（如 `https://sync.example.com`，不带路径）；启用统一登录时必填，回调固定为 `<PUBLIC_URL>/auth/callback` |
| `OBSYNC_OIDC_ISSUER` / `_CLIENT_ID` / `_CLIENT_SECRET` | （空） | 统一登录（OIDC，如 Keycloak）。三个都设置才启用；**半套配置拒绝启动**；非本机必须 https |
| `OBSYNC_REGISTRATION_MODE` | `invite` | `closed` / `invite` / `open`：首次出现的统一账号是否自动建本地账号。**`open` 要求同时配置中心状态检查（下面两行），否则拒绝启动** |
| `OBSYNC_OIDC_STATUS_CLIENT_ID` / `_SECRET` | （空） | 0.20.1：中心状态检查用的**只读**服务账号（client credentials，只授 realm-management 的 `view-users`，client 的作用域映射里也要加它）。配置后，身份中心停用 / 删除的账号最迟 60 秒内被撤销全部设备；未配置时只结束网页会话。两者都设置才启用，半套拒绝启动 |
| `OBSYNC_OIDC_ADMIN_API_URL` | （从 issuer 推导） | 0.20.1：Keycloak 管理接口基址 `https://host/admin/realms/<realm>`；默认把 issuer 里的 `/realms/` 换成 `/admin/realms/` |
| `OBSYNC_PEER_REVOCATION_URL` / `_SECRET` | （空） | 0.20.1：跨产品撤销。URL 是另一个产品（Nexus Portal）的内部地址（如 compose 网络里的 `http://nexus:8787`，路径 `/api/internal/v1/account-revocations` 自动补上）；SECRET 是两个产品**相同**的共享密钥（≥ 32 字节，按字符串原始字节作 HMAC 密钥）。两者都设置才启用「退出所有产品与设备」的跨产品一步与本服务的接收端；半套拒绝启动 |
| `OBSYNC_LEGACY_TOKEN_LOGIN` | `true` | 启用统一登录后是否保留「API Token 网页登录」（管理员认领统一账号前的兜底） |
| `OBSYNC_REQUIRE_E2EE_NEW_VAULTS` | `true` | 新建仓库必须先完成浏览器端（或插件端）加密初始化才接受内容写入 |
| `OBSYNC_WEB_EDITING` | `false` | 允许网页会话写入笔记（网页编辑器、回收站恢复）；默认只读 |
| `OBSYNC_QUOTA_BYTES_PER_USER` | `0`（不限） | 每个账号的存储上限（live + 历史版本，密文字节；支持 `500MB` / `2GB`，`-1` = 明确不限）。只约束非管理员。**`OBSYNC_REGISTRATION_MODE=open` 时必须显式设置，否则拒绝启动** |
| `OBSYNC_QUOTA_VAULTS_PER_USER` | `20` | 每个账号可拥有的仓库数 |
| `OBSYNC_RATE_PER_USER` | `3000` | 每个账号（设备按设备）每分钟请求数，突发 1/6；`0` = 关闭。超出返回 429 `RATE_LIMITED` + `Retry-After` |
| `OBSYNC_UPLOAD_CONCURRENCY_PER_USER` | `8` | 每个账号同时进行的上传数（`0` = 不限） |
| `OBSYNC_MAIL_PROVIDER` | `log` | 产品通知邮件渠道：`log`（只记日志）/ `smtp` / `resend` |
| `OBSYNC_MAIL_FROM` / `OBSYNC_MAIL_REPLY_TO` | （空） | 发件人（如 `LiteSync <no-reply@mail.example.com>`）与回复地址 |
| `OBSYNC_SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_TLS` | 端口 `587`、`starttls` | SMTP 渠道。`_TLS` 只接受 `starttls`（默认）/ `implicit` / `none`，大小写不敏感、首尾空白忽略，**其他值（包括 `startls` 这类拼写错误）拒绝启动**；`starttls` 时服务器不提供 STARTTLS 或证书校验失败一律不发送（不降级为明文，记为配置错误并告警）；`none` 只允许本机回环中继 |
| `OBSYNC_RESEND_API_KEY` / `OBSYNC_RESEND_WEBHOOK_SECRET` | （空） | Resend 渠道；回执密钥为空时 `/hooks/mail/resend` 关闭 |
| `OBSYNC_MAIL_DAILY_BUDGET` | `500` | 全局每 24 小时最多发出的通知邮件；超出的延后发送（不丢弃） |

Compose 额外变量：`LITESYNC_ETC_DIR`（宿主机密钥目录，默认 `./etc-litesync`，
只读挂载为容器内 `/etc/litesync`；一键部署脚本自动生成密钥）。

## 正式支持规模

以下是**正式声明并按此测试**的上限（计划书 §8.7）。超出这些数字不代表一定不能用，
但意味着没有被验证过——出问题时请先回到声明范围内再判断。

| 项目 | 声明上限 | 说明 |
|---|---|---|
| 单仓库文件数 | 20 000 | snapshot / changes 分页 / scrub / GC 均按此规模验证 |
| 单文件历史版本数 | 100（Markdown）、10（附件） | 由 `OBSYNC_HISTORY_MAX_PER_FILE` 等配置约束并强制生效 |
| 单文件大小 | 100 MB | `OBSYNC_MAX_FILE_SIZE`；移动端超过 50 MB 会有内存告警 |
| 客户端待推送变更数 | 10 000 | 超过时同步仍然正确，但单轮耗时会明显变长 |
| 设备数 | 10 | 单用户阶段的实际使用形态 |
| 单实例 Vault 数 | 1 | 0.16.0 起数据模型与隔离已按多租户建立，但 HTTP 层尚未放开多 Vault 路由（见[租户隔离](#租户隔离0160)） |
| 最长离线时间 | 90 天 | 由 `OBSYNC_CHANGES_DAYS` 决定；超过后客户端自动走 snapshot 全量对账，不会漏变更 |

一台普通 SSD 机器上的实测（这些数字随磁盘差异很大，仅供量级参考）：

| 规模 | snapshot | changes 全量分页 | `scrub --full` | 两轮资源治理 |
|---|---|---|---|---|
| 2 000 文件 | 6 ms | 6 ms | 0.29 s | 0.73 s |
| 20 000 文件（声明上限） | 74 ms | 45 ms | 2.5 s | 6.8 s |

上限规模已实际跑过并通过：snapshot 一条不少、changes 分页不重不漏、
`scrub --full` 报 clean、GC 两轮后所有 HEAD 仍可读。

规模测试随代码一起提供：

```bash
go test ./internal/sync/ -run TestScale          # 默认 2 000 文件
LITESYNC_SCALE=20000 go test ./internal/sync/ -run TestScale -timeout 1800s
```

## HTTPS（生产环境必须）

服务本身只讲 HTTP，请放在反向代理后面；Web 端的浏览器解密（WebCrypto）
与会话 Cookie 的 Secure 标记都依赖 HTTPS。Caddy 示例（自动证书）：

```text
sync.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

## 协议 v6（0.13.0）

**0.13.0 是破坏性变更，插件与服务端必须同时升级**（`minProtocolVersion = 6`）。

v5 把 path 当作主键，导致元数据迁移重置 revision、历史撞唯一键、删除丢身份、
改名断历史。v6 把**身份**（`file_id`）与**展示名**（`pseudonym`）彻底分开：

* 所有表以 `file_id` 为主键（并预留 `vault_id`）；`revision` 属于**对象**，
  跨改名 / 迁移 / 删除恢复连续递增；
* 改名与元数据迁移退化为一次元数据更新，**不再产生 tombstone**；
* 删除进入独立的 `tombstones` 台账，迁移对它做**格式转换**而不是删除——
  删除屏障、防复活 revision、恢复所需身份全部保留；重建必须走显式
  `POST /api/v1/files/{fileId}/restore`；
* 新增 `minimumEnvelopeVersion`（仓库级信封下限，单调不减，落库前校验，
  覆盖含**删除后重建**的全部写入路径）与 `formatEpoch`（寻址格式世代，
  变化时客户端丢弃游标全量对账）；
* 元数据迁移是四态状态机 `plain → migrating → verifying → encrypted`，
  验证与不可逆擦除分离；进度写入 `migration_journal`，服务端重启可续跑。

升级时 `db.MigrateToV6` 自动把 v5 数据搬到新模型（journal 驱动、可续跑、幂等），
并把旧表重命名为 `v5_files` / `v5_changes` / `v5_file_versions` **只读保留**作为回滚窗口。
设计与取舍见插件仓库的 `docs/开发计划/v10/adr/`（ADR-001/002/003/006/008）。

## 租户隔离（0.16.0）

服务器从「一个人的仓库」变成「可以装下多个互不可见的仓库」。
0.16.0 先让隔离在结构上成立（数据模型、类型强制、越权矩阵），**0.18.0 放开了
多 Vault 路由**：管理员在网页端生成一次性邀请链接，受邀者自助注册即获得自己的
API Token 与完全独立的仓库（见下方「多用户」一节）。隔离性质由类型系统
和测试守着，而不是靠每个新接口的作者记得带条件。

- **类型层强制**：所有按租户划分的查询都要求一个 `VaultScope`，它的字段不可
  导出、唯一构造入口在认证层，业务代码造不出指向别人 Vault 的范围；零值一律
  硬拒（`ErrVaultScopeMissing`），**绝不退化为默认租户**；
- **CI 期源码扫描**：禁止业务包自行构造 scope，也禁止在 db 包之外手写
  `vault_id = ?`；
- **每 Vault 独立状态**：`repo_state`（含 repoEpoch / headSequence /
  迁移状态）、**写锁**、历史保留策略都按 Vault 划分——共用一把写锁的话，
  一个租户的慢速大附件上传会挡住所有租户，而那不只是慢，它让一个租户的负载
  变成另一个租户可观测的信号；
- **blobID 域化**：`blobID = HMAC-SHA256(vaultSecret, contentHash)`。全局内容
  寻址去重是一个**存在性预言机**——上传一份文件看它是「秒传」还是真传，
  就能判断别的租户是否持有同一份内容。域化之后跨租户去重不可能发生，
  Vault 内部的去重完全保留；E2EE 下不同 Vault 用不同密钥，跨租户去重本来
  也命中不了，这个取舍几乎没有成本；
- **越权矩阵按路由表自动生成**：测试直接扫 `router.go` 抽路由，新增一条路由
  立刻被纳入覆盖；确实要公开的必须在 `publicRoutes` 里显式登记。矩阵覆盖
  60+ 路由，验证无凭据 / 已撤销设备 / 外租户凭据 / 零 scope 一律被拒。

**成员移除**（`DELETE /api/v1/members/{userId}`）在同一个事务里按固定顺序
执行：删成员关系 → **先**撤销该用户全部设备 → 推进 keyEpoch → 标记 Vault Key
待重新封装。响应里原样带回一句 `localPlaintextNotice`，客户端 UI 必须原样展示：
**移除成员不能收回他已经下载到本地的明文**。让用户以为「移除 = 对方再也看不到
任何东西」是危险的误导。

## 多用户与 API Token 重置（0.18.0）

**邀请制多用户**（不开放注册）：管理员在网页端「用户管理」生成邀请链接
（32 字节随机后缀、一次性、默认 24 小时过期、可撤销）；受邀者打开链接、
输入用户名，即获得自己的 API Token 与全中文分步接入教程。每个用户是一个
独立 Vault 的 owner：文件、变更流、历史、分享、设备、E2EE 密钥文档全部
按 Vault 隔离。管理员看得到用户名/设备数/用量，**拿不到任何人的 API Token**
（`users` 表只存 SHA-256）或 E2EE 密码（从不上传）。用户可被禁用（数据保留、
凭据即时失效）或删除（输入用户名确认；级联清库并回收 blob）。Token 丢失
**没有找回流程**（刻意：无恢复流程即无社工面），只能删除后重新邀请。

**API Token 重置**：网页端「账户」页一键轮换自己的 Token——旧 Token 立即
失效、该账户全部设备凭据连带撤销、其他网页会话下线；设备端填新 Token →
「测试连接」即无损恢复。三个关键性质：

- `OBSYNC_TOKEN` 环境变量从 0.18 起只是**首次初始化的种子**：认证一律查库，
  网页轮换后以库为准（启动日志会提示 env 已失效的状态）；
- **E2EE 重置凭证**：启用 E2EE 的 Vault 会在客户端解锁时自动登记
  `HKDF(VMK, "litesync/v1/token-reset-auth")` 的哈希；此后重置端点要求提交
  该派生值——只拿到 Token 的攻击者无法抢先重置把主人锁在门外。存量 Vault
  从升级到首次解锁之间存在一个抢注窗口，救济是 CLI（如实披露，见下）；
- **SSH 兜底**：`obsync token reset`（改库即时生效，无需重启；
  `--user <名>` 指定用户、`--from-env` 回到环境变量值）。

## 单用户多仓库（0.19.0）

一个 API Token 名下可以有多个互相隔离的仓库。目标仓库由请求头 `X-Vault-ID`
显式选择：**头只是「选择」，授权永远由服务端成员关系裁决**——他人仓库一律
404（不泄露存在性）；设备凭据与短期票已绑定仓库，带头无效（被盗设备不能
横向进入主人的其他仓库）。无头 = 默认仓库，0.18 客户端零感知。

- `GET /api/v1/vaults` 列表（含统计与 current 标记）；`POST /api/v1/vaults`
  新建（同用户内唯一名、上限 20）；`PATCH /api/v1/vaults/{id}` 重命名
  （只动展示名）；`DELETE /api/v1/vaults/{id}`（body `confirmName` 必须
  等于仓库名；不能删最后一个；级联清库 + blob GC）
- 每仓库独立：identity / blobID 域密钥 / repo_state / E2EE 密钥文档（同一
  密码在不同仓库派生完全不同的密钥）/ 重置凭证
- 重置 Token 的 E2EE 门禁升级为「名下任一仓库的凭证均可验证」，撤销范围为
  该用户全部仓库的全部设备
- Web 端登录后有仓库切换器（多于一个才显示），各仓库独立解锁；
  「账户 → My vaults」可自助新建 / 重命名 / 删除仓库（删除输入仓库名
  确认；未命名的仓库须先重命名才能删）

## 公开化（0.20.0）

面向「可以开放注册」的一组改动。**全部默认值保持自托管现状不变**：不配置统一登录时仍是 API Token 登录，
网页仍是只读，注册仍需邀请。

- **统一账号（OIDC）**：配置 `OBSYNC_OIDC_*` 后，网页以授权码 + PKCE 登录（state 单次使用并绑定浏览器、
  nonce、iss/aud/azp 校验、RS256/ES256），会话 Cookie `SameSite=Strict`（回调经同站中转页落地）。本地账号由
  `(issuer, subject)` 映射，**邮箱只是资料快照、从不参与匹配**。支持身份服务的 back-channel logout（`sid`/`sub`，
  `jti` 防重放）与「退出所有产品与设备」。旧管理员通过「绑定统一账号」认领（强制重新认证），也可用
  `obsync identity link` 在服务器上认领。零仓库账号是正常状态：需要仓库的接口返回 409 `VAULT_REQUIRED`。
- **浏览器端加密建库**：`POST /api/v2/vaults` 先建 `pending_encryption` 仓库，浏览器生成仓库密钥并用仓库密码
  包装后 `POST /api/v2/vaults/{id}/initialization` 一次提交（keyDoc + 加密状态 + keyEpoch + 信封下限 + 重置凭证，
  同一事务；opId 幂等，响应丢失可续）。初始化完成前一切内容写入返回 409 `VAULT_NOT_READY`。服务器从不接触仓库密码。
- **连接链接 v2**：网页「连接 Obsidian」生成二维码 / 链接，秘密只在 URL fragment；`GET /api/v2/pairings/{id}/envelope`
  读取**不消费**；插件核对仓库与服务器后 `POST /api/v2/device-enrollments/redeem` 显式兑换（`exchangeId` 幂等，响应丢失
  可续；仓库不符不消费）；关闭对话框即撤销；公开端点按 IP 限流。
- **网页 Markdown 编辑**（`OBSYNC_WEB_EDITING=true` 才开启）：CodeMirror 6 源码编辑 + 分栏预览；加密只用与插件
  同源的 crypto-core（`web/src/vendor/litesync-core`，`npm run build` 会校验 MANIFEST，手改即失败），协议与插件完全
  相同（fileId、CAS、内容世代、operationId 幂等、墓碑与显式恢复），**信封不降级**。冲突用插件的三方合并，合并不干净
  就保留双方（冲突副本），绝不最后写覆盖。未同步的修改以仓库密钥派生的独立密钥加密存进 IndexedDB（只有密文），
  重新解锁后可恢复。空闲 15 分钟自动锁定。网页写入的审计身份由服务器生成（`web-…`），客户端自报的设备 ID 不作数。
  网页每 30 秒（以及回到前台时）看一眼 `changes` 游标，别的设备的新建 / 修改 / 删除不刷新页面就能看到；
  正在编辑且有未保存修改的笔记不会被覆盖，保存时合并。
- **正文全文搜索**：在网页里逐篇下载密文、**在本机解密**建索引（只在页面内存里，锁定 / 刷新 / 切换仓库即清除），
  服务器只看到普通的文件下载，搜索词与正文从不发给服务器。
- **回收站**：`GET /api/v1/trash` 列出仍保留的删除记录；恢复走 `POST /api/v1/files/{fileId}/restore`
  （fileId 与全部历史不变、revision 连续、内容世代前进）。路径加密仓库的服务器不知道已删除文件的原路径，网页不提供恢复。
- **配额与限流**：见上表 `OBSYNC_QUOTA_*` / `OBSYNC_RATE_PER_USER`。存储配额在写锁内原子核算、历史计入总量；
  超出返回 413 `QUOTA_EXCEEDED`（`retryable:false`，`details` 给出种类 / 上限 / 已用；旧插件按「跳过此文件」处理），
  读取、导出、删除与清理历史永远可用。管理员可逐账号覆盖：`PUT /api/v1/admin/users/{userId}/quota`
  `{bytes, vaults}`（0 = 跟随默认，-1 = 不限）。账号页与管理员列表显示用量。
- **产品通知邮件**：新设备接入、Token 重置、仓库删除、退出全部设备 / 所有产品时，给**已验证**的统一账号邮箱发纯文本通知
  （不含任何秘密与笔记内容）。outbox 幂等、有限退避、硬退信与投诉进抑制表（配置错误不拉黑收件人）、同一收件人每天最多 20 封、
  全局日预算。注册验证与找回密码邮件由身份服务发送，不经过这里（这里的耐久性与重试语义**不**代表身份邮件也具备）。
  0.20.1 起通知是耐久的：业务操作在**自己的事务里**写一条最小的安全事件（与业务变更同生共死，没有内存队列可以溢出），
  后台 worker 查地址、渲染、入队、发送，每条事件的去向都记下来（已入队 / 没有已验证邮箱 / 收件人当日超限 / 被抑制……）；
  进程在任何时刻退出，未处理的事件重启后照常发出。服务商「已接受但响应丢失」记为一次不确定的尝试，用同一个幂等键重试
  （Resend 按键去重；SMTP 没有服务商侧去重，可能重复——`GET /api/v1/admin/mail/status` 的 `uncertain` 计数看得到）。
- **命令行**：`obsync identity link|list`（SSH 兜底认领，冲突不覆盖）、`obsync vaults pending`（列出未完成初始化的仓库）。

## 账号撤销的三种范围（0.20.1 / ADR-019）

账户中心的「退出与撤销」有三个按钮，每个旁边都写着影响范围；它们**互不混用**：

| 动作 | 入口 | 生效范围 | 不影响 |
|---|---|---|---|
| **A 只退出这个浏览器** | 「退出此浏览器」；身份中心的 back-channel logout（带 `sid` = 那一个会话，只带 `sub` = 本产品该账号的全部网页会话） | 本产品的网页会话 | 设备、未使用的连接链接、身份中心、另一个产品 |
| **B 退出 LiteSync 的全部设备** | 「退出 LiteSync 的全部设备」`POST /api/v2/account/logout-devices` | 本产品：全部网页会话 + 全部设备凭据（含在途的短期票）+ 全部未使用的连接链接 + API Token | 身份中心、另一个产品 |
| **C 退出所有产品与设备** | 「退出所有产品与设备」`POST /api/v2/account/logout-all` | B 的全部 + 身份中心里该账号**所有浏览器**的登录 + 另一个产品的 B | — |
| **D 中心停用 / 删除** | 管理员在身份中心停用或删除用户 | 本产品发现后执行 B（需要配置中心状态检查） | — |

实现要点（如实写下代价与做不到的事）：

- **账号授权代次**：`users.auth_epoch` 只增不减。网页会话、设备凭据、短期票、未使用的连接链接（enrollment / 配对 v2 授予）
  与 API Token 在**签发时**记下签发者凭据的代次，**每次校验**都比较；B / C / D / 管理员停用 / Token 重置在一个事务里把它 +1。
  判定发生在校验时，所以「撤销与兑换并发」也不会留下有效凭据；已消费授权的「响应丢失重放」同样先核对代次。
- **普通退出永远只是 A**：身份中心的会话结束不代表要断开全部 Obsidian。设备只被 B、C、D 撤销。
- **C 逐项报告真实状态**：本产品（事务内立即生效）→ 身份中心（用该用户本人的令牌调用 Keycloak Account REST API
  `DELETE {issuer}/account/sessions?current=true`，只用他自己的 `manage-account`；浏览器拿不到任何身份中心令牌）→ 另一个产品
  （与本产品的撤销同一事务写入 outbox，请求返回前同步投递一次，失败后台按 5 s、15 s、30 s… 重试，7 天后记为失败）。
  三步都完成 `ok` 才是 `true`；否则逐项显示 `pending` / `failed` / `not-configured`。身份中心一步失败时给出账号中心地址，
  提示到「设备活动」手动退出。C 之后本产品的会话都已失效，结果页凭响应里的一次性 `statusToken`（30 分钟）继续查看与
  「重新发送」；之后重新登录可在「账号与设备 → 最近的撤销」看到。
- **跨产品事件**（ADR-019 §2.4）：`POST {对方}/api/internal/v1/account-revocations`，`X-Revocation-Timestamp` +
  `X-Revocation-Signature: v1=<hex(HMAC-SHA256(共享密钥, 时间戳 + "." + 原始请求体))>`，以 `(issuer, subject)` 定位账号
  （任何一方都不使用另一方的本地 user_id）。接收端常数时间验签、时间戳偏差超过 5 分钟拒绝、`eventId` 去重（重复投递返回同样的
  结果）、找不到身份返回 `200 {"applied":false,"reason":"unknown-identity"}`、不转发、单独限流；事件只能撤销，不能授予任何权限。
  400 / 401 记为失败不重试（需运维修正密钥后手动重发），5xx 与网络错误重试。
- **中心状态检查（D）**：任一已认证请求到达时，该账号上一次成功检查超过 60 秒就先同步查一次身份中心（同一账号并发只查一次，
  超时 3 秒；统一登录成功、会话刷新成功也算一次确认）。停用 / 删除 → 立即执行 B，本次请求按撤销返回。身份中心不可达（包括
  401 / 403 这类**配置错误**，它们不会被当成「用户被停用」）时，上一次成功检查在 15 分钟宽限内放行；超过宽限后**设备请求**返回
  `503 IDENTITY_UNAVAILABLE`（可重试，客户端保留本地待发内容），网页会话按会话复核宽限处理。**未配置服务账号时不做这项检查**：
  中心停用只会在刷新复核时结束网页会话，已连接的设备不会自动失效，需要在产品里撤销——启动日志与账户中心都会写明；
  开放公众注册（`OBSYNC_REGISTRATION_MODE=open`）时不配置直接拒绝启动。
- **管理员停用 = B**；**重新启用只恢复登录资格，不复活任何旧凭据**：用户重新登录、重新连接设备即可；只用 API Token 的旧账号
  （v0.18 邀请注册的）需要管理员在服务器上 `obsync token reset --user <名>` 换发新 Token。
- **API Token 也在「全部凭据」之内**：B / C 会让它作废。旧管理员如果只用 `OBSYNC_TOKEN` 登录网页，执行 B 之后需要在服务器上
  运行 `obsync token reset --from-env`（或 `obsync token reset` 换一个新的）——重启服务**不会**让旧 Token 复活（启动日志会提示）。
  Token 重置本身也是一次 B（未使用的连接链接、其他网页会话一起失效，发起重置的会话保留）。
- **做不到的事**：已经下载到设备上的笔记无法远程删除；离线设备在下一次联网时才收到撤销（`401 TOKEN_REVOKED`，客户端保留本地
  待发内容并提示重新连接，不换用其他凭据提交）。

身份中心（Keycloak）需要的配置（realm 模板 / `configure.sh` 增量应用）：两个产品的 client 都 `fullScopeAllowed=false`，作用域映射加
`account` 客户端角色 `manage-account`（用户 access token 因此带 `aud: account`）；中心状态检查用的服务账号只授 realm-management 的
`view-users`，并且**也要加进该 client 的作用域映射**，否则令牌不带这个角色、查询返回 403。

## 设备可信度：签名 checkpoint（0.15.0）

服务器转发的 checkpoint 由**设备**签名，服务器自己不参与签名，因此无法长期
给不同设备看不同的仓库状态而不被发现：设备之间对不上时同步会**停下来**，
而不是自动挑一边。新设备不信任服务器给出的第一份清单——信任锚通过设备配对
传入（密钥只走链接的 `#fragment`）。

相关接口：`POST /api/v1/checkpoint`、`GET /api/v1/checkpoints`、
`PUT /api/v1/device/signing-key`。

## API 一览

认证方式（`/api/*`，0.10.0 起设备级凭据）：

- **根 Token**（`.env` 中的 `OBSYNC_TOKEN`）→ 完整权限。只用于首台设备注册、
  设备管理与灾难恢复，正常运行时不再存在于任何设备上
- **设备 Token**（每台设备独立、只存 hash、可单独撤销）→ 最小权限 scopes：
  `sync`（文件/变更/快照/历史读）、`share`（分享管理）、`key-admin`
  （vault-key 写、E2EE 状态机、历史清理）、`pairing`（添加新设备）。
  备份 admin 与设备管理**不授予任何设备**；历史记录中的设备身份取自
  服务器侧凭据（客户端自报的 `X-Device-ID` 不再作为审计身份）
- **短期 access token**（0.16.0，`POST /api/v1/token`）→ 用长期设备凭据换一张
  分钟级票据（`lst1.<payload>.<HMAC>`，无状态、不落表，TTL 上限 **15 分钟**）。
  长期凭据会留在配置文件、日志、抓包和备份里，而那些地方的生命周期远长于任何
  一次使用。三条性质：**票不能换票**（否则一张泄露的票可以无限续期）、
  **scope 只能收窄**（申请集合必须是设备 scope 的子集）、**撤销不因此变弱**
  （校验时回查设备是否仍然有效，撤销一台被盗设备立刻让它所有在途的票失效）。
  设备 Token 与 access token 走**同一份** scope 判定实现
- Web 只读会话 Cookie（`POST /web/session` 登录换取，HttpOnly +
  SameSite=Strict，7 天）→ **仅白名单 GET**（info / snapshot / file /
  history / version / vault-key），写操作一律 403
- Admin 会话 Cookie（`POST /web/session` 传 `"admin":true` 换取，30 分钟）
  → **仅 `/api/v1/admin/*`**（备份管理）；只读会话触碰 admin 接口一律 403

设备接入流：首台设备填根 Token → 首轮同步自动换发设备凭据；
后续设备扫配对二维码（包内只有一次性注册凭据，根 Token 绝不下发）→
`POST /enroll` 换取自己的设备凭据。撤销丢失的设备：
`curl -X DELETE -H "Authorization: Bearer <根Token>" https://server/api/v1/devices/<id>`

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 健康检查 `{"status":"ok"}`（无认证） |
| GET | `/api/v1/info` | 版本、`protocolVersion` / `minProtocolVersion`（当前均为 **6**）、`vaultId`、`repoEpoch`、`formatEpoch`、`minimumEnvelopeVersion`、`schemaVersion`、`encryptionState` / `keyEpoch` / `metaState`、latestSequence、服务器时间 |
| GET | `/api/v1/changes?since=N&limit=500` | 增量变更；游标过旧时返回 `resyncRequired` + `minSequence` |
| GET | `/api/v1/snapshot` | 当前全部未删除文件的元数据（Web 端 / 全量对账） |
| GET | `/api/v1/file?path=...` | 下载原始字节，元数据在响应 Header |
| PUT | `/api/v1/file` | 上传原始字节，参数在请求 Header（见下） |
| DELETE | `/api/v1/file` | 逻辑删除，Body: `{"path","baseRevision"}` |
| POST | `/api/v1/file/rename` | 改名（0.13.0）：**一次元数据更新**——revision / contentGeneration / blob 不动，**不产生 tombstone**；metaGeneration CAS 不符 → 412，目标被占用或目标名上有 tombstone → 409 |
| POST | `/api/v1/files/{fileId}/restore` | 显式恢复已删除对象（0.13.0）：普通上传无法再穿透墓碑，重建必须走这里 |
| POST | `/api/v1/envelope/complete` | 验证全部 HEAD 为 LSE3 后把仓库信封下限提升到 3（0.13.0 / ADR-006） |
| GET | `/api/v1/history?path=...` | 历史版本列表（revision 降序） |
| DELETE | `/api/v1/history?path=...&beforeRevision=N` | 清理该 revision 之前的历史（E2EE 迁移用） |
| GET | `/api/v1/version?path=...&revision=N` | 下载某历史版本的原始字节 |
| GET | `/api/v1/vault-key` | 读取客户端存放的加密 vault key（opaque JSON） |
| PUT | `/api/v1/vault-key?replace=true` | 保存 vault key；已存在且未 replace → 409 |
| POST | `/api/v1/share` | 创建分享（body 为独立 Share Key 加密的密文） |
| GET | `/api/v1/shares` | 分享列表 |
| DELETE | `/api/v1/share?id=...` | 撤销分享 |
| GET | `/api/v1/admin/backup/status` | 备份状态（上次/下次备份、仓库统计、错误） |
| GET / PUT | `/api/v1/admin/backup/config` | 备份配置；**GET 永不返回 Secret**，PUT 中 Secret 留空 = 保持原值 |
| POST | `/api/v1/admin/backup/test` | R2 连通性 / 凭据 / 仓库状态检测 |
| POST | `/api/v1/admin/backup/init` | 初始化 restic repository（一次性） |
| POST | `/api/v1/admin/backup/run` | 立即备份（异步；任务互斥，运行中返回 409） |
| POST | `/api/v1/admin/backup/check` | restic check 完整性校验（异步） |
| GET | `/api/v1/admin/backup/snapshots` | 快照列表 |
| GET | `/api/v1/admin/backup/restore-plan` | 灾备恢复**预检**（0.17.0）：核对快照、算出会失效的东西，并给出可粘贴的命令；带 `whyNotAButton` 说明为什么最后一步必须停机用 CLI 做 |
| GET / DELETE | `/api/v1/admin/devices` · `/api/v1/admin/devices/{id}` | 运维页设备列表 / 撤销（0.17.0）：含设备名、平台、客户端版本、最近来源 IP；**已撤销的设备仍然列出**（否则「它最后一次活动是什么时候」永远答不了） |
| GET | `/api/v1/admin/migration/status` | 三件会卡住人的事放在一起：元数据迁移状态、blobID 域化、待重新封装 |
| GET | `/api/v1/admin/migration/preflight` | 迁移前置检查（只读，任何时候跑都安全） |
| GET / DELETE | `/api/v1/admin/shares` · `/api/v1/admin/shares/{id}` | 运维页分享列表 / 撤销 |
| POST | `/api/v1/admin/shares/{id}/recover` | 设置新的到期时间。**只能延长有效期**：密文被过期回收后就真的没了（`410 Gone`），主动撤销过的也不能靠它复活（`409 Conflict`） |
| GET | `/api/v1/admin/integrity/scan` · `/events` | 完整性巡检与告警事件（root Token 或 admin 会话） |
| POST | `/api/v1/admin/integrity/purge-quarantine` | 清理隔离区 |
| GET | `/api/v1/file/meta` | 轻量读取对象元数据（改名变更无需下载内容） |
| POST | `/api/v1/meta/migrate` | 单对象伪名化（幂等，断点续传安全） |
| GET | `/api/v1/meta/status` | 迁移状态与 journal 进度（0.13.0） |
| POST | `/api/v1/meta/begin` / `verify` / `complete` / `abort` | 四态迁移状态机（0.13.0）：验证与不可逆擦除分离 |
| POST | `/api/v1/meta/renew` / `takeover` | 迁移租约续期 / 接管（持锁设备离线后由另一台续做） |
| GET | `/api/v1/meta/validate` | 只跑 11 项验证器不改状态（complete 前预检） |
| GET / POST | `/api/v1/meta/tombstones` · `/api/v1/meta/migrate-tombstone` | 删除记录转隐私格式（**转换而不是删除**） |
| GET | `/api/v1/admin/migration/report` | 最近一次擦除报告 |
| POST | `/api/v1/e2ee/begin` | E2EE 迁移开始（0.9.0）：进入 migrating，冻结一切明文写入 |
| POST | `/api/v1/e2ee/complete` | 验证全部 HEAD 均为 LSE 密文后切换到 encrypted，并把信封下限提升到 1 |
| POST | `/api/v1/e2ee/abort` | 放弃迁移，回到 plaintext |
| POST | `/api/v1/devices` | **根 Token 专属**（0.10.0）：直接创建设备凭据（首台设备自注册） |
| GET | `/api/v1/devices` | 设备列表（不含凭据材料，`current` 标记当前设备） |
| DELETE | `/api/v1/devices/{id}` | **根 Token 专属**：撤销设备（下一个请求即 401） |
| POST | `/api/v1/enrollments` | 生成一次性注册凭据（配对包 v2 携带；secret 只返回一次） |
| POST | `/enroll` | **公开**（0.10.0）：一次性注册凭据换设备凭据（secret 即认证） |
| GET | `/api/v1/whoami` | 当前凭据身份（root / device + scopes；不泄露别的租户的存在） |
| POST | `/api/v1/token` | 用设备凭据换短期 access token（0.16.0；TTL ≤ 15 分钟，拒绝用票换票） |
| DELETE | `/api/v1/members/{userId}` | 移除成员（0.16.0）：撤销其全部设备 + 推进 keyEpoch，响应带 `localPlaintextNotice` |
| POST | `/api/v1/account/token-reset` | 重置自己的 API Token（0.18.0）：作废旧 Token + 撤销全部设备 + 踢其他会话；E2EE Vault 需提交重置凭证 |
| PUT | `/api/v1/vault/reset-auth` | 登记重置凭证（0.18.0）：首登记或持旧值更新；会话拿不到覆盖权 |
| POST/GET | `/api/v1/admin/invites`、DELETE `/api/v1/admin/invites/{id}` | 邀请管理（0.18.0，管理员） |
| GET | `/join/{secret}`、`/join/{secret}/info`、POST `/join/{secret}/register` | 注册落地页与消费（0.18.0，公开：secret 即凭证、一次性、404 无差别） |
| GET/POST | `/api/v1/vaults` | 名下仓库列表 / 新建（0.19.0；`X-Vault-ID` 选择目标仓库，授权由成员关系裁决，非成员 404，设备凭据忽略此头） |
| PATCH/DELETE | `/api/v1/vaults/{id}` | 重命名（0.19.x，只动展示名）/ 删除（confirmName 确认、不能删最后一个）——均为用户 Token 专属 |
| GET | `/api/v1/admin/users` | 用户列表（0.18.0）：用户名/设备数/用量，绝不含凭据材料 |
| POST | `/api/v1/admin/users/{id}/disable`、`/enable`、DELETE `/api/v1/admin/users/{id}` | 禁用/解禁/删除（0.18.0；删除需 body 带 `confirmName`） |
| GET | `/api/v1/audit` | 审计事件（成员变更、密钥世代推进等） |
| POST / GET | `/api/v1/checkpoint` · `/api/v1/checkpoints` | 设备签名 checkpoint 的存储与转发（0.15.0） |
| PUT | `/api/v1/device/signing-key` | 注册本设备的 checkpoint 签名公钥 |
| POST | `/api/v1/pairing` | 创建一次性加密配对包（0.8.0；只存密文，默认 5 分钟过期） |
| DELETE | `/api/v1/pairing/{id}` | 撤销配对包（配对窗口关闭时调用） |
| POST | `/pair/{id}/consume` | **公开**消费配对包（一次性；密文仍需链接 fragment 中的密钥解密） |
| GET | `/p/{id}` | **公开**扫码落地页（脚本本地拼 obsidian:// 深链，secret 不经服务器） |
| POST / DELETE | `/web/session` | Web 登录（Token 换只读会话；`admin:true` 加发 admin 会话）/ 登出 |
| GET | `/share/{id}` | **公开**读取分享密文（密钥在链接 fragment 中，服务器拿不到） |
| GET | `/` | **公开** Web 只读端静态资源（embed，CSP 严格策略） |

PUT `/api/v1/file` 的 Header（路径 percent-encode，支持中文文件名）：

```text
X-File-Path:      encodeURIComponent(vault 相对路径)
X-Base-Revision:  新文件为 0，修改为当前已知 revision
X-Content-Hash:   内容的 SHA-256 hex（E2EE 下即密文 hash）
X-File-Mtime:     文件修改时间（毫秒，可选）
X-Action:         upsert（默认）/ merge / restore，记入版本历史
X-Device-ID:      设备标识（可选，用于日志与历史）
X-File-Id:        稳定文件身份，32 位小写 hex（0.11.0，E2EE 新文件预生成）
X-Meta-Enc:       LSM1 加密元数据，≤ 8 KiB 的标准 base64（0.12.0，meta 模式建档必带）
X-Canonical-Hash: canonical path HMAC，64 位小写 hex（0.12.0）
```

上述格式与长度上限自 0.12.1 起在协议层显式校验，违反即 `400 INVALID_HEADER`
（不再依赖 HTTP Server 的总 Header 上限兜底）。

关键行为：

- baseRevision 与服务器不一致 → `409 CONFLICT`，响应携带服务器当前 `revision/hash/deleted`
- 上传内容与服务器现有内容相同 → 幂等成功，不产生新 revision（安全重试）
- 已删除文件重新上传（v0.9 防复活）→ 必须显式携带 tombstone revision；
  `baseRevision=0` 返回 `409`（附 `priorHash` = 删除前内容 hash，客户端据此
  区分「陈旧副本回传」与「同名新内容」）
- 任何路径穿越（`../`、绝对路径、`\`、盘符）→ `400`；Windows 保留名 /
  尾随空格句点 → `400`；与现有文件大小写/NFC 归一化冲突的新路径 → `422`
- E2EE migrating/encrypted 状态下，非 LSE 密文上传一律 `409`（明文写冻结）
- **信封只升不降（0.12.1）**：当前 HEAD 已是 LSE3 时，明文 / LSE1 / LSE2 覆盖
  一律 `409 ENVELOPE_TOO_OLD`

### 错误响应（0.12.1 起统一）

所有错误响应体为：

```json
{ "code": "INVALID_PATH", "message": "safe user-facing message", "retryable": false, "error": "..." }
```

`error` 为兼容字段（0.12.0 及更早的客户端只读它）。**新客户端必须按 `code` 分支，
不得解析 `message` 文案。** 当前码表：

| code | HTTP | 含义 |
| --- | --- | --- |
| `INVALID_PATH` | 400 | 路径非法（穿越、绝对路径、盘符等） |
| `INVALID_HEADER` | 400 | 元数据类 Header 格式/长度非法 |
| `INVALID_BODY` | 400 | 请求体字段非法 |
| `HASH_MISMATCH` | 400 | 实际内容与 `X-Content-Hash` 不符 |
| `META_REQUIRED` | 400 | meta 模式下缺伪名路径或加密元数据 |
| `CONFLICT` | 409 | revision 冲突（响应携带服务器状态） |
| `ENVELOPE_TOO_OLD` | 409 | 信封降级被拒 |
| `PLAINTEXT_REJECTED` | 409 | 明文写冻结 / 内容不是 LSE3 |
| `META_STATE_INVALID` | 409 | 元数据状态机转换非法 |
| `FILE_ID_CONFLICT` | 409 | 客户端预生成的 fileId 已被占用 |
| `TOMBSTONE_PLAINTEXT` | 409 | 存在明文 tombstone，拒绝抹除明文路径 |
| `STALE_META_GENERATION` | 412 | metaGeneration CAS 失败（重取后可重试） |
| `CANONICAL_COLLISION` | 422 | canonical 归一化后与现有文件同名 |
| `NOT_FOUND` / `TOO_LARGE` / `INTERNAL` | 404 / 413 / 5xx | — |
| `AUTH_REQUIRED` | 401 | 0.20：网页会话失效（统一账号被撤销 / 退出），需重新登录，不得跨账号重发 |
| `TOKEN_REVOKED` | 401 | 设备凭据 / 短期票 / API Token 曾有效、已被撤销（单独撤销、退出全部设备、停用、中心停用、Token 重置）；客户端保留本地待发内容，提示重新连接，不换用其他凭据提交 |
| `IDENTITY_UNAVAILABLE` | 503 | 0.20.1：暂时无法向身份中心确认账号状态且已超过 15 分钟宽限（只对设备请求），带 `Retry-After`，`retryable:true`；保留本地待发内容稍后重试，不需要重新连接 |
| `VAULT_REQUIRED` | 409 | 0.20：零仓库账号调用了需要仓库的接口 |
| `VAULT_NOT_READY` | 409 | 0.20：仓库尚未完成加密初始化，拒绝内容写入 |
| `EMAIL_NOT_VERIFIED` | 403 | 0.20：未验证邮箱的统一账号不能建仓库或连接设备 |
| `PAIRING_USED` / `PAIRING_EXPIRED` / `PAIRING_REVOKED` | 410 | 0.20：连接链接已兑换 / 过期 / 撤销 |
| `VAULT_MISMATCH` | 409 | 0.20：兑换时核对的仓库与链接不符（不消费链接） |
| `QUOTA_EXCEEDED` | 413 / 409 | 0.20：**永久性**配额超限（存储 413、仓库数 409），`retryable:false`，`details {kind, limit, used}`；不要自动重试 |
| `RATE_LIMITED` | 429 | 0.20：**临时**限流（请求速率 / 上传并发 / 公开端点），带 `Retry-After`，`retryable:true` |

0.20 新增接口（细节见[公开化（0.20.0）](#公开化0200)）：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/auth/config` | 登录页用：是否启用统一登录、注册模式、是否保留 Token 登录 |
| GET | `/auth/login` · `/auth/callback` · `/auth/link/start` | OIDC 授权码 + PKCE；认领旧账号（强制重新认证） |
| POST | `/auth/logout` · `/auth/backchannel-logout` | 退出本产品；身份服务的 back-channel logout（验签、拒 nonce、jti 防重放） |
| GET | `/api/v2/me` | 账号、角色、引导状态、功能开关、用量与上限 |
| POST | `/api/v2/account/logout-devices` | 0.20.1：动作 B，退出 LiteSync 的全部设备（返回撤销的设备与授权数） |
| POST | `/api/v2/account/logout-all` | 0.20.1：动作 C，退出所有产品与设备；逐项返回 `local` / `identityCenter` / `peers[]` 的真实状态与一次性 `statusToken` |
| GET | `/api/v2/account/revocations` | 0.20.1：最近的撤销事件与跨产品投递状态（只含时间、对象产品、状态与错误类别） |
| POST | `/api/v2/account/revocations/{eventId}/retry` | 0.20.1：重新发送尚未送达的跨产品事件（只能是本人的事件） |
| GET / POST | `/api/v2/revocation-status/{eventId}` · `…/resend` | 0.20.1：**公开**，凭 `X-Revocation-Status-Token`（C 的一次性凭证，30 分钟）查看 / 重发这一个事件；按 IP 限流 |
| POST | `/api/internal/v1/account-revocations` | 0.20.1：**公开**，跨产品撤销事件接收端（HMAC 签名 + 时间窗 + eventId 去重 + 单独限流）；未配置共享密钥时 404 |
| GET / DELETE | `/api/v2/devices` · `/api/v2/devices/{id}` | 本人设备列表与撤销 |
| POST | `/api/v2/vaults` · `/api/v2/vaults/{id}/initialization` | 建 `pending_encryption` 仓库（clientRequestId 幂等）；一次提交加密初始化（opId 幂等） |
| POST | `/api/v2/vaults/{id}/pairing-grants` · `/api/v2/pairings` · DELETE `/api/v2/pairings/{id}` | 发行连接链接、上传加密配对包、撤销 |
| GET | `/api/v2/pairings/{id}/envelope` | **公开**，读取不消费；按 IP 限流 |
| POST | `/api/v2/device-enrollments/redeem` | **公开**，显式兑换（exchangeId 幂等、可续传）；按 IP 限流 |
| GET | `/api/v1/trash` | 回收站列表（恢复走 `POST /api/v1/files/{fileId}/restore`） |
| PUT | `/api/v1/admin/users/{userId}/quota` | 管理员设置账号配额覆盖值 `{bytes, vaults}`（0 = 默认，-1 = 不限） |
| GET | `/api/v1/admin/mail/status` | 管理员：邮件 outbox 计数（不含地址与正文） |
| POST | `/hooks/mail/resend` | 邮件服务商回执（Svix 签名 + 时间窗）；未配置密钥时 404 |

## 功能说明

### 版本历史

- 每次上传/删除写入不可变版本记录；内容以 SHA-256 寻址存于 `blobs/`
  （v0.5 起同一份 blob 同时充当 HEAD 与历史，单份存储）
- 恢复历史 = 客户端下载旧版本重新 PUT（`action=restore`），历史保持线性
- 保留策略：时间 + 数量 +（可选）全局字节预算；最新版本永远保留；
  裁剪顺序「先删元数据 → 确认 blob 无引用 → 再删 blob」

### 端到端加密

服务器对 E2EE 零感知：只代存一份客户端上传的**加密** vault key 文档
（带覆盖保护 + CAS，防止误覆盖导致密文永久不可读）。启用后文件内容均为
LSE 密文，服务器永远无法获得解密密钥或任何明文。

**路径与文件名加密（0.12.0 起，实验功能 / RC）**：插件命令「加密路径与文件名」
把服务器上所有路径替换为随机伪名（=fileId），真实路径改存 **LSM1** 加密元数据
（AAD 绑定 vaultId+keyEpoch+fileId+metaGeneration）。迁移后服务器不再看到
目录结构与文件名；同名并存判定靠客户端 HMAC（服务器只见散列）；
改名 = 元数据更新，内容零重传。要求先完成「升级加密信封 LSE1 → LSE3」。

**0.13.0（协议 v6）起的迁移流程**：`begin` → 逐对象伪名化 → **tombstone 转隐私格式**
→ `verify` → `complete`。关键性质：

* 迁移只改元数据，`revision` / `contentGeneration` / blob 全部不动，**不产生 tombstone**；
* tombstone 做**格式转换**（明文寻址名 → fileId、归一化路径 → 客户端 HMAC）而**不是删除**——
  0.12.0 靠删除 tombstone 抹明文，代价是长期离线设备重新上线会复活已删文件；
* `verify` 是独立一态：验证与不可逆擦除分离，验证失败时数据一个字节都没动；
* `complete` 前跑 11 项验证器，失败返回**完整清单**并保持 `verifying`；
* 完成后 `formatEpoch` +1，所有客户端强制重新对账。

> ⚠️ **`complete` 仍然不可逆，且迁移前备份中仍含明文路径。**
> 擦除报告（`GET /api/v1/admin/migration/report`）会如实登记这一点
> （`claims.backupsCleaned = false`）。销毁迁移前备份之前，不得声称明文路径已不可恢复。

剩余的元数据暴露面：文件大小、修改时间与访问模式（见 v10 计划的 padding/批处理评估）。

信封格式（0.11.0）：新写入使用 **LSE3**——AAD 绑定 vaultId + keyEpoch +
**fileId + contentGeneration**：恶意服务器既无法用其他 vault / 其他密钥世代 /
其他文件的密文做替换重放，也无法把同一文件的**旧版本**当最新 HEAD 重放
（generation 单调，客户端与服务器双侧拒绝回退）；且路径不入 AAD，
E2EE 下改名走原子 MOVE、无需重新加密内容。旧 LSE1/LSE2 密文读取兼容；
插件命令「升级加密信封」可把存量密文批量升级到 LSE3。
迁移期间服务器冻结一切明文写入（状态机见 e2ee 接口）。

**LSE4（0.17.0，大小混淆）**：客户端开启「混淆文件大小」后，新写入使用把明文
填充到桶边界的 LSE4 信封（帧内自带真实长度），服务器只看得到大小区间而不是
精确字节数。服务端要做的只有三件事：识别这个版本、按仓库信封下限判定
（4 > 3，因此**不需要迁移**，存量 LSE3 继续可读）、按双格式解析头部并拒绝截断。
Web 只读端与分享查看页同样实现了 LSE4 解密（含 flags 认证与去填充）。

> 服务器**不决定**谁开启填充，也不知道某个对象是否被填充过——`flags` 进 AAD，
> 抹掉 padded 位会导致认证失败。

### 离线分享查看器（0.10.0）

分享查看页的 JS 由同步服务器下发——理论上「已控制服务器的攻击者」可以
替换页面代码偷取链接 fragment 里的 Share Key。高安全场景请使用仓库中的
**`viewer/litesync-viewer.html`**：完全自包含的单文件页面，从 GitHub 下载一次
保存到本地，打开后粘贴分享链接即可本地解密（服务器只被请求密文本身）；
服务器被攻陷也无法替换你本地保存的这份查看器。

### Web 只读端

Obsidian 风格阅读器（文件树 / Markdown / Outline / 文件名搜索 /
版本历史 / Diff），E2EE 在浏览器本地解密（密钥只存内存，刷新需重新解锁）。
前端源码在仓库 `web/`，构建产物已提交（`internal/web/dist`），
部署无需 Node；改前端后 `cd web && npm run build` 再重新编译服务器。

### 运维页（0.17.0）

设备撤销、迁移状态、完整性告警、备份恢复、分享恢复——这五件事的共同点是
**出事的时候才会用到**，而它们最常见的失败不是写错了，是「只能 SSH 上服务器
敲命令」。事故当天，能不能在手机上撤销一台丢失的设备，和这个功能写得优不优雅
是完全不同量级的问题。

Web 端 **🛠 入口**（与备份页并列，不是塞进去——出事时要能一眼找到），
共用 30 分钟 admin 会话（`POST /web/session` 带 `"admin":true`）：

| 卡片 | 内容 |
|---|---|
| 完整性告警 | 排在最上面：它是唯一一类「已经有内容读不出来了」的信号 |
| 设备 | 名称 / 平台 / 客户端版本 / 最近来源 IP；一键撤销，撤销后下一个请求即 401。**已撤销的设备仍然列出** |
| 迁移 | 元数据迁移状态、blobID 域化进度、待重新封装——「现在到底卡在哪」一眼可答 |
| 分享 | 列表、撤销、设置新的到期时间（预设或自定义） |
| 灾备预检 | 核对快照、算出会失效的东西、给出可粘贴的命令 |

**IP 只在直连方是可信代理（`OBSYNC_TRUSTED_PROXIES`）时才采信转发头**，
客户端伪造的 `X-Forwarded-For` 不进库。

**灾备恢复刻意不是一个网页按钮**：恢复要替换正在运行的进程打开着的文件
（sync.db / WAL / blob），在进程内做这件事意味着先静默请求、关库、换目录、
再重开，中途任何一步失败都会留下既不是旧库也不是新库的半成品——而这一步发生
在你已经出过一次事之后。所以只做能安全做的部分，真正的切换停机后由 CLI 执行。
响应里带 `whyNotAButton` 并由 UI 原样展示，免得看起来像功能没做完。

### 分享（服务端视角）

- 分享密文由客户端用**独立 Share Key** 加密后上传，密钥只在链接的 `#fragment`
  里，服务器从头到尾拿不到；
- 0.17.0 起笔记内嵌的图片会被客户端**一起加密进同一个包**——服务器看到的
  仍然只是一个密文 blob，附件的数量、名字、内容都在密文里；
- 有效期由客户端设置（预设或自定义），过期分享由资源治理任务清理；
- 查看页有严格 CSP，**不加载任何外部资源**：笔记里的外链图片不会把查看者的
  IP 报给第三方；
- 运维页可以撤销分享或设置新的到期时间，但**救不回已经过期回收的密文**，
  也不能推翻一次主动撤销（见上面的 410 / 409）。

### 异地备份（Restic → Cloudflare R2，v0.6）

三层数据保护各司其职：**同步** = 实时多设备一致，**版本历史** = 文件级恢复，
**R2 备份** = 服务器损毁级的灾难恢复。

```text
BackupManager ── 一致性快照（写锁内 VACUUM INTO + hardlink staging）
      │
    restic ────── 加密 / 去重 / 快照管理（fork 子进程，用完即退）
      │
Cloudflare R2 ── S3 兼容对象存储（免费额度 10GB/月，egress 免费）
```

**配置流程**（部署后全程在 Web 完成，无需 SSH）：
浏览器打开 Web 端 → `⚙` → Backup → Admin unlock（输入 Token）→
填 R2 Account ID / Bucket / S3 凭据 → Generate 生成 Restic 恢复密码
（**立即存入密码管理器**，服务器损毁后没有它备份无法解开）→
Test connection → Initialize → Backup now → 勾选 Enable automatic backup。

- **计划**：每 6 小时备份；每日 forget（keep-last 8 / daily 14 / weekly 8 /
  monthly 6）、每周 prune、每月 check；单任务互斥，绝不并发
- **一致性**：绝不直接备份运行中的 `/data`——短暂持全局写锁生成
  `.backup-staging/`（SQLite `VACUUM INTO` + blob hardlink + manifest），
  restic 读 staging，同步全程不受影响
- **安全**：R2 凭据与 Restic 密码以 AES-256-GCM 密文存于 SQLite，解密密钥
  `backup-config.key` 在 `/data` **之外**（单独拷贝数据目录拿不到凭据）；
  凭据只经子进程环境变量传给 restic，不进命令行 / 日志；客户端永远接触不到
- **失败策略**：备份任何失败只标记 `Backup = Failed` 并在下个周期重试，
  绝不影响同步
- **R2 侧要求**：Bucket 保持 private；凭据只授予该 Bucket 的
  Object Read & Write；**绝不要配置 R2 Lifecycle 自动删除**（会损坏 restic
  仓库，生命周期只能由 forget/prune 管理）；暂不启用 Bucket Lock

### 灾难恢复指南（Disaster Recovery）

前提：你有 ① R2 凭据 ② Restic 恢复密码（密码管理器里那份）。

```bash
# 1. 停止 LiteSync（新机器则跳过）
cd litesync/server && docker compose down

# 2. 从 R2 恢复到临时目录（宿主机装 restic 或用容器）
export RESTIC_REPOSITORY='s3:https://<ACCOUNT_ID>.r2.cloudflarestorage.com/<bucket>/restic'
export RESTIC_PASSWORD='<恢复密码>'
export AWS_ACCESS_KEY_ID='<AccessKeyID>' AWS_SECRET_ACCESS_KEY='<SecretAccessKey>'
restic snapshots                       # 确认快照存在
restic restore latest --target /tmp/litesync-restore

# 3. 校验并替换 /data（快照内容在 .backup-staging/current/ 下）
RESTORED=$(find /tmp/litesync-restore -type d -name current -path '*backup-staging*')
cat "$RESTORED/backup-manifest.json"   # 确认版本与 latestSequence
mv server/data server/data.broken 2>/dev/null || true
mkdir -p server/data && cp -a "$RESTORED"/sync.db "$RESTORED"/blobs "$RESTORED"/shares server/data/
[ -d "$RESTORED/vaults" ] && cp -a "$RESTORED/vaults" server/data/

# 4.【必须】旋转 repo epoch（v0.9+）：作废所有客户端的旧游标
#    否则游标新于恢复点的设备会静默跳过恢复后产生的变更区间
docker run --rm -v "$PWD/server/data:/data" kjoner/litesync-server:latest rotate-epoch
#（或本地二进制：OBSYNC_DATA_DIR=server/data obsync rotate-epoch）

# 5. 重新部署并验证（.env 不在备份里，Token 丢了就重新生成并更新各设备）
bash scripts/litesync-install.sh
curl http://127.0.0.1:8080/health
```

恢复后各设备下次连接会检测到 repoEpoch 变化，自动暂停增量同步并提示
重新走接入向导的「安全合并」：本地在备份点之后产生的新内容全部保留，
与服务器恢复版本的差异走正常冲突流程，不会被静默覆盖或丢弃。

## 备份后端

支持两种 restic 仓库：

| provider | 配置 | 适用 |
|---|---|---|
| `r2`（默认） | `accountId` / `bucket` / `accessKeyId` / `secretAccessKey`，或用 `endpoint` 指向任意 S3 兼容服务（B2 / MinIO…） | 异地备份 |
| `local` | `localPath`（**必须是绝对路径**） | 备份到挂载的 NAS、外接盘或另一块硬盘 |

`localPath` 强制绝对路径：相对路径会随服务的工作目录漂移，而「备份仓库找不到」
这件事往往要到需要恢复的那天才被发现。

> ⚠️ 本地仓库若与数据目录在**同一块盘**上，同一次硬件故障会同时带走两者。
> 代码不强制检查（挂载点是否独立只有你知道），但请务必指向独立的存储。

本地后端让灾备恢复演练随时可做——一个没人演练过恢复的备份系统，等于没有备份。
建议按 `obsync backup create` → 破坏测试副本 → `obsync backup restore --new-epoch`
的顺序至少完整走一次。

## PostgreSQL 元数据库（可选）

默认的 SQLite 足够单机部署使用。需要把元数据放进统一管理的 PostgreSQL 时，设置
`OBSYNC_DB=postgres` 与 `OBSYNC_PG_DSN`。**只有元数据进 PG**；密文 Blob 仍在数据目录，
备份仍由 restic 负责，两者都不变。

**数据库要求**

- PostgreSQL 13 及以上（演练与 CI 用 16）；为 LiteSync 建**独立的库与账号**，账号只需要这个库的
  建表与读写权限，不要用超级用户。
- 库必须是 **C 排序**（与 SQLite 的字节序比较一致，路径排序与分页才不会因 locale 漂移）；
  否则服务拒绝启动：

  ```sql
  CREATE ROLE litesync LOGIN PASSWORD '…';
  CREATE DATABASE litesync OWNER litesync TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C';
  ```
- `OBSYNC_PG_DSN` 例：`postgres://litesync:…@db:5432/litesync?sslmode=require`。它只从环境变量读取，
  不接受命令行参数，也不会出现在日志、报告与错误信息里。
- 当前版本对 PG 使用**单连接**（与 SQLite 现状相同的事务与锁语义，正确性优先）。
  吞吐与 SQLite 部署同一量级；连接并发优化是后续工作，届时会单独说明。

**从现有 SQLite 迁移（需要一个短维护窗口）**

```bash
# 0. 先用当前版本在 SQLite 上正常启动一次（完成表结构升级），再停服务；做一次备份
obsync backup create
# 1. 只读演练：结构兼容性 + 逐表行数 + 每仓库摘要（不连接目标库）
obsync migrate-to-pg --dry-run
# 2. 正式导入。服务必须已停止——这一条是机器检查：运行中的服务持有数据目录锁
#    （$OBSYNC_DATA_DIR/.obsync-server.lock），拿不到锁直接拒绝；迁移期间本命令持有它，服务也无法中途启动。
#    目标库必须为空；导入与校验在目标库的同一个事务里，校验不通过整体回滚
OBSYNC_PG_DSN='postgres://…' obsync migrate-to-pg
# 3. 只有 ok=true 且 targetState=committed-verified 才算成功；切换：OBSYNC_DB=postgres（保留 OBSYNC_PG_DSN）后启动服务
```

导入后在**同一个源快照**上、**提交之前**、在同一个目标事务里逐表校验（每个值按目标列类型规范化后做与行顺序
无关的摘要）；另外核对每个仓库的对象/版本/墓碑/变更计数、content_hash 集合、repoEpoch / headSequence /
formatEpoch / keyEpoch / 信封下限、keyDoc 指纹，以及自增序列的高水位（id 永不复用）。任一不符即整体回滚，
源库不动。提交之后再用一个新快照复核一次（证明导入期间源库没有被写入）。
报告是机器可读的 JSON（标准输出 + `$OBSYNC_DATA_DIR/migrate-to-pg-report.json`），其中 `targetState`
如实写出目标库最后的状态：

| targetState | 含义 | 下一步 |
|---|---|---|
| `untouched` | 目标没有任何提交（失败发生在写入前，或导入与校验的事务已回滚） | 修正问题后直接重跑 |
| `committed-verified` | 已提交且校验通过 | 切换（第 3 步） |
| `commit-unknown` | 提交调用本身报错（例如连接在提交时断开），结果不确定 | **不要**在这个库上启动服务；先检查它是否为空，非空就换一个新的空库重跑 |
| `copied-not-enabled` | 已复制并校验，但源库在迁移期间被写入（新快照对不上）；没有写迁移标记 | **不要**在这个库上启动服务；停掉所有写入者，换一个新的空库重跑 |
| `already-migrated` | 目标已有与源库逐表一致的数据（重复运行） | 只做了校验，可以切换 |

重复运行是幂等的：目标已有与源库逐表一致的数据时只做校验；不一致则拒绝，不碰任何一边。
`sourceLock` 字段说明锁检查的结果；文件系统不支持独占锁时（`unsupported:…`）命令会如实警告，只能人工确认服务已停止，
提交后的新快照复核仍会发现迁移期间的写入。同一数据目录也只能运行一个服务：第二个进程启动时会因锁被占用而拒绝。

迁移保留全部身份与世代（vaultId、fileId、revision、各 generation、墓碑、checkpoint、
repoEpoch），**不旋转 epoch**——客户端游标照常续用，不会进入灾备合并。

迁移成功后数据目录里会写入 `migrated-to-postgres.json`：此后以 SQLite 方式启动会被拒绝。
旧 `sync.db` 停在切换那一刻，一旦 PG 上有了新写入，把它接回去等于让所有客户端看到一段倒退的
历史，所以它只能作为只读的历史副本保留。**回退**请走经过校验的反向导出：

```bash
# 停服务 → 导出（导出后逐表校验）→ 用导出件替换 sync.db → 删除标记 → OBSYNC_DB=sqlite 启动
OBSYNC_PG_DSN='postgres://…' obsync export-sqlite --out /data/sync.db.from-postgres
```

**备份与恢复（PG 部署）**

- `backup create` 不再依赖 SQLite 的 `VACUUM INTO`：在 LiteSync 全局写锁窗口里，用
  `REPEATABLE READ READ ONLY` 事务把 PG 导出成一个当前表结构的 SQLite 文件（导出后逐表校验），
  同一窗口内 hard link Blob——元数据快照与 Blob 清单取自同一时刻（这就是 Blob 保留水位：
  锁内没有上传提交，也没有 GC 删除）。备份格式与 SQLite 部署完全相同，所以任一种部署的备份
  都能恢复到任一种部署。不需要安装与服务器主版本匹配的 `pg_dump`。
- manifest 记录元数据引用的 blob 数与**缺失数**；缺失不会让备份失败（否则一个已隔离的坏 blob
  会挡住全部后续备份），但会写进 manifest 与日志，恢复时再报告一次。
- `backup restore --new-epoch <id>`：恢复写入 `OBSYNC_PG_RESTORE_DSN` 指向的**新的空库**
  （非空直接拒绝，不覆盖任何已有数据），当前库只用来读备份配置、原样保留作为退路；
  Blob 数据目录照旧挪开再换上。导入、逐表校验与**全部仓库**的 repoEpoch 旋转在同一个事务里完成，
  不存在「数据已在、epoch 未转」的中间态。完成后把 `OBSYNC_PG_DSN` 指向恢复出的库再启动。

**PG 部署上如实说明的差异**

- 明文路径擦除（元数据加密迁移的最后一步）在 PG 上照样执行（`VACUUM FULL` 重写表），但报告**不会**
  声称 WAL 已截断或数据文件已扫描：PG 的 WAL、流复制副本与 PG 自身的基础备份由数据库服务器管理，
  明文路径可能在其中留存到被回收为止。报告里只断言逻辑表已无哨兵。
- 完整性巡检里的数据库页级自检（SQLite 的 `integrity_check`）在 PG 上显示为 `not-run`：
  页校验与索引校验是数据库服务器的职责（建库时开启 data checksums，按需使用 `amcheck`）。

## 运维命令

服务停止时对着同一个数据目录运行（`OBSYNC_DATA_DIR` 指向它）；
`obsync ops` 可以随时打印这份清单：

```bash
obsync backup create                         # 立即创建一次备份
obsync backup verify                         # restic check
obsync backup restore --new-epoch <snapshot> # 恢复 + 旋转 repoEpoch（见下）
obsync integrity scan [--full]               # 完整性巡检；--full 重算每个 blob 的 hash

obsync migration preflight                   # 迁移前置检查（只读，任何时候跑都安全）
obsync migration status                      # 元数据迁移状态与 journal 进度
obsync migration resume                      # 释放已过期的迁移租约，任一设备可接管续做
obsync migration abort                       # 中止迁移并回到 plain（已迁移对象保持可读）

obsync token reset                           # 重置管理员 API Token（打印一次，只存哈希）
obsync token reset --user <名>               # 重置指定用户的 Token
obsync token reset --from-env                # 把管理员 Token 重设为 OBSYNC_TOKEN 的值

obsync blobid status                         # 还有多少 blob 停留在裸 contentHash 上
obsync blobid migrate                        # dry-run：只报告要改名多少个
obsync blobid migrate --confirm              # 真正执行（**不可逆**，先 backup create）

obsync rotate-epoch [--vault <id> | --all]   # 手工旋转 repoEpoch（restore 会自动做；多用户实例灾备恢复后用 --all）

obsync migrate-to-pg --dry-run               # 只读源 SQLite：逐表行数与每仓库摘要（不连接目标库）
obsync migrate-to-pg                         # SQLite → OBSYNC_PG_DSN：目标须为空；已完成则只校验；输出 JSON 报告
obsync export-sqlite --out <path>            # PostgreSQL → 新 SQLite 文件并逐表校验（切换后的回退路径）
```

`backup restore` 会旋转**全部**仓库的 repoEpoch（0.20 起；之前从 restore 路径进来只转了 default，
多仓库实例恢复后请补跑一次 `obsync rotate-epoch --all`）。

`restore` **强制要求 `--new-epoch`**：不旋转 repoEpoch 的话，客户端会带着
恢复点之前的旧游标继续增量同步，从而静默跳过「恢复点之后曾经存在」的那段变更。
恢复流程本身也刻意保守——恢复内容先落临时目录，旧数据目录被**挪到**
`restore-backup-<时间戳>` 而不是删除（恢复错快照时那是唯一的退路）。

`integrity scan` 发现问题时以非零码退出，可以直接接进 cron 告警。
被判定损坏的内容会停止对外提供（返回 `503 CONTENT_CORRUPTED` 而不是 404），
坏副本移入 `blobs/_quarantine/` 保留取证。

同样的能力也有 HTTP 接口（需 root Token 或 admin 会话）：
`GET /api/v1/admin/integrity/scan`、`/events`、
`POST /api/v1/admin/integrity/purge-quarantine`。

## 开发与源码构建

架构约定、不变量与改动这份代码时的注意事项见 [AGENTS.md](AGENTS.md)。

本地直接运行（不使用 Docker）：

```bash
OBSYNC_TOKEN=$(openssl rand -hex 32) go run ./cmd/obsync
```

Windows PowerShell：

```powershell
$env:OBSYNC_TOKEN = 'your-random-token'; go run ./cmd/obsync
```

从源码构建 Docker 镜像（不使用 Docker Hub 预构建镜像时的高级用法，
一键部署脚本在镜像拉取失败时也会自动走这条路径）：

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

镜像发布（维护者）：推送 `v*` 格式的 Git tag（须与 `cmd/obsync/main.go`
中的版本号一致）→ GitHub Actions 自动测试并将 multi-arch 镜像推送到
Docker Hub（见 `.github/workflows/docker-publish.yml`）；普通 push / PR
只跑 CI，不发布镜像。

## 测试

```bash
go test ./...
```

覆盖：认证与只读/admin 会话矩阵、上传/下载/删除、revision 冲突、幂等重传、
changes 顺序/分页/裁剪与 resync、路径穿越（含 URL encoded）、中文路径、
版本历史与 retention、vault-key 保护、分享生命周期、维护任务、
HEAD→blob 迁移、CSP 响应头、双设备协议场景，以及备份专项
（加密配置往返与防泄露、staging 一致性快照、restic 调用参数/env 隔离、
任务互斥、Secret 永不出现在 API 响应）。

另有几组「不靠人记得」的结构性测试：

- **崩溃点注入**：在 blob 落盘前后、事务提交前后强制中断，验证不留半成品；
- **跨租户越权矩阵**：按 `router.go` 自动生成，新增路由立刻被纳入覆盖；
- **去重不得短路**：命中去重的上传必须和全新上传读走同样多的请求体
  （存在性预言机最常见的形态就是「秒传」与「真传」在耗时和流量上判若两物）；
- **不变量标注**：`TestInvariantsAreAnnotated` 检查 INV-01/02/06/07/08/11/12
  每一条都有测试认领；
- **规模测试**：`LITESYNC_SCALE=20000 go test ./internal/sync/ -run TestScale`；
- **灾备演练**：真实 restic 仓库上跑 create → 破坏 → restore 全流程。
- **两种数据库各跑一遍**：同一套测试在 PostgreSQL 上再跑（CI 的 `test-postgres` job；
  本地 `LITESYNC_TEST_PG_ADMIN_DSN=… scripts/test-pg.sh`，为本次运行建独立库、跑完删除）。
  另有 PG 分支的灾备演练（恢复到全新实例、注入缺失 blob）与 MG-03 离线迁移演练
  （`internal/pgdrill`：合成 SQLite → PG → 在 PG 上启动，逐项比对与越权抽查）。

## 许可（License）

[AGPL-3.0](LICENSE)。你可以自由地自托管、修改和分发本服务器；
如果你基于修改后的版本对外提供网络服务，必须向该服务的用户提供修改后的源码。

配套的 [Obsidian 插件](https://github.com/KJoner/litesync)为独立程序
（仅通过 HTTP API 通信），采用 MIT 许可。
