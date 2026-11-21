# AGENTS.md — LiteSync Server 仓库系统说明

面向接手这份代码的人（或 AI 助手）。README 讲**怎么部署和用**，这份讲**怎么改**。

---

## 1. 这是什么

`litesync-server` = Go + SQLite + 内容寻址 Blob 存储实现的私有同步服务器，
内嵌 Web 只读客户端、运维页与 Restic → Cloudflare R2 异地备份。
配套的 Obsidian 插件在 [litesync](https://github.com/KJoner/litesync)。
元数据库默认 SQLite（数据目录里的 `sync.db`），可选 PostgreSQL（批次 G：`OBSYNC_DB=postgres`，
见 §3 的 `internal/db/pgdriver.go` 与 README「PostgreSQL 元数据库」）；Blob 始终在数据目录。

**双仓结构**（2026-08 起）：

| 仓库 | 内容 | tag 约定 |
|---|---|---|
| `litesync-server`（本仓） | Go 服务端 + Web 端，AGPL-3.0 | **有 v 前缀**，如 `v0.17.1` |
| `litesync` | Obsidian 插件，MIT | **无 v 前缀**，如 `0.17.0` |

两仓**独立发版**，只通过 HTTP API 通信；兼容性由 `/api/v1/info` 的
`protocolVersion` / `minProtocolVersion` 区间判定。当前协议 **v6**。

本机路径：服务端 `D:\myProject\litesync-server`，插件 `D:\myProject\litesync`。

## 2. 常用命令

```bash
go test ./...                                        # 全量测试
go vet ./...
OBSYNC_TOKEN=$(openssl rand -hex 32) go run ./cmd/obsync   # 本地起服务
LITESYNC_SCALE=20000 go test ./internal/sync/ -run TestScale -timeout 1800s

cd web && npm run build                              # 改了前端必须重新构建
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

Windows：`scripts\dev-server.ps1`；`$env:OBSYNC_TOKEN = '...'; go run ./cmd/obsync`。

同一套测试在 PostgreSQL 上再跑一遍（批次 G；CI 的 `test-postgres` job 做同样的事）：

```bash
# 为本次运行建一个 C 排序的独立库，跑完删除；每个测试在里面再用独立 schema
LITESYNC_TEST_PG_ADMIN_DSN='postgres://u:p@127.0.0.1:5432/postgres?sslmode=disable' scripts/test-pg.sh ./...
# 或直接指定一个（C 排序的）测试库：
LITESYNC_TEST_PG_DSN='postgres://u:p@127.0.0.1:5432/lstest?sslmode=disable' go test ./...
# 可选第二个实例：恢复演练把它当「全新实例」
LITESYNC_TEST_PG_RESTORE_DSN='postgres://u:p@127.0.0.1:5433/lstest?sslmode=disable'
# MG-03 离线迁移演练（合成 SQLite → PG → 在 PG 上启动 → 逐项比对 + 越权抽查）
LITESYNC_TEST_PG_DSN=... LITESYNC_MG03_FILES=200 go test ./internal/pgdrill -v
```

## 3. 代码地图

```
cmd/obsync/
├── main.go        进程入口、版本常量、启动自检、rotate-epoch [--vault|--all]
├── token.go       `obsync token reset`：API Token 重置的 SSH 兜底（v0.18）
├── ops.go         运维 CLI：backup / integrity / migration / blobid
├── database.go    元数据库打开入口（OBSYNC_DB=sqlite|postgres）+「已迁移到 PG」标记拦截（批次 G）
└── migrate_pg.go  `migrate-to-pg`（dry-run / 导入 / 校验 / 幂等）与 `export-sqlite`（反向导出）（批次 G）
internal/
├── api/           HTTP 层：router、认证与 scope、各资源 handler、运维接口
├── sync/          业务核心：Service、对象读写、改名/恢复、迁移、完整性、维护任务
├── db/            SQLite：schema、迁移、租户模型、对象/变更/墓碑/设备/分享
├── storage/       Blob 存储、blobID 域化、路径归一、分享密文
├── backup/        restic 旁路：一致性 staging、配置加密、恢复、保留策略
├── failpoint/     崩溃点注入（测试用，生产路径零开销）
├── config/        环境变量解析与校验（database.go：OBSYNC_DB / OBSYNC_PG_DSN）
├── pgdrill/       （只有测试）MG-03 离线迁移演练：合成 SQLite → PG → 在 PG 上启动逐项比对
└── web/dist/      Web 前端构建产物（**已提交**，部署无需 Node）
web/               Web 前端源码（只读端 / 运维页 / 分享页 / 配对落地页 / 离线查看器）
viewer/            自包含单文件离线查看器（用户下载到本地保存）
```

### 关键文件

| 文件 | 为什么重要 |
|---|---|
| `internal/api/router.go` | 全部路由 + 错误码表；**越权矩阵测试直接扫它抽路由** |
| `internal/api/auth.go` | 三类身份（用户 Token / 设备 Token / 会话）+ access token；`scopeOf(r)` 是 handler 取租户范围的唯一入口 |
| `internal/db/users.go` | 用户 Token 落库（只存 SHA-256）、启动对账、重置凭证（E2EE 知识证明）（v0.18） |
| `internal/db/vaults_user.go` | 单用户多仓库（v0.19）：仓库 CRUD、`createVaultTx`/`deleteVaultRowsTx` 与注册/删用户共用防清单漂移 |
| `internal/api/auth.go` 的 `resolveVaultChoice` | X-Vault-ID 解析（v0.19）：头只是选择、授权由 membership 裁决、非成员 404、设备凭据一律忽略头 |
| `internal/db/invites.go` | 邀请与注册事务：一次性 secret、user+vault+membership+repo_state 原子建立（v0.18） |
| `internal/api/account.go` / `users_admin.go` | 账户自救（重置 Token）与用户管理/邀请/注册端点（v0.18） |
| `internal/db/tenancy.go` | `VaultScope`：字段不可导出，唯一构造入口在认证层 |
| `internal/storage/blobid.go` | `blobID = HMAC(vaultSecret, contentHash)`，消除存在性预言机 |
| `internal/sync/vault_state.go` | 每 Vault 一把写锁、每 Vault 保留策略 |
| `internal/sync/service.go` | 协议 v6 核心：身份与展示名分离 |
| `internal/backup/snapshot.go` | 一致性 staging；**锁语义在这里踩过坑**（见 §7）；PG 部署走只读快照事务导出（批次 G） |
| `internal/db/pgdriver.go` | PostgreSQL 方言适配（批次 G）：驱动层把 `?` 改写为 `$n`、DDL 类型映射、登记在案的 SQLite 专属语句翻译；**未登记的 SQLite 专属语句一律报错** |
| `internal/db/dbcopy.go` / `dbrestore.go` | 跨方言整库复制 + 逐表摘要校验（迁移、反向导出、PG 备份共用）；恢复导入与全部仓库 epoch 旋转同一事务 |
| `internal/api/oidc.go` + `internal/sync/identity.go` + `internal/db/identities.go` | 0.20 统一账号（ADR-011）：OIDC 依赖方（PKCE、state 绑浏览器、nonce/iss/aud/azp、back-channel logout）；`(issuer, subject)` → 本地用户，**邮箱从不参与匹配** |
| `internal/api/vaults_v2.go` + `internal/sync/vault_init.go` + `internal/db/vault_init.go` | 浏览器端加密建库状态机（ADR-012）：`pending_encryption → initializing（10 分钟租约）→ ready`，提交原子、opId 幂等；`readyGate` + `guardWriteReady` 两道写入闸门 |
| `internal/sync/pairing_v2.go` + `internal/db/enroll_v2.go` | 连接链接 v2（ADR-014）：envelope 读取不消费、显式兑换、exchangeId 加密暂存可续传、公开端点按 IP 限流 |
| `internal/api/quota.go` + `internal/sync/quota.go` + `internal/db/quota.go` | 0.20 配额与限流：存储配额在 `Upload` 写锁内核算（历史计入）、仓库数、按身份令牌桶 + 上传并发、管理员逐用户覆盖 |
| `internal/mail/` + `internal/db/mail_outbox.go` | 产品通知邮件（ADR-018）：log/smtp/resend、outbox 幂等与退避、抑制表、按收件人与全局日预算 |
| `web/src/vendor/litesync-core/` | 与插件逐字节一致的 crypto-core / merge-core（MANIFEST 校验，`npm run build` 先跑 `check:core`）；**只能用 `web/scripts/vendor-core.mjs` 从插件仓重新生成，手改必失败** |
| `web/src/write.ts` + `note-editor.ts` + `editor.ts` | 网页写端（ADR-015）：与插件同协议（CAS、世代、operationId、墓碑/恢复），信封不降级，冲突保留双方，加密草稿只存密文；CodeMirror 单独打包 `/editor.js` |

## 4. 数据模型（协议 v6）

- **身份与展示名分离**：所有表以 `file_id` 为主键，`pseudonym` 只是服务器可见
  的寻址名（plain 模式 = 真实路径，meta-encrypted 模式 = fileId）。
- **revision 属于对象**，跨改名 / 元数据迁移 / 删除恢复**连续递增**。
- **改名 = 一次元数据更新**，不产生 tombstone、内容零重传。
- **删除进入 `tombstones` 台账**，绝不删行；重建必须走显式
  `POST /api/v1/files/{fileId}/restore`。
- **`minimumEnvelopeVersion`**（仓库级信封下限，单调不减，落库前校验）与
  **`formatEpoch`**（寻址格式世代，变化时客户端丢弃游标全量对账）。
- **元数据迁移是四态状态机** `plain → migrating → verifying → encrypted`，
  验证与不可逆擦除分离，进度写 `migration_journal`，重启可续跑。
- **每 Vault 独立**：`repo_state`（repoEpoch / headSequence / 迁移状态 /
  keyEpoch / formatEpoch）、写锁、`vault_retention`、`audit_events`。

数据库结构升级在 `db.Open` 时自动完成、幂等、可续跑，**但不可回滚**——
旧版代码读不了重建后的表。因此跨版本升级前必须 `obsync backup create`。

## 5. 必须守住的不变量

计划书 §2 的 12 条不变量里，本仓负责这几条，
`TestInvariantsAreAnnotated` 检查每条都有测试认领：

| 编号 | 内容 | 实现 |
|---|---|---|
| INV-01 | 写入成功 ⇒ blob 已持久化且 hash 正确 | `BlobStore.CommitAs` 在事务提交前落盘 |
| INV-02 | headSequence 永不下降；snapshot 与 sequence 同一时刻 | `NextSequence` 同事务分配；水位线独立记录，**不是 `MAX(sequence)`** |
| INV-06 | 删除事实必须保留 | `tombstones` 台账（ADR-002） |
| INV-07 | 信封只升不降 | `RaiseMinimumEnvelopeVersion`（SQL 自带 `< ?` 保护） |
| INV-08 | 加密完成后无真实路径残留 | 擦除 + 哨兵扫描（ADR-008） |
| INV-11 | 迁移可恢复、可重复、幂等 | `migration_journal`、四态状态机 |
| INV-12 | 每个查询/变更/blob/sequence 限定到 vault | `VaultScope` + 源码扫描 guard |

插件仓负责 INV-03/04/05/09/10（见那边的 AGENTS.md）。

## 6. 隔离与安全的硬约束

改任何一处涉及数据访问的代码前先读这一节，CI 会当场拦住违反项：

1. **不许自己造 `VaultScope`**。唯一构造入口是认证层的 `ScopeFromAuth`；
   `tenancy_guard_test.go` 禁止业务包调用它，也禁止在 `db` 包之外手写
   `vault_id = ?`。这条约束在开发期真的拦下过两次。
   v0.18 的补充：`Service` 的业务方法一律从参数收 `VaultScope`（api 层用
   `scopeOf(r)` 构造）；`defaultScope()` 只允许出现在三类地方——启动路径、
   实例级操作（备份快照点、维护遍历起点）、单用户遗留 CLI——请求处理路径上
   调用它 = 把别人的请求算到 default 头上。维护任务用 `db.AllVaultScopes`
   遍历全部租户。写入侧的归属由 db 层按 scope **无条件强制**
   （`UpsertHead` 等直接覆写 `VaultID`，调用方结构体里写什么都不算数）。
2. **零值 scope 一律硬拒**（`ErrVaultScopeMissing`），**绝不退化为默认租户**——
   后者会把「忘了取范围」的编程错误变成静默的跨租户访问，而且测试还会通过。
3. **新增路由必须被越权矩阵覆盖**。矩阵按 `router.go` 自动生成；确实要公开的
   路由必须在 `publicRoutes` 里显式登记，逼作者当场判断「这条真的能公开吗」。
4. **去重不得短路**：命中去重的上传必须和全新上传读走同样多的请求体。
   「秒传」与「真传」在耗时和流量上判若两物，那正是存在性预言机最常见的形态。
5. **响应里不得出现 `blobId`**，也不得有任何路由按 blob 直接寻址
   （那会绕过 HEAD 上的租户校验）。
6. **审计身份取服务器侧凭据**，客户端自报的 `X-Device-ID` 不作数。
7. **转发头只在可信代理时采信**（`OBSYNC_TRUSTED_PROXIES`），
   否则客户端可以随便写自己的来源 IP。
8. **日志不得泄露明文路径**（`logprivacy_test.go` 盯着这一条）。
9. **网页会话的权限是白名单**（`session.go` 的 `webSessionAllowed`，0.20 起还有 `webContentWrite`）：
   新增给网页用的接口要同时登记白名单；内容写入只在 `OBSYNC_WEB_EDITING=true` 时放行，且要求同源 Origin、
   成员角色可写，审计身份由服务器生成（`web-…`）。
10. **配额只拦新增，不拦读取与清理**：存储检查必须留在 `Upload` 的写锁内、幂等短路之后（否则并发上传会一起越过
    上限，或把响应丢失后的原样重试误判为超限）。永久超限（`QUOTA_EXCEEDED`，`retryable:false`）与临时限流
    （`RATE_LIMITED`，429 + `Retry-After`）不得混用——客户端靠它决定要不要重试。
11. **CSP 不放宽**：`style-src 'self'` 拦内联 `<style>`。第三方组件（如 CodeMirror）的样式走
    Constructable Stylesheets（`editor.ts` 的 `installCspSafeStyles`），不要为它们开 `'unsafe-inline'`。

## 7. 踩过的坑（都是真事故，别再来一遍）

- **`.gitignore` 的前导斜杠**：`obsync` 不带前导斜杠会匹配**任意层级**的同名
  目录——`cmd/obsync/` 整个运维 CLI 曾因此从未被提交，而本地编译一直正常
  （文件就在磁盘上）。直到 CI 在干净 checkout 上跑 `go vet` 才暴露。
  写忽略规则时问一句：它会不会误伤源码目录？
- **持锁期间回调加锁方法 = 死锁**（v0.17.1）：`buildStaging` 的闭包在
  `WithGlobalLock` 持锁期间回调了 `Service.LatestSequence`，而它自己也要拿同一把
  不可重入的互斥锁 → 运行中的服务器**第一次执行备份即整库死锁**，
  `/health` 与静态页照常响应，症状极具迷惑性。**它溜过了六轮 RC**，因为 CLI 与
  测试替身的 `WithGlobalLock` 都是无锁直通，恰好绕开真实实现。
  教训有两条：① 需要的值在锁内读好、当参数传进闭包，别让闭包回调加锁方法；
  ② **测试替身如果绕开了被测的语义，那条测试等于没写**——
  `TestBuildStagingWithRealServiceLock` 用真实锁语义跑，并带 15 秒看门狗。
- **Web 前端构建产物已提交**（`internal/web/dist`），部署无需 Node。
  改了 `web/` 就必须 `cd web && npm run build` 再重新编译服务器，
  否则线上跑的还是旧资产——「查看端行为像旧版」十有八九是这个或镜像标签。
- **`obsync restore` 强制要求 `--new-epoch`**：不旋转 repoEpoch 的话，客户端会
  带着恢复点之前的旧游标继续增量同步，**静默跳过**恢复点之后那段变更。
- **blobID 域化后 `CommitAs(tmp, blobID, contentHash, strict)` 的两个参数不能混**：
  「文件叫什么」和「内容应该哈希成什么」必须分开传，用文件名当期望哈希的老写法
  在域化之后会把每个 blob 都判成损坏。
- **PostgreSQL 方言（批次 G，写 SQL 时两种库都要过）**：
  ① `ON CONFLICT … DO UPDATE SET x = x + 1` 在 PG 上**整句报错**（未限定列名有歧义），
  必须写 `x = 表名.x + 1`——GC 候选计数曾因此在 PG 上静默失效（报错被吞 → 永不删除）；
  ② `EXISTS(...)` 在 PG 是布尔，扫不进 int64，要 `CASE WHEN … THEN 1 ELSE 0 END`；
  ③ 唯一约束判断用 `db.IsUniqueViolation`，别匹配错误文案；
  ④ 时间用 Go 传参，别用 `strftime`；`rowid`、`x'..'` 字面量、`PRAGMA`、`sqlite_master`
  在 PG 上都不存在——驱动层只翻译 `pgRewrites` 表里登记的那几条，其余**当场报错**；
  ⑤ 需要不同**行为**的地方（备份快照、擦除报告、页级自检）用 `db.IsPostgres` 显式分支，
  而且报告文案要跟着变：PG 上 WAL 不归我们截断、数据文件扫不到，报告里不得沿用 SQLite 的断言；
  ⑥ PG 库必须是 C 排序（`OpenPostgres` 会拒绝其他 locale），否则路径排序与分页和 SQLite 不一致。
- **恢复后只转了 default 的 epoch**（批次 G 发现）：`backup restore` 曾调用按 `os.Args`
  判断 `--all` 的 `rotateEpoch()`，从 restore 路径进来永远只转 default——多仓库部署里
  其他仓库的客户端会沿用旧游标。现在恢复一律 `db.RotateAllEpochs`（PG 恢复在导入事务里做）。

## 8. 测试组织

`go test ./...`。除常规单元与接口测试外，有几组结构性测试值得了解：

| 测试 | 作用 |
|---|---|
| `internal/api/tenancy_matrix_test.go` | 按路由表**自动生成**的跨租户越权矩阵（60+ 路由） |
| `internal/db/tenancy_guard_test.go` | 源码扫描：谁在乱造 scope、谁在手写 `vault_id = ?` |
| `internal/sync/crashpoint_test.go` | 崩溃点注入（`internal/failpoint`），验证不留半成品 |
| `internal/sync/blobid_drill_test.go` | 迁移演练：真实仓库退回老格式跑完迁移，**逐字节**比对 |
| `internal/backup/restore_drill_test.go` | 真实 restic 仓库上的 create → 破坏 → restore |
| `internal/backup/staging_lock_test.go` | 真实锁语义 + 看门狗（见 §7 的死锁事故） |
| `internal/sync/scale_test.go` | 规模上限（默认 2 000，可 `LITESYNC_SCALE=20000`） |
| `internal/db/invariants_test.go` | 每条 INV 都有测试认领 |
| `internal/db/pgdriver_test.go` | PG 改写器：占位符、字面量/注释、DDL 类型、登记语句、未登记语句拒绝（批次 G） |
| `internal/db/dbcopy_test.go` | 跨方言复制：通用填充覆盖**每张表每一列**（新表自动纳入）、发散检测、非空拒绝、旧库拒绝、SQLite→PG→SQLite 往返 |
| `internal/backup/restore_drill_pg_test.go` | PG 分支灾备演练：真 restic → 全新 PG 实例恢复 → 启动 → 旧设备视角（epoch 旋转、删除不复活）；注入缺失 blob 必须被报告 |
| `internal/pgdrill/mg03_test.go` | MG-03 离线迁移演练：合成 SQLite（多用户/多仓库/LSM1/checkpoint/配对/身份/outbox）→ PG → 逐项比对 + 越权抽查 + 耗时 |
| `internal/api/oidc_test.go` | 内嵌模拟身份服务：PKCE、回调重放、登录 CSRF、iss/aud/azp/nonce/exp/未知密钥篡改、注册模式、旧管理员认领、back-channel logout |
| `internal/api/vault_init_test.go` | 建库状态机全周期、v1 兼容、配对 v2 发行/envelope/兑换/重放/撤销、8 路并发兑换只成功 1 个 |
| `internal/api/web_edit_test.go` / `quota_test.go` | 网页写入闸门（默认只读、同源、只读成员、审计身份）、回收站；配额（原子、历史计入、幂等放行、覆盖值）与限流 |
| `web/test/*.test.ts`（`cd web && npm test`） | crypto-core 冻结向量对比、网页写端协议层（信封不降级、世代、重试同密文、三方合并、加密草稿隔离、附件命名） |

**两种库各跑一遍**：设置 `LITESYNC_TEST_PG_DSN` 后，测试二进制里的 `db.Open(path)` 改走 PG
（每个路径一个独立 schema，重开同一路径 = 同一 schema，「关闭再打开模拟重启」语义不变）。
专测旧 SQLite 文件库升级路径的用例（v5→v6、单行 repo_state、SQLite 部署的恢复演练）固定用
`db.OpenSQLiteFile`，两种模式下都照常针对 SQLite 运行。

**做过变异测试的地方**（去掉某条检查看矩阵是否变红）值得保持：去掉租户校验
会产生 61 处断言失败，去掉 `object_versions` 的 repoint 会让迁移演练立刻失败。

## 9. 发版流程

1. 改 `cmd/obsync/main.go` 的 `version` 常量；
2. 提交后打 **带 v 前缀**的 tag（预发布后缀被容忍：常量 `0.17.0` 可打 `v0.17.0-rc.6`）；
3. `docker-publish.yml` 自动跑测试并推 multi-arch 镜像到 Docker Hub
   `kjoner/litesync-server`，标签含精确版本 / 次版本 / 主版本 / `latest`；
4. 普通 push / PR 只跑 CI，不发布镜像。

版本常量与 tag 不一致时 CI 会拒。

## 10. 工作约定

- **提交与推送只在用户明确指示时执行**（「提交」「发版」等）。
  提交人 `KJoner <KJoner@users.noreply.github.com>`，提交信息**中文**，
  末行 `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`。
- **计划书与 ADR 在插件仓的 `docs/开发计划/`**（gitignored，本机可读）。
  协议级决策的权威出处是 `v10/adr/`（ADR-001…010），其中 ADR-010 是多租户
  隔离模型，ADR-007 是 repoEpoch 灾备流程，ADR-008 是擦除与备份保留政策。
- **面向用户的说明写进 README**，且必须如实写清代价与做不到什么
  （例如成员移除收不回已下载的明文、灾备恢复最后一步必须停机执行）。
  这个项目的文档基调是：宁可承认缺口，不可让用户以为自己被保护了。
