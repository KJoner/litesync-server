# obsync — 单用户 Obsidian 私有同步服务器

一个使用 Go + SQLite + 内容寻址 Blob 存储实现的单用户、低资源、增量式
Obsidian 私有同步服务器，内嵌 Web 只读客户端与 Restic → Cloudflare R2 异地备份。

> ⚠️ **Sync is not Backup（同步不等于备份）**
> 同步只保护多设备一致性；灾难恢复请启用内置的 R2 异地备份（见下），
> 或自行定期备份整个 `/data` 目录。

## 架构（v0.6）

```text
一个 Go Binary + 一个 SQLite 文件 + 一个内容寻址 Blob 目录（+ restic 备份旁路）
```

```text
/data
├── sync.db      # 元数据：files（HEAD）/ file_versions（历史）/ changes / shares
├── blobs/       # 唯一内容存储：SHA-256 寻址、不可变、跨版本跨文件去重
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
  SQLite checkpoint / 按需 VACUUM，并输出资源统计日志
- 备份是**服务器旁路能力**（v0.6）：不改动 revision / changes / E2EE / merge
  任何协议；restic 仅在备份任务执行时 fork，无常驻内存开销

## 一键部署 / 更新

```bash
bash <(wget -qO- https://raw.githubusercontent.com/KJoner/litesync/master/scripts/litesync-install.sh)
```

首次执行：克隆代码、生成 `.env`（随机 Token，端口被占用时自动改用
8081–8099 中的空闲端口）、构建镜像、启动并输出配置信息。
再次执行：拉取最新代码重新构建部署，`.env` 和 `data/` 保持不变。

## 快速开始（Docker）

```bash
cd server
cp .env.example .env
# 生成随机 token 并填入 .env
openssl rand -hex 32

docker compose up -d
curl http://127.0.0.1:8080/health
```

只需要持久化 `./data` 目录。compose 已配置日志轮转（10MB × 3）。

## 本地运行（不使用 Docker）

```bash
OBSYNC_TOKEN=$(openssl rand -hex 32) go run ./cmd/obsync
```

Windows PowerShell：

```powershell
$env:OBSYNC_TOKEN = 'your-random-token'; go run ./cmd/obsync
```

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

Compose 额外变量：`LITESYNC_ETC_DIR`（宿主机密钥目录，默认 `./etc-litesync`，
只读挂载为容器内 `/etc/litesync`；一键部署脚本自动生成密钥）。

## HTTPS（生产环境必须）

服务本身只讲 HTTP，请放在反向代理后面；Web 端的浏览器解密（WebCrypto）
与会话 Cookie 的 Secure 标记都依赖 HTTPS。Caddy 示例（自动证书）：

```text
sync.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

## API 一览

认证方式（`/api/*`）：

- `Authorization: Bearer <token>`（插件 / CLI）→ **完整权限**（含 admin）
- Web 只读会话 Cookie（`POST /web/session` 登录换取，HttpOnly +
  SameSite=Strict，7 天）→ **仅白名单 GET**（info / snapshot / file /
  history / version / vault-key），写操作一律 403
- Admin 会话 Cookie（`POST /web/session` 传 `"admin":true` 换取，30 分钟）
  → **仅 `/api/v1/admin/*`**（备份管理）；只读会话触碰 admin 接口一律 403

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 健康检查 `{"status":"ok"}`（无认证） |
| GET | `/api/v1/info` | 版本、latestSequence、服务器时间 |
| GET | `/api/v1/changes?since=N&limit=500` | 增量变更；游标过旧时返回 `resyncRequired` + `minSequence` |
| GET | `/api/v1/snapshot` | 当前全部未删除文件的元数据（Web 端 / 全量对账） |
| GET | `/api/v1/file?path=...` | 下载原始字节，元数据在响应 Header |
| PUT | `/api/v1/file` | 上传原始字节，参数在请求 Header（见下） |
| DELETE | `/api/v1/file` | 逻辑删除，Body: `{"path","baseRevision"}` |
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
```

关键行为：

- baseRevision 与服务器不一致 → `409`，响应携带服务器当前 `revision/hash/deleted`
- 上传内容与服务器现有内容相同 → 幂等成功，不产生新 revision（安全重试）
- 已删除文件重新上传 → `baseRevision` 用 0 或 tombstone revision 均可
- 任何路径穿越（`../`、绝对路径、`\`、盘符）→ `400`

## 功能说明

### 版本历史

- 每次上传/删除写入不可变版本记录；内容以 SHA-256 寻址存于 `blobs/`
  （v0.5 起同一份 blob 同时充当 HEAD 与历史，单份存储）
- 恢复历史 = 客户端下载旧版本重新 PUT（`action=restore`），历史保持线性
- 保留策略：时间 + 数量 +（可选）全局字节预算；最新版本永远保留；
  裁剪顺序「先删元数据 → 确认 blob 无引用 → 再删 blob」

### 端到端加密

服务器对 E2EE 零感知：只代存一份客户端上传的**加密** vault key 文档
（带覆盖保护，防止误覆盖导致密文永久不可读）。启用后文件内容均为
`LSE1` 密文，服务器永远无法获得解密密钥或任何明文。

### Web 只读端

Obsidian 风格阅读器（文件树 / Markdown / Outline / 文件名搜索 /
版本历史 / Diff），E2EE 在浏览器本地解密（密钥只存内存，刷新需重新解锁）。
前端源码在仓库 `web/`，构建产物已提交（`server/internal/web/dist`），
部署无需 Node；改前端后 `cd web && npm run build` 再重新编译服务器。

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

# 4. 重新部署并验证（.env 不在备份里，Token 丢了就重新生成并更新各设备）
bash scripts/litesync-install.sh
curl http://127.0.0.1:8080/health
```

恢复后各设备照常连接：客户端游标若新于恢复点，changes 接口会触发
snapshot 全量对账自动回齐，不需要手工干预。

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
