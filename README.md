# obsync — 单用户 Obsidian 私有同步服务器

一个使用 Go + SQLite + 本地文件系统实现的单用户、低资源、增量式 Obsidian 私有同步服务器。

> ⚠️ **Sync is not Backup（同步不等于备份）**
> 本服务只负责在多台设备之间同步笔记，不能替代备份。
> 请定期用 restic / rclone / rsync 等工具备份整个 `/data` 目录。

## 架构

```text
一个 Go Binary + 一个 SQLite 文件 + 一个 Vault 文件目录
```

- 元数据（路径、hash、revision、change sequence）保存在 SQLite（WAL 模式）
- 文件原始字节保存在 `data/vaults/default/` 下的本地磁盘
- 每个文件独立 revision，上传/删除都必须携带 baseRevision，不一致返回 409
- 所有变更写入 changes 表（递增 sequence），客户端按 `since` 增量拉取
- 上传采用「临时文件 → 校验 SHA-256 → 原子改名 → SQLite 事务」，断电不产生半文件

## 一键部署 / 更新

```bash
bash <(wget -qO- https://raw.githubusercontent.com/KJoner/litesync/master/scripts/litesync-install.sh)
```

首次执行：克隆代码、生成 `.env`（随机 Token，端口被占用时自动改用 8081–8099
中的空闲端口）、构建镜像、启动并输出配置信息。
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

只需要持久化 `./data` 目录（SQLite + Vault 文件都在里面）。

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
| `OBSYNC_LISTEN` | `:8080` | 监听地址 |
| `OBSYNC_DATA_DIR` | `./data` | 数据目录（SQLite + Vault 文件 + 历史 blob） |
| `OBSYNC_MAX_FILE_SIZE` | `104857600` | 单文件大小上限（字节，默认 100MB） |
| `OBSYNC_LOG_LEVEL` | `info` | debug / info / warn / error |
| `OBSYNC_HISTORY_ENABLED` | `true` | 版本历史开关 |
| `OBSYNC_HISTORY_DAYS` | `90` | 历史保留天数（0 = 不按天数裁剪） |
| `OBSYNC_HISTORY_MAX_PER_FILE` | `100` | 每文件保留版本数（0 = 不限） |

## HTTPS（生产环境必须）

服务本身只讲 HTTP，请放在反向代理后面。Caddy 示例（自动申请证书）：

```text
sync.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

## API 一览

所有 `/api/*` 接口要求 `Authorization: Bearer <token>`，`/health` 不需要。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 健康检查 `{"status":"ok"}` |
| GET | `/api/v1/info` | 版本、latestSequence、服务器时间 |
| GET | `/api/v1/changes?since=N&limit=500` | 增量变更列表 |
| GET | `/api/v1/file?path=...` | 下载原始字节，元数据在响应 Header |
| PUT | `/api/v1/file` | 上传原始字节，参数在请求 Header |
| DELETE | `/api/v1/file` | 逻辑删除，Body: `{"path","baseRevision"}` |
| GET | `/api/v1/history?path=...` | 历史版本列表（revision 降序） |
| DELETE | `/api/v1/history?path=...&beforeRevision=N` | 清理该 revision 之前的历史（E2EE 迁移用） |
| GET | `/api/v1/version?path=...&revision=N` | 下载某历史版本的原始字节 |
| GET | `/api/v1/vault-key` | 读取客户端存放的加密 vault key（opaque JSON） |
| PUT | `/api/v1/vault-key?replace=true` | 保存 vault key；已存在且未 replace → 409 |

### 版本历史（v0.2）

- 每次上传/删除都会写入不可变版本记录；文件内容以 SHA-256 内容寻址存入
  `data/blobs/`（相同内容跨版本/跨文件只存一份）
- `PUT /api/v1/file` 可带 `X-Action: upsert|merge|restore` 标记版本类型；
  恢复历史版本由客户端下载旧版本后重新 PUT（`action=restore`），
  历史保持线性，服务器不执行明文恢复
- retention：保留最近 N 个 + 最近 N 天，最新版本永远保留；
  裁剪顺序为「先删元数据 → 确认 blob 无引用 → 再删 blob」
- v0.1 升级：启动时自动为存量文件补记当前版本（幂等 backfill）

### 端到端加密（v0.3）

服务器对 E2EE **零感知**：加解密全部发生在客户端，服务器只是多存了
一份客户端上传的加密 vault key 文档（`PUT /api/v1/vault-key`，本身也是
密文）。启用 E2EE 后所有文件内容均为 `LSE1` 格式密文，`X-Content-Hash`
即密文 hash；服务器永远无法获得解密密钥或任何明文。
vault key 有覆盖保护（防止误覆盖导致密文数据永久不可读）。

PUT 的 Header（路径必须 percent-encode，以支持中文等非 ASCII 文件名）：

```text
X-File-Path:      encodeURIComponent(vault 相对路径)
X-Base-Revision:  新文件为 0，修改为当前已知 revision
X-Content-Hash:   内容的 SHA-256 hex
X-File-Mtime:     文件修改时间（毫秒，可选）
```

关键行为：

- baseRevision 与服务器不一致 → `409`，响应携带服务器当前 `revision/hash/deleted`
- 上传内容与服务器现有内容相同 → 幂等成功，不产生新 revision（安全重试）
- 已删除文件重新上传 → `baseRevision` 用 0 或 tombstone revision 均可
- 任何路径穿越（`../`、绝对路径、`\`、盘符）→ `400`

## 测试

```bash
go test ./...
```

覆盖：认证、上传/下载/删除、revision 冲突、幂等重传、changes 顺序与分页、
路径穿越（含 URL encoded）、中文路径、文件大小限制、原子写入。
