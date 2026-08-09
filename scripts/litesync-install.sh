#!/usr/bin/env bash
#
# litesync 一键部署 / 更新脚本
#
# 全新部署（在希望存放代码的目录下执行，会克隆到 ./litesync）：
#   bash <(wget -qO- https://raw.githubusercontent.com/KJoner/litesync/master/scripts/litesync-install.sh)
#
# 重新部署 / 更新版本：
#   在同一目录（或仓库目录内）再次执行同一条命令即可。
#   .env（含 Token）和 data/ 数据目录会被完整保留。
#
set -euo pipefail

REPO_URL="https://github.com/KJoner/litesync.git"
BRANCH="${LITESYNC_BRANCH:-master}"

info() { printf '\033[1;32m[litesync]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[litesync]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[litesync]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------- 依赖检查 ----------
command -v git >/dev/null 2>&1 || die "未找到 git，请先安装"
command -v docker >/dev/null 2>&1 || die "未找到 docker，请先安装"
docker info >/dev/null 2>&1 || die "Docker daemon 未运行或当前用户无权限"

if docker compose version >/dev/null 2>&1; then
	COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
	COMPOSE="docker-compose"
else
	die "未找到 docker compose"
fi

# ---------- 定位 / 获取代码 ----------
is_repo() { [ -f "$1/server/docker-compose.yml" ] && [ -d "$1/.git" ]; }

if is_repo "$(pwd)"; then
	REPO_DIR="$(pwd)"                       # 在仓库根目录内执行
elif is_repo "$(cd .. && pwd)"; then
	REPO_DIR="$(cd .. && pwd)"              # 在 server/ 等子目录内执行
elif is_repo "$(pwd)/litesync"; then
	REPO_DIR="$(pwd)/litesync"              # 在安装目录的上层执行
else
	REPO_DIR="$(pwd)/litesync"
	info "克隆代码到 $REPO_DIR ..."
	git clone --depth 1 -b "$BRANCH" "$REPO_URL" "$REPO_DIR"
fi

cd "$REPO_DIR"

info "更新代码到最新版本 ..."
git fetch --depth 1 origin "$BRANCH"
git reset --hard "origin/$BRANCH" >/dev/null
VERSION="$(git log -1 --format='%h %s')"

cd server

# ---------- 生成 .env（仅首次；重新部署保留原配置） ----------
port_busy() { ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"; }

if [ ! -f .env ]; then
	if command -v openssl >/dev/null 2>&1; then
		TOKEN="$(openssl rand -hex 32)"
	else
		TOKEN="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
	fi

	PORT=8080
	if command -v ss >/dev/null 2>&1 && port_busy "$PORT"; then
		for p in $(seq 8081 8099); do
			if ! port_busy "$p"; then PORT="$p"; break; fi
		done
		warn "端口 8080 已被占用，改用空闲端口 $PORT"
	fi

	cat > .env <<-EOF
	OBSYNC_TOKEN=$TOKEN
	OBSYNC_PORT=$PORT
	# OBSYNC_BIND=127.0.0.1
	# OBSYNC_MAX_FILE_SIZE=104857600
	# OBSYNC_LOG_LEVEL=info
	EOF
	info "已生成 .env（包含随机 Token）"
else
	info "检测到已有 .env，保留现有配置（Token / 端口不变）"
fi

# shellcheck disable=SC1091
set -a; . ./.env; set +a
BIND="${OBSYNC_BIND:-127.0.0.1}"
PORT="${OBSYNC_PORT:-8080}"

# ---------- 备份配置密钥（v6；仅首次生成，重新部署完整保留） ----------
# backup-config.key 与 /data 分离：R2 凭据以 AES-256-GCM 密文存在数据库里，
# 单独复制 /data 无法解出凭据。丢失该文件只需在 Web 重新填一次 R2 配置。
ETC_DIR="${LITESYNC_ETC_DIR:-$PWD/etc-litesync}"
KEY_FILE="$ETC_DIR/backup-config.key"
if [ ! -f "$KEY_FILE" ]; then
	mkdir -p "$ETC_DIR"
	if command -v openssl >/dev/null 2>&1; then
		openssl rand -hex 32 > "$KEY_FILE"
	else
		head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$KEY_FILE"
	fi
	chmod 600 "$KEY_FILE"
	chmod 700 "$ETC_DIR"
	info "已生成备份配置密钥 $KEY_FILE"
else
	info "检测到已有 backup-config.key，保留不变"
fi

# ---------- 构建并启动 ----------
info "构建镜像并启动容器 ..."
$COMPOSE up -d --build

# 清理更新后遗留的悬空镜像（不影响使用中的镜像）
docker image prune -f >/dev/null 2>&1 || true

# ---------- 健康检查 ----------
info "等待服务就绪 ..."
health() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsS "http://127.0.0.1:${PORT}/health" 2>/dev/null
	else
		wget -qO- "http://127.0.0.1:${PORT}/health" 2>/dev/null
	fi
}
OK=""
for _ in $(seq 1 30); do
	if health >/dev/null; then OK=1; break; fi
	sleep 1
done
if [ -z "$OK" ]; then
	$COMPOSE logs --tail 30
	die "健康检查失败，请查看上方日志"
fi

SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$SERVER_IP" ] || SERVER_IP="<服务器IP>"

# ---------- 输出关键配置信息 ----------
echo
echo "=============================================================="
echo " litesync 部署完成 ✓   $(health)"
echo "--------------------------------------------------------------"
echo " 当前版本  : $VERSION"
echo " 安装目录  : $REPO_DIR"
echo " 数据目录  : $REPO_DIR/server/data   ← 唯一需要备份的目录"
echo " 监听地址  : http://$BIND:$PORT"
echo " API Token : ${OBSYNC_TOKEN}"
echo "--------------------------------------------------------------"
echo " Obsidian 插件设置："
echo "   Server URL : https://你的域名（经 Nginx/Caddy 反代到 127.0.0.1:$PORT）"
echo "   API Token  : 同上"
if [ "$BIND" = "127.0.0.1" ]; then
	echo " 注意：当前仅监听 127.0.0.1，外网访问需要配置 HTTPS 反向代理。"
fi
echo "--------------------------------------------------------------"
echo " 异地备份  : 浏览器打开 Web 端 → ⚙ → Backup 配置 Cloudflare R2"
echo "             （backup-config.key 位于 $ETC_DIR，请勿删除）"
echo "--------------------------------------------------------------"
echo " 常用命令（在 $REPO_DIR/server 下执行）："
echo "   查看日志 : $COMPOSE logs -f"
echo "   重启服务 : $COMPOSE restart"
echo "   停止服务 : $COMPOSE down"
echo " 更新版本  : 重新执行本安装命令即可（保留 Token 与数据）"
echo "=============================================================="
