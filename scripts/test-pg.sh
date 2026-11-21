#!/usr/bin/env bash
# 在 PostgreSQL 上跑同一套测试（批次 G：同一套测试在 SQLite 与 PG 上各跑一遍）。
#
# 用法：
#   LITESYNC_TEST_PG_ADMIN_DSN='postgres://user:pass@127.0.0.1:5432/postgres?sslmode=disable' \
#     scripts/test-pg.sh [go test 参数，默认 ./...]
#
# - 为本次运行新建一个独立数据库（C 排序，与 SQLite 的字节序比较一致），跑完无论成败都删除；
# - 每个测试在这个库里再用独立 schema（db.Open 的测试重定向按文件路径分配），互不干扰；
# - 可选 LITESYNC_TEST_PG_RESTORE_DSN：第二个 PG 实例，恢复演练把它当作「全新实例」。
# 需要 psql 与一个有 CREATEDB 权限的账号。
set -euo pipefail

admin="${LITESYNC_TEST_PG_ADMIN_DSN:?请设置 LITESYNC_TEST_PG_ADMIN_DSN（有 CREATEDB 权限的连接串）}"
name="litesync_test_$(date +%s)_$$"

psql "$admin" -v ON_ERROR_STOP=1 -q -c \
  "CREATE DATABASE $name TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'"
cleanup() { psql "$admin" -q -c "DROP DATABASE IF EXISTS $name WITH (FORCE)" >/dev/null || true; }
trap cleanup EXIT

# 把连接串里的库名换成本次运行的库（保留主机、账号与查询参数）
dsn="$(printf '%s' "$admin" | sed -E "s#^(postgres(ql)?://[^/?]+)(/[^?]*)?#\1/$name#")"

if [ "$#" -eq 0 ]; then set -- ./...; fi
LITESYNC_TEST_PG_DSN="$dsn" go test -count=1 "$@"
