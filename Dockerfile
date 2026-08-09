# 构建阶段
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/obsync ./cmd/obsync

# 运行阶段：二进制 + CA 证书 + restic（备份用，仅在备份任务运行时 fork，无常驻内存开销）
FROM alpine:3.22
RUN apk add --no-cache ca-certificates restic
COPY --from=build /out/obsync /usr/local/bin/obsync

ENV OBSYNC_LISTEN=:8080 \
    OBSYNC_DATA_DIR=/data \
    OBSYNC_BACKUP_KEY_FILE=/etc/litesync/backup-config.key

VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["obsync"]
