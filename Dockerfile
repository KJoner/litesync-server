# 构建阶段
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/obsync ./cmd/obsync

# 运行阶段：仅包含二进制和 CA 证书，镜像保持轻量
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/obsync /usr/local/bin/obsync

ENV OBSYNC_LISTEN=:8080 \
    OBSYNC_DATA_DIR=/data

VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["obsync"]
