# 本地开发服务器：编译并前台运行 obsync（Ctrl+C 停止）
# 用法：.\scripts\dev-server.ps1  [-Listen 127.0.0.1:8080] [-DataDir D:\dev\obsidian\obsync-data]
param(
    [string]$Listen = "127.0.0.1:8080",
    [string]$DataDir = "D:\dev\obsidian\obsync-data",
    [string]$Token = "litesync-dev-token-0123456789abcdef"
)
$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent

Push-Location (Join-Path $repo "server")
try {
    go build -o obsync.exe ./cmd/obsync
    $env:OBSYNC_TOKEN = $Token
    $env:OBSYNC_LISTEN = $Listen
    $env:OBSYNC_DATA_DIR = $DataDir
    $env:OBSYNC_LOG_LEVEL = "debug"
    Write-Host "obsync dev server -> http://$Listen   data: $DataDir" -ForegroundColor Green
    Write-Host "API Token: $Token" -ForegroundColor Green
    .\obsync.exe
}
finally {
    Pop-Location
}
