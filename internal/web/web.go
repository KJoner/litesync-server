// Package web 内嵌 Web 只读端的静态构建产物。
// dist/ 由仓库根目录 web/ 构建（npm run build），产物提交进仓库，
// 因此服务器构建与部署无需 Node 环境。
package web

import "embed"

//go:embed all:dist
var Dist embed.FS
