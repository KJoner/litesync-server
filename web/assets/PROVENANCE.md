# 网页端静态素材来源

| 文件 | 用途 | 来源与处理 |
| --- | --- | --- |
| `auth-art.webp` | 欢迎页左侧的装饰背景（只在宽屏加载；手机不下载） | 设计包 `litesync-nexus-ui-v2/prototype/assets/auth-art.png`（1122×1402，sha256 `59020c17542c9e6279d899bd35066b255b05921ebb7af14cc6ae334555b0cd3f`，无文字、无 logo 的生成素材），用 Pillow 转为 WebP（quality 85，尺寸不变）；本文件 sha256 `fe70b55d4deeeec774b0f5eecadd6bbb535fde82c9dd2c10255a14b34da41d2b` |

素材只做装饰：页面上的文字都由 HTML 渲染；图里没有任何真实笔记、邮箱或仓库名。
`web/build.mjs` 把本目录的图片原样复制到 `internal/web/dist/assets/`（由服务端同源提供，CSP 的 `img-src 'self'` 即可）。
