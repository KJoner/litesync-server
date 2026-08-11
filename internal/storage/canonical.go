package storage

import (
	"strings"

	"golang.org/x/text/unicode/norm"
)

// CanonicalKey 返回跨平台归一化后的路径（NFC 规范化 + 小写折叠）。
// Linux 服务器允许 "Note.md" 与 "note.md" 并存，但它们在默认的
// Windows（大小写不敏感）与 macOS（NFD + 大小写不敏感）文件系统上会映射为
// 同一个文件——同步下去必然互相覆盖。上传时用该 key 拒绝并存冲突路径。
func CanonicalKey(p string) string {
	return strings.ToLower(norm.NFC.String(p))
}
