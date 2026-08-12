package api

// 元数据 Header 的格式与长度限制（v0.12.1 / LS-121-S04）。
//
// 之前这些 Header 只依赖 net/http 的「所有 Header 合计上限」做保护：
// 单个 8 KiB 的 X-Meta-Enc 与 64 KiB 的 X-Canonical-Hash 都能通过，
// 一路带进 SQLite 行、changes 日志和响应头。上限必须显式声明在协议层，
// 而不是碰巧由 HTTP Server 的实现细节兜住。

const (
	// maxMetaEncHeader：LSM1 加密元数据（base64）。正常几百字节，留足扩展余量。
	maxMetaEncHeader = 8 << 10
	// fileIDHexLen：稳定文件身份 = 16 字节 hex。
	fileIDHexLen = 32
	// canonicalHashHexLen：canonical path HMAC = SHA-256 hex。
	canonicalHashHexLen = 64
	// maxKeyEpoch：信封头是 u32，keyEpoch ∈ [1, 2^32)。
	maxKeyEpoch = uint64(1)<<32 - 1
	// maxGeneration：JS 客户端只能精确比较到 2^53-1，超出即无法可靠做抗回退判断。
	maxGeneration = uint64(1)<<53 - 1
)

func isLowerHexOfLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// isBase64Header：标准 base64 字符集（含 padding），不含空白与控制字符。
func isBase64Header(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '+' || r == '/' || r == '=':
		default:
			return false
		}
	}
	return true
}

// validateMetaHeaders 校验上传请求中的元数据类 Header。
// 返回非空字符串表示哪一个 Header 非法（调用方回 400 INVALID_HEADER）。
//
// 空值一律视为「未携带」而放行——是否必需由业务状态机（meta 模式建档必带）决定。
func validateMetaHeaders(h headerGetter) string {
	if v := h.Get("X-File-Id"); v != "" && !isLowerHexOfLen(v, fileIDHexLen) {
		return "X-File-Id"
	}
	if v := h.Get("X-Canonical-Hash"); v != "" && !isLowerHexOfLen(v, canonicalHashHexLen) {
		return "X-Canonical-Hash"
	}
	if v := h.Get("X-Meta-Enc"); v != "" && (len(v) > maxMetaEncHeader || !isBase64Header(v)) {
		return "X-Meta-Enc"
	}
	if v := h.Get("X-Key-Epoch"); v != "" && !isBoundedUint(v, 1, maxKeyEpoch) {
		return "X-Key-Epoch"
	}
	if v := h.Get("X-Content-Generation"); v != "" && !isBoundedUint(v, 0, maxGeneration) {
		return "X-Content-Generation"
	}
	if v := h.Get("X-Meta-Generation"); v != "" && !isBoundedUint(v, 0, maxGeneration) {
		return "X-Meta-Generation"
	}
	return ""
}

type headerGetter interface{ Get(string) string }

// isBoundedUint：十进制无符号整数且落在 [min, max]（不接受符号、前后空白、超长串）。
func isBoundedUint(s string, minValue, maxValue uint64) bool {
	if s == "" || len(s) > 20 {
		return false
	}
	var v uint64
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
		d := uint64(r - '0')
		if v > (^uint64(0)-d)/10 {
			return false // 溢出
		}
		v = v*10 + d
	}
	return v >= minValue && v <= maxValue
}
