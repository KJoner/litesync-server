package api

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"time"

	syncsvc "github.com/KJoner/litesync-server/internal/sync"
	"github.com/KJoner/litesync-server/internal/web"
)

// 一次性加密配对包（v8 新设备接入）。
// 安全模型与文件分享一致：服务器只代存密文；解密密钥（pairSecret）只存在于
// 配对链接的 #fragment 中，浏览器不会把 fragment 发给服务器。
// 配对包默认 5 分钟过期、消费即删；创建/撤销需要根 Token，消费公开
//（新设备此时还没有 Token——id 为 128-bit 随机值，且拿到密文仍需 secret 解密）。

// 配对密文大小上限：配置包只有几百字节，8KB 足够宽裕。
const maxPairingSize = 8 << 10

// createPairing POST /api/v1/pairing  Body {"ciphertext":"...","ttlSeconds":300}
func (h *handlers) createPairing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ciphertext string `json:"ciphertext"`
		TTLSeconds int    `json:"ttlSeconds"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxPairingSize+1024)).Decode(&req); err != nil ||
		req.Ciphertext == "" || len(req.Ciphertext) > maxPairingSize {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	id, expiresAt, err := h.svc.CreatePairing(req.Ciphertext, time.Duration(req.TTLSeconds)*time.Second)
	if err != nil {
		h.internalError(w, "pairing create", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "expiresAt": expiresAt})
}

// consumePairing POST /pair/{id}/consume（公开，一次性）
func (h *handlers) consumePairing(w http.ResponseWriter, r *http.Request) {
	ciphertext, err := h.svc.ConsumePairing(r.PathValue("id"))
	if err != nil {
		if errors.Is(err, syncsvc.ErrPairingNotFound) {
			writeErr(w, http.StatusNotFound, "pairing not found, expired, or already used")
			return
		}
		h.internalError(w, "pairing consume", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ciphertext": ciphertext})
}

// deletePairing DELETE /api/v1/pairing/{id}（配对窗口关闭时撤销）
func (h *handlers) deletePairing(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DeletePairing(r.PathValue("id")); err != nil {
		h.internalError(w, "pairing delete", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// pairLanding GET /p/{id}：扫码落地页（公开静态页；id 与 secret 由页面脚本
// 从 location 中读取后拼成 obsidian:// 链接，不经过服务器）。
func (h *handlers) pairLanding(w http.ResponseWriter, _ *http.Request) {
	raw, err := fs.ReadFile(web.Dist, "dist/pair.html")
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(raw) //nolint:errcheck
}
