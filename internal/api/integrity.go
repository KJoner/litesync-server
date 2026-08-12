package api

import (
	"net/http"
	"time"
)

// 完整性运维接口（v0.13.3 / 计划书 §7.2、§7.8 的 `integrity scan`）。
//
// 都挂在 /api/v1/admin 下，因此走 ADMIN capability——只读会话触碰一律 403。

// integrityScan 触发一次完整性 scrub。
// GET /api/v1/admin/integrity/scan?full=1
//
// full=1 时对每个 blob 全量重算 hash（能抓位腐坏，但要把所有内容读一遍）；
// 默认只校验存在性与尺寸。
//
// 同步执行：scrub 会持服务锁，异步跑反而更难解释「现在到底扫完没有」。
// 大仓库上这个请求会比较慢，运维接口不做超时优化。
func (h *handlers) integrityScan(w http.ResponseWriter, r *http.Request) {
	full := r.URL.Query().Get("full") == "1" || r.URL.Query().Get("full") == "true"
	rep, err := h.svc.Scrub(full)
	if err != nil {
		h.internalError(w, "integrity scan", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dbCheck":         rep.DBCheck,
		"headsChecked":    rep.HeadsChecked,
		"versionsChecked": rep.VersionsChecked,
		"sharesChecked":   rep.SharesChecked,
		"issues":          rep.Issues,
		"unservable":      rep.Unservable,
		"full":            full,
		// details 只含 blob hash 与分类，不含任何用户路径（§7.7）
		"details": rep.Details,
	})
}

// integrityEvents 列出完整性事件账本。
// GET /api/v1/admin/integrity/events?all=1
func (h *handlers) integrityEvents(w http.ResponseWriter, r *http.Request) {
	all := r.URL.Query().Get("all") == "1" || r.URL.Query().Get("all") == "true"
	events, err := h.svc.IntegrityEvents(!all)
	if err != nil {
		h.internalError(w, "integrity events", err)
		return
	}
	out := make([]map[string]any, 0, len(events))
	for i := range events {
		e := &events[i]
		out = append(out, map[string]any{
			"blobId":       e.BlobID,
			"kind":         e.Kind,
			"detail":       e.Detail,
			"detectedAt":   e.DetectedAt,
			"serving":      e.Serving,
			"resolved":     e.Resolved,
			"affectedRefs": e.AffectedRefs,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}

// integrityPurgeQuarantine 按独立保留期清理隔离区（§7.3）。
// POST /api/v1/admin/integrity/purge-quarantine
//
// 保留期为 0（默认）时什么都不做——隔离区里是取证材料，不能因为跑了一次
// 清理接口就消失。要真正删除必须先配置 OBSYNC_QUARANTINE_DAYS。
func (h *handlers) integrityPurgeQuarantine(w http.ResponseWriter, _ *http.Request) {
	n, err := h.svc.PurgeQuarantine(time.Now())
	if err != nil {
		h.internalError(w, "purge quarantine", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"purged": n})
}
