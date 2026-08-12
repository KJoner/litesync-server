package api

import (
	"net/http"
	"strconv"
)

type apiChange struct {
	Sequence int64 `json:"sequence"`
	// Path 是服务器可见的寻址名（plain=真实路径，encrypted=fileId）
	Path string `json:"path"`
	// FileID 是稳定身份（协议 v6）：客户端据此对账，不再依赖 path
	FileID   string `json:"fileId"`
	Action   string `json:"action"`
	Revision int64  `json:"revision"`
	Hash     string `json:"hash,omitempty"`
	// ContentGeneration：LSE3 抗回退比较用
	ContentGeneration int64 `json:"contentGeneration,omitempty"`
	// MetaGeneration：hash 未变但世代变新 = 仅改名，客户端做本地 rename 而不是下载
	MetaGeneration int64 `json:"metaGeneration,omitempty"`
}

// changes 返回 since 之后的增量变更。
// GET /api/v1/changes?since=123&limit=500
func (h *handlers) changes(w http.ResponseWriter, r *http.Request) {
	since := int64(0)
	if v := r.URL.Query().Get("since"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "invalid since")
			return
		}
		since = n
	}
	limit := int64(500)
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			writeErr(w, http.StatusBadRequest, "invalid limit")
			return
		}
		limit = min(n, 2000)
	}

	res, err := h.svc.Changes(since, limit)
	if err != nil {
		h.internalError(w, "changes", err)
		return
	}
	if res.ResyncRequired {
		// 客户端游标早于已裁剪的水位线：必须走 snapshot 全量对账重建游标
		writeJSON(w, http.StatusOK, map[string]any{
			"repoEpoch":      res.RepoEpoch,
			"formatEpoch":    res.FormatEpoch,
			"headSequence":   res.LatestSequence,
			"latestSequence": res.LatestSequence,
			"resyncRequired": true,
			"minSequence":    res.MinSequence,
			"hasMore":        false,
			"changes":        []apiChange{},
		})
		return
	}
	out := make([]apiChange, 0, len(res.Changes))
	for _, c := range res.Changes {
		out = append(out, apiChange{
			Sequence:          c.Sequence,
			Path:              c.Pseudonym,
			FileID:            c.FileID,
			Action:            c.Action,
			Revision:          c.Revision,
			Hash:              c.ContentHash,
			ContentGeneration: c.ContentGeneration,
			MetaGeneration:    c.MetaGeneration,
		})
	}
	// 记录该设备已确认到的 sequence：tombstone 清理的第二个条件（ADR-002 §3.4）
	if id := auditDeviceID(r); id != "" && since > 0 {
		h.svc.AckSequence(id, since) //nolint:errcheck
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"repoEpoch":      res.RepoEpoch,
		"formatEpoch":    res.FormatEpoch,
		"headSequence":   res.LatestSequence,
		"latestSequence": res.LatestSequence,
		"hasMore":        res.HasMore,
		"changes":        out,
	})
}
