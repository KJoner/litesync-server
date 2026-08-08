package api

import (
	"net/http"
	"strconv"
)

type apiChange struct {
	Sequence int64  `json:"sequence"`
	Path     string `json:"path"`
	Action   string `json:"action"`
	Revision int64  `json:"revision"`
	Hash     string `json:"hash,omitempty"`
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
			Sequence: c.Sequence,
			Path:     c.Path,
			Action:   c.Action,
			Revision: c.Revision,
			Hash:     c.ContentHash,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"latestSequence": res.LatestSequence,
		"hasMore":        res.HasMore,
		"changes":        out,
	})
}
