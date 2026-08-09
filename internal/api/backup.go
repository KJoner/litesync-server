package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"obsync/internal/backup"
)

// 备份管理接口（v6）：全部挂在 /api/v1/admin/* 下，
// 需要根 Token 或短期 Admin 会话（authGate 强制），只读 Web 会话一律 403。
//
// 安全红线：GET config 永远不返回任何 Secret；
// PUT config 中 Secret 字段留空表示保持原值。

func (h *handlers) backupManager(w http.ResponseWriter) *backup.Manager {
	if h.opts.Backup == nil {
		writeErr(w, http.StatusServiceUnavailable, "backup is not available on this server")
		return nil
	}
	return h.opts.Backup
}

// GET /api/v1/admin/backup/status
func (h *handlers) backupStatus(w http.ResponseWriter, _ *http.Request) {
	m := h.backupManager(w)
	if m == nil {
		return
	}
	writeJSON(w, http.StatusOK, m.Status())
}

// GET /api/v1/admin/backup/config
func (h *handlers) backupGetConfig(w http.ResponseWriter, _ *http.Request) {
	m := h.backupManager(w)
	if m == nil {
		return
	}
	writeJSON(w, http.StatusOK, m.GetConfig())
}

// PUT /api/v1/admin/backup/config
func (h *handlers) backupPutConfig(w http.ResponseWriter, r *http.Request) {
	m := h.backupManager(w)
	if m == nil {
		return
	}
	var u backup.Update
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&u); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	view, err := m.SetConfig(u)
	if err != nil {
		if errors.Is(err, backup.ErrKeyUnavailable) {
			writeErr(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// POST /api/v1/admin/backup/test
// 连接测试结果始终以 200 返回（ok/initialized/error），方便前端展示。
func (h *handlers) backupTest(w http.ResponseWriter, r *http.Request) {
	m := h.backupManager(w)
	if m == nil {
		return
	}
	err := m.Test(r.Context())
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "initialized": true})
	case errors.Is(err, backup.ErrRepoNotInitialized):
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "initialized": false})
	case errors.Is(err, backup.ErrNotConfigured), errors.Is(err, backup.ErrKeyUnavailable):
		writeErr(w, http.StatusBadRequest, err.Error())
	default:
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
	}
}

// POST /api/v1/admin/backup/init
func (h *handlers) backupInit(w http.ResponseWriter, r *http.Request) {
	m := h.backupManager(w)
	if m == nil {
		return
	}
	if err := m.Initialize(r.Context()); err != nil {
		if errors.Is(err, backup.ErrJobRunning) {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"initialized": true})
}

// POST /api/v1/admin/backup/run
// 备份可能持续数分钟，异步执行；进度通过 status 轮询。
func (h *handlers) backupRun(w http.ResponseWriter, _ *http.Request) {
	m := h.backupManager(w)
	if m == nil {
		return
	}
	if m.Status().Running {
		writeErr(w, http.StatusConflict, "a backup job is already running")
		return
	}
	go func() {
		if _, err := m.Backup(context.Background(), "manual"); err != nil {
			h.opts.Logger.Warn("manual backup failed", "error", err)
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

// POST /api/v1/admin/backup/check
func (h *handlers) backupCheck(w http.ResponseWriter, _ *http.Request) {
	m := h.backupManager(w)
	if m == nil {
		return
	}
	if m.Status().Running {
		writeErr(w, http.StatusConflict, "a backup job is already running")
		return
	}
	go func() {
		if err := m.Check(context.Background()); err != nil {
			h.opts.Logger.Warn("backup check failed", "error", err)
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

// GET /api/v1/admin/backup/snapshots
func (h *handlers) backupSnapshots(w http.ResponseWriter, r *http.Request) {
	m := h.backupManager(w)
	if m == nil {
		return
	}
	snaps, err := m.ListSnapshots(r.Context())
	if err != nil {
		if errors.Is(err, backup.ErrRepoNotInitialized) {
			writeJSON(w, http.StatusOK, map[string]any{"snapshots": []backup.Snapshot{}, "initialized": false})
			return
		}
		if errors.Is(err, backup.ErrNotConfigured) || errors.Is(err, backup.ErrKeyUnavailable) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if snaps == nil {
		snaps = []backup.Snapshot{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshots": snaps, "initialized": true})
}
