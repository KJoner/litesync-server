package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/KJoner/litesync-server/internal/db"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// 签名 checkpoint 接口（v0.15.0 / 计划书 §9）。
//
// 服务器在这里只是个公告板：存下设备签名的状态快照，并原样转发。
// 它既不验证签名，也不在分叉时替用户做选择——那两件事只要交给服务器，
// 整套 freshness 机制就退回到「相信服务器」。

// publishCheckpoint 发布一个签名 checkpoint。
// POST /api/v1/checkpoint
func (h *handlers) publishCheckpoint(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hash         string `json:"hash"`
		RepoEpoch    string `json:"repoEpoch"`
		HeadSequence int64  `json:"headSequence"`
		PreviousHash string `json:"previousHash"`
		Body         string `json:"body"`
		Signature    string `json:"signature"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&req); err != nil {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "invalid request body", false)
		return
	}
	err := h.svc.PublishCheckpoint(syncsvc.PublishCheckpointParams{
		Hash:         req.Hash,
		RepoEpoch:    req.RepoEpoch,
		HeadSequence: req.HeadSequence,
		PreviousHash: req.PreviousHash,
		DeviceID:     auditDeviceID(r),
		Body:         req.Body,
		Signature:    req.Signature,
	})
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"hash": req.Hash})
	case errors.Is(err, syncsvc.ErrCheckpointRevokedDevice):
		writeCoded(w, http.StatusForbidden, CodeCheckpointRejected,
			"revoked devices cannot publish checkpoints", false)
	case errors.Is(err, syncsvc.ErrCheckpointNoSigningKey):
		writeCoded(w, http.StatusForbidden, CodeCheckpointRejected,
			"device has no registered signing key", false)
	case errors.Is(err, syncsvc.ErrCheckpointEpochMismatch):
		writeCoded(w, http.StatusConflict, CodeRepoEpochMismatch, "repo epoch mismatch", false)
	case errors.Is(err, syncsvc.ErrCheckpointInvalid):
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "invalid checkpoint", false)
	default:
		h.internalError(w, "publish checkpoint", err)
	}
}

// getCheckpoints 拉取游标之后的 checkpoint 链。
// GET /api/v1/checkpoints?since=<headSequence>
func (h *handlers) getCheckpoints(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	bundle, err := h.svc.Checkpoints(since, 200)
	if err != nil {
		h.internalError(w, "checkpoints", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"repoEpoch":   bundle.RepoEpoch,
		"checkpoints": apiCheckpoints(bundle.Checkpoints),
		// conflicting 非空即分叉证据：服务器如实交出去，由客户端停机并展示。
		// 悄悄丢掉其中一份才是最糟的做法——那会让 equivocation 变得不可见
		"conflicting":    apiCheckpoints(bundle.Conflicting),
		"signingKeys":    bundle.SigningKeys,
		"revokedDevices": bundle.RevokedDevices,
	})
}

// registerSigningKey 登记本设备的 checkpoint 签名公钥。
// PUT /api/v1/device/signing-key   Body: {"publicKey": "<base64 SPKI>"}
func (h *handlers) registerSigningKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req); err != nil {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "invalid request body", false)
		return
	}
	deviceID := auditDeviceID(r)
	if deviceID == "" {
		// 根 Token 没有设备身份：签名密钥是**设备**的属性，无处安放
		writeCoded(w, http.StatusForbidden, CodeCheckpointRejected,
			"signing keys belong to devices; use a device credential", false)
		return
	}
	if err := h.svc.RegisterSigningKey(deviceID, req.PublicKey); err != nil {
		if errors.Is(err, syncsvc.ErrCheckpointInvalid) {
			writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "invalid public key", false)
			return
		}
		h.internalError(w, "register signing key", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func apiCheckpoints(list []db.Checkpoint) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for i := range list {
		c := &list[i]
		out = append(out, map[string]any{
			"hash":            c.Hash,
			"repoEpoch":       c.RepoEpoch,
			"headSequence":    c.HeadSequence,
			"previousHash":    c.PreviousHash,
			"signingDeviceId": c.SigningDeviceID,
			"body":            c.Body,
			"signature":       c.Signature,
			"createdAt":       c.CreatedAt,
		})
	}
	return out
}
