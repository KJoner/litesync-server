package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// 管理 UI 的后端接口（v0.17 / 计划书 §11.3）。
//
// §11.3 列的五件事——设备撤销、migration 状态、integrity alert、backup restore、
// 分享恢复——的共同点是：**出事的时候才会用到**。
//
// 这类功能最常见的失败不是写错了，而是「只能 SSH 上服务器敲命令」。
// 事故当天，能不能在手机上撤销一台丢失的设备，和这个功能写没写得优雅相比，
// 是完全不同量级的问题。
//
// 全部挂在 /api/v1/admin/ 下：根 Token 或短期 admin 会话，普通同步设备一律拒绝。

// adminDevices 列出全部设备（含已撤销）。
// GET /api/v1/admin/devices
//
// 已撤销的也要列出来：撤销之后最该被回答的问题是「它是什么时候被撤销的、
// 撤销之前最后一次活动是什么时候」，把行删掉就永远答不了了。
func (h *handlers) adminDevices(w http.ResponseWriter, _ *http.Request) {
	devices, err := h.svc.ListDevices()
	if err != nil {
		h.internalError(w, "admin devices", err)
		return
	}
	out := make([]map[string]any, 0, len(devices))
	for i := range devices {
		d := &devices[i]
		out = append(out, map[string]any{
			"id":            d.DeviceID,
			"name":          d.Name,
			"scopes":        strings.Split(d.Scopes, ","),
			"createdAt":     d.CreatedAt,
			"lastSeenAt":    d.LastSeenAt,
			"revoked":       d.Revoked,
			"hasSigningKey": d.SigningPublicKey != "",
			// §15 第 3 步：迁移前要能一眼看出哪台还没升级
			"clientVersion":  d.ClientVersion,
			"clientProtocol": d.ClientProtocol,
			// v0.17 运维页增强：丢设备那天要能一眼认出「哪台是那部手机、
			// 它最后从哪个网络连上来」
			"platform": d.Platform,
			"lastIp":   d.LastIP,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

// adminRevokeDevice 撤销一台设备。
// DELETE /api/v1/admin/devices/{id}
//
// 撤销立刻生效：长期凭据作废，它已经换出去的短期 access token 也一起失效
// （VerifyAccessToken 每次都回查设备状态）。丢设备时争的就是这几分钟。
func (h *handlers) adminRevokeDevice(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/devices/")
	if id == "" || strings.Contains(id, "/") {
		writeErr(w, http.StatusBadRequest, "missing device id")
		return
	}
	ok, err := h.svc.RevokeDevice(id)
	if err != nil {
		h.internalError(w, "admin revoke device", err)
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "device not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": id})
}

// adminMigrationStatus 汇总元数据迁移的当前状态。
// GET /api/v1/admin/migration/status
//
// 迁移是本项目里唯一一个「卡住了就必须有人介入」的长流程。
// 把租约持有者、截止 sequence 与 journal 进度放在一个地方，
// 是为了让「现在到底卡在哪」这个问题一眼能答。
func (h *handlers) adminMigrationStatus(w http.ResponseWriter, _ *http.Request) {
	st, err := h.svc.MigrationStatusOf()
	if err != nil {
		h.internalError(w, "admin migration status", err)
		return
	}
	blob, berr := h.svc.NeedsBlobIDMigration()
	if berr != nil {
		h.svc.Logf("admin: blobid migration check failed: %v", berr)
	}
	rewrap, rerr := h.svc.PendingRewrapEpoch()
	if rerr != nil {
		h.svc.Logf("admin: pending rewrap check failed: %v", rerr)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"meta":                 st,
		"needsBlobIdMigration": blob,
		"pendingRewrapEpoch":   rewrap,
	})
}

// adminShares 列出全部分享（含已撤销与已过期）。
// GET /api/v1/admin/shares
func (h *handlers) adminShares(w http.ResponseWriter, _ *http.Request) {
	shares, err := h.svc.ListShares()
	if err != nil {
		h.internalError(w, "admin shares", err)
		return
	}
	now := time.Now().Unix()
	out := make([]map[string]any, 0, len(shares))
	for i := range shares {
		s := &shares[i]
		expired := s.ExpiresAt > 0 && s.ExpiresAt <= now
		out = append(out, map[string]any{
			"id":        s.ID,
			"size":      s.Size,
			"createdAt": s.CreatedAt,
			"expiresAt": s.ExpiresAt,
			"revoked":   s.Revoked,
			"expired":   expired,
			// 密文是否还在：过期回收会删掉它，删掉之后「延长有效期」就没意义了
			"recoverable": !s.Revoked && h.svc.ShareCiphertextExists(s.ID),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"shares": out})
}

// adminRecoverShare 延长一个尚未被回收的分享的有效期。
// POST /api/v1/admin/shares/{id}/recover  Body: {"expiresAt": <unix>}
//
// 这不是「恢复已删除的分享」——密文一旦被回收就真的没了，服务器手上
// 没有任何能重建它的东西（分享的密钥从不上传）。能做的只是把一个
// **误设了过短有效期**的分享往后延。名字叫 recover 是因为用户视角就是恢复，
// 但响应里必须把这个区别说清楚，否则用户会以为被回收的也能救回来。
func (h *handlers) adminRecoverShare(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/shares/")
	id := strings.TrimSuffix(rest, "/recover")
	if id == "" || strings.Contains(id, "/") {
		writeErr(w, http.StatusBadRequest, "missing share id")
		return
	}
	var req struct {
		ExpiresAt int64 `json:"expiresAt"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}

	if req.ExpiresAt <= time.Now().Unix() {
		writeErr(w, http.StatusBadRequest, "expiresAt must be in the future")
		return
	}
	err := h.svc.ExtendShare(id, req.ExpiresAt)
	switch {
	case errors.Is(err, syncsvc.ErrShareGone):
		writeErr(w, http.StatusGone,
			"分享的密文已被回收，无法恢复：服务器不持有分享密钥，没有任何能重建它的材料。请重新创建分享")
	case errors.Is(err, syncsvc.ErrShareRevoked):
		writeErr(w, http.StatusConflict, "分享已被主动撤销，不能通过延长有效期恢复")
	case err != nil:
		h.internalError(w, "admin recover share", err)
	default:
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "expiresAt": req.ExpiresAt})
	}
}

// adminRevokeShare 撤销一个分享。
// DELETE /api/v1/admin/shares/{id}
//
// 撤销立刻生效并回收密文：分享链接落到不该看的人手里时，争的同样是这几分钟。
// 与「延长有效期」相反，这是一次明确的意图表达——撤销后不能再通过 recover 推翻。
func (h *handlers) adminRevokeShare(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/shares/")
	if id == "" || strings.Contains(id, "/") {
		writeErr(w, http.StatusBadRequest, "missing share id")
		return
	}
	err := h.svc.RevokeShare(id)
	switch {
	case errors.Is(err, syncsvc.ErrNotFound):
		writeErr(w, http.StatusNotFound, "share not found")
	case err != nil:
		h.internalError(w, "admin revoke share", err)
	default:
		writeJSON(w, http.StatusOK, map[string]any{"revoked": id})
	}
}

// adminRestorePlan 给出一次灾备恢复的预检结果与**准确的命令**。
// GET /api/v1/admin/backup/restore-plan?snapshot=<id>
//
// # 为什么恢复不是一个网页按钮
//
// 恢复会把整个数据目录换掉——而正在运行的这个进程恰恰把那些文件（sync.db、
// WAL、blob）打开着。在进程内部做这件事意味着先静默所有请求、关掉数据库、
// 换目录、再重新打开，中途任何一步失败都会留下一个既不是旧库也不是新库的
// 半成品。灾备流程本身出错是最糟的一类故障：它发生在你已经出过一次事之后。
//
// 所以这里只做能安全做的部分：核对快照存在、算出会失效的东西、
// 给出可以直接粘贴执行的命令。真正的切换在服务器停机后由 CLI 完成。
func (h *handlers) adminRestorePlan(w http.ResponseWriter, r *http.Request) {
	snapshot := r.URL.Query().Get("snapshot")
	if snapshot == "" {
		writeErr(w, http.StatusBadRequest, "missing snapshot")
		return
	}
	seq, err := h.svc.LatestSequence()
	if err != nil {
		h.internalError(w, "admin restore plan", err)
		return
	}
	devices, err := h.svc.ListDevices()
	if err != nil {
		h.internalError(w, "admin restore plan", err)
		return
	}
	active := 0
	for i := range devices {
		if !devices[i].Revoked {
			active++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"snapshot":        snapshot,
		"currentSequence": seq,
		"activeDevices":   active,
		"command":         "obsync backup restore " + snapshot,
		"consequences": []string{
			"数据目录会被快照内容整体替换；",
			"repoEpoch 会被旋转，所有客户端的游标与 baseRevision 随之作废；",
			"共 " + strconv.Itoa(active) + " 台在用设备下次同步时会进入灾备合并流程；",
			"服务器恢复出来的内容与客户端本地的内容都会保留，差异走冲突流程，不静默丢弃任何一方。",
		},
		"whyNotAButton": "恢复要替换正在运行的进程打开着的文件（sync.db / WAL / blob）。" +
			"在进程内做这件事，中途失败会留下既不是旧库也不是新库的半成品——" +
			"而这一步发生在你已经出过一次事之后。请停机后在服务器上执行上面的命令。",
	})
}

// adminPreflight 迁移前置检查（§15 第 3/6/7 步）。
// GET /api/v1/admin/migration/preflight?client=0.17.0
//
// 与 CLI 的 `obsync migration preflight` 是同一份逻辑。放到 Web 上是因为
// §15 的第 3 步要挨个核对设备，而那件事在浏览器里做比 SSH 上去做自然得多。
func (h *handlers) adminPreflight(w http.ResponseWriter, r *http.Request) {
	rep, err := h.svc.MigrationPreflight(r.URL.Query().Get("client"))
	if err != nil {
		h.internalError(w, "admin preflight", err)
		return
	}
	issues := make([]map[string]any, 0, len(rep.Issues))
	for i := range rep.Issues {
		issues = append(issues, map[string]any{
			"blocking": rep.Issues[i].Blocking,
			"code":     rep.Issues[i].Code,
			"detail":   rep.Issues[i].Detail,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"blocked":             rep.Blocked(),
		"activeDevices":       rep.ActiveDevices,
		"staleDevices":        rep.StaleDevices,
		"unknownVersion":      rep.UnknownVersion,
		"outdatedClient":      rep.OutdatedClient,
		"metaState":           rep.MetaState,
		"formatEpoch":         rep.FormatEpoch,
		"envelopeFloor":       rep.EnvelopeFloor,
		"latestSequence":      rep.LatestSequence,
		"plaintextTombstones": rep.PlaintextTombstones,
		"orphanVersions":      rep.OrphanVersions,
		"missingBlobs":        rep.MissingBlobs,
		"issues":              issues,
	})
}
