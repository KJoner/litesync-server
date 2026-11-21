package api

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
	syncsvc "github.com/KJoner/litesync-server/internal/sync"
)

// 配额与限流（v0.20 / 需求 §12、接口约定 §错误码）。
//
// 两类错误必须分得开（「不让客户端无限重试」）：
//   - QUOTA_EXCEEDED：永久性超限（存储、仓库数），retryable=false，details 给出种类 / 上限 / 已用；
//     存储超限用 413——0.19/0.20 插件对 413 的既有处理是「跳过这个文件、继续同步其他」，
//     不会形成重试风暴；
//   - RATE_LIMITED：临时限流（请求速率、上传并发），429 + Retry-After，retryable=true。

// CodeQuotaExceeded 永久性配额超限。
const CodeQuotaExceeded = "QUOTA_EXCEEDED"

func writeQuotaExceeded(w http.ResponseWriter, status int, e *syncsvc.QuotaExceededError, msg string) {
	writeCodedDetails(w, status, CodeQuotaExceeded, msg, false, map[string]any{
		"kind": e.Kind, "limit": e.Limit, "used": e.Used,
	})
}

func writeRateLimited(w http.ResponseWriter, wait time.Duration, kind string) {
	secs := int(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeCodedDetails(w, http.StatusTooManyRequests, CodeRateLimited, "too many requests; retry later", true,
		map[string]any{"kind": kind, "retryAfterSeconds": secs})
}

// identityLimiter 按身份（账号 / 设备）的令牌桶限流 + 上传并发计数。
type identityLimiter struct {
	mu         sync.Mutex
	rate       float64 // 每秒补充的令牌
	burst      float64
	buckets    map[string]*tokenBucket
	maxUploads int
	uploads    map[string]int
	lastSweep  time.Time
	now        func() time.Time
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// newIdentityLimiter perMin=0 关闭限流；maxUploads=0 不限上传并发。突发容量 = 每分钟额度的 1/6（至少 60）。
func newIdentityLimiter(perMin, maxUploads int) *identityLimiter {
	l := &identityLimiter{buckets: map[string]*tokenBucket{}, uploads: map[string]int{}, maxUploads: maxUploads, now: time.Now}
	if perMin > 0 {
		l.rate = float64(perMin) / 60
		l.burst = math.Max(60, float64(perMin)/6)
	}
	return l
}

// allow 消耗一个令牌；不够时返回需要等待的时长。
func (l *identityLimiter) allow(key string) (bool, time.Duration) {
	if l == nil || l.rate <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.buckets[key]
	if b == nil {
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	l.sweep(now)
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
}

// sweep 定期清掉已经回满、长时间不活动的桶（调用方持锁）。
func (l *identityLimiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < time.Minute {
		return
	}
	l.lastSweep = now
	for k, b := range l.buckets {
		if now.Sub(b.last) > 10*time.Minute {
			delete(l.buckets, k)
		}
	}
}

// acquireUpload 占一个上传并发槽；返回释放函数。
func (l *identityLimiter) acquireUpload(key string) (func(), bool) {
	if l == nil || l.maxUploads <= 0 {
		return func() {}, true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.uploads[key] >= l.maxUploads {
		return nil, false
	}
	l.uploads[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			if l.uploads[key]--; l.uploads[key] <= 0 {
				delete(l.uploads, key)
			}
		})
	}, true
}

// rateKey 账号身份按账号计（同一账号的网页会话与用户 Token 共用额度），设备按设备计。
func rateKey(id *authIdentity) string {
	switch {
	case id.UserID != "":
		return "u:" + id.UserID
	case id.DeviceID != "":
		return "d:" + id.DeviceID
	default:
		return "anon"
	}
}

// rateGate 位于 authGate 之后：只对已认证的 /api 请求生效（公开端点有各自的按 IP 限流）。
func rateGate(h *handlers, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := identityFrom(r)
		if id == nil {
			next.ServeHTTP(w, r)
			return
		}
		key := rateKey(id)
		if ok, wait := h.limiter.allow(key); !ok {
			writeRateLimited(w, wait, "rate")
			return
		}
		if r.Method == http.MethodPut && r.URL.Path == "/api/v1/file" {
			release, ok := h.limiter.acquireUpload(key)
			if !ok {
				writeRateLimited(w, time.Second, "concurrency")
				return
			}
			defer release()
		}
		next.ServeHTTP(w, r)
	})
}

// writeVaultLimit 仓库数达到上限：409 QUOTA_EXCEEDED（与「同名仓库」的 409 CONFLICT 分开，
// 界面据此给出「删除不用的仓库或联系管理员」而不是「换个名字」）。
func (h *handlers) writeVaultLimit(w http.ResponseWriter, userID string) {
	u, err := h.svc.UserUsage(userID)
	if err != nil {
		writeCoded(w, http.StatusConflict, CodeQuotaExceeded, "已达到仓库数量上限", false)
		return
	}
	writeCodedDetails(w, http.StatusConflict, CodeQuotaExceeded, "已达到仓库数量上限（"+strconv.FormatInt(u.VaultsLimit, 10)+" 个）", false,
		map[string]any{"kind": "vaults", "limit": u.VaultsLimit, "used": u.Vaults})
}

// usageJSON 账号页 / 管理员列表共用的用量结构（limit 0 = 不限）。
func usageJSON(u syncsvc.Usage) map[string]any {
	return map[string]any{
		"bytesUsed": u.BytesUsed, "bytesLimit": u.BytesLimit,
		"vaults": u.Vaults, "vaultsLimit": u.VaultsLimit,
		"overrideBytes": u.OverrideBytes, "overrideVaults": u.OverrideVaults,
	}
}

// adminSetQuota 管理员设置某个账号的配额覆盖值（需求 §5：管理员可管理账号状态、配额）。
// PUT /api/v1/admin/users/{userId}/quota  {bytes, vaults}：0 = 跟随服务器默认，-1 = 不限，>0 = 指定值。
func (h *handlers) adminSetQuota(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userId")
	var req struct {
		Bytes  int64 `json:"bytes"`
		Vaults int64 `json:"vaults"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.Bytes < -1 || req.Vaults < -1 {
		writeCoded(w, http.StatusBadRequest, CodeInvalidBody, "bytes / vaults must be -1 (unlimited), 0 (server default) or a positive number", false)
		return
	}
	if err := h.svc.SetUserQuota(userID, req.Bytes, req.Vaults); err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			writeCoded(w, http.StatusNotFound, CodeNotFound, "user not found", false)
			return
		}
		h.internalError(w, "admin set quota", err)
		return
	}
	u, err := h.svc.UserUsage(userID)
	if err != nil {
		h.internalError(w, "admin set quota usage", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"userId": userID, "usage": usageJSON(u)})
}
