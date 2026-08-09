package backup

// Status 备份状态（持久化于 vault_meta key = backup-status，明文 JSON，不含任何 Secret）。
type Status struct {
	// 运行环境
	KeyAvailable bool   `json:"keyAvailable"` // backup-config.key 是否可用
	KeyError     string `json:"keyError,omitempty"`
	ResticOK     bool   `json:"resticOk"` // restic 二进制是否可执行
	ResticVersion string `json:"resticVersion,omitempty"`

	// 配置概览
	Enabled    bool `json:"enabled"`
	Configured bool `json:"configured"`

	// 当前任务
	Running   bool   `json:"running"`
	RunningOp string `json:"runningOp,omitempty"` // backup / prune / check / ...

	// 上次备份
	LastStartedAt   int64  `json:"lastStartedAt,omitempty"` // Unix 秒
	LastCompletedAt int64  `json:"lastCompletedAt,omitempty"`
	LastDurationMs  int64  `json:"lastDurationMs,omitempty"`
	LastSnapshotID  string `json:"lastSnapshotId,omitempty"`
	LastError       string `json:"lastError,omitempty"`

	// 计划任务
	NextRunAt    int64 `json:"nextRunAt,omitempty"`
	LastForgetAt int64 `json:"lastForgetAt,omitempty"`
	LastPruneAt  int64 `json:"lastPruneAt,omitempty"`
	LastCheckAt  int64 `json:"lastCheckAt,omitempty"`

	// 仓库统计（best-effort，备份成功后刷新）
	RepositorySize int64 `json:"repositorySize,omitempty"` // 去重后原始字节（估算值）
	SnapshotCount  int   `json:"snapshotCount,omitempty"`
	BudgetBytes    int64 `json:"budgetBytes,omitempty"`
}

// BackupResult 单次备份的结果。
type BackupResult struct {
	SnapshotID string `json:"snapshotId"`
	DurationMs int64  `json:"durationMs"`
	FilesNew   int64  `json:"filesNew"`
	FilesChanged int64 `json:"filesChanged"`
	DataAdded  int64  `json:"dataAdded"`
}

// Snapshot 是 restic snapshots --json 的精简条目。
type Snapshot struct {
	ID      string   `json:"id"`
	ShortID string   `json:"short_id"`
	Time    string   `json:"time"`
	Paths   []string `json:"paths"`
	Tags    []string `json:"tags"`
}
