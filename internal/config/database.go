package config

import (
	"fmt"
	"os"
	"strings"
)

// Database 是元数据库的选择（批次 G / ADR-018 §2.1）。
//
//   - OBSYNC_DB = sqlite（默认）| postgres
//   - OBSYNC_PG_DSN：PostgreSQL 连接串，**只**从环境变量取；String() 与日志永不输出它。
//
// Blob（密文文件）始终在 OBSYNC_DATA_DIR 下，与选哪种元数据库无关。
type Database struct {
	Driver      string // "sqlite" | "postgres"
	PostgresDSN string
	// Warning 非空时由调用方记一条日志（例如设置了 DSN 却仍在用 SQLite——迁移/回退过程中
	// 这是合法状态，不拒绝启动，但要让管理员看得到「现在实际用的是哪个库」）。
	Warning string
}

// IsPostgres 报告是否使用 PostgreSQL。
func (d Database) IsPostgres() bool { return d.Driver == "postgres" }

// String 只给出方言，绝不包含 DSN（里面有口令）。
func (d Database) String() string { return d.Driver }

// LoadDatabase 解析数据库选择。半套配置（选了 postgres 却没给 DSN）直接报错。
func LoadDatabase() (Database, error) {
	drv := strings.ToLower(strings.TrimSpace(getenv("OBSYNC_DB", "sqlite")))
	dsn := strings.TrimSpace(os.Getenv("OBSYNC_PG_DSN"))
	switch drv {
	case "sqlite":
		d := Database{Driver: "sqlite"}
		if dsn != "" {
			d.Warning = "OBSYNC_PG_DSN is set but OBSYNC_DB is not 'postgres': using SQLite (data dir sync.db)"
		}
		return d, nil
	case "postgres", "postgresql", "pg":
		if dsn == "" {
			return Database{}, fmt.Errorf("OBSYNC_DB=postgres requires OBSYNC_PG_DSN (e.g. postgres://user:pass@host:5432/litesync?sslmode=require)")
		}
		return Database{Driver: "postgres", PostgresDSN: dsn}, nil
	default:
		return Database{}, fmt.Errorf("invalid OBSYNC_DB: %q (use sqlite/postgres)", drv)
	}
}
