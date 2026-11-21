package main

// 元数据库的打开入口（批次 G：OBSYNC_DB=sqlite|postgres）。服务与运维命令都从这里打开，
// 规则因此只有一份：选了 PG 就连 OBSYNC_PG_DSN；选了 SQLite 就用数据目录里的 sync.db，
// 并且拒绝使用「已经迁移到 PG」的旧 SQLite（见 migratedMarker）。

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/KJoner/litesync-server/internal/config"
	"github.com/KJoner/litesync-server/internal/db"
)

// migratedMarkerName：migrate-to-pg 成功后写进数据目录的标记文件。
//
// 需求 §12.4：切换后已经有新写入时，不能简单把旧 SQLite 重新接回当回滚——它停在切换
// 那一刻，接回去等于让所有客户端看到一段「倒退的历史」。标记存在时以 SQLite 方式启动
// 一律拒绝；要回到 SQLite，走 `obsync export-sqlite`（经过校验的反向迁移）后再删标记。
const migratedMarkerName = "migrated-to-postgres.json"

type migratedMarker struct {
	MigratedAt      string `json:"migratedAt"`
	LitesyncVersion string `json:"litesyncVersion"`
	Source          string `json:"source"`
	Tables          int    `json:"tables"`
	TotalRows       int64  `json:"totalRows"`
	Note            string `json:"note"`
}

func dataDirFromEnv() string {
	if d := os.Getenv("OBSYNC_DATA_DIR"); d != "" {
		return d
	}
	return "./data"
}

func refuseIfMigrated(dataDir string) error {
	raw, err := os.ReadFile(filepath.Join(dataDir, migratedMarkerName))
	if err != nil {
		return nil // 没有标记
	}
	var m migratedMarker
	json.Unmarshal(raw, &m) //nolint:errcheck // 标记损坏也照样拒绝
	return fmt.Errorf("this data directory was migrated to PostgreSQL at %s (marker %s): "+
		"running on the old SQLite would serve stale data and fork the history. Set OBSYNC_DB=postgres. "+
		"To move back to SQLite deliberately, use `obsync export-sqlite` (verified reverse migration), "+
		"install the export as sync.db, then delete the marker", m.MigratedAt, migratedMarkerName)
}

// openDatabase 按 OBSYNC_DB 打开（必要时创建）元数据库：服务启动与普通运维命令用。
func openDatabase(dataDir string, syncFull bool) (*sql.DB, config.Database, error) {
	dbc, err := config.LoadDatabase()
	if err != nil {
		return nil, dbc, err
	}
	if dbc.IsPostgres() {
		d, err := db.OpenPostgres(dbc.PostgresDSN)
		return d, dbc, err
	}
	if err := refuseIfMigrated(dataDir); err != nil {
		return nil, dbc, err
	}
	d, err := db.OpenWithSync(filepath.Join(dataDir, "sync.db"), syncFull)
	return d, dbc, err
}

// openExistingDB 打开一个**已存在**的元数据库（rotate-epoch / token / identity 等兜底命令）：
// 路径或 DSN 写错时报错，而不是悄悄新建一个空库然后在空库上「操作成功」。
func openExistingDB() (*sql.DB, error) {
	dataDir := dataDirFromEnv()
	dbc, err := config.LoadDatabase()
	if err != nil {
		return nil, err
	}
	if dbc.IsPostgres() {
		raw, err := db.OpenPostgresRaw(dbc.PostgresDSN)
		if err != nil {
			return nil, err
		}
		exists, err := db.TableExists(raw, "repo_state")
		raw.Close()
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, fmt.Errorf("no LiteSync database found at OBSYNC_PG_DSN (repo_state table missing)")
		}
		return db.OpenPostgres(dbc.PostgresDSN)
	}
	if err := refuseIfMigrated(dataDir); err != nil {
		return nil, err
	}
	p := filepath.Join(dataDir, "sync.db")
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("database not found at %s (set OBSYNC_DATA_DIR): %w", p, err)
	}
	return db.Open(p)
}

// rotateAllAfterRestore 在恢复出的 SQLite 库上，用一个事务旋转全部仓库的 repoEpoch。
func rotateAllAfterRestore(dataDir string) error {
	d, err := db.Open(filepath.Join(dataDir, "sync.db"))
	if err != nil {
		return err
	}
	defer d.Close()
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	rotated, err := db.RotateAllEpochs(tx)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	for _, r := range rotated {
		fmt.Printf("repo epoch rotated (vault %s): %s → %s\n", r.VaultID, short(r.OldEpoch), short(r.NewEpoch))
	}
	return nil
}
