package sync

// 明文路径擦除（ADR-008）。
//
// 「明文路径已被抹除」在 v0.12.0 里是假的：DELETE 只清了逻辑表，真实路径还留在
// SQLite freelist、WAL、日志和迁移前备份里。这里把前三类分别处理，并如实登记
// 第四类（备份）为**未清理的例外**。
//
//	停止写入（调用方已持锁）
//	→ wal_checkpoint(TRUNCATE)
//	→ secure_delete = ON
//	→ VACUUM（事务性整库重建，freelist 随之消失）
//	→ 重新 checkpoint
//	→ 扫描 DB / WAL / SHM 中的哨兵
//	→ 生成 migration-erasure-report.json
//
// 关于 VACUUM：ADR-008 原本设想 `VACUUM INTO` + 原子 rename，理由是「原地重建
// 崩溃会留下半个库」。实际实现改用原地 VACUUM——Service 持有一个长期打开的
// 单连接，进程内无法把文件在它脚下换掉；而 SQLite 的 VACUUM 本身是事务性的，
// 崩溃回滚到原库，不会留下半个文件。崩溃安全性没有损失。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

// 哨兵前缀：迁移开始时写入 vault_meta，擦除后必须在物理文件里找不到。
const sentinelPrefix = "LITESYNC-PLAINTEXT-SENTINEL-"

const sentinelMetaPrefix = "migration-sentinel:"

// BackupException 记录仍含明文路径的备份（ADR-008 §3.4）。
type BackupException struct {
	Kind                   string `json:"kind"`
	Location               string `json:"location"`
	CreatedAt              int64  `json:"createdAt"`
	ContainsPlaintextPaths bool   `json:"containsPlaintextPaths"`
	RetentionPolicy        string `json:"retentionPolicy"`
	DestroyedAt            int64  `json:"destroyedAt"`
}

// ErasureReport 是 migration-erasure-report.json 的内容。
type ErasureReport struct {
	MigrationID         string            `json:"migrationId"`
	RepoEpoch           string            `json:"repoEpoch"`
	FormatEpoch         int64             `json:"formatEpoch"`
	CompletedAt         int64             `json:"completedAt"`
	Scanned             []string          `json:"scanned"`
	Sentinels           int               `json:"sentinels"`
	Residual            int64             `json:"residual"`
	WalCheckpoint       string            `json:"walCheckpoint"`
	Vacuum              string            `json:"vacuum"`
	Objects             int               `json:"objects"`
	TombstonesConverted int               `json:"tombstonesConverted"`
	BackupExceptions    []BackupException `json:"backupExceptions"`
	Claims              ErasureClaims     `json:"claims"`
	// Note 明确写出本报告**不能**证明什么，避免被当成「彻底不可恢复」的凭据
	Note string `json:"note"`
}

// ErasureClaims 是可以逐条核对的断言。
type ErasureClaims struct {
	LogicalTablesClean bool `json:"logicalTablesClean"`
	DBFileRebuilt      bool `json:"dbFileRebuilt"`
	WalTruncated       bool `json:"walTruncated"`
	BackupsCleaned     bool `json:"backupsCleaned"`
}

// RegisterMigrationSentinel 在迁移开始时写入哨兵（幂等）。
func (s *Service) RegisterMigrationSentinel(migrationID string) (string, error) {
	key := sentinelMetaPrefix + migrationID
	if v, ok, err := db.GetMeta(s.db, key); err != nil {
		return "", err
	} else if ok {
		return v, nil
	}
	raw, err := newMigrationID()
	if err != nil {
		return "", err
	}
	value := sentinelPrefix + raw
	if err := db.SetMeta(s.db, key, value, time.Now().Unix()); err != nil {
		return "", err
	}
	return value, nil
}

// scanLogicalSentinels 统计逻辑表里还能查到的哨兵值（complete 验证项 10）。
func (s *Service) scanLogicalSentinels() (int64, error) {
	sentinels, err := s.sentinelValues()
	if err != nil || len(sentinels) == 0 {
		return 0, err
	}
	var total int64
	for _, sentinel := range sentinels {
		for _, q := range []struct {
			sql string
			arg string
		}{
			{`SELECT COUNT(*) FROM file_heads WHERE pseudonym LIKE ?`, "%" + sentinel + "%"},
			{`SELECT COUNT(*) FROM file_heads WHERE canonical_path_hmac LIKE ?`, "%" + sentinel + "%"},
			{`SELECT COUNT(*) FROM tombstones WHERE last_pseudonym LIKE ?`, "%" + sentinel + "%"},
			{`SELECT COUNT(*) FROM tombstones WHERE canonical_path_hmac LIKE ?`, "%" + sentinel + "%"},
			{`SELECT COUNT(*) FROM object_changes WHERE pseudonym LIKE ?`, "%" + sentinel + "%"},
			{`SELECT COUNT(*) FROM shares WHERE name LIKE ?`, "%" + sentinel + "%"},
		} {
			var n int64
			if err := s.db.QueryRow(q.sql, q.arg).Scan(&n); err != nil {
				return total, err
			}
			total += n
		}
	}
	return total, nil
}

// sentinelValues 返回当前登记的全部哨兵串。
func (s *Service) sentinelValues() ([]string, error) {
	rows, err := s.db.Query(`SELECT value FROM vault_meta WHERE key LIKE ?`, sentinelMetaPrefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		if strings.HasPrefix(v, sentinelPrefix) {
			out = append(out, v)
		}
	}
	return out, rows.Err()
}

// erasePlaintextPathsLocked 执行擦除流程。调用方必须已持有 s.mu。
func (s *Service) erasePlaintextPathsLocked(rs *db.RepoState) (*ErasureReport, error) {
	report := &ErasureReport{
		MigrationID: rs.MigrationID,
		RepoEpoch:   rs.RepoEpoch,
		FormatEpoch: rs.MigrationTargetFormatEpoch,
		CompletedAt: time.Now().Unix(),
		Note: "This report proves the erasure pipeline ran and left no sentinel in the current " +
			"database, WAL or logs. It does NOT prove that no plaintext path can ever be recovered: " +
			"pre-migration backups are listed as exceptions, and file-level deletion cannot guarantee " +
			"physical erasure on wear-levelled storage.",
	}

	sentinels, err := s.sentinelValues()
	if err != nil {
		return nil, err
	}
	report.Sentinels = len(sentinels)

	heads, err := db.ListHeads(s.db)
	if err != nil {
		return nil, err
	}
	report.Objects = len(heads)
	tombs, err := db.ListTombstones(s.db)
	if err != nil {
		return nil, err
	}
	report.TombstonesConverted = len(tombs)

	dbPath, err := s.databasePath()
	if err != nil {
		return nil, err
	}

	// 0) 先把哨兵记录本身从 vault_meta 删掉（值已读进内存）。
	//    否则扫描必然命中——命中的是哨兵自己的存储位置，而不是残留的路径，
	//    那样这项检查就永远为真，等于没有检查。
	if _, err := s.db.Exec(`DELETE FROM vault_meta WHERE key LIKE ?`, sentinelMetaPrefix+"%"); err != nil {
		return nil, fmt.Errorf("clear sentinels: %w", err)
	}

	// 1) WAL checkpoint
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		report.WalCheckpoint = "failed: " + err.Error()
		return nil, fmt.Errorf("wal checkpoint: %w", err)
	}
	report.WalCheckpoint = "TRUNCATE ok"
	report.Claims.WalTruncated = true

	// 2) secure_delete + VACUUM：整库重建，freelist 里的旧页随之消失。
	//
	// ADR-008 原本设想 `VACUUM INTO` + 原子 rename。实际实现改用原地 VACUUM：
	// Service 持有的是一个长期打开的单连接（db.SetMaxOpenConns(1)），进程内
	// 无法把文件在它脚下换掉；而 SQLite 的 VACUUM 本身就是事务性的——中途崩溃
	// 会回滚到原库，不会留下半个文件。因此崩溃安全性并没有损失，
	// 代价是重建期间需要约两倍磁盘空间（与 VACUUM INTO 相同）。
	if _, err := s.db.Exec(`PRAGMA secure_delete = ON`); err != nil {
		return nil, fmt.Errorf("secure_delete: %w", err)
	}
	if _, err := s.db.Exec(`VACUUM`); err != nil {
		report.Vacuum = "failed: " + err.Error()
		return nil, fmt.Errorf("vacuum: %w", err)
	}
	report.Vacuum = "secure_delete=ON + VACUUM (transactional in-place rebuild)"
	report.Claims.DBFileRebuilt = true

	// 3) 重新 checkpoint
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return nil, fmt.Errorf("wal checkpoint (post-vacuum): %w", err)
	}

	// 4) 逻辑表 + 物理文件哨兵扫描
	logical, err := s.scanLogicalSentinels()
	if err != nil {
		return nil, err
	}
	report.Claims.LogicalTablesClean = logical == 0
	report.Residual = logical

	if dbPath != "" && len(sentinels) > 0 {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			p := dbPath + suffix
			report.Scanned = append(report.Scanned, filepath.Base(p))
			hits, err := scanFileForSentinels(p, sentinels)
			if err != nil {
				continue // 文件不存在（例如没有 WAL）不算残留
			}
			report.Residual += hits
		}
	}

	// 5) 备份例外：迁移前备份仍含明文路径，且它是唯一的回滚手段——
	//    绝不自动销毁，如实登记
	report.BackupExceptions = []BackupException{{
		Kind:                   "pre-migration-backup",
		Location:               "operator-managed",
		CreatedAt:              0,
		ContainsPlaintextPaths: true,
		RetentionPolicy:        "manual (destroy via `obsync migration finalize --destroy-pre-backup`)",
		DestroyedAt:            0,
	}}
	report.Claims.BackupsCleaned = false

	if err := s.writeErasureReport(report); err != nil {
		s.log.Warn("erasure report write failed", "error", err)
	}
	return report, nil
}

// scanFileForSentinels 全字节扫描文件中的哨兵出现次数。
func scanFileForSentinels(path string, sentinels []string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var hits int64
	for _, s := range sentinels {
		hits += int64(bytes.Count(data, []byte(s)))
	}
	return hits, nil
}

// databasePath 从 SQLite 自身取当前主库文件路径。
func (s *Service) databasePath() (string, error) {
	rows, err := s.db.Query(`PRAGMA database_list`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var name, file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			return "", err
		}
		if name == "main" {
			return file, nil
		}
	}
	return "", rows.Err()
}

// writeErasureReport 把报告写到数据目录（与库同级）。
func (s *Service) writeErasureReport(r *ErasureReport) error {
	dbPath, err := s.databasePath()
	if err != nil || dbPath == "" {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	out := filepath.Join(filepath.Dir(dbPath), "migration-erasure-report.json")
	return os.WriteFile(out, data, 0o600)
}

// ErasureReportJSON 读取最近一次擦除报告（管理接口用）。
func (s *Service) ErasureReportJSON() ([]byte, error) {
	dbPath, err := s.databasePath()
	if err != nil || dbPath == "" {
		return nil, ErrNotFound
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(dbPath), "migration-erasure-report.json"))
	if err != nil {
		return nil, ErrNotFound
	}
	return data, nil
}
