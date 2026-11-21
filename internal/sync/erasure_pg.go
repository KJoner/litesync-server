package sync

// 明文路径擦除在 PostgreSQL 上的如实报告（批次 G）。
//
// erasure.go 的流水线是为 SQLite 写的：wal_checkpoint(TRUNCATE) + secure_delete + VACUUM
// + 对 DB/WAL/SHM 文件做全字节哨兵扫描。换到 PG 上，驱动层把这些语句翻成了空操作或
// VACUUM FULL——**流水线照样跑完，但报告里的断言不再成立**：
//
//   - PG 的 WAL（pg_wal）由数据库服务器管理，LiteSync 截断不了；明文可能留在 WAL 段、
//     流复制副本和 PG 自己的基础备份里，直到它们被回收；
//   - VACUUM FULL 把表重写进新文件，旧文件被 unlink 而不是覆写；
//   - 数据文件在数据库服务器上，应用读不到，文件级哨兵扫描做不了。
//
// 隐私报告里写死的断言是最有害的失真，所以这里在 PG 上改写报告：WalTruncated=false、
// 说明 VACUUM FULL 实际做了什么、Note 写清楚只扫描了逻辑表。报告本身存进 vault_meta
//（PG 部署的数据目录旁没有 sync.db 可以「同级」放文件）。

import (
	"time"

	"github.com/KJoner/litesync-server/internal/db"
)

const erasureReportMetaKey = "migration-erasure-report"

func applyPostgresErasureCaveats(r *ErasureReport) {
	r.WalCheckpoint = "not applicable on PostgreSQL: WAL (pg_wal) is managed by the database server and is not truncated by LiteSync"
	r.Claims.WalTruncated = false
	r.Vacuum = "VACUUM FULL on LiteSync's own tables in the current schema (tables rewritten into new files; the old files are unlinked by PostgreSQL, not overwritten)"
	r.Scanned = []string{}
	r.Note = "PostgreSQL deployment: only logical tables were scanned for sentinels — the database files, WAL " +
		"segments, replicas and PostgreSQL base backups live on the database server and were NOT scanned. " +
		"Plaintext paths may persist there until WAL is recycled and old backups expire. " +
		"Pre-migration backups are listed as exceptions; file-level deletion cannot guarantee physical " +
		"erasure on wear-levelled storage."
}

func (s *Service) writeErasureReportPG(data []byte) error {
	return db.SetMeta(s.db, erasureReportMetaKey, string(data), time.Now().Unix())
}

func (s *Service) erasureReportPG() ([]byte, error) {
	v, ok, err := db.GetMeta(s.db, erasureReportMetaKey)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFound
	}
	return []byte(v), nil
}

// DBCheckNotRunPostgres 是 Scrub 在 PG 上的 DBCheck 取值：如实说明没有执行页级检查
// （不冒充 "ok"，也不计为问题）。测试按方言断言「健康库应有的值」时用它。
const DBCheckNotRunPostgres = "not-run: postgresql (page/index verification is the database server's job: enable data_checksums, use amcheck)"
