package sync

import (
	"strings"
	"testing"
)

// 批次 G：PG 上擦除报告不得沿用 SQLite 的断言（WAL 已截断、文件已扫描）。
// 隐私报告里写死的断言是最有害的失真——参数（库的种类）变了，文案必须跟着变。
func TestPostgresErasureReportDoesNotClaimSQLiteGuarantees(t *testing.T) {
	r := &ErasureReport{
		WalCheckpoint: "TRUNCATE ok",
		Vacuum:        "secure_delete=ON + VACUUM (transactional in-place rebuild)",
		Scanned:       []string{"sync.db", "sync.db-wal"},
		Claims:        ErasureClaims{LogicalTablesClean: true, DBFileRebuilt: true, WalTruncated: true},
		Note:          "left no sentinel in the current database, WAL or logs",
	}
	applyPostgresErasureCaveats(r)
	if r.Claims.WalTruncated {
		t.Fatal("PostgreSQL WAL is not truncated by LiteSync; the claim must be false")
	}
	if len(r.Scanned) != 0 {
		t.Fatalf("no database file was scanned on PostgreSQL: %v", r.Scanned)
	}
	if strings.Contains(r.Vacuum, "secure_delete") || !strings.Contains(r.Vacuum, "VACUUM FULL") {
		t.Fatalf("vacuum description must say what actually ran: %q", r.Vacuum)
	}
	if !strings.Contains(r.Note, "NOT scanned") || strings.Contains(r.Note, "left no sentinel in the current database, WAL") {
		t.Fatalf("note must state the scan limits honestly: %q", r.Note)
	}
	if !r.Claims.LogicalTablesClean {
		t.Fatal("the logical-table result is still valid and must be kept")
	}
}
