package db

// 跨方言整库复制与校验（批次 G / 迁移方案 M6、M7）。
//
// 三个用途共用这一套实现：
//   - `obsync migrate-to-pg`：SQLite 文件库 → PostgreSQL（正式切换）；
//   - `obsync export-sqlite`：PostgreSQL → SQLite 文件（经过校验的反向导出 = 切换后的回退路径）；
//   - PG 部署的备份：把 PG 在一个 REPEATABLE READ 只读事务里导出成一个一致的 sync.db
//     放进 staging（internal/backup），restic 与恢复流程、备份格式与 SQLite 部署完全相同。
//
// 正确性靠校验而不是靠「复制代码没写错」：复制完成后在**同一个源快照**上重新读两边，
// 每个值按目标列类型规范化后逐行哈希、排序再哈希（与行顺序、NULL 排序规则无关），
// 两边摘要必须逐表相等；另外核对每仓库的业务计数、世代字段、content_hash 集合与
// keyDoc 指纹，以及自增序列的高水位（「id 永不复用」在两种库之间保持）。
// 任一不符即失败：源库只读，目标写入在单个事务里，失败整体回滚。

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type colKind int

const (
	kindText colKind = iota
	kindInt
	kindBlob
	kindReal
)

type colInfo struct {
	name string
	kind colKind
}

func kindOf(declared string) colKind {
	t := strings.ToUpper(declared)
	switch {
	case strings.Contains(t, "INT"):
		return kindInt
	case strings.Contains(t, "BLOB"), strings.Contains(t, "BYTEA"):
		return kindBlob
	case strings.Contains(t, "REAL"), strings.Contains(t, "DOUB"), strings.Contains(t, "FLOA"), strings.Contains(t, "NUMERIC"):
		return kindReal
	default:
		return kindText
	}
}

// copySide 是复制的一端：查询入口（通常是一个事务）+ 方言。
type copySide struct {
	q  dbtx
	pg bool
}

// beginSnapshot 在源库上开一个只读快照事务：之后的全部读取（复制与校验）都看到同一时刻。
// PG 用 REPEATABLE READ READ ONLY；SQLite（WAL）的读事务本身就是快照。
func beginSnapshot(d *sql.DB) (*sql.Tx, error) {
	if IsPostgres(d) {
		return d.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	}
	return d.Begin()
}

// listTables 返回业务表（排除各自的系统表），按名字排序。
func listTables(s copySide) ([]string, error) {
	q := `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`
	if s.pg {
		q = `SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' ORDER BY table_name`
	}
	rows, err := s.q.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func copyColumns(s copySide, table string) ([]colInfo, error) {
	var rows *sql.Rows
	var err error
	if s.pg {
		rows, err = s.q.Query(`SELECT column_name, data_type FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = ? ORDER BY ordinal_position`, table)
	} else {
		rows, err = s.q.Query(`SELECT name, type FROM pragma_table_info(?) ORDER BY cid`, table)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []colInfo
	for rows.Next() {
		var c colInfo
		var typ string
		if err := rows.Scan(&c.name, &typ); err != nil {
			return nil, err
		}
		c.kind = kindOf(typ)
		out = append(out, c)
	}
	return out, rows.Err()
}

// normalize 把一个值规范化成目标列类型应有的 Go 值（SQLite 是动态类型，PG 是强类型）。
func normalize(table, col string, kind colKind, v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	bad := func() error {
		return fmt.Errorf("%s.%s: cannot represent %T value as the target column type", table, col, v)
	}
	switch kind {
	case kindInt:
		switch x := v.(type) {
		case int64:
			return x, nil
		case int:
			return int64(x), nil
		case int32:
			return int64(x), nil
		case bool:
			if x {
				return int64(1), nil
			}
			return int64(0), nil
		case float64:
			if x == math.Trunc(x) && !math.IsInf(x, 0) {
				return int64(x), nil
			}
		case string:
			if n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64); err == nil {
				return n, nil
			}
		case []byte:
			if n, err := strconv.ParseInt(strings.TrimSpace(string(x)), 10, 64); err == nil {
				return n, nil
			}
		}
		return nil, bad()
	case kindText:
		var s string
		switch x := v.(type) {
		case string:
			s = x
		case []byte:
			s = string(x)
		case int64:
			s = strconv.FormatInt(x, 10)
		case float64:
			s = strconv.FormatFloat(x, 'g', -1, 64)
		case bool:
			s = strconv.FormatBool(x)
		default:
			return nil, bad()
		}
		// PG 的 text 不能存 NUL 与非法 UTF-8：源库里真有这种值时必须当场暴露，
		// 而不是让某一行在导入时莫名失败
		if !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
			return nil, fmt.Errorf("%s.%s: text value is not valid UTF-8 (or contains NUL)", table, col)
		}
		return s, nil
	case kindBlob:
		switch x := v.(type) {
		case []byte:
			return x, nil
		case string:
			return []byte(x), nil
		}
		return nil, bad()
	case kindReal:
		switch x := v.(type) {
		case float64:
			return x, nil
		case int64:
			return float64(x), nil
		case string:
			if f, err := strconv.ParseFloat(x, 64); err == nil {
				return f, nil
			}
		}
		return nil, bad()
	}
	return nil, bad()
}

// canonical 把规范化后的值编码成与方言无关的字节（摘要用）。
func canonical(buf []byte, v any) []byte {
	var tmp [8]byte
	switch x := v.(type) {
	case nil:
		return append(buf, 'n')
	case int64:
		binary.BigEndian.PutUint64(tmp[:], uint64(x))
		buf = append(buf, 'i')
		return append(buf, tmp[:]...)
	case float64:
		binary.BigEndian.PutUint64(tmp[:], math.Float64bits(x))
		buf = append(buf, 'f')
		return append(buf, tmp[:]...)
	case string:
		binary.BigEndian.PutUint64(tmp[:], uint64(len(x)))
		buf = append(buf, 's')
		buf = append(buf, tmp[:]...)
		return append(buf, x...)
	case []byte:
		binary.BigEndian.PutUint64(tmp[:], uint64(len(x)))
		buf = append(buf, 'b')
		buf = append(buf, tmp[:]...)
		return append(buf, x...)
	}
	return append(buf, '?')
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// tableDigest：与行顺序无关的整表摘要（逐行哈希 → 排序 → 再哈希）。
func tableDigest(q dbtx, table string, cols []colInfo) (int64, string, error) {
	names := make([]string, len(cols))
	for i, c := range cols {
		names[i] = quoteIdent(c.name)
	}
	rows, err := q.Query(`SELECT ` + strings.Join(names, ", ") + ` FROM ` + quoteIdent(table))
	if err != nil {
		return 0, "", err
	}
	defer rows.Close()
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	var hashes [][32]byte
	buf := make([]byte, 0, 256)
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return 0, "", err
		}
		buf = buf[:0]
		for i, c := range cols {
			nv, err := normalize(table, c.name, c.kind, vals[i])
			if err != nil {
				return 0, "", err
			}
			buf = canonical(buf, nv)
		}
		hashes = append(hashes, sha256.Sum256(buf))
	}
	if err := rows.Err(); err != nil {
		return 0, "", err
	}
	sort.Slice(hashes, func(i, j int) bool { return string(hashes[i][:]) < string(hashes[j][:]) })
	h := sha256.New()
	for _, x := range hashes {
		h.Write(x[:])
	}
	return int64(len(hashes)), hex.EncodeToString(h.Sum(nil)), nil
}

// ---------------------------------------------------------------- 报告

// TableReport 是一张表的复制/校验结果。
type TableReport struct {
	Table        string `json:"table"`
	Columns      int    `json:"columns"`
	SourceRows   int64  `json:"sourceRows"`
	TargetRows   int64  `json:"targetRows"`
	SourceDigest string `json:"sourceDigest,omitempty"`
	TargetDigest string `json:"targetDigest,omitempty"`
	Match        bool   `json:"match"`
}

// VaultSummary 是一个仓库的业务级核对数据（两边各取一份，必须完全相同）。
type VaultSummary struct {
	VaultID           string `json:"vaultId"`
	Objects           int64  `json:"objects"`
	LiveObjects       int64  `json:"liveObjects"`
	Versions          int64  `json:"versions"`
	Tombstones        int64  `json:"tombstones"`
	Changes           int64  `json:"changes"`
	ContentHashSet    string `json:"contentHashSet"`
	RepoEpoch         string `json:"repoEpoch"`
	HeadSequence      int64  `json:"headSequence"`
	FormatEpoch       int64  `json:"formatEpoch"`
	KeyEpoch          int64  `json:"keyEpoch"`
	MinEnvelope       int64  `json:"minimumEnvelopeVersion"`
	KeyDocFingerprint string `json:"keyDocFingerprint"`
}

// CopyReport 是一次复制（或纯校验 / 演练）的完整结果，可直接序列化为机器可读 JSON。
type CopyReport struct {
	Direction     string           `json:"direction"`
	Mode          string           `json:"mode"` // dry-run | copy | verify-only | export
	StartedAt     string           `json:"startedAt"`
	DurationMs    int64            `json:"durationMs"`
	Tables        []TableReport    `json:"tables"`
	SkippedTables []string         `json:"skippedSourceTables,omitempty"`
	SourceVaults  []VaultSummary   `json:"sourceVaults,omitempty"`
	TargetVaults  []VaultSummary   `json:"targetVaults,omitempty"`
	SourceSeqHW   map[string]int64 `json:"sourceSequenceHighWater,omitempty"`
	TargetSeqHW   map[string]int64 `json:"targetSequenceHighWater,omitempty"`
	TotalRows     int64            `json:"totalRows"`
	OK            bool             `json:"ok"`
	Problems      []string         `json:"problems,omitempty"`
}

func newReport(direction, mode string) *CopyReport {
	return &CopyReport{Direction: direction, Mode: mode, StartedAt: time.Now().UTC().Format(time.RFC3339)}
}

// ---------------------------------------------------------------- 规划

// unmigratedV5Table：v5 → v6 尚未执行的旧表——必须先用当前版本完成升级。
func unmigratedV5Table(name string) bool {
	return name == "files" || name == "changes" || name == "file_versions"
}

// legacyV5Copy：v6 迁移后保留的只读 v5 旧表（只为换回 0.12.x 二进制回滚用，PG 上没有意义）。
func legacyV5Copy(name string) bool { return strings.HasPrefix(name, "v5_") }

type tablePlan struct {
	table string
	cols  []colInfo // 列（类型取目标）
}

// ErrSourceSchemaOlder：源库结构落后于当前版本，需要先用当前版本正常启动一次完成升级。
var ErrSourceSchemaOlder = errors.New("source database schema is older than this LiteSync version; " +
	"start this LiteSync version once on the SQLite database (it runs the schema migrations), stop it, then retry")

func planCopy(src, dst copySide, rep *CopyReport) ([]tablePlan, error) {
	srcTables, err := listTables(src)
	if err != nil {
		return nil, err
	}
	dstTables, err := listTables(dst)
	if err != nil {
		return nil, err
	}
	inDst := map[string]bool{}
	for _, t := range dstTables {
		inDst[t] = true
	}
	srcSet := map[string]bool{}
	for _, t := range srcTables {
		srcSet[t] = true
		if inDst[t] {
			continue
		}
		switch {
		case unmigratedV5Table(t):
			rep.Problems = append(rep.Problems, "source still has the unmigrated v5 table "+t)
			return nil, ErrSourceSchemaOlder
		case legacyV5Copy(t):
			rep.SkippedTables = append(rep.SkippedTables, t+" (read-only v5 rollback copy; not carried over)")
		default:
			rep.Problems = append(rep.Problems, "source table "+t+" is unknown to this LiteSync version")
			return nil, errors.New("source has tables this LiteSync version does not know (is the source newer?)")
		}
	}
	var plan []tablePlan
	for _, t := range dstTables {
		if !srcSet[t] {
			rep.Problems = append(rep.Problems, "table "+t+" does not exist in the source")
			return nil, ErrSourceSchemaOlder
		}
		sc, err := copyColumns(src, t)
		if err != nil {
			return nil, err
		}
		dc, err := copyColumns(dst, t)
		if err != nil {
			return nil, err
		}
		srcCols := map[string]bool{}
		for _, c := range sc {
			srcCols[c.name] = true
		}
		dstCols := map[string]bool{}
		for _, c := range dc {
			dstCols[c.name] = true
		}
		for _, c := range sc {
			if !dstCols[c.name] {
				rep.Problems = append(rep.Problems, fmt.Sprintf("column %s.%s exists only in the source; copying would lose it", t, c.name))
				return nil, errors.New("source has columns this LiteSync version does not know (is the source newer?)")
			}
		}
		// 缺列 = 源库还没跑过当前版本的迁移。用默认值补齐「多半」等价，但有的迁移不只是
		// 加列（例如 repo_state 按仓库拆分）——不猜，要求先正常升级
		var missing []string
		for _, c := range dc {
			if !srcCols[c.name] {
				missing = append(missing, c.name)
			}
		}
		if len(missing) > 0 {
			rep.Problems = append(rep.Problems, fmt.Sprintf("table %s is missing columns %v in the source", t, missing))
			return nil, ErrSourceSchemaOlder
		}
		plan = append(plan, tablePlan{table: t, cols: dc})
	}
	return plan, nil
}

// nonEmptyTables 列出已有数据的表（「目标必须为空」的判定）。
func nonEmptyTables(q dbtx, plan []tablePlan) ([]string, error) {
	var out []string
	for _, p := range plan {
		var n int64
		if err := q.QueryRow(`SELECT COUNT(*) FROM ` + quoteIdent(p.table)).Scan(&n); err != nil {
			return nil, err
		}
		if n > 0 {
			out = append(out, fmt.Sprintf("%s(%d)", p.table, n))
		}
	}
	return out, nil
}

// maxParamsPerStatement：SQLite 默认上限 32766、PG 65535，取两者都安全的值。
const maxParamsPerStatement = 30000

func copyTable(src, dst dbtx, p tablePlan) error {
	if len(p.cols) == 0 {
		return nil
	}
	names := make([]string, len(p.cols))
	for i, c := range p.cols {
		names[i] = quoteIdent(c.name)
	}
	rows, err := src.Query(`SELECT ` + strings.Join(names, ", ") + ` FROM ` + quoteIdent(p.table))
	if err != nil {
		return err
	}
	defer rows.Close()
	batch := maxParamsPerStatement / len(p.cols)
	if batch > 500 {
		batch = 500
	}
	if batch < 1 {
		batch = 1
	}
	rowPh := "(" + strings.TrimSuffix(strings.Repeat("?, ", len(p.cols)), ", ") + ")"
	prefix := `INSERT INTO ` + quoteIdent(p.table) + ` (` + strings.Join(names, ", ") + `) VALUES `
	vals := make([]any, len(p.cols))
	ptrs := make([]any, len(p.cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	var args []any
	n := 0
	flush := func() error {
		if n == 0 {
			return nil
		}
		q := prefix + strings.TrimSuffix(strings.Repeat(rowPh+", ", n), ", ")
		_, err := dst.Exec(q, args...)
		args = args[:0]
		n = 0
		return err
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		for i, c := range p.cols {
			nv, err := normalize(p.table, c.name, c.kind, vals[i])
			if err != nil {
				return err
			}
			args = append(args, nv)
		}
		n++
		if n >= batch {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return flush()
}

// ---------------------------------------------------------------- 自增序列高水位

type identityCol struct{ table, column string }

func pgIdentityColumns(q dbtx) ([]identityCol, error) {
	rows, err := q.Query(`SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema = current_schema() AND is_identity = 'YES' ORDER BY table_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []identityCol
	for rows.Next() {
		var c identityCol
		if err := rows.Scan(&c.table, &c.column); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// seqHighWater：每张自增表「曾经分配过的最大 id」。SQLite 的 AUTOINCREMENT 保证 id 永不复用
// （即使最大的那行被删了，sqlite_sequence 仍记着它）；只按 MAX(id) 续号会在迁移后复用旧 id。
func seqHighWater(s copySide) (map[string]int64, error) {
	out := map[string]int64{}
	if s.pg {
		cols, err := pgIdentityColumns(s.q)
		if err != nil {
			return nil, err
		}
		for _, c := range cols {
			var seq string
			if err := s.q.QueryRow(`SELECT pg_get_serial_sequence(?, ?)`, c.table, c.column).Scan(&seq); err != nil {
				return nil, err
			}
			var last int64
			var called bool
			if err := s.q.QueryRow(`SELECT last_value, is_called FROM `+seq).Scan(&last, &called); err != nil {
				return nil, err
			}
			if !called {
				last--
			}
			out[c.table] = last
		}
		return out, nil
	}
	var n int
	if err := s.q.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence'`).Scan(&n); err != nil {
		return nil, err
	}
	if n == 0 {
		return out, nil
	}
	rows, err := s.q.Query(`SELECT name, seq FROM sqlite_sequence`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var seq int64
		if err := rows.Scan(&name, &seq); err != nil {
			return nil, err
		}
		out[name] = seq
	}
	return out, rows.Err()
}

// applySeqHighWater 让目标的自增序列从 max(源高水位, 现有最大 id) 之后继续。
func applySeqHighWater(dst copySide, hw map[string]int64) error {
	if dst.pg {
		cols, err := pgIdentityColumns(dst.q)
		if err != nil {
			return err
		}
		for _, c := range cols {
			var maxID int64
			if err := dst.q.QueryRow(`SELECT COALESCE(MAX(` + quoteIdent(c.column) + `), 0) FROM ` + quoteIdent(c.table)).Scan(&maxID); err != nil {
				return err
			}
			next := maxID
			if hw[c.table] > next {
				next = hw[c.table]
			}
			if _, err := dst.q.Exec(`SELECT setval(pg_get_serial_sequence(?, ?), ?, false)`, c.table, c.column, next+1); err != nil {
				return fmt.Errorf("advance identity %s.%s: %w", c.table, c.column, err)
			}
		}
		return nil
	}
	for table, v := range hw {
		var cur sql.NullInt64
		err := dst.q.QueryRow(`SELECT seq FROM sqlite_sequence WHERE name = ?`, table).Scan(&cur)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if _, err := dst.q.Exec(`INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)`, table, v); err != nil {
				return err
			}
		case err != nil:
			return err
		case cur.Int64 < v:
			if _, err := dst.q.Exec(`UPDATE sqlite_sequence SET seq = ? WHERE name = ?`, v, table); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------- 校验

func verifyPlan(src, dst copySide, plan []tablePlan, rep *CopyReport) error {
	rep.Tables = rep.Tables[:0]
	rep.TotalRows = 0
	ok := true
	for _, p := range plan {
		sn, sd, err := tableDigest(src.q, p.table, p.cols)
		if err != nil {
			return fmt.Errorf("digest source %s: %w", p.table, err)
		}
		dn, dd, err := tableDigest(dst.q, p.table, p.cols)
		if err != nil {
			return fmt.Errorf("digest target %s: %w", p.table, err)
		}
		tr := TableReport{Table: p.table, Columns: len(p.cols),
			SourceRows: sn, TargetRows: dn, SourceDigest: sd, TargetDigest: dd, Match: sn == dn && sd == dd}
		if !tr.Match {
			ok = false
			rep.Problems = append(rep.Problems, fmt.Sprintf("table %s differs (rows %d vs %d)", p.table, sn, dn))
		}
		rep.Tables = append(rep.Tables, tr)
		rep.TotalRows += sn
	}
	var err error
	if rep.SourceVaults, err = vaultSummaries(src.q); err != nil {
		return err
	}
	if rep.TargetVaults, err = vaultSummaries(dst.q); err != nil {
		return err
	}
	if fmt.Sprintf("%+v", rep.SourceVaults) != fmt.Sprintf("%+v", rep.TargetVaults) {
		ok = false
		rep.Problems = append(rep.Problems, "per-vault summaries differ")
	}
	if rep.SourceSeqHW, err = seqHighWater(src); err != nil {
		return err
	}
	if rep.TargetSeqHW, err = seqHighWater(dst); err != nil {
		return err
	}
	for t, v := range rep.SourceSeqHW {
		if rep.TargetSeqHW[t] < v {
			ok = false
			rep.Problems = append(rep.Problems, fmt.Sprintf("sequence high-water of %s regressed (%d < %d): ids could be reused", t, rep.TargetSeqHW[t], v))
		}
	}
	rep.OK = ok
	if !ok {
		return errors.New("verification failed: source and target differ")
	}
	return nil
}

// vaultKeyDocKey 与 sync.vaultKeyMetaKeyFor 同一规则（default 用无后缀的历史键）。
func vaultKeyDocKey(vaultID string) string {
	if vaultID == DefaultVaultID {
		return "vault-key"
	}
	return "vault-key:" + vaultID
}

// vaultSummaries：每仓库业务计数 + 世代字段 + content_hash 集合摘要 + keyDoc 指纹。
func vaultSummaries(q dbtx) ([]VaultSummary, error) {
	ids := map[string]bool{}
	for _, stmt := range []string{`SELECT vault_id FROM repo_state`, `SELECT vault_id FROM vaults`} {
		rows, err := q.Query(stmt)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			ids[id] = true
		}
		rows.Close()
	}
	list := make([]string, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	sort.Strings(list)
	out := make([]VaultSummary, 0, len(list))
	for _, id := range list {
		v := VaultSummary{VaultID: id}
		for _, c := range []struct {
			stmt string
			dst  *int64
		}{
			{`SELECT COUNT(*) FROM file_objects WHERE vault_id = ?`, &v.Objects},
			{`SELECT COUNT(*) FROM file_objects WHERE vault_id = ? AND object_state = 'live'`, &v.LiveObjects},
			{`SELECT COUNT(*) FROM object_versions WHERE vault_id = ?`, &v.Versions},
			{`SELECT COUNT(*) FROM tombstones WHERE vault_id = ?`, &v.Tombstones},
			{`SELECT COUNT(*) FROM object_changes WHERE vault_id = ?`, &v.Changes},
		} {
			if err := q.QueryRow(c.stmt, id).Scan(c.dst); err != nil {
				return nil, fmt.Errorf("vault summary (%s): %w", c.stmt, err)
			}
		}
		// content_hash 集合摘要：Go 侧排序后哈希（与方言的排序规则无关）
		rows, err := q.Query(`SELECT content_hash FROM object_versions WHERE vault_id = ?
			UNION ALL SELECT content_hash FROM file_heads WHERE vault_id = ?`, id, id)
		if err != nil {
			return nil, err
		}
		var hs []string
		for rows.Next() {
			var h sql.NullString
			if err := rows.Scan(&h); err != nil {
				rows.Close()
				return nil, err
			}
			hs = append(hs, h.String)
		}
		rows.Close()
		sort.Strings(hs)
		sum := sha256.Sum256([]byte(strings.Join(hs, "\n")))
		v.ContentHashSet = hex.EncodeToString(sum[:])
		err = q.QueryRow(`SELECT repo_epoch, head_sequence, format_epoch, key_epoch, minimum_envelope_version
			FROM repo_state WHERE vault_id = ?`, id).Scan(&v.RepoEpoch, &v.HeadSequence, &v.FormatEpoch, &v.KeyEpoch, &v.MinEnvelope)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		var doc string
		if err := q.QueryRow(`SELECT value FROM vault_meta WHERE key = ?`, vaultKeyDocKey(id)).Scan(&doc); err == nil {
			s := sha256.Sum256([]byte(doc))
			v.KeyDocFingerprint = hex.EncodeToString(s[:])
		} else if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// ---------------------------------------------------------------- 公开入口

// CreateSchemaOnly 建表（与 Open 相同的 DDL 与缺列补齐），但**不**写入任何种子行
// （复制的目标库：数据全部来自源库）。
func CreateSchemaOnly(d *sql.DB) error {
	if _, err := d.Exec(allSchema()); err != nil {
		return fmt.Errorf("init schema: %w", err)
	}
	if err := migrateColumns(d); err != nil {
		return fmt.Errorf("migrate columns: %w", err)
	}
	return migrateJournalKindCheck(d)
}

// OpenSQLiteReadOnly 只读打开一个 SQLite 文件库（不建表、不迁移、不写种子行；
// 连接级 query_only，任何写语句都会被 SQLite 拒绝）。复制的源库用。
func OpenSQLiteReadOnly(path string) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	d, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(1)
	d.SetConnMaxLifetime(0)
	d.SetConnMaxIdleTime(0)
	for _, p := range []string{"PRAGMA busy_timeout=5000", "PRAGMA query_only=ON"} {
		if _, err := d.Exec(p); err != nil {
			d.Close()
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	return d, nil
}

// DryRunCopy 只读源库：结构兼容性检查 + 逐表行数 + 每仓库摘要。目标结构取自当前版本的
// schema（在内存 SQLite 里建一份），不连接、不触碰目标库。
func DryRunCopy(src *sql.DB) (*CopyReport, error) {
	start := time.Now()
	rep := newReport(dialectOf(src)+"->postgres", "dry-run")
	shape, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return rep, err
	}
	defer shape.Close()
	shape.SetMaxOpenConns(1)
	if err := CreateSchemaOnly(shape); err != nil {
		return rep, err
	}
	tx, err := beginSnapshot(src)
	if err != nil {
		return rep, err
	}
	defer tx.Rollback() //nolint:errcheck
	s := copySide{q: tx, pg: IsPostgres(src)}
	plan, err := planCopy(s, copySide{q: shape}, rep)
	if err != nil {
		return rep, err
	}
	for _, p := range plan {
		var n int64
		if err := tx.QueryRow(`SELECT COUNT(*) FROM ` + quoteIdent(p.table)).Scan(&n); err != nil {
			return rep, err
		}
		rep.Tables = append(rep.Tables, TableReport{Table: p.table, Columns: len(p.cols), SourceRows: n, Match: true})
		rep.TotalRows += n
	}
	if rep.SourceVaults, err = vaultSummaries(tx); err != nil {
		return rep, err
	}
	if rep.SourceSeqHW, err = seqHighWater(s); err != nil {
		return rep, err
	}
	rep.OK = len(rep.Problems) == 0
	rep.DurationMs = time.Since(start).Milliseconds()
	return rep, nil
}

// ErrTargetNotEmpty：目标库已有数据。
var ErrTargetNotEmpty = errors.New("target database is not empty")

// TargetIsEmpty 报告目标库（已建 schema）的全部业务表是否都没有数据。
func TargetIsEmpty(dst *sql.DB) (bool, []string, error) {
	tables, err := listTables(copySide{q: dst, pg: IsPostgres(dst)})
	if err != nil {
		return false, nil, err
	}
	plan := make([]tablePlan, 0, len(tables))
	for _, t := range tables {
		plan = append(plan, tablePlan{table: t})
	}
	n, err := nonEmptyTables(dst, plan)
	return len(n) == 0, n, err
}

// CopyDatabase 把 src 的全部业务数据复制到 dst（dst 必须已建好 schema 且为空），然后在
// 同一个源快照上逐表校验。src 只读；dst 的写入在单个事务里，任一错误整体回滚。
func CopyDatabase(src, dst *sql.DB) (*CopyReport, error) {
	start := time.Now()
	rep := newReport(dialectOf(src)+"->"+dialectOf(dst), "copy")
	stx, err := beginSnapshot(src)
	if err != nil {
		return rep, err
	}
	defer stx.Rollback() //nolint:errcheck
	s := copySide{q: stx, pg: IsPostgres(src)}
	d := copySide{q: dst, pg: IsPostgres(dst)}
	plan, err := planCopy(s, d, rep)
	if err != nil {
		return rep, err
	}
	if n, err := nonEmptyTables(dst, plan); err != nil {
		return rep, err
	} else if len(n) > 0 {
		rep.Problems = append(rep.Problems, "target is not empty: "+strings.Join(n, ", "))
		return rep, ErrTargetNotEmpty
	}
	if err := copyInto(s, dst, plan); err != nil {
		return rep, err
	}
	err = verifyPlan(s, d, plan, rep)
	rep.DurationMs = time.Since(start).Milliseconds()
	return rep, err
}

func copyInto(s copySide, dst *sql.DB, plan []tablePlan) error {
	tx, err := dst.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	for _, p := range plan {
		if err := copyTable(s.q, tx, p); err != nil {
			return fmt.Errorf("copy %s: %w", p.table, err)
		}
	}
	hw, err := seqHighWater(s)
	if err != nil {
		return err
	}
	if err := applySeqHighWater(copySide{q: tx, pg: IsPostgres(dst)}, hw); err != nil {
		return err
	}
	return tx.Commit()
}

// VerifyDatabases 只做校验（迁移已完成后的重复运行 = 幂等：只校验，不写）。
func VerifyDatabases(src, dst *sql.DB) (*CopyReport, error) {
	start := time.Now()
	rep := newReport(dialectOf(src)+"->"+dialectOf(dst), "verify-only")
	stx, err := beginSnapshot(src)
	if err != nil {
		return rep, err
	}
	defer stx.Rollback() //nolint:errcheck
	s := copySide{q: stx, pg: IsPostgres(src)}
	d := copySide{q: dst, pg: IsPostgres(dst)}
	plan, err := planCopy(s, d, rep)
	if err != nil {
		return rep, err
	}
	err = verifyPlan(s, d, plan, rep)
	rep.DurationMs = time.Since(start).Milliseconds()
	return rep, err
}

// ExportToSQLiteFile 把 src（通常是 PG）导出成一个新的、自包含的 SQLite 文件并校验。
// 源端在一个只读快照事务里读取：导出结果是同一时刻的一致快照。
// path 必须不存在；失败时删除半成品。
func ExportToSQLiteFile(src *sql.DB, path string) (*CopyReport, error) {
	start := time.Now()
	rep := newReport(dialectOf(src)+"->sqlite", "export")
	if _, err := os.Stat(path); err == nil {
		return rep, fmt.Errorf("export target %s already exists", path)
	}
	dst, err := sql.Open("sqlite", path)
	if err != nil {
		return rep, err
	}
	ok := false
	defer func() {
		dst.Close()
		if !ok {
			for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
				os.Remove(path + suffix) //nolint:errcheck
			}
		}
	}()
	dst.SetMaxOpenConns(1)
	// DELETE 日志模式：导出结果是一个单文件（不留 -wal），适合直接交给 restic
	for _, p := range []string{"PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL"} {
		if _, err := dst.Exec(p); err != nil {
			return rep, fmt.Errorf("%s: %w", p, err)
		}
	}
	if err := CreateSchemaOnly(dst); err != nil {
		return rep, err
	}
	stx, err := beginSnapshot(src)
	if err != nil {
		return rep, err
	}
	defer stx.Rollback() //nolint:errcheck
	s := copySide{q: stx, pg: IsPostgres(src)}
	d := copySide{q: dst}
	plan, err := planCopy(s, d, rep)
	if err != nil {
		return rep, err
	}
	if err := copyInto(s, dst, plan); err != nil {
		return rep, err
	}
	if err := verifyPlan(s, d, plan, rep); err != nil {
		return rep, err
	}
	ok = true
	rep.DurationMs = time.Since(start).Milliseconds()
	return rep, nil
}

func dialectOf(d *sql.DB) string {
	if IsPostgres(d) {
		return "postgres"
	}
	return "sqlite"
}
