package db

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
)

// Vacuum 重建 LiteSync 自己的表，让删除留下的旧数据从库文件里消失（路径加密完成后的擦除、低频维护用）。
//
//   - SQLite：VACUUM（事务性的整库重建；库文件里只有 LiteSync 的表）。
//   - PostgreSQL：VACUUM FULL，但只对**当前 schema 里、由 LiteSync 建立的表**逐一点名。
//
// 不带表名的 VACUUM FULL 在 PG 上是整库操作：它会重写同一个库里其他应用、其他 schema 的表；连接角色是超级用户
// 时还会逐个重写系统目录（pg_class、pg_attribute…）并持有排他锁，与库里任何并发的建表事务互相等待。
// 2026-11-21 CI（go-postgres 17.10）：一个测试进程的擦除跑了 `VACUUM FULL`，在 pg_attribute 上等另一个测试进程尚未
// 提交的建表事务，而后者在等 pg_attribute 的 RowExclusiveLock → 40P01 deadlock detected。各测试本来就按 schema
// 隔离，是这条整库语句穿透了隔离；生产上 LiteSync 与别的应用共用一个库时也会出同样的事。
// 只点 LiteSync 自己建的表名（取自建表 DDL），即使部署在与别的应用共用的 schema（例如 public）里也不会碰别人的表。
func Vacuum(d *sql.DB) error {
	if !IsPostgres(d) {
		_, err := d.Exec(`VACUUM`)
		return err
	}
	tables, err := ownTablesInCurrentSchema(d)
	if err != nil {
		return err
	}
	if len(tables) == 0 {
		return fmt.Errorf("vacuum: no LiteSync tables found in the current schema (search_path misconfigured?)")
	}
	_, err = d.Exec(`VACUUM FULL ` + strings.Join(tables, ", "))
	return err
}

var reCreateTable = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+([A-Za-z_][A-Za-z0-9_]*)`)

// ownTableNames 是 LiteSync 建立的全部表名（从 allSchema 的 DDL 里取，新增表自动包含）。
func ownTableNames() map[string]bool {
	names := map[string]bool{}
	for _, m := range reCreateTable.FindAllStringSubmatch(allSchema(), -1) {
		names[strings.ToLower(m[1])] = true
	}
	return names
}

// ownTablesInCurrentSchema 返回当前 schema 里属于 LiteSync 的表（已按 schema.table 加引号）。
func ownTablesInCurrentSchema(d *sql.DB) ([]string, error) {
	rows, err := d.Query(`SELECT c.relname, quote_ident(n.nspname) || '.' || quote_ident(c.relname)
		FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND c.relkind = 'r' ORDER BY c.relname`)
	if err != nil {
		return nil, fmt.Errorf("list tables to vacuum: %w", err)
	}
	defer rows.Close()
	own := ownTableNames()
	var tables []string
	for rows.Next() {
		var name, qualified string
		if err := rows.Scan(&name, &qualified); err != nil {
			return nil, err
		}
		if own[strings.ToLower(name)] {
			tables = append(tables, qualified)
		}
	}
	return tables, rows.Err()
}
