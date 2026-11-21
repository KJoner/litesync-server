package config

import (
	"strings"
	"testing"
)

func TestLoadDatabaseDefaultsToSQLite(t *testing.T) {
	t.Setenv("OBSYNC_DB", "")
	t.Setenv("OBSYNC_PG_DSN", "")
	d, err := LoadDatabase()
	if err != nil || d.IsPostgres() || d.Driver != "sqlite" || d.Warning != "" {
		t.Fatalf("default = %+v, %v", d, err)
	}
}

func TestLoadDatabasePostgresNeedsDSN(t *testing.T) {
	t.Setenv("OBSYNC_DB", "postgres")
	t.Setenv("OBSYNC_PG_DSN", "")
	if _, err := LoadDatabase(); err == nil {
		t.Fatal("OBSYNC_DB=postgres without OBSYNC_PG_DSN must be rejected")
	}
	t.Setenv("OBSYNC_PG_DSN", "postgres://u:secret-pw@db:5432/litesync")
	d, err := LoadDatabase()
	if err != nil || !d.IsPostgres() {
		t.Fatalf("postgres config = %+v, %v", d, err)
	}
	if strings.Contains(d.String(), "secret-pw") {
		t.Fatal("String() must never contain the DSN")
	}
}

func TestLoadDatabaseWarnsWhenDSNIgnored(t *testing.T) {
	t.Setenv("OBSYNC_DB", "sqlite")
	t.Setenv("OBSYNC_PG_DSN", "postgres://u:p@db/x")
	d, err := LoadDatabase()
	if err != nil || d.IsPostgres() || d.Warning == "" {
		t.Fatalf("want sqlite with a warning, got %+v %v", d, err)
	}
	if strings.Contains(d.Warning, "u:p@") {
		t.Fatal("warning must not echo the DSN")
	}
}

func TestLoadDatabaseRejectsUnknownDriver(t *testing.T) {
	t.Setenv("OBSYNC_DB", "mysql")
	if _, err := LoadDatabase(); err == nil {
		t.Fatal("unknown OBSYNC_DB must be rejected")
	}
}
