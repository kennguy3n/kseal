package db

import (
	"testing"
	"testing/fstest"
)

func TestLoadMigrationsSortsAndFiltersSQL(t *testing.T) {
	fsys := fstest.MapFS{
		"002_b.sql":  {Data: []byte("create table b();")},
		"001_a.sql":  {Data: []byte("create table a();")},
		"readme.txt": {Data: []byte("ignore me")},
	}
	ms, err := LoadMigrations(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 {
		t.Fatalf("expected 2 migrations, got %d", len(ms))
	}
	if ms[0].Name != "001_a.sql" || ms[1].Name != "002_b.sql" {
		t.Fatalf("migrations not sorted: %s, %s", ms[0].Name, ms[1].Name)
	}
}
