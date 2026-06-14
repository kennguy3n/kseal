package ingest

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempFile(t *testing.T, contents string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClickHouseConfigDefaults(t *testing.T) {
	c := ClickHouseConfig{Addr: []string{"ch:9000"}}
	c.withDefaults()
	if c.Table != "telemetry_events" {
		t.Fatalf("default table = %q", c.Table)
	}
	if c.Database != "kseal" {
		t.Fatalf("default database = %q", c.Database)
	}
	if c.DialTimeout <= 0 || c.MaxOpenConns <= 0 || c.MaxIdleConns <= 0 {
		t.Fatalf("pool/timeout must default positive: %+v", c)
	}
}

func TestClickHouseConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     ClickHouseConfig
		wantErr bool
	}{
		{"no addr", ClickHouseConfig{}, true},
		{"ok", ClickHouseConfig{Addr: []string{"ch:9000"}}, false},
		{"unsafe table", ClickHouseConfig{Addr: []string{"ch:9000"}, Table: "events; DROP TABLE x"}, true},
		{"unsafe cluster", ClickHouseConfig{Addr: []string{"ch:9000"}, Cluster: "a b"}, true},
		{"negative ttl", ClickHouseConfig{Addr: []string{"ch:9000"}, RetentionTTLDays: -1}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.withDefaults()
			err := tc.cfg.validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("validate() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestIsSafeIdentifier(t *testing.T) {
	// The guard's job is SQL-injection safety: only [A-Za-z0-9_] is permitted,
	// so any whitespace, punctuation, or quoting is rejected.
	safe := []string{"telemetry_events", "events", "Tbl_1", "_x", "abc123"}
	unsafe := []string{"", "a.b", "ev ents", "ev;ents", "ev-ents", "events`", "drop table"}
	for _, s := range safe {
		if !isSafeIdentifier(s) {
			t.Errorf("expected %q to be safe", s)
		}
	}
	for _, s := range unsafe {
		if isSafeIdentifier(s) {
			t.Errorf("expected %q to be unsafe", s)
		}
	}
}
