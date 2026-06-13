package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const fixtureCatalog = "mastg/testdata/catalog.md"

func TestRunMarkdownNoEvidence(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.md")
	code, err := run([]string{"-catalog", fixtureCatalog, "-out", out}, os.Stdout, os.Stderr)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	data, rerr := os.ReadFile(out)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(data) == 0 {
		t.Fatal("empty report")
	}
}

func TestRunBlocksOnFailure(t *testing.T) {
	ev := filepath.Join(t.TempDir(), "ev.json")
	writeJSON(t, ev, map[string]any{
		"release": "1.0",
		"results": []map[string]any{
			{"match": "No sensitive data in logs", "status": "fail", "note": "leak"},
		},
	})
	code, err := run([]string{"-catalog", fixtureCatalog, "-evidence", ev, "-format", "json", "-out", filepath.Join(t.TempDir(), "r.json")}, os.Stdout, os.Stderr)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != exitBlocked {
		t.Fatalf("exit code = %d, want %d (blocked)", code, exitBlocked)
	}
}

func TestRunRejectsBadFormat(t *testing.T) {
	code, err := run([]string{"-catalog", fixtureCatalog, "-format", "yaml"}, os.Stdout, os.Stderr)
	if err == nil {
		t.Fatal("expected error for bad format")
	}
	if code != exitErr {
		t.Fatalf("exit code = %d, want %d", code, exitErr)
	}
}

func TestRunMissingCatalog(t *testing.T) {
	code, err := run([]string{"-catalog", filepath.Join(t.TempDir(), "nope.md")}, os.Stdout, os.Stderr)
	if err == nil {
		t.Fatal("expected error for missing catalog")
	}
	if code != exitErr {
		t.Fatalf("exit code = %d", code)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
