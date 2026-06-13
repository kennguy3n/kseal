package cli

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// updateGolden regenerates golden files when -update is passed:
//
//	go test ./... -run TestX -update
var updateGolden = flag.Bool("update", false, "update golden files")

// volatileKeys are fields whose values are non-deterministic (server-assigned
// ids/timestamps). They are normalized to fixed placeholders before golden
// comparison so the golden files assert structure and stable values only.
var volatileKeys = map[string]any{
	"id":         "<id>",
	"tenant_id":  "<tenant>",
	"created_at": 0,
	"updated_at": 0,
	"app_id":     "<app>",
}

// normalizeVolatile walks a decoded JSON value and replaces volatile fields.
func normalizeVolatile(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if repl, ok := volatileKeys[k]; ok {
				t[k] = repl
				continue
			}
			t[k] = normalizeVolatile(child)
		}
		return t
	case []any:
		for i, child := range t {
			t[i] = normalizeVolatile(child)
		}
		return t
	default:
		return v
	}
}

// assertGoldenJSON compares got (raw JSON bytes) against the named golden file
// after normalizing volatile fields. With -update it rewrites the golden file.
func assertGoldenJSON(t *testing.T, name string, got string) {
	t.Helper()
	var decoded any
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, got)
	}
	decoded = normalizeVolatile(decoded)
	norm, err := json.MarshalIndent(decoded, "", "  ")
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	norm = append(norm, '\n')

	path := filepath.Join("testdata", name)
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(path, norm, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update to create): %v", path, err)
	}
	if string(want) != string(norm) {
		t.Errorf("golden mismatch for %s:\n--- want ---\n%s\n--- got ---\n%s", name, want, norm)
	}
}
