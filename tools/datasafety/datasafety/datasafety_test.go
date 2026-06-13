package datasafety

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/kennguy3n/kseal/tools/privacy-manifest/contract"
)

var update = flag.Bool("update", false, "update golden files")

func canonical(t *testing.T) *contract.Contract {
	t.Helper()
	c, err := contract.Canonical()
	if err != nil {
		t.Fatalf("load contract: %v", err)
	}
	return c
}

func TestGenerateDefaultPosture(t *testing.T) {
	f := Generate(canonical(t), Options{})
	if !f.EncryptedInTransit {
		t.Error("encrypted_in_transit must be true")
	}
	if f.SharesData {
		t.Error("kseal must declare no third-party sharing")
	}
	if !f.CollectsData {
		t.Error("collects_data must be true (risk signals + install id)")
	}
	for _, d := range f.DataTypes {
		if d.DataType == "Approximate location" {
			t.Error("coarse location is off by default and must be omitted")
		}
		if d.Shared {
			t.Errorf("data type %q must not be shared", d.DataType)
		}
	}
}

func TestGenerateIncludeOptionalAddsLocation(t *testing.T) {
	f := Generate(canonical(t), Options{IncludeOptional: true})
	found := false
	for _, d := range f.DataTypes {
		if d.DataType == "Approximate location" {
			found = true
			if !d.Optional {
				t.Error("approximate location should be optional")
			}
		}
	}
	if !found {
		t.Error("approximate location must be present with IncludeOptional")
	}
}

func TestJSONIsValidAndDeterministic(t *testing.T) {
	f := Generate(canonical(t), Options{IncludeOptional: true})
	a, err := f.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	if err := json.Unmarshal(a, &probe); err != nil {
		t.Fatalf("form JSON is invalid: %v", err)
	}
	b, _ := f.JSON()
	if string(a) != string(b) {
		t.Fatal("form JSON is not deterministic")
	}
}

func TestGolden(t *testing.T) {
	cJSON, _ := Generate(canonical(t), Options{IncludeOptional: true}).JSON()
	assertGolden(t, "datasafety.json", cJSON)
	assertGolden(t, "datasafety-default.md", Generate(canonical(t), Options{}).Markdown())
	assertGolden(t, "datasafety-optional.md", Generate(canonical(t), Options{IncludeOptional: true}).Markdown())
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update): %v", path, err)
	}
	if string(want) != string(got) {
		t.Errorf("golden mismatch for %s:\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}
