package xcprivacy

import (
	"encoding/xml"
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

func TestGenerateDefaultOmitsOptional(t *testing.T) {
	m := Generate(canonical(t), Options{})
	if m.Tracking {
		t.Error("kseal manifest must declare NSPrivacyTracking=false")
	}
	types := map[string]CollectedType{}
	for _, ct := range m.CollectedTypes {
		types[ct.Type] = ct
	}
	if _, ok := types["NSPrivacyCollectedDataTypeCoarseLocation"]; ok {
		t.Error("coarse location is off by default and must be omitted without --include-optional")
	}
	for _, want := range []string{"NSPrivacyCollectedDataTypeDeviceID", "NSPrivacyCollectedDataTypeOtherDiagnosticData"} {
		ct, ok := types[want]
		if !ok {
			t.Fatalf("missing collected data type %s", want)
		}
		if ct.Linked || ct.Tracking {
			t.Errorf("%s must be unlinked and non-tracking", want)
		}
	}
	if len(m.AccessedAPIs) != 2 {
		t.Fatalf("expected 2 required-reason APIs, got %d", len(m.AccessedAPIs))
	}
}

func TestGenerateIncludeOptional(t *testing.T) {
	m := Generate(canonical(t), Options{IncludeOptional: true})
	found := false
	for _, ct := range m.CollectedTypes {
		if ct.Type == "NSPrivacyCollectedDataTypeCoarseLocation" {
			found = true
			if !ct.Optional {
				t.Error("coarse location should be marked optional")
			}
		}
	}
	if !found {
		t.Error("coarse location must be included with IncludeOptional")
	}
}

func TestXMLIsWellFormedAndDeterministic(t *testing.T) {
	m := Generate(canonical(t), Options{})
	xmlBytes := m.XML()
	if err := xml.Unmarshal(xmlBytes, new(struct {
		XMLName xml.Name `xml:"plist"`
	})); err != nil {
		t.Fatalf("generated manifest is not well-formed XML: %v", err)
	}
	// Determinism: regenerating yields identical bytes.
	if string(m.XML()) != string(xmlBytes) {
		t.Fatal("manifest XML is not deterministic")
	}
}

func TestXMLGolden(t *testing.T) {
	cases := map[string]Options{
		"default.xcprivacy":          {},
		"include-optional.xcprivacy": {IncludeOptional: true},
	}
	for name, opts := range cases {
		m := Generate(canonical(t), opts)
		assertGolden(t, name, m.XML())
	}
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
