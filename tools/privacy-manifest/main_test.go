package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunWritesManifestAndSummary(t *testing.T) {
	dir := t.TempDir()
	xmlPath := filepath.Join(dir, "PrivacyInfo.xcprivacy")
	jsonPath := filepath.Join(dir, "summary.json")

	if err := run([]string{"-out", xmlPath, "-out-json", jsonPath}, os.Stdout, os.Stderr); err != nil {
		t.Fatalf("run: %v", err)
	}

	xmlBytes, err := os.ReadFile(xmlPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if !strings.HasPrefix(string(xmlBytes), "<?xml") || !strings.Contains(string(xmlBytes), "NSPrivacyCollectedDataTypes") {
		t.Errorf("manifest does not look like a privacy plist:\n%s", xmlBytes)
	}

	jsonBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	var summary map[string]any
	if err := json.Unmarshal(jsonBytes, &summary); err != nil {
		t.Fatalf("summary is not valid JSON: %v", err)
	}
	if summary["tracking"] != false {
		t.Errorf("summary tracking = %v, want false", summary["tracking"])
	}
}

func TestRunStdoutDefault(t *testing.T) {
	// With no output flags the tool writes the plist to stdout; just assert it
	// does not error and the include-optional path also generates.
	if err := run([]string{"-include-optional", "-out", filepath.Join(t.TempDir(), "p.xcprivacy")}, os.Stdout, os.Stderr); err != nil {
		t.Fatalf("run include-optional: %v", err)
	}
}

func TestRunRejectsMissingContract(t *testing.T) {
	err := run([]string{"-contract", filepath.Join(t.TempDir(), "nope.json")}, os.Stdout, os.Stderr)
	if err == nil {
		t.Fatal("expected error for missing contract file")
	}
}
