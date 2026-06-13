package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunWritesFormAndSummary(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "data-safety.json")
	mdPath := filepath.Join(dir, "data-safety.md")

	if err := run([]string{"-out-json", jsonPath, "-out-md", mdPath}, os.Stdout, os.Stderr); err != nil {
		t.Fatalf("run: %v", err)
	}

	jb, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read json: %v", err)
	}
	var form map[string]any
	if err := json.Unmarshal(jb, &form); err != nil {
		t.Fatalf("form is not valid JSON: %v", err)
	}
	if form["encrypted_in_transit"] != true {
		t.Errorf("encrypted_in_transit = %v", form["encrypted_in_transit"])
	}

	mb, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read md: %v", err)
	}
	if !strings.Contains(string(mb), "Google Play Data Safety") {
		t.Errorf("markdown missing header:\n%s", mb)
	}
}

func TestRunRejectsMissingContract(t *testing.T) {
	if err := run([]string{"-contract", filepath.Join(t.TempDir(), "nope.json")}, os.Stdout, os.Stderr); err == nil {
		t.Fatal("expected error for missing contract")
	}
}
