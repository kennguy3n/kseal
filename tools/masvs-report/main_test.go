package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cliCatalog = "## MASVS-CODE\n\nObjective: code.\n\n" +
	"| MASVS objective | kseal control | Module | MASTG |\n|---|---|---|---|\n" +
	"| Build provenance | Build proof records hashes | build proof | unregistered build flagged |\n"

const cliManifest = `{"schema":"kseal.build-proof/v1","platform":"android","build_hash":"abc123abc123",
"app":{"package_id":"com.example","version_name":"1.0","version_code":1},"sdk":{"version":"0.1.0"},
"seed":{"digest":"dd"},"transforms":[{"name":"polymorphism","status":"applied","details":{}}],"artifacts":[]}`

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunWritesReports(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "manifest.json")
	catalog := filepath.Join(dir, "catalog.md")
	if err := os.WriteFile(manifest, []byte(cliManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalog, []byte(cliCatalog), 0o644); err != nil {
		t.Fatal(err)
	}
	md := filepath.Join(dir, "out", "report.md")
	js := filepath.Join(dir, "out", "report.json")

	if err := run([]string{"-manifest", manifest, "-catalog", catalog, "-out-md", md, "-out-json", js}); err != nil {
		t.Fatalf("run: %v", err)
	}
	mdData, err := os.ReadFile(md)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mdData), "Build provenance") {
		t.Error("markdown missing evidenced control")
	}
	jsData, err := os.ReadFile(js)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(jsData), `"platform": "android"`) {
		t.Error("json missing platform")
	}
}

func TestRunRequiresManifest(t *testing.T) {
	if err := run([]string{"-catalog", "x.md"}); err == nil {
		t.Fatal("expected error when -manifest missing")
	}
}

func TestRunRejectsBadManifest(t *testing.T) {
	manifest := writeTemp(t, "bad.json", `{"nope":true}`)
	catalog := writeTemp(t, "catalog.md", cliCatalog)
	if err := run([]string{"-manifest", manifest, "-catalog", catalog}); err == nil {
		t.Fatal("expected error for unrecognized manifest schema")
	}
}
