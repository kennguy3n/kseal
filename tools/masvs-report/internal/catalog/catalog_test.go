package catalog

import "testing"

const sampleMD = "# kseal — MASVS Control Mapping\n\n" +
	"## Table of Contents\n\n- ignore me\n\n" +
	"## MASVS-CODE\n\n" +
	"Objective: dependency hygiene, secure defaults,\n" +
	"code quality.\n\n" +
	"| MASVS objective | kseal control | Phase | Module / component | MASTG verification |\n" +
	"|---|---|---|---|---|\n" +
	"| Memory safety in native | Rust core; CFI/MTE for native components where supported | P1/P3 | Rust core; build-time hardening | Build verification: CFI/MTE flags present |\n" +
	"| Build provenance | Build proof records hashes/manifests; runtime verifies | P3 | Build proof | Verify unregistered build |\n\n" +
	"---\n\n" +
	"## MASVS-RESILIENCE\n\n" +
	"Objective: obfuscation, anti-tamper.\n\n" +
	"| MASVS objective | kseal control | Phase | Module / component | MASTG verification |\n" +
	"|---|---|---|---|---|\n" +
	"| Obfuscation + polymorphism | Per-build polymorphic obfuscation | P3 | Build plane | diff two builds |\n\n" +
	"## Coverage Summary by Phase\n\n" +
	"| MASVS category | P0 | P1 |\n|---|---|---|\n| CODE | research | Partial |\n"

func TestParseExtractsCategoriesAndControls(t *testing.T) {
	cat, err := Parse(sampleMD)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cat.Categories) != 2 {
		t.Fatalf("categories = %d (%+v), want 2 (Coverage Summary must be ignored)", len(cat.Categories), cat.Categories)
	}
	code, ok := cat.Find("MASVS-CODE")
	if !ok {
		t.Fatal("MASVS-CODE not found")
	}
	if code.Objective != "dependency hygiene, secure defaults, code quality." {
		t.Errorf("wrapped objective not joined: %q", code.Objective)
	}
	if len(code.Controls) != 2 {
		t.Fatalf("CODE controls = %d, want 2", len(code.Controls))
	}
	if code.Controls[0].Objective != "Memory safety in native" || code.Controls[0].Phase != "P1/P3" {
		t.Errorf("control[0] = %+v", code.Controls[0])
	}
	if code.Controls[1].Control != "Build proof records hashes/manifests; runtime verifies" {
		t.Errorf("control[1] = %+v", code.Controls[1])
	}
}

func TestParseRejectsEmptyDoc(t *testing.T) {
	if _, err := Parse("# nothing here\n"); err == nil {
		t.Fatal("expected error when no MASVS-* categories present")
	}
}

func TestParseRejectsMalformedRow(t *testing.T) {
	bad := "## MASVS-CODE\n\n| MASVS objective | kseal control | Phase | Module | MASTG |\n|---|---|---|---|---|\n| only | three | cols |\n"
	if _, err := Parse(bad); err == nil {
		t.Fatal("expected error for row with too few columns")
	}
}
