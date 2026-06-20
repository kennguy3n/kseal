package mastg

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "update golden files")

func fixtureCatalog(t *testing.T) *Catalog {
	t.Helper()
	md, err := os.ReadFile(filepath.Join("testdata", "catalog.md"))
	if err != nil {
		t.Fatal(err)
	}
	cat, err := ParseCatalog(string(md))
	if err != nil {
		t.Fatalf("parse fixture catalog: %v", err)
	}
	return cat
}

func TestParseCatalogStructure(t *testing.T) {
	cat := fixtureCatalog(t)
	if len(cat.Categories) != 2 {
		t.Fatalf("want 2 categories, got %d", len(cat.Categories))
	}
	storage, ok := findCategory(cat, "MASVS-STORAGE")
	if !ok {
		t.Fatal("missing MASVS-STORAGE")
	}
	if len(storage.Controls) != 3 {
		t.Fatalf("MASVS-STORAGE want 3 controls, got %d", len(storage.Controls))
	}
	if storage.Objective == "" {
		t.Error("objective not captured")
	}
}

func TestProcedureDerivation(t *testing.T) {
	procs := fixtureCatalog(t).Procedures()
	byID := map[string]Procedure{}
	for _, p := range procs {
		byID[p.ID] = p
	}

	logs := byID["MASVS-STORAGE/no-sensitive-data-in-logs"]
	if logs.Plane != PlaneDevice {
		t.Errorf("logs plane = %s, want device", logs.Plane)
	}
	if len(logs.MASTGTests) != 1 || logs.MASTGTests[0] != "MASTG-STORAGE" {
		t.Errorf("logs MASTG tests = %v", logs.MASTGTests)
	}

	secrets := byID["MASVS-STORAGE/no-secrets-in-app-storage"]
	if got := secrets.MASTGTests; len(got) != 2 || got[0] != "MASTG-RESILIENCE" || got[1] != "MASTG-STORAGE" {
		t.Errorf("secrets MASTG tests = %v, want sorted [MASTG-RESILIENCE MASTG-STORAGE]", got)
	}

	tenant := byID["MASVS-STORAGE/tenant-data-isolated-at-rest"]
	if tenant.Plane != PlaneServer {
		t.Errorf("tenant-isolated plane = %s, want server", tenant.Plane)
	}

	ser := byID["MASVS-CRYPTO/deterministic-serialization"]
	if ser.Plane != PlaneOther {
		t.Errorf("serialization plane = %s, want other (must not be misread as tenant)", ser.Plane)
	}
	if ser.Method != "Property test" {
		t.Errorf("serialization method = %q, want %q", ser.Method, "Property test")
	}
}

func TestParseCatalogUsesHeaderNamesAndIgnoresPhaseColumn(t *testing.T) {
	md := `## MASVS-AUTH

Objective: authentication controls are enforced.

| MASVS objective | kseal control | Phase | Module / component | MASTG verification |
|---|---|---|---|---|
| Proof binding | Request proof bound to build | P1/P2 | Rust trust core | MASTG-AUTH: replay request proof and assert deny |
`
	cat, err := ParseCatalog(md)
	if err != nil {
		t.Fatalf("parse catalog with phase column: %v", err)
	}
	ctrl := cat.Categories[0].Controls[0]
	if ctrl.Module != "Rust trust core" {
		t.Fatalf("module parsed from wrong column: %q", ctrl.Module)
	}
	if ctrl.MASTG != "MASTG-AUTH: replay request proof and assert deny" {
		t.Fatalf("mastg parsed from wrong column: %q", ctrl.MASTG)
	}
}

func TestRunDefaultsAreFailSafe(t *testing.T) {
	rep := fixtureCatalog(t).Run(&Evidence{}, RunOptions{})
	// No evidence: device procedures pending, others informational; nothing
	// passes or fails on its own.
	if rep.Summary[StatusPass] != 0 || rep.Summary[StatusFail] != 0 {
		t.Errorf("expected no pass/fail without evidence, got %+v", rep.Summary)
	}
	if rep.Gating.Blocked {
		t.Error("default run must not block the release")
	}
	if rep.Summary[StatusPending] == 0 {
		t.Error("expected device procedures to be pending")
	}
}

func TestRunRequirePassBlocksPending(t *testing.T) {
	rep := fixtureCatalog(t).Run(&Evidence{}, RunOptions{RequirePass: true})
	if !rep.Gating.Blocked {
		t.Fatal("require-pass should block pending device procedures")
	}
	if rep.Gating.Failed != 0 {
		t.Fatalf("require-pass should not synthesize failures: %+v", rep.Gating)
	}
	if rep.Gating.Pending == 0 || len(rep.Gating.PendingIDs) == 0 {
		t.Fatalf("pending device procedures should be reported: %+v", rep.Gating)
	}
}

func TestAssertionOverridesOverlayAndGates(t *testing.T) {
	ev := &Evidence{
		Release: "1.0",
		Results: []AssertedResult{
			{Match: "MASTG-STORAGE", Status: StatusObserved, Note: "area review"},
			{Match: "No sensitive data in logs", Status: StatusFail, Note: "PII leaked to logcat"},
		},
	}
	rep := fixtureCatalog(t).Run(ev, RunOptions{})
	var logs Result
	for _, r := range rep.Results {
		if r.Procedure.ID == "MASVS-STORAGE/no-sensitive-data-in-logs" {
			logs = r
		}
	}
	if logs.Status != StatusFail {
		t.Errorf("specific assertion must override bulk match: got %s", logs.Status)
	}
	if !rep.Gating.Blocked || rep.Gating.Failed != 1 {
		t.Errorf("a failed assertion must block: %+v", rep.Gating)
	}
}

func TestMASVSReportOverlayObserved(t *testing.T) {
	report := `{"categories":[{"name":"MASVS-STORAGE","controls":[
		{"objective":"No secrets in app storage","evidence":{"status":"evidenced"}}
	]}]}`
	ev := &Evidence{}
	if err := ev.MergeMASVSReport([]byte(report)); err != nil {
		t.Fatal(err)
	}
	rep := fixtureCatalog(t).Run(ev, RunOptions{})
	for _, r := range rep.Results {
		if r.Procedure.ID == "MASVS-STORAGE/no-secrets-in-app-storage" {
			if r.Status != StatusObserved {
				t.Errorf("overlay should mark observed, got %s", r.Status)
			}
			return
		}
	}
	t.Fatal("control not found")
}

func TestLoadEvidenceRejectsBadStatus(t *testing.T) {
	if _, err := LoadEvidence([]byte(`{"results":[{"match":"x","status":"bogus"}]}`)); err == nil {
		t.Fatal("expected invalid status error")
	}
	if _, err := LoadEvidence([]byte(`{"results":[{"match":"","status":"pass"}]}`)); err == nil {
		t.Fatal("expected empty match error")
	}
	if _, err := LoadEvidence([]byte(`{"nope":1}`)); err == nil {
		t.Fatal("expected unknown-field error")
	}
}

func TestLoadEvidenceAcceptsAllExplicitStatuses(t *testing.T) {
	ev, err := LoadEvidence([]byte(`{"release":"fixture","results":[
		{"match":"logs","status":"pass","note":"device passed"},
		{"match":"storage","status":"fail","note":"device failed"},
		{"match":"crypto","status":"pending","note":"lab queued"},
		{"match":"serialization","status":"not-applicable","note":"not shipped"}
	]}`))
	if err != nil {
		t.Fatalf("load evidence: %v", err)
	}
	if len(ev.Results) != 4 {
		t.Fatalf("results=%d, want 4", len(ev.Results))
	}
}

func TestGolden(t *testing.T) {
	cat := fixtureCatalog(t)
	base := cat.Run(&Evidence{}, RunOptions{})
	assertGolden(t, "report-base.md", base.Markdown())

	ev := &Evidence{
		Release:   "2.0",
		Platform:  "android",
		BuildHash: "abc123",
		Results: []AssertedResult{
			{Match: "No sensitive data in logs", Status: StatusPass, Note: "logcat clean"},
			{Match: "MASTG-CRYPTO", Status: StatusObserved, Note: "algorithm review"},
		},
	}
	overlay := `{"categories":[{"name":"MASVS-STORAGE","controls":[{"objective":"No secrets in app storage","evidence":{"status":"partial"}}]}]}`
	if err := ev.MergeMASVSReport([]byte(overlay)); err != nil {
		t.Fatal(err)
	}
	rep := cat.Run(ev, RunOptions{})
	jsonBytes, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "report-evidenced.json", jsonBytes)
	assertGolden(t, "report-evidenced.md", rep.Markdown())

	failed := cat.Run(&Evidence{
		Release: "2.1",
		Results: []AssertedResult{
			{Match: "No sensitive data in logs", Status: StatusFail, Note: "PII leaked to logcat"},
		},
	}, RunOptions{})
	assertGolden(t, "report-failed.md", failed.Markdown())
}

func findCategory(c *Catalog, name string) (*Category, bool) {
	for i := range c.Categories {
		if c.Categories[i].Name == name {
			return &c.Categories[i], true
		}
	}
	return nil, false
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
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
