package report

import (
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/kseal/tools/masvs-report/internal/buildproof"
	"github.com/kennguy3n/kseal/tools/masvs-report/internal/catalog"
)

const catalogMD = "## MASVS-STORAGE\n\nObjective: storage.\n\n" +
	"| MASVS objective | kseal control | Phase | Module | MASTG |\n|---|---|---|---|---|\n" +
	"| No secrets in app storage | No static secrets shipped | P1 | secret protection | static scan |\n" +
	"| Tenant data isolated at rest | Logical tenant_id | P1/P4 | control plane | cross-tenant read deny |\n\n" +
	"## MASVS-CODE\n\nObjective: code.\n\n" +
	"| MASVS objective | kseal control | Phase | Module | MASTG |\n|---|---|---|---|---|\n" +
	"| Memory safety in native | Rust core; CFI/MTE where supported | P1/P3 | build hardening | CFI/MTE flags present |\n" +
	"| Build provenance | Build proof records hashes | P3 | build proof | unregistered build flagged |\n\n" +
	"## MASVS-RESILIENCE\n\nObjective: resilience.\n\n" +
	"| MASVS objective | kseal control | Phase | Module | MASTG |\n|---|---|---|---|---|\n" +
	"| Obfuscation + polymorphism | Per-build polymorphic obfuscation | P3 | build plane | diff two builds |\n" +
	"| Anti-tamper / integrity | App-integrity + build-proof binding | P2/P3 | modules 1,2 | patch binary |\n"

const androidManifest = `{
  "schema":"kseal.build-proof/v1","platform":"android",
  "build_hash":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "app":{"package_id":"com.example.app","version_name":"1.4.2","version_code":142},
  "sdk":{"name":"kseal-android","version":"0.1.0"},
  "seed":{"digest":"5a5a5a5a5a5a5a5a","algorithm":"HKDF-SHA256"},
  "tooling":{"gradle":"8.11.1"},
  "transforms":[
    {"name":"native-library-harden","status":"applied","details":{"library_count":3,"summary":{"cfi_enabled":2,"cfi_unsupported":1,"mte_enabled":1}}},
    {"name":"polymorphism","status":"applied","details":{}},
    {"name":"string-resource-seal","status":"applied","details":{"count":12}}
  ],
  "artifacts":[{"path":"a","sha256":"1"}]
}`

const iosManifest = `{
  "schemaVersion":"1.0","platform":"ios","sdkVersion":"0.1.0",
  "buildHash":"4eb1bb423e5939c59577d78ad5a9e9c60af244367b808a12a7d53d1e408b933b",
  "versionName":"1.4.2","versionCode":142,
  "polymorphism":{"seedDigest":"60bf07c488aa","algorithm":"sha256-ctr"},
  "toolVersions":{"swift":"5.10"},
  "transforms":[
    {"kind":"string-obfuscation","algorithm":"seed-xor/sha256-ctr","count":3},
    {"kind":"macho-section-integrity","algorithm":"sha256","count":2,"detail":{"slices":"1","format":"macho"}}
  ],
  "modules":["string-hardening","polymorphism","build-proof","macho-section-integrity"],
  "integrity":{"format":"macho","slices":[{"arch":"arm64","fileType":"execute","pie":true,"encrypted":false,"sections":[{"hash":"x"},{"hash":""}]}]}
}`

func fixedGen() *Generator {
	return &Generator{Now: func() time.Time { return time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC) }}
}

func generate(t *testing.T, manifestJSON string) *Report {
	t.Helper()
	m, err := buildproof.Parse([]byte(manifestJSON))
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	cat, err := catalog.Parse(catalogMD)
	if err != nil {
		t.Fatalf("parse catalog: %v", err)
	}
	return fixedGen().Generate(m, cat)
}

// evidenceFor returns the evidence for a control objective in a category.
func evidenceFor(r *Report, category, objective string) (Evidence, bool) {
	for _, c := range r.Categories {
		if c.Name != category {
			continue
		}
		for _, ctl := range c.Controls {
			if ctl.Objective == objective {
				return ctl.Evidence, true
			}
		}
	}
	return Evidence{}, false
}

func TestAndroidEvidenceMapping(t *testing.T) {
	r := generate(t, androidManifest)

	cases := []struct {
		cat, obj, status string
		mustContain      string
	}{
		{"MASVS-CODE", "Memory safety in native", StatusEvidenced, "CFI enabled=2"},
		{"MASVS-CODE", "Build provenance", StatusEvidenced, "kseal.build-proof/v1"},
		{"MASVS-RESILIENCE", "Obfuscation + polymorphism", StatusEvidenced, "polymorphism seed"},
		{"MASVS-RESILIENCE", "Anti-tamper / integrity", StatusEvidenced, "build_hash"},
		{"MASVS-STORAGE", "No secrets in app storage", StatusEvidenced, "sealed"},
		{"MASVS-STORAGE", "Tenant data isolated at rest", StatusInformational, "another plane"},
	}
	for _, c := range cases {
		ev, ok := evidenceFor(r, c.cat, c.obj)
		if !ok {
			t.Errorf("%s/%s: control not found", c.cat, c.obj)
			continue
		}
		if ev.Status != c.status {
			t.Errorf("%s/%s: status = %q, want %q (detail: %s)", c.cat, c.obj, ev.Status, c.status, ev.Detail)
		}
		if !strings.Contains(ev.Detail, c.mustContain) {
			t.Errorf("%s/%s: detail %q missing %q", c.cat, c.obj, ev.Detail, c.mustContain)
		}
	}
	if r.Summary.EvidencedControls != 5 {
		t.Errorf("evidenced = %d, want 5", r.Summary.EvidencedControls)
	}
}

func TestIOSEvidenceMapping(t *testing.T) {
	r := generate(t, iosManifest)

	// Mach-O integrity is the strong anti-tamper evidence on iOS.
	if ev, _ := evidenceFor(r, "MASVS-RESILIENCE", "Anti-tamper / integrity"); ev.Status != StatusEvidenced || !strings.Contains(ev.Detail, "Mach-O section-hash") {
		t.Errorf("ios anti-tamper = %+v", ev)
	}
	// iOS has no native .so plane: memory-safety-in-native is not-applicable, not absent.
	if ev, _ := evidenceFor(r, "MASVS-CODE", "Memory safety in native"); ev.Status != StatusNotApplicable {
		t.Errorf("ios native memory = %+v, want not-applicable", ev)
	}
	if ev, _ := evidenceFor(r, "MASVS-STORAGE", "No secrets in app storage"); ev.Status != StatusEvidenced {
		t.Errorf("ios secrets = %+v", ev)
	}
}

// A build with no native hardening must report memory-safety as absent (Android)
// — i.e. a missing control is reflected, not silently passed.
func TestMissingNativeReflectedAsAbsent(t *testing.T) {
	const noNative = `{"schema":"kseal.build-proof/v1","platform":"android","build_hash":"h","app":{},"sdk":{},"seed":{"digest":"d"},"transforms":[{"name":"polymorphism","status":"applied","details":{}}],"artifacts":[]}`
	r := generate(t, noNative)
	ev, _ := evidenceFor(r, "MASVS-CODE", "Memory safety in native")
	if ev.Status != StatusAbsent {
		t.Errorf("status = %q, want absent", ev.Status)
	}
}

// A native step that ran but found nothing must be reported as skipped, never
// silently dropped (the "toolchain unsupported → reported, not skipped" path).
func TestSkippedNativeReflectedAsSkipped(t *testing.T) {
	const skipped = `{"schema":"kseal.build-proof/v1","platform":"android","build_hash":"h","app":{},"sdk":{},"seed":{"digest":"d"},"transforms":[{"name":"native-library-harden","status":"skipped","details":{}}],"artifacts":[]}`
	r := generate(t, skipped)
	ev, _ := evidenceFor(r, "MASVS-CODE", "Memory safety in native")
	if ev.Status != StatusSkipped {
		t.Errorf("status = %q, want skipped; detail %q", ev.Status, ev.Detail)
	}
}

// Altering the catalog so a rule's target control disappears must surface the
// evidence as orphaned rather than dropping it.
func TestAlteredCatalogProducesOrphan(t *testing.T) {
	altered := strings.Replace(catalogMD, "Build provenance", "Renamed provenance control", 1)
	m, err := buildproof.Parse([]byte(androidManifest))
	if err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Parse(altered)
	if err != nil {
		t.Fatal(err)
	}
	r := fixedGen().Generate(m, cat)
	found := false
	for _, o := range r.Orphans {
		if o.Category == "MASVS-CODE" && o.Expected == "Build provenance" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected orphan for renamed 'Build provenance' control; orphans=%+v", r.Orphans)
	}
}

func TestMarkdownAndJSONRender(t *testing.T) {
	r := generate(t, androidManifest)

	md := r.Markdown()
	for _, want := range []string{
		"# kseal — MASVS Evidence Report",
		"## MASVS-RESILIENCE",
		"Build hash | `9f86d081884c",
		"evidenced",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	// Cells must not break the table: details with pipes are escaped.
	if strings.Count(md, "\n|") < 10 {
		t.Error("markdown tables look malformed")
	}

	js, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `"generatedAt": "2026-06-13T00:00:00Z"`) {
		t.Error("JSON missing fixed generatedAt")
	}
	// Deterministic: two renders are byte-identical.
	js2, _ := r.JSON()
	if string(js) != string(js2) {
		t.Error("JSON render is not deterministic")
	}
}
