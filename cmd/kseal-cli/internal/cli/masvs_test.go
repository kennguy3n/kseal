package cli

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

func TestNormalizeModule(t *testing.T) {
	cases := map[string]string{
		"anti-hooking": "antihooking",
		"anti_hooking": "antihooking",
		"antiHooking":  "antihooking",
		"  RASP ":      "rasp",
	}
	for in, want := range cases {
		if got := normalizeModule(in); got != want {
			t.Errorf("normalizeModule(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildMASVSReport_CoverageAndGaps(t *testing.T) {
	b := &ksealv1.Build{
		Id:          "b1",
		AppId:       "app-1",
		BuildHash:   "deadbeef",
		VersionName: "1.2.3",
		Manifest:    `{"modules":["rasp","attestation","anti-hooking"],"transforms":["polymorph"]}`,
	}
	rep := buildMASVSReport(b)

	if rep.BuildHash != "deadbeef" {
		t.Fatalf("build hash = %q", rep.BuildHash)
	}
	if rep.TotalCategories != len(masvsCategories) {
		t.Fatalf("total categories = %d", rep.TotalCategories)
	}

	covered := map[string]MASVSCategoryCoverage{}
	for _, c := range rep.Categories {
		covered[c.Category] = c
	}
	// attestation -> AUTH+NETWORK; rasp -> PLATFORM+RESILIENCE; anti-hooking -> RESILIENCE.
	for _, cat := range []string{"AUTH", "NETWORK", "PLATFORM", "RESILIENCE"} {
		if !covered[cat].Covered {
			t.Errorf("expected %s covered", cat)
		}
	}
	// STORAGE/CRYPTO/CODE/PRIVACY have no contributing module here -> gaps.
	for _, cat := range []string{"STORAGE", "CRYPTO", "CODE", "PRIVACY"} {
		if covered[cat].Covered {
			t.Errorf("expected %s to be a gap", cat)
		}
	}
	if rep.CoveredCount != 4 || len(rep.Gaps) != 4 {
		t.Fatalf("coverage = %d, gaps = %d", rep.CoveredCount, len(rep.Gaps))
	}
	// The honest-evidence note is always present.
	if len(rep.Notes) == 0 {
		t.Fatal("expected an evidence-limitation note")
	}
}

func TestBuildMASVSReport_EmptyManifestNoted(t *testing.T) {
	rep := buildMASVSReport(&ksealv1.Build{Id: "b", BuildHash: "abc"})
	if rep.CoveredCount != 0 {
		t.Fatalf("empty manifest should cover nothing, got %d", rep.CoveredCount)
	}
	if len(rep.Gaps) != len(masvsCategories) {
		t.Fatalf("all categories should be gaps, got %d", len(rep.Gaps))
	}
	foundEmptyNote := false
	for _, n := range rep.Notes {
		if n == "build manifest is empty: no module provenance to map; only the build-hash proof is available" {
			foundEmptyNote = true
		}
	}
	if !foundEmptyNote {
		t.Fatalf("missing empty-manifest note: %v", rep.Notes)
	}
}

func TestBuildMASVSReport_UnmappedModuleNoted(t *testing.T) {
	rep := buildMASVSReport(&ksealv1.Build{Manifest: `{"modules":["quantumshield"]}`})
	found := false
	for _, n := range rep.Notes {
		if n == `module "quantumshield" is not mapped to a MASVS category` {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unmapped-module note, got %v", rep.Notes)
	}
}

// TestBuildMASVS_Command exercises the command end-to-end against a seeded build.
func TestBuildMASVS_Command(t *testing.T) {
	ts := newTestServer(t)
	ctx := context.Background()
	app, err := ts.Store.CreateApp(ctx, registry.CreateAppInput{
		TenantID: ts.TenantID, Name: "App", Platform: ksealv1.Platform_PLATFORM_ANDROID, PackageID: "com.acme.app",
	})
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	build, err := ts.Store.CreateBuild(ctx, registry.CreateBuildInput{
		TenantID: ts.TenantID, AppID: app.GetId(), BuildHash: "cafef00d", VersionName: "2.0.0",
		Manifest: `{"modules":["rasp","integrity","crypto"],"tool":"gradle-plugin@1.0"}`,
	})
	if err != nil {
		t.Fatalf("create build: %v", err)
	}

	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "build", "masvs", build.GetId())
	if code != ExitOK {
		t.Fatalf("masvs exit=%d out=%s", code, out)
	}
	var rep MASVSReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if rep.BuildHash != "cafef00d" {
		t.Fatalf("build hash = %q", rep.BuildHash)
	}
	if len(rep.Modules) != 3 {
		t.Fatalf("modules = %v", rep.Modules)
	}
	// crypto -> CRYPTO, integrity -> CODE+RESILIENCE, rasp -> PLATFORM+RESILIENCE.
	want := map[string]bool{"CRYPTO": true, "CODE": true, "RESILIENCE": true, "PLATFORM": true}
	for _, c := range rep.Categories {
		if want[c.Category] && !c.Covered {
			t.Errorf("expected %s covered", c.Category)
		}
	}
}
