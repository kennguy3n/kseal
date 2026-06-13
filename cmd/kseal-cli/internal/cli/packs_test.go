package cli

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// TestLoadPacks_AllValid asserts every bundled pack loads, validates, and
// composes into a valid authoring document — the contract that lets `apply`
// trust the embedded data without re-checking at every call site.
func TestLoadPacks_AllValid(t *testing.T) {
	packs, err := loadPacks()
	if err != nil {
		t.Fatalf("loadPacks: %v", err)
	}
	wantIDs := map[string]bool{"fintech": false, "gaming": false, "health": false, "media": false}
	for _, p := range packs {
		if _, ok := wantIDs[p.ID]; !ok {
			t.Errorf("unexpected pack id %q", p.ID)
		}
		wantIDs[p.ID] = true
		if problems := p.validate(); len(problems) > 0 {
			t.Errorf("pack %s invalid: %v", p.ID, problems)
		}
		pf, err := p.toPolicyFile(p.defaultPolicyName(), "")
		if err != nil {
			t.Fatalf("pack %s toPolicyFile: %v", p.ID, err)
		}
		if problems := pf.Validate(); len(problems) > 0 {
			t.Errorf("pack %s composed policy invalid: %v", p.ID, problems)
		}
	}
	for id, seen := range wantIDs {
		if !seen {
			t.Errorf("missing expected pack %q", id)
		}
	}
}

func TestFindPack_UnknownIsUsageError(t *testing.T) {
	_, err := findPack("nope")
	if err == nil {
		t.Fatal("expected error for unknown pack")
	}
	if ExitCode(err) != ExitUsage {
		t.Fatalf("unknown pack should be a usage error, got exit %d", ExitCode(err))
	}
}

// TestPackToPolicyFile_RoundTrip verifies signal_weights and thresholds survive
// composition into the exact JSON shape the server stores, so a pack scores
// identically to a hand-authored policy.
func TestPackToPolicyFile_RoundTrip(t *testing.T) {
	pack := PolicyPack{
		ID: "x", Name: "x", EnforcementMode: "block",
		ModulesEnabled: []string{"rasp"},
		RiskThresholds: map[string]uint32{"HIGH_RISK": 90},
		SignalWeights:  map[string]uint32{"4": 65},
	}
	pf, err := pack.toPolicyFile("p", "app-1")
	if err != nil {
		t.Fatalf("toPolicyFile: %v", err)
	}
	weights, th, err := pf.scoringTables()
	if err != nil {
		t.Fatalf("scoringTables: %v", err)
	}
	if weights[4] != 65 {
		t.Fatalf("weight bit 4 = %d, want 65", weights[4])
	}
	if th["HIGH_RISK"] != 90 {
		t.Fatalf("HIGH_RISK threshold = %d, want 90", th["HIGH_RISK"])
	}
	if pf.AppID != "app-1" {
		t.Fatalf("app id = %q, want app-1", pf.AppID)
	}
}

func TestDiffPolicy_AllFieldKinds(t *testing.T) {
	current := policyShape{
		Mode:       ksealv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE,
		Thresholds: map[string]uint32{"HIGH_RISK": 90, "LOW_RISK": 20},
		Weights:    map[uint32]uint32{0: 40, 4: 60},
		Modules:    []string{"rasp", "integrity"},
	}
	candidate := policyShape{
		Mode:       ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK,
		Thresholds: map[string]uint32{"HIGH_RISK": 70, "LOW_RISK": 20},
		Weights:    map[uint32]uint32{0: 50, 4: 60},
		Modules:    []string{"rasp", "attestation"},
	}
	diff := diffPolicy("x", current, candidate)
	if !diff.HasChanges() {
		t.Fatal("expected changes")
	}
	byField := map[string]FieldChange{}
	for _, ch := range diff.Changes {
		byField[ch.Field] = ch
	}
	if c := byField["enforcement_mode"]; c.From != "observe" || c.To != "block" {
		t.Errorf("mode change = %+v", c)
	}
	if c := byField["risk_thresholds.HIGH_RISK"]; c.From != "90" || c.To != "70" {
		t.Errorf("HIGH_RISK change = %+v", c)
	}
	if _, ok := byField["risk_thresholds.LOW_RISK"]; ok {
		t.Error("unchanged LOW_RISK threshold should not appear")
	}
	if c := byField["signal_weights.0"]; c.From != "40" || c.To != "50" {
		t.Errorf("weight 0 change = %+v", c)
	}
	if _, ok := byField["signal_weights.4"]; ok {
		t.Error("unchanged weight 4 should not appear")
	}
	if c := byField["modules_enabled.+"]; c.To != "attestation" {
		t.Errorf("module add = %+v", c)
	}
	if c := byField["modules_enabled.-"]; c.From != "integrity" {
		t.Errorf("module remove = %+v", c)
	}
}

// TestDiffPolicy_Identical confirms diffing a pack against an identical policy
// yields no changes — the basis for idempotent bulk apply.
func TestDiffPolicy_Identical(t *testing.T) {
	pack, err := findPack("fintech")
	if err != nil {
		t.Fatal(err)
	}
	shape, err := pack.shape()
	if err != nil {
		t.Fatal(err)
	}
	diff := diffPolicy(pack.ID, shape, shape)
	if diff.HasChanges() {
		t.Fatalf("identical shapes should not diff: %+v", diff.Changes)
	}
}

func TestCanonLevel(t *testing.T) {
	cases := map[string]string{
		"HIGH_RISK":             "HIGH_RISK",
		"TRUST_LEVEL_HIGH_RISK": "HIGH_RISK",
		"  low_risk ":           "LOW_RISK",
	}
	for in, want := range cases {
		if got := canonLevel(in); got != want {
			t.Errorf("canonLevel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveTenantSelection(t *testing.T) {
	// CSV + file merge with de-dup and order preservation.
	file := writeFile(t, "tenants.txt", "t2\n# comment\n\nt3\nt1\n")
	got, err := resolveTenantSelection("t1, t2 ,t1", file)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want := []string{"t1", "t2", "t3"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	if _, err := resolveTenantSelection("", ""); err == nil {
		t.Fatal("expected error for empty selection")
	} else if ExitCode(err) != ExitUsage {
		t.Fatalf("empty selection should be usage error, got exit %d", ExitCode(err))
	}
}

// ---- integration tests against the in-process server ----

func TestPackApply_CreatesAndActivates(t *testing.T) {
	ts := newTestServer(t)

	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "policy", "pack", "apply", "fintech", "--activate")
	if code != ExitOK {
		t.Fatalf("apply exit=%d out=%s", code, out)
	}
	var created policyView
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if created.ID == "" || !created.IsActive {
		t.Fatalf("expected active policy, got %+v", created)
	}
	if created.EnforcementMode != "ENFORCEMENT_MODE_BLOCK" {
		t.Fatalf("fintech pack should be block mode, got %q", created.EnforcementMode)
	}

	// The active policy now matches the pack: a fresh diff must be empty.
	diffOut, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "policy", "pack", "diff", "fintech")
	if code != ExitOK {
		t.Fatalf("diff exit=%d out=%s", code, diffOut)
	}
	var diff PackDiff
	if err := json.Unmarshal([]byte(diffOut), &diff); err != nil {
		t.Fatalf("decode diff: %v\n%s", err, diffOut)
	}
	if diff.HasChanges() {
		t.Fatalf("diff after apply+activate should be empty, got %+v", diff.Changes)
	}
}

func TestPackApply_DryRunCreatesNothing(t *testing.T) {
	ts := newTestServer(t)

	_, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "--dry-run", "-o", "json", "policy", "pack", "apply", "gaming")
	if code != ExitOK {
		t.Fatalf("dry-run apply exit=%d", code)
	}
	policies, err := ts.Store.ListPolicies(context.Background(), ts.TenantID, "")
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	if len(policies) != 0 {
		t.Fatalf("dry-run must not create a policy, found %d", len(policies))
	}
}

func TestPackDiff_AgainstEmptyShowsChanges(t *testing.T) {
	ts := newTestServer(t)
	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "policy", "pack", "diff", "health")
	if code != ExitOK {
		t.Fatalf("diff exit=%d out=%s", code, out)
	}
	var diff PackDiff
	if err := json.Unmarshal([]byte(out), &diff); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if !diff.HasChanges() {
		t.Fatal("expected changes diffing against no active policy")
	}
}

func TestPackBulkApply_IdempotentAndFaultIsolated(t *testing.T) {
	ts := newTestServer(t)

	// A second tenant the operator key is NOT authorized for: the control plane
	// denies cross-tenant requests, so this must surface as a per-tenant error
	// without aborting the batch.
	other, err := ts.Store.CreateTenant(context.Background(), registry.CreateTenantInput{Name: "Other", Slug: "other", Tier: "growth"})
	if err != nil {
		t.Fatalf("seed other tenant: %v", err)
	}

	// Dry-run first: nothing is created, the authorized tenant is "would-apply".
	dryOut, _, code := ts.run(t, nil, "--dry-run", "-o", "json", "policy", "pack", "bulk-apply", "media",
		"--tenants", ts.TenantID+","+other.Id)
	if code != ExitOK {
		t.Fatalf("dry bulk exit=%d out=%s", code, dryOut)
	}
	var dry struct {
		Results []bulkResultView `json:"results"`
	}
	if err := json.Unmarshal([]byte(dryOut), &dry); err != nil {
		t.Fatalf("decode dry: %v\n%s", err, dryOut)
	}
	if len(dry.Results) != 2 {
		t.Fatalf("want 2 results, got %d", len(dry.Results))
	}
	if got := resultFor(dry.Results, ts.TenantID).Status; got != "would-apply" {
		t.Fatalf("authorized tenant dry status = %q, want would-apply", got)
	}
	if got := resultFor(dry.Results, other.Id).Status; got != "error" {
		t.Fatalf("cross-tenant dry status = %q, want error", got)
	}

	// Real apply: authorized tenant gets the policy created+activated.
	applyOut, _, code := ts.run(t, nil, "-o", "json", "policy", "pack", "bulk-apply", "media",
		"--tenants", ts.TenantID, "--activate")
	if code != ExitOK {
		t.Fatalf("bulk apply exit=%d out=%s", code, applyOut)
	}
	var applied struct {
		Results []bulkResultView `json:"results"`
	}
	if err := json.Unmarshal([]byte(applyOut), &applied); err != nil {
		t.Fatalf("decode applied: %v", err)
	}
	if got := resultFor(applied.Results, ts.TenantID); got.Status != "activated" || got.PolicyID == "" {
		t.Fatalf("apply result = %+v, want activated with policy id", got)
	}

	// Re-run: the active policy already matches, so the tenant is skipped.
	reOut, _, code := ts.run(t, nil, "-o", "json", "policy", "pack", "bulk-apply", "media", "--tenants", ts.TenantID)
	if code != ExitOK {
		t.Fatalf("re-run exit=%d out=%s", code, reOut)
	}
	var rerun struct {
		Results []bulkResultView `json:"results"`
	}
	if err := json.Unmarshal([]byte(reOut), &rerun); err != nil {
		t.Fatalf("decode rerun: %v", err)
	}
	if got := resultFor(rerun.Results, ts.TenantID).Status; got != "unchanged" {
		t.Fatalf("re-run status = %q, want unchanged (idempotent)", got)
	}
}

func resultFor(results []bulkResultView, tenant string) bulkResultView {
	for _, r := range results {
		if r.TenantID == tenant {
			return r
		}
	}
	return bulkResultView{}
}
