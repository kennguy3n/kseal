package canary

import (
	"testing"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

func active(tenant, app, cand, stable string, percent uint32) *ksealv1.CanaryStatus {
	return &ksealv1.CanaryStatus{
		TenantId: tenant, AppId: app, CandidatePolicyId: cand, StablePolicyId: stable,
		Percent: percent, State: ksealv1.CanaryState_CANARY_STATE_ACTIVE,
	}
}

func TestRegistryEmptyByDefault(t *testing.T) {
	r := NewRegistry()
	if _, ok := r.Lookup("t", "a"); ok {
		t.Fatal("empty registry must report no rollout")
	}
	if id, cand := r.Cohort("t", "a", "i"); id != "" || cand {
		t.Fatalf("empty registry cohort must be stable, got %q,%v", id, cand)
	}
}

func TestRegistryReplaceFiltersInactive(t *testing.T) {
	r := NewRegistry()
	rolledBack := active("t", "old", "c", "s", 50)
	rolledBack.State = ksealv1.CanaryState_CANARY_STATE_ROLLED_BACK
	r.Replace([]*ksealv1.CanaryStatus{
		active("t", "app1", "cand", "stable", 100),
		rolledBack,
	})
	if _, ok := r.Lookup("t", "app1"); !ok {
		t.Fatal("active rollout should be present")
	}
	if _, ok := r.Lookup("t", "old"); ok {
		t.Fatal("non-active rollout must be filtered out of the snapshot")
	}
}

func TestRegistryCohortSelection(t *testing.T) {
	r := NewRegistry()
	r.Replace([]*ksealv1.CanaryStatus{active("t", "app1", "cand", "stable", 100)})
	id, candidate := r.Cohort("t", "app1", "inst")
	if !candidate || id != "cand" {
		t.Fatalf("at 100%% instance must get candidate, got %q,%v", id, candidate)
	}

	r.Replace([]*ksealv1.CanaryStatus{active("t", "app1", "cand", "stable", 0)})
	id, candidate = r.Cohort("t", "app1", "inst")
	if candidate || id != "stable" {
		t.Fatalf("at 0%% instance must get stable, got %q,%v", id, candidate)
	}
}

func TestRegistryReplaceIsAtomicView(t *testing.T) {
	// A reader holding a prior lookup result is unaffected by a later Replace;
	// each Lookup reads the current published snapshot.
	r := NewRegistry()
	r.Replace([]*ksealv1.CanaryStatus{active("t", "app1", "c1", "s", 100)})
	a1, _ := r.Lookup("t", "app1")
	r.Replace([]*ksealv1.CanaryStatus{active("t", "app1", "c2", "s", 100)})
	a2, _ := r.Lookup("t", "app1")
	if a1.CandidatePolicyID != "c1" || a2.CandidatePolicyID != "c2" {
		t.Fatalf("snapshots should be independent: %q then %q", a1.CandidatePolicyID, a2.CandidatePolicyID)
	}
}
