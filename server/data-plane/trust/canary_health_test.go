package trust

import (
	"testing"

	"github.com/kennguy3n/kseal/server/control-plane/compliance"
	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/data-plane/canary"
	"github.com/kennguy3n/kseal/server/data-plane/guardrails"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	appconfig "github.com/kennguy3n/kseal/server/shared/config"
)

func flags(t *testing.T, spec string) appconfig.FeatureFlags {
	t.Helper()
	ff, err := appconfig.ParseFeatureFlags(spec)
	if err != nil {
		t.Fatal(err)
	}
	return ff
}

func canaryReg(tenant, app, cand string) *canary.Registry {
	r := canary.NewRegistry()
	r.Replace([]*ksealv1.CanaryStatus{{
		TenantId: tenant, AppId: app, CandidatePolicyId: cand, StablePolicyId: "stable",
		Percent: 100, State: ksealv1.CanaryState_CANARY_STATE_ACTIVE,
	}})
	return r
}

func TestRecordCanaryHealthAttributesToCohort(t *testing.T) {
	const tenant, app, cand = "t1", "app1", "cand"
	svc := NewService(registry.NewMemStore(), nil, nil, 0)
	det := guardrails.NewDetector(0)
	svc.AttachCanaryHealth(det, canaryReg(tenant, app, cand), flags(t, "*:"+compliance.FlagCanaryRollout+"=true"))

	// 8 denies + 2 allows on the candidate cohort -> 0.8 block rate.
	for i := 0; i < 8; i++ {
		svc.recordCanaryHealth(tenant, app, "inst", ksealv1.RequestProofResult_DECISION_DENY)
	}
	for i := 0; i < 2; i++ {
		svc.recordCanaryHealth(tenant, app, "inst", ksealv1.RequestProofResult_DECISION_ALLOW)
	}

	rate, total := det.Sample(tenant, app, cand)
	if total != 10 {
		t.Fatalf("expected 10 samples on candidate cohort, got %d", total)
	}
	if rate < 0.79 || rate > 0.81 {
		t.Fatalf("expected ~0.8 block rate, got %v", rate)
	}
}

func TestRecordCanaryHealthFlagGated(t *testing.T) {
	const tenant, app, cand = "t1", "app1", "cand"
	svc := NewService(registry.NewMemStore(), nil, nil, 0)
	det := guardrails.NewDetector(0)
	// Flag off: nothing recorded.
	svc.AttachCanaryHealth(det, canaryReg(tenant, app, cand), flags(t, ""))
	svc.recordCanaryHealth(tenant, app, "inst", ksealv1.RequestProofResult_DECISION_DENY)
	if _, total := det.Sample(tenant, app, cand); total != 0 {
		t.Fatalf("flag off must record nothing, got %d", total)
	}
}

func TestRecordCanaryHealthNoInstanceNoOp(t *testing.T) {
	const tenant, app, cand = "t1", "app1", "cand"
	svc := NewService(registry.NewMemStore(), nil, nil, 0)
	det := guardrails.NewDetector(0)
	svc.AttachCanaryHealth(det, canaryReg(tenant, app, cand), flags(t, "*:"+compliance.FlagCanaryRollout+"=true"))
	// Empty instance id -> no cohort attribution.
	svc.recordCanaryHealth(tenant, app, "", ksealv1.RequestProofResult_DECISION_DENY)
	if _, total := det.Sample(tenant, app, cand); total != 0 {
		t.Fatalf("empty instance must record nothing, got %d", total)
	}
}

func TestRecordCanaryHealthDisabledWithoutAttach(t *testing.T) {
	const tenant, app = "t1", "app1"
	svc := NewService(registry.NewMemStore(), nil, nil, 0)
	// No AttachCanaryHealth call -> detector is nil, must not panic.
	svc.recordCanaryHealth(tenant, app, "inst", ksealv1.RequestProofResult_DECISION_DENY)
}
