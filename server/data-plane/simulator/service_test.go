package simulator

import (
	"context"
	"testing"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/data-plane/ingest"
	"github.com/kennguy3n/kseal/server/shared/risk"
)

func seed(t *testing.T) ingest.AnalyticsStore {
	t.Helper()
	store := ingest.NewInMemoryAnalyticsStore()
	var events []ingest.StoredEvent
	// 8 clean, 2 rooted devices.
	for i := 0; i < 8; i++ {
		events = append(events, ingest.StoredEvent{TenantID: "t1", AppID: "a1", RiskBits: 0, TimeBucket: int64(i)})
	}
	for i := 0; i < 2; i++ {
		events = append(events, ingest.StoredEvent{TenantID: "t1", AppID: "a1", RiskBits: risk.BitRootJailbreak | risk.BitHooking, TimeBucket: int64(100 + i)})
	}
	if err := store.Write(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestSimulateDiff(t *testing.T) {
	store := seed(t)
	sim := New(store)

	current := PolicySpec{Mode: ksealv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE}
	// Candidate blocks: same scoring but BLOCK mode, low thresholds so rooted -> critical.
	candidate := PolicySpec{
		Mode:       ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK,
		Thresholds: map[string]uint32{"CRITICAL": 1},
	}

	report, err := sim.Simulate(context.Background(), "t1", "a1", 0, 0, current, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if report.Total != 10 {
		t.Fatalf("total = %d", report.Total)
	}
	// Under observe everything is allowed; candidate blocks the 2 rooted devices.
	if report.NewlyBlocked != 2 {
		t.Fatalf("newly blocked = %d, want 2", report.NewlyBlocked)
	}
	if report.CurrentCounts[ksealv1.RequestProofResult_DECISION_DENY] != 0 {
		t.Fatal("observe mode should never deny")
	}
}

func TestSimulateEmptyRange(t *testing.T) {
	sim := New(ingest.NewInMemoryAnalyticsStore())
	report, err := sim.Simulate(context.Background(), "t1", "a1", 0, 0, PolicySpec{}, PolicySpec{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Total != 0 || report.Changed != 0 {
		t.Fatalf("expected empty report, got %+v", report)
	}
}
