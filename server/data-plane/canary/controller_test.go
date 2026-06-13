package canary

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/kennguy3n/kseal/server/control-plane/compliance"
	"github.com/kennguy3n/kseal/server/control-plane/registry"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

type fakeHealth struct {
	rate    float64
	samples int64
}

func (f fakeHealth) CanaryHealth(_, _, _ string) (float64, int64) { return f.rate, f.samples }

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newCanaryStore(t *testing.T) *compliance.MemStore {
	t.Helper()
	return compliance.NewMemStore(registry.NewMemStore())
}

func setCanary(t *testing.T, s *compliance.MemStore, percent uint32, threshold float64) {
	t.Helper()
	if _, err := s.SetCanary(context.Background(), compliance.CanaryInput{
		TenantID: "t1", AppID: "app1", CandidatePolicyID: "cand", StablePolicyID: "stable",
		Percent: percent, RollbackThreshold: threshold,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestControllerRollsBackOnBreach(t *testing.T) {
	ctx := context.Background()
	store := newCanaryStore(t)
	setCanary(t, store, 20, 0.05)
	reg := NewRegistry()
	ctl := NewController(store, fakeHealth{rate: 0.5, samples: 100}, reg, Config{MinSamples: 20, Logger: quietLogger()})

	ctl.evaluateOnce(ctx)

	cs, err := store.GetCanary(ctx, "t1", "app1")
	if err != nil {
		t.Fatal(err)
	}
	if cs.State != ksealv1.CanaryState_CANARY_STATE_ROLLED_BACK {
		t.Fatalf("expected rollback on breach, state=%v", cs.State)
	}
	if cs.BlockRate != 0.5 || cs.SampleCount != 100 {
		t.Fatalf("rollback should record observed health, got %+v", cs)
	}
}

func TestControllerNoRollbackBelowThreshold(t *testing.T) {
	ctx := context.Background()
	store := newCanaryStore(t)
	setCanary(t, store, 20, 0.05)
	ctl := NewController(store, fakeHealth{rate: 0.01, samples: 100}, NewRegistry(), Config{MinSamples: 20, Logger: quietLogger()})

	ctl.evaluateOnce(ctx)

	cs, _ := store.GetCanary(ctx, "t1", "app1")
	if cs.State != ksealv1.CanaryState_CANARY_STATE_ACTIVE {
		t.Fatalf("healthy canary must stay active, state=%v", cs.State)
	}
}

func TestControllerNoRollbackBelowMinSamples(t *testing.T) {
	ctx := context.Background()
	store := newCanaryStore(t)
	setCanary(t, store, 20, 0.05)
	// Block rate is high but sample count is below the statistical floor.
	ctl := NewController(store, fakeHealth{rate: 0.9, samples: 3}, NewRegistry(), Config{MinSamples: 20, Logger: quietLogger()})

	ctl.evaluateOnce(ctx)

	cs, _ := store.GetCanary(ctx, "t1", "app1")
	if cs.State != ksealv1.CanaryState_CANARY_STATE_ACTIVE {
		t.Fatalf("must not roll back on too few samples, state=%v", cs.State)
	}
}

func TestControllerRefreshesRegistrySnapshot(t *testing.T) {
	ctx := context.Background()
	store := newCanaryStore(t)
	setCanary(t, store, 100, 0.05)
	reg := NewRegistry()
	ctl := NewController(store, fakeHealth{rate: 0, samples: 0}, reg, Config{MinSamples: 20, Logger: quietLogger()})

	ctl.evaluateOnce(ctx)

	id, candidate := reg.Cohort("t1", "app1", "inst")
	if !candidate || id != "cand" {
		t.Fatalf("controller should publish the active canary to the registry, got %q,%v", id, candidate)
	}
}
