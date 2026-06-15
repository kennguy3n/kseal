package fleet

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

const (
	bitEmulator = uint64(1) << 2 // risk.BitEmulator
	bitRoot     = uint64(1) << 0 // risk.BitRootJailbreak
)

// clock is a manually-advanced time source for deterministic window tests.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Unix(1_700_000_000, 0)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func testConfig(clk *clock) Config {
	c := DefaultConfig()
	c.Window = 10 * time.Second // bucketSize = 1s
	c.Buckets = 10
	c.MinSamples = 50
	c.now = clk.now
	return c
}

const (
	testBuild  = "b1"
	testRegion = ""
)

// feedBucket observes `total` attestations in the current epoch, of which
// `withBit` assert `bit`.
func feedBucket(e *Engine, clk *clock, tenant, app string, bit uint64, total, withBit int) {
	for i := 0; i < total; i++ {
		var bits uint64
		if i < withBit {
			bits = bit
		}
		e.Observe(tenant, app, testBuild, testRegion, bits, clk.now())
	}
}

func TestColdStartTrip(t *testing.T) {
	clk := newClock()
	e := New(testConfig(clk))
	// No baseline yet; 40% emulator over 100 samples exceeds the cold-start floor.
	feedBucket(e, clk, "t1", "a1", bitEmulator, 100, 40)
	a := e.Assess("t1", "a1", testBuild, testRegion)
	if !a.Anomalous {
		t.Fatalf("expected cold-start anomaly, got %+v", a)
	}
	if len(a.Signals) != 1 || a.Signals[0].Name != "emulator" {
		t.Fatalf("expected emulator signal, got %+v", a.Signals)
	}
	if a.Signals[0].SurgeRatio != 0 {
		t.Fatalf("cold-start trip should report zero surge ratio, got %v", a.Signals[0].SurgeRatio)
	}
}

func TestMinSamplesGate(t *testing.T) {
	clk := newClock()
	e := New(testConfig(clk))
	// 100% emulator but only 10 samples — below MinSamples, must not trip.
	feedBucket(e, clk, "t1", "a1", bitEmulator, 10, 10)
	if a := e.Assess("t1", "a1", testBuild, testRegion); a.Anomalous {
		t.Fatalf("expected no anomaly below MinSamples, got %+v", a)
	}
}

func TestUnobservedScopeIsClean(t *testing.T) {
	clk := newClock()
	e := New(testConfig(clk))
	if a := e.Assess("nope", "nope", testBuild, testRegion); a.Anomalous || a.Observed != 0 {
		t.Fatalf("unobserved scope should be clean, got %+v", a)
	}
}

func TestBaselineLearnThenSurge(t *testing.T) {
	clk := newClock()
	e := New(testConfig(clk))
	// Phase 1: 20 buckets at a steady 5% emulator rate seeds a low baseline.
	for b := 0; b < 20; b++ {
		feedBucket(e, clk, "t1", "a1", bitEmulator, 100, 5)
		clk.advance(time.Second)
	}
	// A steady 5% rate must not trip (current ≈ baseline).
	if a := e.Assess("t1", "a1", testBuild, testRegion); a.Anomalous {
		t.Fatalf("steady baseline must not be anomalous, got %+v", a)
	}
	// Phase 2: a surge to 80% across a full window.
	for b := 0; b < 10; b++ {
		feedBucket(e, clk, "t1", "a1", bitEmulator, 100, 80)
		clk.advance(time.Second)
	}
	a := e.Assess("t1", "a1", testBuild, testRegion)
	if !a.Anomalous {
		t.Fatalf("expected surge anomaly, got %+v", a)
	}
	sig := a.Signals[0]
	if sig.Name != "emulator" {
		t.Fatalf("expected emulator, got %q", sig.Name)
	}
	if sig.SurgeRatio < 3 {
		t.Fatalf("expected surge ratio >= 3, got %v (baseline=%v current=%v)", sig.SurgeRatio, sig.Baseline, sig.CurrentRate)
	}
}

func TestAbsoluteFloorSuppressesTinyRates(t *testing.T) {
	clk := newClock()
	cfg := testConfig(clk)
	e := New(cfg)
	// Seed a tiny ~1% baseline.
	for b := 0; b < 20; b++ {
		feedBucket(e, clk, "t1", "a1", bitEmulator, 100, 1)
		clk.advance(time.Second)
	}
	// Rise to 5%: that's a 5x surge over baseline, but still below the 15%
	// absolute floor, so it must NOT trip (avoids noise on rare signals).
	for b := 0; b < 10; b++ {
		feedBucket(e, clk, "t1", "a1", bitEmulator, 100, 5)
		clk.advance(time.Second)
	}
	if a := e.Assess("t1", "a1", testBuild, testRegion); a.Anomalous {
		t.Fatalf("5%% rate below absolute floor must not trip, got %+v", a)
	}
}

func TestWindowRollClearsAnomaly(t *testing.T) {
	clk := newClock()
	e := New(testConfig(clk))
	// Cold-start surge trips immediately.
	feedBucket(e, clk, "t1", "a1", bitEmulator, 100, 60)
	if a := e.Assess("t1", "a1", testBuild, testRegion); !a.Anomalous {
		t.Fatalf("expected initial anomaly, got %+v", a)
	}
	// Advance a full window of clean buckets; the surge ages out.
	for b := 0; b < 11; b++ {
		clk.advance(time.Second)
		feedBucket(e, clk, "t1", "a1", bitEmulator, 100, 0)
	}
	if a := e.Assess("t1", "a1", testBuild, testRegion); a.Anomalous {
		t.Fatalf("expected anomaly to clear after window roll, got %+v", a)
	}
}

func TestSnapshotAndTenantSnapshot(t *testing.T) {
	clk := newClock()
	e := New(testConfig(clk))
	feedBucket(e, clk, "t1", "a1", bitEmulator, 100, 70)
	feedBucket(e, clk, "t2", "a9", bitRoot, 100, 70)
	feedBucket(e, clk, "t1", "a2", 0, 100, 0) // clean, must not appear

	all := e.Snapshot()
	if len(all) != 2 {
		t.Fatalf("expected 2 anomalous scopes, got %d: %+v", len(all), all)
	}
	t1 := e.TenantSnapshot("t1")
	if len(t1) != 1 || t1[0].AppID != "a1" {
		t.Fatalf("expected only t1/a1 in tenant snapshot, got %+v", t1)
	}
}

func TestLRUEvictionBoundsMemory(t *testing.T) {
	clk := newClock()
	cfg := testConfig(clk)
	cfg.MaxScopes = shardCount // per-shard cap of 1
	e := New(cfg)
	for i := 0; i < 5000; i++ {
		app := fmt.Sprintf("app-%d", i)
		e.Observe("t1", app, testBuild, testRegion, bitEmulator, clk.now())
	}
	total := 0
	for s := range e.shards {
		e.shards[s].mu.Lock()
		total += len(e.shards[s].byKey)
		if e.shards[s].lru.Len() != len(e.shards[s].byKey) {
			e.shards[s].mu.Unlock()
			t.Fatalf("shard %d lru/map mismatch: %d vs %d", s, e.shards[s].lru.Len(), len(e.shards[s].byKey))
		}
		e.shards[s].mu.Unlock()
	}
	if total > cfg.MaxScopes {
		t.Fatalf("tracked scopes %d exceeds MaxScopes %d", total, cfg.MaxScopes)
	}
	if total == 0 {
		t.Fatalf("expected some scopes tracked")
	}
}

func TestConcurrentObserveAssess(t *testing.T) {
	clk := newClock()
	e := New(testConfig(clk))
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			app := fmt.Sprintf("a%d", g%4)
			for i := 0; i < 1000; i++ {
				e.Observe("t1", app, testBuild, testRegion, bitEmulator, clk.now())
				_ = e.Assess("t1", app, testBuild, testRegion)
			}
		}(g)
	}
	wg.Wait()
	// A heavy emulator load should leave at least one app anomalous.
	if len(e.TenantSnapshot("t1")) == 0 {
		t.Fatalf("expected at least one anomalous app after concurrent load")
	}
}

func TestDefaultsApplied(t *testing.T) {
	e := New(Config{})
	if e.cfg.Window <= 0 || e.cfg.Buckets <= 0 || len(e.cfg.Signals) == 0 {
		t.Fatalf("defaults not applied: %+v", e.cfg)
	}
	if e.bucketSize != e.cfg.Window/time.Duration(e.cfg.Buckets) {
		t.Fatalf("bucketSize not derived from window/buckets")
	}
	if e.cfg.VelocityFactor <= 1 || e.cfg.VelocityMinVolume <= 0 || e.cfg.VelocityColdVolume <= 0 {
		t.Fatalf("velocity defaults not applied: %+v", e.cfg)
	}
}

// feedCohort observes `total` clean attestations for an explicit cohort.
func feedCohort(e *Engine, clk *clock, tenant, app, build, region string, total int) {
	for i := 0; i < total; i++ {
		e.Observe(tenant, app, build, region, 0, clk.now())
	}
}

func TestVelocitySurgeOnVolumeSpike(t *testing.T) {
	clk := newClock()
	e := New(testConfig(clk))
	// Seed a steady low arrival baseline of 20 clean attestations/bucket for
	// long enough to seed the volume baseline (> Buckets buckets recycle).
	for b := 0; b < 15; b++ {
		feedBucket(e, clk, "t1", "a1", 0, 20, 0)
		clk.advance(time.Second)
	}
	// A sudden volume spike in the next bucket — every attestation is clean, so
	// only the volume velocity (not any signal) can detect it.
	feedBucket(e, clk, "t1", "a1", 0, 2000, 0)
	a := e.Assess("t1", "a1", testBuild, testRegion)
	if !a.Anomalous || !a.VelocitySurge {
		t.Fatalf("expected velocity surge, got %+v", a)
	}
	if len(a.Signals) != 0 {
		t.Fatalf("velocity surge must carry no per-signal trips, got %+v", a.Signals)
	}
	if a.VelocityRatio < float64(e.cfg.VelocityFactor) {
		t.Fatalf("expected velocity ratio >= %v, got %v", e.cfg.VelocityFactor, a.VelocityRatio)
	}
}

func TestColdStartVelocityFlood(t *testing.T) {
	clk := newClock()
	cfg := testConfig(clk)
	e := New(cfg)
	// A brand-new cohort with no baseline floods past the cold-start volume in a
	// single window — the classic "thousands of siblings appear at once".
	feedBucket(e, clk, "t1", "a1", 0, cfg.VelocityColdVolume+50, 0)
	a := e.Assess("t1", "a1", testBuild, testRegion)
	if !a.Anomalous || !a.VelocitySurge {
		t.Fatalf("expected cold-start velocity flood to trip, got %+v", a)
	}
}

func TestCohortIsolationByBuildAndRegion(t *testing.T) {
	clk := newClock()
	e := New(testConfig(clk))
	// A surge confined to build "bad" / region "US" must not implicate the same
	// app's other build/region cohorts.
	for i := 0; i < 100; i++ {
		bits := uint64(0)
		if i < 70 {
			bits = bitEmulator
		}
		e.Observe("t1", "a1", "bad", "US", bits, clk.now())
	}
	feedCohort(e, clk, "t1", "a1", "good", "US", 100)

	if a := e.Assess("t1", "a1", "bad", "US"); !a.Anomalous {
		t.Fatalf("expected surging cohort to be anomalous, got %+v", a)
	}
	if a := e.Assess("t1", "a1", "good", "US"); a.Anomalous {
		t.Fatalf("clean cohort must not inherit another cohort's surge, got %+v", a)
	}

	anomalies := e.TenantSnapshot("t1")
	if len(anomalies) != 1 || anomalies[0].BuildHash != "bad" || anomalies[0].Region != "US" {
		t.Fatalf("expected exactly the bad/US cohort, got %+v", anomalies)
	}
}
