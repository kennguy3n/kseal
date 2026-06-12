package guardrails

import (
	"testing"
	"time"
)

// TestWindowExpiresOldTraffic proves the sliding window drops traffic older than
// the window: a burst of blocks measured long ago must not keep a now-healthy
// scope flagged, and the scope is pruned once it has no recent traffic.
func TestWindowExpiresOldTraffic(t *testing.T) {
	d := NewDetector(0.05)
	now := time.Unix(0, 0)
	d.now = func() time.Time { return now }

	for i := 0; i < 100; i++ {
		d.RecordDecision("t1", "a1", "p1", true) // 100% block, all in one window
	}
	if got := d.BlockRate("t1", "a1", "p1"); got < 0.99 {
		t.Fatalf("expected ~100%% within window, got %f", got)
	}

	// Advance well beyond the full window: the old buckets fall out of range.
	now = now.Add(defaultWindow + time.Minute)
	if got := d.BlockRate("t1", "a1", "p1"); got != 0 {
		t.Fatalf("expected 0 block rate after window, got %f", got)
	}
	if alerts := d.Evaluate(20); len(alerts) != 0 {
		t.Fatalf("stale scope should not alert, got %d", len(alerts))
	}
	// Evaluate prunes scopes with no traffic left in the window.
	if _, ok := d.scopes[scopeKey{"t1", "a1", "p1"}]; ok {
		t.Fatal("stale scope should have been pruned")
	}
}

func TestBlockRateAndAlert(t *testing.T) {
	d := NewDetector(0.05)
	// 100 requests, 10 blocked = 10% > 5% threshold.
	for i := 0; i < 100; i++ {
		d.RecordDecision("t1", "a1", "p1", i < 10)
	}
	if got := d.BlockRate("t1", "a1", "p1"); got < 0.099 || got > 0.101 {
		t.Fatalf("block rate = %f", got)
	}
	alerts := d.Evaluate(20)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Tenant != "t1" || alerts[0].Recommend == "" {
		t.Fatalf("bad alert: %+v", alerts[0])
	}
}

func TestNoAlertUnderThreshold(t *testing.T) {
	d := NewDetector(0.05)
	for i := 0; i < 100; i++ {
		d.RecordDecision("t1", "a1", "p1", i < 2) // 2%
	}
	if len(d.Evaluate(20)) != 0 {
		t.Fatal("should not alert under threshold")
	}
}

func TestMinSamplesGuard(t *testing.T) {
	d := NewDetector(0.05)
	// 100% block rate but only 3 samples — below min sample size.
	for i := 0; i < 3; i++ {
		d.RecordDecision("t1", "a1", "p1", true)
	}
	if len(d.Evaluate(20)) != 0 {
		t.Fatal("should not alert below min samples")
	}
}

func TestModuleFalsePositiveRate(t *testing.T) {
	d := NewDetector(0.05)
	for i := 0; i < 10; i++ {
		d.RecordModule("t1", "a1", "p1", "root", i < 4) // 40% FP
	}
	if got := d.ModuleFalsePositiveRate("t1", "a1", "p1", "root"); got < 0.39 || got > 0.41 {
		t.Fatalf("module FP rate = %f", got)
	}
}

func TestAlertsSortedByBlockRate(t *testing.T) {
	d := NewDetector(0.05)
	for i := 0; i < 100; i++ {
		d.RecordDecision("t1", "a1", "low", i < 10)  // 10%
		d.RecordDecision("t1", "a1", "high", i < 30) // 30%
	}
	alerts := d.Evaluate(20)
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts, got %d", len(alerts))
	}
	if alerts[0].BlockRate < alerts[1].BlockRate {
		t.Fatal("alerts not sorted descending by block rate")
	}
}
