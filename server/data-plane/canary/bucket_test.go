package canary

import (
	"fmt"
	"testing"
)

func TestInCanaryBoundaries(t *testing.T) {
	if InCanary("t", "a", "i", 0) {
		t.Fatal("0% must include nobody")
	}
	if InCanary("t", "a", "", 50) {
		t.Fatal("empty instance id must stay stable (fail-safe)")
	}
	if !InCanary("t", "a", "i", 100) {
		t.Fatal("100% must include everybody")
	}
}

func TestInCanaryDeterministic(t *testing.T) {
	const tenant, app, inst = "t1", "app1", "instance-xyz"
	first := InCanary(tenant, app, inst, 50)
	for i := 0; i < 100; i++ {
		if InCanary(tenant, app, inst, 50) != first {
			t.Fatal("bucketing must be deterministic across calls")
		}
	}
}

func TestInCanaryMonotonicInPercent(t *testing.T) {
	// Once an instance is in the cohort at percent p, it stays in for all p' > p
	// (the bucket is fixed; only the threshold grows).
	const tenant, app, inst = "t", "a", "monotonic-instance"
	wasIn := false
	for p := uint32(0); p <= 100; p++ {
		in := InCanary(tenant, app, inst, p)
		if wasIn && !in {
			t.Fatalf("instance left cohort as percent rose to %d", p)
		}
		wasIn = wasIn || in
	}
	if !wasIn {
		t.Fatal("instance should be in cohort by 100%")
	}
}

func TestBucketingDistribution(t *testing.T) {
	// Roughly 'percent' of a large instance population should land in the cohort.
	const tenant, app = "t", "a"
	const n = 10000
	const percent = 30
	in := 0
	for i := 0; i < n; i++ {
		if InCanary(tenant, app, fmt.Sprintf("inst-%d", i), percent) {
			in++
		}
	}
	got := float64(in) / float64(n) * 100
	if got < percent-3 || got > percent+3 {
		t.Fatalf("distribution off: wanted ~%d%%, got %.1f%%", percent, got)
	}
}

func TestBucketingTenantIndependence(t *testing.T) {
	// The same instance id under two tenants should not be perfectly correlated;
	// at least some instances differ in membership.
	diff := 0
	for i := 0; i < 1000; i++ {
		inst := fmt.Sprintf("i-%d", i)
		if InCanary("tenantA", "app", inst, 50) != InCanary("tenantB", "app", inst, 50) {
			diff++
		}
	}
	if diff == 0 {
		t.Fatal("expected tenant-scoped buckets to differ for some instances")
	}
}
