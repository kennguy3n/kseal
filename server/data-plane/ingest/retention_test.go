package ingest

import (
	"context"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

type fakeRetentionResolver struct {
	days map[string]int
	err  error
}

func (r fakeRetentionResolver) RawRetentionDays(_ context.Context, tenantID string) (int, bool, error) {
	if r.err != nil {
		return 0, false, r.err
	}
	d, ok := r.days[tenantID]
	return d, ok, nil
}

// seedEvents writes one event per tenant at the given age (days before now).
func ageBucket(now time.Time, days int) int64 {
	return now.Add(-time.Duration(days) * 24 * time.Hour).Unix()
}

func TestPurgeRespectsPerTenantWindows(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC)
	store := NewInMemoryAnalyticsStore()

	// tenant-a: 7-day window; tenant-b: 60-day window.
	// Each tenant gets an old event (40 days) and a fresh event (1 day).
	events := []StoredEvent{
		{ID: "a-old", TenantID: "tenant-a", TimeBucket: ageBucket(now, 40)},
		{ID: "a-new", TenantID: "tenant-a", TimeBucket: ageBucket(now, 1)},
		{ID: "b-old", TenantID: "tenant-b", TimeBucket: ageBucket(now, 40)},
		{ID: "b-new", TenantID: "tenant-b", TimeBucket: ageBucket(now, 1)},
	}
	if err := store.Write(ctx, events); err != nil {
		t.Fatal(err)
	}

	resolver := fakeRetentionResolver{days: map[string]int{"tenant-a": 7, "tenant-b": 60}}
	p := NewPurger(store, resolver, 30, WithClock(fakeClock{now}))
	report, err := p.PurgeOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Only tenant-a's old event (40 > 7) is purged; tenant-b keeps both (40 < 60).
	if report.EventsPurged != 1 {
		t.Fatalf("expected 1 purged, got %d", report.EventsPurged)
	}
	remaining := idsByTenant(t, store)
	if got := remaining["tenant-a"]; len(got) != 1 || got[0] != "a-new" {
		t.Fatalf("tenant-a should keep only a-new, got %v", got)
	}
	if got := remaining["tenant-b"]; len(got) != 2 {
		t.Fatalf("tenant-b should keep both, got %v", got)
	}
}

func TestPurgeNeverCrossesTenants(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC)
	store := NewInMemoryAnalyticsStore()
	// Both tenants have an identically-aged old event, but only tenant-a has a
	// short window; tenant-b's event must survive.
	_ = store.Write(ctx, []StoredEvent{
		{ID: "a-old", TenantID: "tenant-a", TimeBucket: ageBucket(now, 40)},
		{ID: "b-old", TenantID: "tenant-b", TimeBucket: ageBucket(now, 40)},
	})
	resolver := fakeRetentionResolver{days: map[string]int{"tenant-a": 7, "tenant-b": 365}}
	p := NewPurger(store, resolver, 30, WithClock(fakeClock{now}))
	if _, err := p.PurgeOnce(ctx); err != nil {
		t.Fatal(err)
	}
	remaining := idsByTenant(t, store)
	if len(remaining["tenant-a"]) != 0 {
		t.Fatalf("tenant-a old event should be purged, got %v", remaining["tenant-a"])
	}
	if got := remaining["tenant-b"]; len(got) != 1 || got[0] != "b-old" {
		t.Fatalf("tenant-b event must not be touched, got %v", got)
	}
}

func TestPurgeFallsBackToPlatformDefault(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC)
	store := NewInMemoryAnalyticsStore()
	_ = store.Write(ctx, []StoredEvent{
		{ID: "old", TenantID: "tenant-x", TimeBucket: ageBucket(now, 45)},
		{ID: "mid", TenantID: "tenant-x", TimeBucket: ageBucket(now, 20)},
	})
	// No per-tenant override -> platform default of 30 days applies.
	resolver := fakeRetentionResolver{days: map[string]int{}}
	p := NewPurger(store, resolver, 30, WithClock(fakeClock{now}))
	report, err := p.PurgeOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.EventsPurged != 1 {
		t.Fatalf("expected 1 purged at default window, got %d", report.EventsPurged)
	}
	remaining := idsByTenant(t, store)
	if got := remaining["tenant-x"]; len(got) != 1 || got[0] != "mid" {
		t.Fatalf("expected only mid retained, got %v", got)
	}
}

func TestPurgeDisabledWhenNoWindow(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC)
	store := NewInMemoryAnalyticsStore()
	_ = store.Write(ctx, []StoredEvent{
		{ID: "ancient", TenantID: "tenant-x", TimeBucket: ageBucket(now, 1000)},
	})
	// Platform default 0 and no override -> retain indefinitely (fail-safe).
	resolver := fakeRetentionResolver{days: map[string]int{}}
	p := NewPurger(store, resolver, 0, WithClock(fakeClock{now}))
	report, err := p.PurgeOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.EventsPurged != 0 {
		t.Fatalf("expected nothing purged when retention disabled, got %d", report.EventsPurged)
	}
}

func TestPurgePerTenantOverrideZeroDisables(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC)
	store := NewInMemoryAnalyticsStore()
	_ = store.Write(ctx, []StoredEvent{
		{ID: "old", TenantID: "tenant-x", TimeBucket: ageBucket(now, 90)},
	})
	// Override of 0 is treated as "not set" -> platform default applies.
	resolver := fakeRetentionResolver{days: map[string]int{"tenant-x": 0}}
	p := NewPurger(store, resolver, 30, WithClock(fakeClock{now}))
	report, err := p.PurgeOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.EventsPurged != 1 {
		t.Fatalf("expected default window to purge the 90-day event, got %d", report.EventsPurged)
	}
}

func TestPurgePropagatesResolverError(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryAnalyticsStore()
	_ = store.Write(ctx, []StoredEvent{{ID: "e", TenantID: "t", TimeBucket: 1}})
	p := NewPurger(store, fakeRetentionResolver{err: context.DeadlineExceeded}, 30)
	if _, err := p.PurgeOnce(ctx); err == nil {
		t.Fatal("expected resolver error to propagate")
	}
}

func idsByTenant(t *testing.T, s *InMemoryAnalyticsStore) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	all, err := s.Query(context.Background(), Query{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		out[e.TenantID] = append(out[e.TenantID], e.ID)
	}
	return out
}
