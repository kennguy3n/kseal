package query

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/data-plane/ingest"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
)

func tenantCtx(tenantID string) context.Context {
	return auth.WithTenant(context.Background(), tenantID)
}

func seedEvents(t *testing.T, store *ingest.InMemoryAnalyticsStore, evs []ingest.StoredEvent) {
	t.Helper()
	if err := store.Write(context.Background(), evs); err != nil {
		t.Fatal(err)
	}
}

func TestListEventsScopedAndPaginated(t *testing.T) {
	analytics := ingest.NewInMemoryAnalyticsStore()
	now := time.Now().Unix()
	var evs []ingest.StoredEvent
	for i := 0; i < 5; i++ {
		evs = append(evs, ingest.StoredEvent{
			ID: string(rune('a' + i)), TenantID: "t1", AppID: "app", EventType: ksealv1.EventType_EVENT_TYPE_DEBUGGER,
			RiskLevel: ksealv1.TrustLevel_TRUST_LEVEL_LOW_RISK, TimeBucket: now + int64(i),
		})
	}
	// An event for a different tenant must never surface.
	evs = append(evs, ingest.StoredEvent{ID: "z", TenantID: "other", AppID: "app", TimeBucket: now + 100})
	seedEvents(t, analytics, evs)

	svc := NewService(registry.NewMemStore(), analytics)
	ctx := tenantCtx("t1")

	resp, err := svc.ListEvents(ctx, connect.NewRequest(&ksealv1.ListEventsRequest{TenantId: "t1", PageSize: 2}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Events) != 2 {
		t.Fatalf("want 2 events, got %d", len(resp.Msg.Events))
	}
	// Recent-first ordering: highest TimeBucket (id "e") first.
	if resp.Msg.Events[0].Id != "e" {
		t.Fatalf("want newest first (e), got %s", resp.Msg.Events[0].Id)
	}
	if resp.Msg.NextPageToken == "" {
		t.Fatal("expected a next page token")
	}

	// Page through the rest; only t1's 5 events, never "other".
	seen := map[string]bool{}
	token := ""
	for {
		r, err := svc.ListEvents(ctx, connect.NewRequest(&ksealv1.ListEventsRequest{TenantId: "t1", PageSize: 2, PageToken: token}))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range r.Msg.Events {
			if e.TenantId != "t1" {
				t.Fatalf("cross-tenant event leaked: %s/%s", e.TenantId, e.Id)
			}
			if seen[e.Id] {
				t.Fatalf("duplicate event across pages: %s", e.Id)
			}
			seen[e.Id] = true
		}
		token = r.Msg.NextPageToken
		if token == "" {
			break
		}
	}
	if len(seen) != 5 {
		t.Fatalf("want 5 distinct t1 events across pages, got %d", len(seen))
	}
}

func TestListEventsRejectsCrossTenant(t *testing.T) {
	svc := NewService(registry.NewMemStore(), ingest.NewInMemoryAnalyticsStore())
	// Authenticated as t1 but asking for t2.
	_, err := svc.ListEvents(tenantCtx("t1"), connect.NewRequest(&ksealv1.ListEventsRequest{TenantId: "t2"}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}

func TestListEventsRequiresAuth(t *testing.T) {
	svc := NewService(registry.NewMemStore(), ingest.NewInMemoryAnalyticsStore())
	_, err := svc.ListEvents(context.Background(), connect.NewRequest(&ksealv1.ListEventsRequest{TenantId: "t1"}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
}

func TestListEventsFilters(t *testing.T) {
	analytics := ingest.NewInMemoryAnalyticsStore()
	now := time.Now().Unix()
	seedEvents(t, analytics, []ingest.StoredEvent{
		{ID: "1", TenantID: "t1", AppID: "a", EventType: ksealv1.EventType_EVENT_TYPE_DEBUGGER, RiskLevel: ksealv1.TrustLevel_TRUST_LEVEL_HIGH_RISK, TimeBucket: now},
		{ID: "2", TenantID: "t1", AppID: "b", EventType: ksealv1.EventType_EVENT_TYPE_ROOT_RISK, RiskLevel: ksealv1.TrustLevel_TRUST_LEVEL_LOW_RISK, TimeBucket: now},
		{ID: "3", TenantID: "t1", AppID: "a", EventType: ksealv1.EventType_EVENT_TYPE_ROOT_RISK, RiskLevel: ksealv1.TrustLevel_TRUST_LEVEL_HIGH_RISK, TimeBucket: now},
	})
	svc := NewService(registry.NewMemStore(), analytics)
	ctx := tenantCtx("t1")

	resp, err := svc.ListEvents(ctx, connect.NewRequest(&ksealv1.ListEventsRequest{
		TenantId:   "t1",
		AppId:      "a",
		EventTypes: []ksealv1.EventType{ksealv1.EventType_EVENT_TYPE_ROOT_RISK},
		RiskLevels: []ksealv1.TrustLevel{ksealv1.TrustLevel_TRUST_LEVEL_HIGH_RISK},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Events) != 1 || resp.Msg.Events[0].Id != "3" {
		t.Fatalf("filter mismatch: %+v", resp.Msg.Events)
	}
}

func TestGetTenantOverview(t *testing.T) {
	store := registry.NewMemStore()
	ten, err := store.CreateTenant(context.Background(), registry.CreateTenantInput{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := tenantCtx(ten.Id)
	if _, err := store.CreateApp(auth.WithTenant(context.Background(), ten.Id), registry.CreateAppInput{TenantID: ten.Id, Name: "App", Platform: ksealv1.Platform_PLATFORM_ANDROID, PackageID: "com.acme"}); err != nil {
		t.Fatal(err)
	}

	analytics := ingest.NewInMemoryAnalyticsStore()
	now := time.Now().Unix()
	seedEvents(t, analytics, []ingest.StoredEvent{
		{ID: "1", TenantID: ten.Id, AppID: "a", TimeBucket: now},
		{ID: "2", TenantID: ten.Id, AppID: "a", TimeBucket: now - 1},
		{ID: "old", TenantID: ten.Id, AppID: "a", TimeBucket: now - int64((48 * time.Hour).Seconds())},
		{ID: "x", TenantID: "other", AppID: "a", TimeBucket: now},
	})

	svc := NewService(store, analytics)
	resp, err := svc.GetTenantOverview(ctx, connect.NewRequest(&ksealv1.GetTenantOverviewRequest{TenantId: ten.Id}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.AppCount != 1 {
		t.Fatalf("want 1 app, got %d", resp.Msg.AppCount)
	}
	if resp.Msg.EventsLast_24H != 2 {
		t.Fatalf("want 2 events in last 24h (excluding old + other tenant), got %d", resp.Msg.EventsLast_24H)
	}
	if len(resp.Msg.RecentEvents) != 3 {
		t.Fatalf("want 3 recent t-scoped events, got %d", len(resp.Msg.RecentEvents))
	}
	for _, e := range resp.Msg.RecentEvents {
		if e.TenantId != ten.Id {
			t.Fatalf("cross-tenant recent event: %s", e.TenantId)
		}
	}
}

func TestGetTrustSessionStats(t *testing.T) {
	store := registry.NewMemStore()
	ten, err := store.CreateTenant(context.Background(), registry.CreateTenantInput{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	bg := context.Background()
	mk := func(id string, level int32) {
		if err := store.CreateTrustSession(bg, &registry.TrustSession{
			TokenID: id, TenantID: ten.Id, AppID: "a", RiskLevel: level, SessionSecret: []byte("s"), IssuedAt: 100, ExpiresAt: 1 << 40,
		}); err != nil {
			t.Fatal(err)
		}
	}
	mk("s1", int32(ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED))
	mk("s2", int32(ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED))
	mk("s3", int32(ksealv1.TrustLevel_TRUST_LEVEL_HIGH_RISK))
	if err := store.RecordFailedAttestation(bg, &registry.TrustSession{TenantID: ten.Id, AppID: "a", IssuedAt: 100}); err != nil {
		t.Fatal(err)
	}
	// Cross-tenant session must not be counted.
	other, _ := store.CreateTenant(bg, registry.CreateTenantInput{Name: "Other", Slug: "other"})
	if err := store.CreateTrustSession(bg, &registry.TrustSession{TokenID: "o1", TenantID: other.Id, AppID: "a", SessionSecret: []byte("s"), IssuedAt: 100, ExpiresAt: 1 << 40}); err != nil {
		t.Fatal(err)
	}

	svc := NewService(store, ingest.NewInMemoryAnalyticsStore())
	resp, err := svc.GetTrustSessionStats(tenantCtx(ten.Id), connect.NewRequest(&ksealv1.GetTrustSessionStatsRequest{TenantId: ten.Id}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.TotalSessions != 4 {
		t.Fatalf("want 4 total sessions, got %d", resp.Msg.TotalSessions)
	}
	if resp.Msg.TokensIssued != 3 {
		t.Fatalf("want 3 tokens issued, got %d", resp.Msg.TokensIssued)
	}
	if resp.Msg.AttestationsFailed != 1 {
		t.Fatalf("want 1 attestation failed, got %d", resp.Msg.AttestationsFailed)
	}
	if resp.Msg.SessionsByTrustLevel["TRUSTED"] != 2 || resp.Msg.SessionsByTrustLevel["HIGH_RISK"] != 1 {
		t.Fatalf("by-level mismatch: %+v", resp.Msg.SessionsByTrustLevel)
	}
}
