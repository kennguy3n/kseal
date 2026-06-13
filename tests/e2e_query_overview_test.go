package tests

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
)

func TestE2EQueryOverviewAndIsolation(t *testing.T) {
	requireHarness(t)
	ctx := context.Background()

	store := newStore(t)

	// Two independent tenants sharing one analytics store, to prove reads are
	// strictly tenant-scoped with no cross-tenant leakage.
	tenantA := makeTenant(t, store, "ovw-a")
	appA := makeApp(t, store, tenantA.Id, "com.kseal.a")
	makeBuild(t, store, tenantA.Id, appA.Id)
	activatePolicy(t, store, tenantA.Id, appA.Id, ksealv1.EnforcementMode_ENFORCEMENT_MODE_STEP_UP, "{}", "")
	registerWebhook(t, store, tenantA.Id, "https://example.test/a", ksealv1.EventType_EVENT_TYPE_ROOT_RISK)

	tenantB := makeTenant(t, store, "ovw-b")
	appB := makeApp(t, store, tenantB.Id, "com.kseal.b")
	makeBuild(t, store, tenantB.Id, appB.Id)
	activatePolicy(t, store, tenantB.Id, appB.Id, ksealv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE, "{}", "")

	p := newPipeline(t, store, 100000, nil)
	now := time.Now().Unix()
	// 3 events for A, 2 for B.
	p.submit(t, tenantA.Id, appA.Id, &ksealv1.TelemetryBatch{Platform: ksealv1.Platform_PLATFORM_ANDROID, Events: []*ksealv1.TelemetryEvent{
		telemetryEvent(ksealv1.EventType_EVENT_TYPE_ROOT_RISK, 0, now-60, "a1"),
		telemetryEvent(ksealv1.EventType_EVENT_TYPE_DEBUGGER, 0, now-120, "a2"),
		telemetryEvent(ksealv1.EventType_EVENT_TYPE_HOOKING_DETECTED, 0, now-180, "a3"),
	}})
	p.submit(t, tenantB.Id, appB.Id, &ksealv1.TelemetryBatch{Platform: ksealv1.Platform_PLATFORM_IOS, Events: []*ksealv1.TelemetryEvent{
		telemetryEvent(ksealv1.EventType_EVENT_TYPE_ROOT_RISK, 0, now-60, "b1"),
		telemetryEvent(ksealv1.EventType_EVENT_TYPE_ROOT_RISK, 0, now-120, "b2"),
	}})
	if got := p.waitForEvents(t, tenantA.Id, 3); got != 3 {
		t.Fatalf("tenant A: expected 3 events, got %d", got)
	}
	if got := p.waitForEvents(t, tenantB.Id, 2); got != 2 {
		t.Fatalf("tenant B: expected 2 events, got %d", got)
	}

	// Seed trust sessions: A has 2 issued (TRUSTED, MEDIUM) + 1 failed; B has 1.
	seedSession(t, store, tenantA.Id, appA.Id, ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED, now)
	seedSession(t, store, tenantA.Id, appA.Id, ksealv1.TrustLevel_TRUST_LEVEL_MEDIUM_RISK, now)
	seedFailed(t, store, tenantA.Id, appA.Id, now)
	seedSession(t, store, tenantB.Id, appB.Id, ksealv1.TrustLevel_TRUST_LEVEL_LOW_RISK, now)

	t.Run("tenant_overview_is_per_tenant", func(t *testing.T) {
		resp, err := p.query.GetTenantOverview(asTenant(tenantA.Id), connect.NewRequest(&ksealv1.GetTenantOverviewRequest{TenantId: tenantA.Id}))
		if err != nil {
			t.Fatalf("overview A: %v", err)
		}
		o := resp.Msg
		if o.AppCount != 1 || o.BuildCount != 1 || o.ActivePolicyCount != 1 || o.WebhookCount != 1 {
			t.Fatalf("unexpected counts for A: %+v", o)
		}
		if o.EventsLast_24H != 3 {
			t.Fatalf("expected 3 events in last 24h for A, got %d", o.EventsLast_24H)
		}
		if len(o.RecentEvents) != 3 {
			t.Fatalf("expected 3 recent events for A, got %d", len(o.RecentEvents))
		}
		for _, e := range o.RecentEvents {
			if e.TenantId != tenantA.Id {
				t.Fatalf("tenant B event leaked into A overview: %s", e.TenantId)
			}
		}

		// Tenant B sees only its own data.
		respB, err := p.query.GetTenantOverview(asTenant(tenantB.Id), connect.NewRequest(&ksealv1.GetTenantOverviewRequest{TenantId: tenantB.Id}))
		if err != nil {
			t.Fatalf("overview B: %v", err)
		}
		if respB.Msg.EventsLast_24H != 2 || respB.Msg.WebhookCount != 0 {
			t.Fatalf("unexpected counts for B: %+v", respB.Msg)
		}
	})

	t.Run("trust_session_stats_are_per_tenant", func(t *testing.T) {
		resp, err := p.query.GetTrustSessionStats(asTenant(tenantA.Id), connect.NewRequest(&ksealv1.GetTrustSessionStatsRequest{TenantId: tenantA.Id}))
		if err != nil {
			t.Fatalf("stats A: %v", err)
		}
		s := resp.Msg
		if s.TotalSessions != 3 || s.TokensIssued != 2 || s.AttestationsFailed != 1 {
			t.Fatalf("unexpected stats for A: %+v", s)
		}
		if s.SessionsByTrustLevel["TRUSTED"] != 1 || s.SessionsByTrustLevel["MEDIUM_RISK"] != 1 {
			t.Fatalf("unexpected by-level for A: %+v", s.SessionsByTrustLevel)
		}

		respB, err := p.query.GetTrustSessionStats(asTenant(tenantB.Id), connect.NewRequest(&ksealv1.GetTrustSessionStatsRequest{TenantId: tenantB.Id}))
		if err != nil {
			t.Fatalf("stats B: %v", err)
		}
		if respB.Msg.TokensIssued != 1 || respB.Msg.SessionsByTrustLevel["LOW_RISK"] != 1 {
			t.Fatalf("unexpected stats for B: %+v", respB.Msg)
		}
		if respB.Msg.SessionsByTrustLevel["TRUSTED"] != 0 {
			t.Fatal("tenant A session leaked into B stats")
		}
	})

	t.Run("cross_tenant_reads_denied", func(t *testing.T) {
		// A caller authenticated as tenant A may never read tenant B's data by
		// passing B's id in the request body.
		cases := []func() error{
			func() error {
				_, err := p.query.ListEvents(asTenant(tenantA.Id), connect.NewRequest(&ksealv1.ListEventsRequest{TenantId: tenantB.Id}))
				return err
			},
			func() error {
				_, err := p.query.GetTenantOverview(asTenant(tenantA.Id), connect.NewRequest(&ksealv1.GetTenantOverviewRequest{TenantId: tenantB.Id}))
				return err
			},
			func() error {
				_, err := p.query.GetTrustSessionStats(asTenant(tenantA.Id), connect.NewRequest(&ksealv1.GetTrustSessionStatsRequest{TenantId: tenantB.Id}))
				return err
			},
		}
		for i, fn := range cases {
			err := fn()
			if err == nil {
				t.Fatalf("case %d: expected cross-tenant denial, got nil", i)
			}
			if connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("case %d: expected PermissionDenied, got %v", i, connect.CodeOf(err))
			}
		}

		// An unauthenticated caller (no tenant in context) is rejected.
		_, err := p.query.ListEvents(ctx, connect.NewRequest(&ksealv1.ListEventsRequest{TenantId: tenantA.Id}))
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("expected Unauthenticated without tenant context, got %v", connect.CodeOf(err))
		}

		// Even scoped to its OWN tenant, A's event listing never contains B's data.
		listed, err := p.query.ListEvents(asTenant(tenantA.Id), connect.NewRequest(&ksealv1.ListEventsRequest{TenantId: tenantA.Id, PageSize: 100}))
		if err != nil {
			t.Fatalf("list A: %v", err)
		}
		if len(listed.Msg.Events) != 3 {
			t.Fatalf("expected exactly 3 events for A, got %d", len(listed.Msg.Events))
		}
	})
}

func asTenant(tenantID string) context.Context {
	return auth.WithTenant(context.Background(), tenantID)
}

func seedSession(t *testing.T, store registry.Store, tenantID, appID string, level ksealv1.TrustLevel, now int64) {
	t.Helper()
	err := store.CreateTrustSession(context.Background(), &registry.TrustSession{
		TokenID:       uuid.NewString(),
		TenantID:      tenantID,
		AppID:         appID,
		BuildHash:     buildHash,
		InstanceID:    uniqueSlug("inst"),
		RiskLevel:     int32(level),
		SessionSecret: []byte("seeded-secret"),
		IssuedAt:      now,
		ExpiresAt:     now + 900,
	})
	if err != nil {
		t.Fatalf("seed trust session: %v", err)
	}
}

func seedFailed(t *testing.T, store registry.Store, tenantID, appID string, now int64) {
	t.Helper()
	err := store.RecordFailedAttestation(context.Background(), &registry.TrustSession{
		TokenID:    uuid.NewString(),
		TenantID:   tenantID,
		AppID:      appID,
		BuildHash:  buildHash,
		InstanceID: uniqueSlug("inst"),
		RiskLevel:  int32(ksealv1.TrustLevel_TRUST_LEVEL_CRITICAL),
		IssuedAt:   now,
		ExpiresAt:  now + 900,
	})
	if err != nil {
		t.Fatalf("seed failed attestation: %v", err)
	}
}
