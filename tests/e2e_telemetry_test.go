package tests

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
)

func TestE2ETelemetryIngestAndQuery(t *testing.T) {
	requireHarness(t)

	store := newStore(t)

	t.Run("ingest_then_read_back_paginated_and_filtered", func(t *testing.T) {
		tenant := makeTenant(t, store, "tel-ingest")
		app := makeApp(t, store, tenant.Id, "com.kseal.telemetry")
		p := newPipeline(t, store, 100000, nil)

		now := time.Now().Unix()
		// Five events with distinct, descending-in-time buckets so the
		// recent-first keyset order is deterministic. Mix event types and risk
		// bits so filters have something to select.
		events := []*ksealv1.TelemetryEvent{
			telemetryEvent(ksealv1.EventType_EVENT_TYPE_ROOT_RISK, 0, now-1*3600, "h-root-1"),
			telemetryEvent(ksealv1.EventType_EVENT_TYPE_DEBUGGER, 0, now-2*3600, "h-dbg-1"),
			telemetryEvent(ksealv1.EventType_EVENT_TYPE_ROOT_RISK, riskRoot, now-3*3600, "h-root-2"),
			telemetryEvent(ksealv1.EventType_EVENT_TYPE_HOOKING_DETECTED, 0, now-4*3600, "h-hook-1"),
			telemetryEvent(ksealv1.EventType_EVENT_TYPE_ROOT_RISK, 0, now-5*3600, "h-root-3"),
		}
		resp := p.submit(t, tenant.Id, app.Id, &ksealv1.TelemetryBatch{
			Events: events, SdkVersion: "test", Platform: ksealv1.Platform_PLATFORM_ANDROID,
		})
		if resp.Accepted != int32(len(events)) || resp.Rejected != 0 {
			t.Fatalf("expected %d accepted/0 rejected, got accepted=%d rejected=%d (%s)", len(events), resp.Accepted, resp.Rejected, resp.RejectionReason)
		}
		if got := p.waitForEvents(t, tenant.Id, len(events)); got != len(events) {
			t.Fatalf("expected %d events readable, got %d", len(events), got)
		}

		ctx := auth.WithTenant(context.Background(), tenant.Id)

		// Keyset pagination across multiple pages (page size 2 over 5 events).
		var ids []string
		var lastTB int64 = 1<<62 - 1
		token := ""
		pages := 0
		for {
			page, err := p.query.ListEvents(ctx, connect.NewRequest(&ksealv1.ListEventsRequest{
				TenantId: tenant.Id, PageSize: 2, PageToken: token,
			}))
			if err != nil {
				t.Fatalf("list events: %v", err)
			}
			pages++
			for _, e := range page.Msg.Events {
				// recent-first: timestamps must be non-increasing across the walk.
				if e.Timestamp > lastTB {
					t.Fatalf("pagination not recent-first: %d after %d", e.Timestamp, lastTB)
				}
				lastTB = e.Timestamp
				ids = append(ids, e.Id)
				if e.TenantId != tenant.Id {
					t.Fatalf("cross-tenant event leaked: %s", e.TenantId)
				}
			}
			token = page.Msg.NextPageToken
			if token == "" {
				break
			}
		}
		if len(ids) != len(events) {
			t.Fatalf("expected %d events across pages, got %d", len(events), len(ids))
		}
		if pages < 2 {
			t.Fatalf("expected at least 2 pages, got %d", pages)
		}
		if dups := duplicateCount(ids); dups != 0 {
			t.Fatalf("pagination returned %d duplicate ids", dups)
		}

		// Filter by event type: only ROOT_RISK (3 of 5).
		filtered, err := p.query.ListEvents(ctx, connect.NewRequest(&ksealv1.ListEventsRequest{
			TenantId: tenant.Id, PageSize: 100, EventTypes: []ksealv1.EventType{ksealv1.EventType_EVENT_TYPE_ROOT_RISK},
		}))
		if err != nil {
			t.Fatalf("filtered list: %v", err)
		}
		if len(filtered.Msg.Events) != 3 {
			t.Fatalf("expected 3 ROOT_RISK events, got %d", len(filtered.Msg.Events))
		}
		for _, e := range filtered.Msg.Events {
			if e.EventType != ksealv1.EventType_EVENT_TYPE_ROOT_RISK {
				t.Fatalf("event-type filter leaked %v", e.EventType)
			}
		}

		// Filter by risk level: exactly the one event with elevated risk bits.
		highRisk, err := p.query.ListEvents(ctx, connect.NewRequest(&ksealv1.ListEventsRequest{
			TenantId: tenant.Id, PageSize: 100, RiskLevels: []ksealv1.TrustLevel{ksealv1.TrustLevel_TRUST_LEVEL_LOW_RISK},
		}))
		if err != nil {
			t.Fatalf("risk filter: %v", err)
		}
		if len(highRisk.Msg.Events) != 1 {
			t.Fatalf("expected 1 LOW_RISK event (riskRoot=40 -> LOW_RISK), got %d", len(highRisk.Msg.Events))
		}
	})

	t.Run("quota_exceeded_rejects_batch", func(t *testing.T) {
		tenant := makeTenant(t, store, "tel-quota")
		app := makeApp(t, store, tenant.Id, "com.kseal.quota")
		p := newPipeline(t, store, 5, nil) // 5 events/minute budget

		now := time.Now().Unix()
		batch := &ksealv1.TelemetryBatch{Platform: ksealv1.Platform_PLATFORM_ANDROID}
		for i := 0; i < 10; i++ {
			batch.Events = append(batch.Events, telemetryEvent(ksealv1.EventType_EVENT_TYPE_ROOT_RISK, 0, now, "over-quota"))
		}
		resp := p.submit(t, tenant.Id, app.Id, batch)
		if !resp.QuotaExceeded {
			t.Fatalf("expected quota exceeded, got %+v", resp)
		}
		if resp.Accepted != 0 || resp.Rejected != 10 {
			t.Fatalf("expected 0 accepted/10 rejected, got accepted=%d rejected=%d", resp.Accepted, resp.Rejected)
		}
	})

	t.Run("unknown_app_rejected", func(t *testing.T) {
		tenant := makeTenant(t, store, "tel-unknown")
		p := newPipeline(t, store, 100000, nil)
		resp := p.submit(t, tenant.Id, "00000000-0000-4000-8000-000000000000", &ksealv1.TelemetryBatch{
			Events:   []*ksealv1.TelemetryEvent{telemetryEvent(ksealv1.EventType_EVENT_TYPE_ROOT_RISK, 0, time.Now().Unix(), "x")},
			Platform: ksealv1.Platform_PLATFORM_ANDROID,
		})
		if resp.Rejected != 1 || resp.RejectionReason == "" {
			t.Fatalf("expected rejection for unknown app, got %+v", resp)
		}
	})
}

// riskRoot is the BitRootJailbreak weight input; risk.Score(BitRootJailbreak)=40
// which maps to LOW_RISK (>=20, <50).
const riskRoot uint64 = 1 << 0

func telemetryEvent(et ksealv1.EventType, riskBits uint64, bucket int64, installHash string) *ksealv1.TelemetryEvent {
	return &ksealv1.TelemetryEvent{
		EventType:                  et,
		RiskBits:                   riskBits,
		Confidence:                 ksealv1.Confidence_CONFIDENCE_MEDIUM,
		AppBuildHash:               buildHash,
		TenantScopedInstallKeyHash: installHash,
		CoarseTimeBucket:           bucket,
	}
}

func duplicateCount(ids []string) int {
	seen := map[string]bool{}
	dups := 0
	for _, id := range ids {
		if seen[id] {
			dups++
		}
		seen[id] = true
	}
	return dups
}
