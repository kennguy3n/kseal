// Package query implements the dashboard's read surface (QueryService): stored
// risk events, tenant overview counters, and trust-session statistics. Every RPC
// is tenant-scoped — the caller's authenticated tenant (from the auth
// interceptor) must match the request tenant_id, and all reads filter on that
// tenant so there are no cross-tenant reads.
package query

import (
	"context"
	"errors"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/data-plane/ingest"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
	"github.com/kennguy3n/kseal/server/shared/auth"
)

// defaultRecentEvents is how many recent events the overview panel returns.
const defaultRecentEvents = 10

// Service implements the Connect QueryService over the registry store and the
// ingest analytics store.
type Service struct {
	ksealv1connect.UnimplementedQueryServiceHandler

	store     registry.Store
	analytics ingest.AnalyticsStore
	recentN   int
}

// NewService builds a QueryService handler reading from the registry store and
// the analytics store behind ingest.
func NewService(store registry.Store, analytics ingest.AnalyticsStore) *Service {
	return &Service{store: store, analytics: analytics, recentN: defaultRecentEvents}
}

// requireTenant authenticates the caller and enforces that the request tenant
// matches the caller's tenant, returning the resolved tenant id to scope reads.
func requireTenant(ctx context.Context, bodyTenant string) (string, error) {
	tenant, err := auth.TenantFrom(ctx)
	if err != nil {
		return "", connect.NewError(connect.CodeUnauthenticated, errors.New("missing tenant context"))
	}
	if bodyTenant != "" && bodyTenant != tenant {
		return "", connect.NewError(connect.CodePermissionDenied, errors.New("cross-tenant request denied"))
	}
	return tenant, nil
}

// ListEvents returns a recent-first, keyset-paginated page of stored events for
// the caller's tenant, honoring app / event-type / risk-level / time filters.
func (s *Service) ListEvents(ctx context.Context, req *connect.Request[ksealv1.ListEventsRequest]) (*connect.Response[ksealv1.ListEventsResponse], error) {
	m := req.Msg
	tenant, err := requireTenant(ctx, m.TenantId)
	if err != nil {
		return nil, err
	}
	q := ingest.Query{
		TenantID:   tenant, // always scope to the authenticated tenant
		AppID:      m.AppId,
		EventTypes: m.EventTypes,
		RiskLevels: m.RiskLevels,
		From:       millisToSec(m.StartTime),
		To:         millisToSec(m.EndTime),
	}
	page, err := s.analytics.ListEvents(ctx, q, int(m.PageSize), m.PageToken)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	out := &ksealv1.ListEventsResponse{
		Events:        make([]*ksealv1.EventRecord, 0, len(page.Events)),
		NextPageToken: page.NextCursor,
	}
	for _, e := range page.Events {
		out.Events = append(out.Events, toEventRecord(e))
	}
	return connect.NewResponse(out), nil
}

// GetTenantOverview composes the dashboard summary: registry cardinalities,
// event volume over the last 24h, and the most recent events.
func (s *Service) GetTenantOverview(ctx context.Context, req *connect.Request[ksealv1.GetTenantOverviewRequest]) (*connect.Response[ksealv1.GetTenantOverviewResponse], error) {
	tenant, err := requireTenant(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	counts, err := s.store.GetTenantCounts(ctx, tenant)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	since := time.Now().Add(-24 * time.Hour).Unix()
	last24h, err := s.analytics.Count(ctx, ingest.Query{TenantID: tenant, From: since})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	recent, err := s.analytics.ListEvents(ctx, ingest.Query{TenantID: tenant}, s.recentN, "")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp := &ksealv1.GetTenantOverviewResponse{
		AppCount:          int32(counts.Apps),
		BuildCount:        int32(counts.Builds),
		ActivePolicyCount: int32(counts.ActivePolicies),
		WebhookCount:      int32(counts.Webhooks),
		EventsLast_24H:    int64(last24h),
		RecentEvents:      make([]*ksealv1.EventRecord, 0, len(recent.Events)),
	}
	for _, e := range recent.Events {
		resp.RecentEvents = append(resp.RecentEvents, toEventRecord(e))
	}
	return connect.NewResponse(resp), nil
}

// GetTrustSessionStats aggregates trust-session outcomes for the caller's tenant
// over the requested window.
func (s *Service) GetTrustSessionStats(ctx context.Context, req *connect.Request[ksealv1.GetTrustSessionStatsRequest]) (*connect.Response[ksealv1.GetTrustSessionStatsResponse], error) {
	m := req.Msg
	tenant, err := requireTenant(ctx, m.TenantId)
	if err != nil {
		return nil, err
	}
	stats, err := s.store.GetTrustSessionStats(ctx, tenant, millisToSec(m.StartTime), millisToSec(m.EndTime))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	byLevel := make(map[string]int64, len(stats.ByRiskLevel))
	for lvl, n := range stats.ByRiskLevel {
		byLevel[trustLevelName(lvl)] = n
	}
	return connect.NewResponse(&ksealv1.GetTrustSessionStatsResponse{
		TotalSessions:        stats.TotalSessions,
		TokensIssued:         stats.TokensIssued,
		AttestationsFailed:   stats.AttestationsFailed,
		SessionsByTrustLevel: byLevel,
	}), nil
}

// toEventRecord projects a stored analytics event onto the wire EventRecord.
func toEventRecord(e ingest.StoredEvent) *ksealv1.EventRecord {
	rec := &ksealv1.EventRecord{
		Id:           e.ID,
		TenantId:     e.TenantID,
		AppId:        e.AppID,
		EventType:    e.EventType,
		RiskLevel:    e.RiskLevel,
		RiskBits:     e.RiskBits,
		Confidence:   e.Confidence,
		AppBuildHash: e.BuildHash,
		PolicyHash:   e.PolicyHash,
		Timestamp:    e.TimeBucket * 1000, // stored seconds -> wire millis
	}
	if e.Country != "" {
		c := e.Country
		rec.CountryOrRegion = &c
	}
	return rec
}

// trustLevelName renders a TrustLevel enum value as the short dashboard key
// (e.g. TRUST_LEVEL_TRUSTED -> "TRUSTED").
func trustLevelName(lvl int32) string {
	name := ksealv1.TrustLevel(lvl).String()
	return strings.TrimPrefix(name, "TRUST_LEVEL_")
}

// millisToSec converts unix millis to unix seconds, preserving 0 (unbounded).
func millisToSec(ms int64) int64 {
	if ms == 0 {
		return 0
	}
	return ms / 1000
}
