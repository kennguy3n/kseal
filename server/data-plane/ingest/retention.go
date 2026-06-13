package ingest

import (
	"context"
	"fmt"
	"time"
)

// secondsPerDay is the retention-window unit. TimeBucket on StoredEvent is a
// coarse unix-seconds bucket, so windows are expressed in days of seconds.
const secondsPerDay = int64(24 * 60 * 60)

// Clock returns the current time. Production uses the wall clock; tests inject a
// fixed clock so purge windows are deterministic.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// RetentionResolver reports a tenant's raw-telemetry retention window in days.
// ok=false means the tenant has no explicit override and the platform default
// applies.
type RetentionResolver interface {
	RawRetentionDays(ctx context.Context, tenantID string) (days int, ok bool, err error)
}

// RawEventStore is the subset of raw-telemetry storage the purger needs. The
// in-memory analytics store implements it for the MVP; a ClickHouse-backed
// store implements the same contract later. PurgeRawEventsOlderThan must delete
// only the named tenant's raw events (tenant isolation) and leave derived or
// aggregate analytics intact.
type RawEventStore interface {
	// TenantIDs returns the distinct tenants that currently hold raw events.
	TenantIDs(ctx context.Context) ([]string, error)
	// PurgeRawEventsOlderThan deletes the tenant's raw events whose TimeBucket
	// is strictly older than cutoffBucket and returns how many were removed.
	PurgeRawEventsOlderThan(ctx context.Context, tenantID string, cutoffBucket int64) (int, error)
}

// Purger enforces per-tenant raw-telemetry retention windows. It is fully
// interface-driven so it unit-tests against a fake clock and store.
//
// Privacy: raw events are deleted once they age past the tenant's window;
// derived/aggregate analytics are retained by the store. Tenant isolation is
// enforced because the store deletes strictly per tenant id.
type Purger struct {
	store       RawEventStore
	resolver    RetentionResolver
	clock       Clock
	defaultDays int
}

// PurgerOption configures a Purger.
type PurgerOption func(*Purger)

// WithClock overrides the wall clock (tests inject a fixed clock).
func WithClock(c Clock) PurgerOption {
	return func(p *Purger) {
		if c != nil {
			p.clock = c
		}
	}
}

// NewPurger builds a Purger. defaultDays is the platform-wide retention window
// applied to tenants without an explicit override; defaultDays <= 0 disables
// purging (retain indefinitely) as a fail-safe.
func NewPurger(store RawEventStore, resolver RetentionResolver, defaultDays int, opts ...PurgerOption) *Purger {
	p := &Purger{
		store:       store,
		resolver:    resolver,
		clock:       realClock{},
		defaultDays: defaultDays,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// PurgeReport summarizes one purge pass.
type PurgeReport struct {
	TenantsScanned int
	EventsPurged   int
}

// retentionDaysFor resolves the effective window for a tenant: the per-tenant
// override when set and positive, otherwise the platform default. A non-positive
// result means "retain indefinitely".
func (p *Purger) retentionDaysFor(ctx context.Context, tenantID string) (int, error) {
	days, ok, err := p.resolver.RawRetentionDays(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	if ok && days > 0 {
		return days, nil
	}
	return p.defaultDays, nil
}

// PurgeOnce runs a single retention pass over every tenant with raw events.
func (p *Purger) PurgeOnce(ctx context.Context) (PurgeReport, error) {
	tenants, err := p.store.TenantIDs(ctx)
	if err != nil {
		return PurgeReport{}, fmt.Errorf("list tenants: %w", err)
	}
	now := p.clock.Now().Unix()
	report := PurgeReport{TenantsScanned: len(tenants)}
	for _, tenantID := range tenants {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		days, err := p.retentionDaysFor(ctx, tenantID)
		if err != nil {
			return report, fmt.Errorf("retention for tenant %s: %w", tenantID, err)
		}
		if days <= 0 {
			// Retain indefinitely for this tenant.
			continue
		}
		cutoff := now - int64(days)*secondsPerDay
		purged, err := p.store.PurgeRawEventsOlderThan(ctx, tenantID, cutoff)
		if err != nil {
			return report, fmt.Errorf("purge tenant %s: %w", tenantID, err)
		}
		report.EventsPurged += purged
	}
	return report, nil
}

// Run purges on the given interval until the context is cancelled. Errors are
// returned only on shutdown; transient per-pass errors are surfaced via onError
// if provided, otherwise ignored so a single failure does not stop retention.
func (p *Purger) Run(ctx context.Context, interval time.Duration, onError func(error)) {
	if interval <= 0 {
		interval = time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := p.PurgeOnce(ctx); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}
