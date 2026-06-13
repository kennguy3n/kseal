package registry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/kseal/server/shared/db"
)

// DedicatedResolver answers, per tenant, whether the dedicated/regulated
// isolation tier is active. It reads the dedicated_isolation column on the
// tenants table and satisfies crypto.TenantIsolationResolver.
//
// Dedicated isolation and CMK are mutually exclusive: a tenant with a
// customer-managed key already has a per-tenant DEK domain, so the resolver
// reports dedicated only when cmk_kms_uri IS NULL. This prevents dedicated HKDF
// sealing from shadowing a customer's BYOK key.
//
// Signing-key open happens on the config-fetch path, so the resolver caches
// lookups for a short TTL (mirroring CMKResolver) to keep tier selection off the
// hot path while staying responsive to configuration changes.
type DedicatedResolver struct {
	db  *db.DB
	ttl time.Duration

	mu        sync.RWMutex
	cache     map[string]dedicatedCacheEntry
	lastSweep time.Time
}

type dedicatedCacheEntry struct {
	enabled   bool
	expiresAt time.Time
}

// NewDedicatedResolver builds a resolver over the database. ttl <= 0 uses
// DefaultCMKCacheTTL (the same window as CMK).
func NewDedicatedResolver(database *db.DB, ttl time.Duration) *DedicatedResolver {
	if ttl <= 0 {
		ttl = DefaultCMKCacheTTL
	}
	return &DedicatedResolver{db: database, ttl: ttl, cache: map[string]dedicatedCacheEntry{}}
}

// DedicatedIsolation reports whether the tenant is on the dedicated tier (and
// has no customer-managed key).
func (r *DedicatedResolver) DedicatedIsolation(ctx context.Context, tenantID string) (bool, error) {
	if tenantID == "" {
		return false, errors.New("registry: empty tenant id for dedicated lookup")
	}
	now := time.Now()
	r.mu.RLock()
	if e, ok := r.cache[tenantID]; ok && now.Before(e.expiresAt) {
		r.mu.RUnlock()
		return e.enabled, nil
	}
	r.mu.RUnlock()

	var enabled bool
	// tenants is admin-scoped (no RLS); a direct PK lookup is correct and fast.
	err := r.db.Pool.QueryRow(ctx,
		`SELECT dedicated_isolation AND cmk_kms_uri IS NULL FROM tenants WHERE id = $1`, tenantID).Scan(&enabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, fmt.Errorf("%w: tenant %s", ErrNotFound, tenantID)
		}
		return false, fmt.Errorf("dedicated lookup: %w", err)
	}

	r.mu.Lock()
	r.cache[tenantID] = dedicatedCacheEntry{enabled: enabled, expiresAt: now.Add(r.ttl)}
	r.sweepLocked(now)
	r.mu.Unlock()
	return enabled, nil
}

// sweepLocked drops expired entries at most once per TTL so the cache stays
// bounded by the tenants seen within the window. The caller must hold the write
// lock.
func (r *DedicatedResolver) sweepLocked(now time.Time) {
	if now.Sub(r.lastSweep) < r.ttl {
		return
	}
	for id, e := range r.cache {
		if !now.Before(e.expiresAt) {
			delete(r.cache, id)
		}
	}
	r.lastSweep = now
}

// SetTenantDedicatedIsolation turns the dedicated tier on or off for a tenant
// and invalidates the cached entry so the change takes effect immediately for
// this process.
func (r *DedicatedResolver) SetTenantDedicatedIsolation(ctx context.Context, tenantID string, enabled bool) error {
	if tenantID == "" {
		return fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	tag, err := r.db.Pool.Exec(ctx,
		`UPDATE tenants SET dedicated_isolation = $2, updated_at = now() WHERE id = $1`, tenantID, enabled)
	if err != nil {
		return fmt.Errorf("set dedicated isolation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: tenant %s", ErrNotFound, tenantID)
	}
	r.mu.Lock()
	delete(r.cache, tenantID)
	r.mu.Unlock()
	return nil
}
