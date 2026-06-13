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

// CMKResolver answers, per tenant, whether customer-managed keys (BYOK/CMK) are
// configured and which KMS key URI to wrap/unwrap that tenant's DEK under. It
// reads the cmk_kms_uri column on the tenants table and satisfies
// crypto.TenantKMSResolver.
//
// Signing-key open happens on the config-fetch path, so the resolver caches
// lookups for a short TTL to keep wrap/unwrap selection off the hot path while
// staying responsive to configuration changes.
type CMKResolver struct {
	db  *db.DB
	ttl time.Duration

	mu    sync.RWMutex
	cache map[string]cmkCacheEntry
}

type cmkCacheEntry struct {
	uri       string
	enabled   bool
	expiresAt time.Time
}

// DefaultCMKCacheTTL bounds how long a tenant's CMK configuration is cached.
const DefaultCMKCacheTTL = 30 * time.Second

// NewCMKResolver builds a resolver over the database. ttl <= 0 uses
// DefaultCMKCacheTTL.
func NewCMKResolver(database *db.DB, ttl time.Duration) *CMKResolver {
	if ttl <= 0 {
		ttl = DefaultCMKCacheTTL
	}
	return &CMKResolver{db: database, ttl: ttl, cache: map[string]cmkCacheEntry{}}
}

// KMSKeyURI returns the tenant's CMK key URI and whether CMK is enabled for it.
func (r *CMKResolver) KMSKeyURI(ctx context.Context, tenantID string) (string, bool, error) {
	if tenantID == "" {
		return "", false, errors.New("registry: empty tenant id for cmk lookup")
	}
	now := time.Now()
	r.mu.RLock()
	if e, ok := r.cache[tenantID]; ok && now.Before(e.expiresAt) {
		r.mu.RUnlock()
		return e.uri, e.enabled, nil
	}
	r.mu.RUnlock()

	var uri *string
	// tenants is admin-scoped (no RLS); a direct PK lookup is correct and fast.
	err := r.db.Pool.QueryRow(ctx,
		`SELECT cmk_kms_uri FROM tenants WHERE id = $1`, tenantID).Scan(&uri)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, fmt.Errorf("%w: tenant %s", ErrNotFound, tenantID)
		}
		return "", false, fmt.Errorf("cmk lookup: %w", err)
	}

	value := ""
	enabled := false
	if uri != nil && *uri != "" {
		value = *uri
		enabled = true
	}
	r.mu.Lock()
	r.cache[tenantID] = cmkCacheEntry{uri: value, enabled: enabled, expiresAt: now.Add(r.ttl)}
	r.mu.Unlock()
	return value, enabled, nil
}

// SetTenantCMKKeyURI configures (uri != "") or clears (uri == "") a tenant's
// customer-managed key. It invalidates the cached entry so the change takes
// effect immediately for this process.
func (r *CMKResolver) SetTenantCMKKeyURI(ctx context.Context, tenantID, uri string) error {
	if tenantID == "" {
		return fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	var arg interface{}
	if uri != "" {
		arg = uri
	}
	tag, err := r.db.Pool.Exec(ctx,
		`UPDATE tenants SET cmk_kms_uri = $2, updated_at = now() WHERE id = $1`, tenantID, arg)
	if err != nil {
		return fmt.Errorf("set cmk uri: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: tenant %s", ErrNotFound, tenantID)
	}
	r.mu.Lock()
	delete(r.cache, tenantID)
	r.mu.Unlock()
	return nil
}
