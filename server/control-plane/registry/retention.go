package registry

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/kseal/server/shared/db"
)

// RetentionResolver answers a tenant's raw-telemetry retention window from the
// raw_retention_days column on the tenants table. It satisfies the data plane's
// retention resolver contract used by the purge routine. ok=false means the
// tenant has no override and the platform default applies.
type RetentionResolver struct {
	db *db.DB
}

// NewRetentionResolver builds a resolver over the database.
func NewRetentionResolver(database *db.DB) *RetentionResolver {
	return &RetentionResolver{db: database}
}

// RawRetentionDays returns the tenant's configured retention window in days.
func (r *RetentionResolver) RawRetentionDays(ctx context.Context, tenantID string) (int, bool, error) {
	if tenantID == "" {
		return 0, false, errors.New("registry: empty tenant id for retention lookup")
	}
	var days *int32
	// tenants is admin-scoped (no RLS); a direct PK lookup is correct and fast.
	err := r.db.Pool.QueryRow(ctx,
		`SELECT raw_retention_days FROM tenants WHERE id = $1`, tenantID).Scan(&days)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, fmt.Errorf("%w: tenant %s", ErrNotFound, tenantID)
		}
		return 0, false, fmt.Errorf("retention lookup: %w", err)
	}
	if days == nil {
		return 0, false, nil
	}
	return int(*days), true, nil
}

// SetTenantRawRetentionDays sets (days >= 0) or clears (days < 0) a tenant's
// raw-telemetry retention window. Clearing reverts the tenant to the platform
// default.
func (r *RetentionResolver) SetTenantRawRetentionDays(ctx context.Context, tenantID string, days int) error {
	if tenantID == "" {
		return fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	var arg interface{}
	if days >= 0 {
		arg = int32(days)
	}
	tag, err := r.db.Pool.Exec(ctx,
		`UPDATE tenants SET raw_retention_days = $2, updated_at = now() WHERE id = $1`, tenantID, arg)
	if err != nil {
		return fmt.Errorf("set retention days: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: tenant %s", ErrNotFound, tenantID)
	}
	return nil
}
