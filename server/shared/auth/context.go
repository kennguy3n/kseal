package auth

import (
	"context"
	"errors"
	"strings"
)

type ctxKey int

const (
	principalKey ctxKey = iota
	requestIDKey
)

// Principal is the authenticated identity attached to a request after the auth
// middleware runs. For SDK (device-plane) calls only TenantID is populated, set
// from the validated request body; for control-plane calls the API key fields
// are also present.
type Principal struct {
	TenantID      string
	APIKeyID      string
	Scopes        []string
	PlatformAdmin bool
}

// HasScope reports whether the principal carries the named scope. Scopes are
// explicit: an empty scope set grants no privileges. A literal "*" grants every
// non-platform scope. Platform scopes are only honored for principals that were
// explicitly marked as platform admins.
func (p *Principal) HasScope(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
		if strings.HasSuffix(s, ":*") && strings.HasPrefix(scope, strings.TrimSuffix(s, "*")) && !strings.HasPrefix(scope, "platform:") {
			return true
		}
		if s == "*" && !strings.HasPrefix(scope, "platform:") {
			return true
		}
		if p.PlatformAdmin && s == "platform:*" && strings.HasPrefix(scope, "platform:") {
			return true
		}
	}
	return false
}

// ErrNoTenant indicates the context carried no tenant identity.
var ErrNoTenant = errors.New("auth: no tenant in context")

// WithPrincipal returns a child context carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalFrom extracts the principal placed by the auth middleware.
func PrincipalFrom(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey).(*Principal)
	return p, ok
}

// WithTenant attaches a tenant-only principal (used by device-plane RPCs whose
// tenant is established from the validated request body).
func WithTenant(ctx context.Context, tenantID string) context.Context {
	if p, ok := PrincipalFrom(ctx); ok {
		clone := *p
		clone.TenantID = tenantID
		return WithPrincipal(ctx, &clone)
	}
	return WithPrincipal(ctx, &Principal{TenantID: tenantID})
}

// TenantFrom returns the tenant id bound to ctx.
func TenantFrom(ctx context.Context) (string, error) {
	p, ok := PrincipalFrom(ctx)
	if !ok || p.TenantID == "" {
		return "", ErrNoTenant
	}
	return p.TenantID, nil
}

// EnforceTenant is the row-level-security guard: it returns an error when a row
// belonging to rowTenantID is accessed under a different tenant context. This is
// the application-layer complement to Postgres RLS and must wrap every
// cross-boundary read/write.
func EnforceTenant(ctx context.Context, rowTenantID string) error {
	tenant, err := TenantFrom(ctx)
	if err != nil {
		return err
	}
	if rowTenantID != "" && rowTenantID != tenant {
		return ErrCrossTenant
	}
	return nil
}

// ErrCrossTenant indicates an attempted access across tenant boundaries.
var ErrCrossTenant = errors.New("auth: cross-tenant access denied")

// WithRequestID stores the request id for logging/tracing correlation.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDFrom returns the request id bound to ctx, if any.
func RequestIDFrom(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}
