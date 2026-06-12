// Package registry is the control-plane source of truth for tenants, apps,
// builds, policies, protection profiles, API keys, signing keys, webhooks, and
// trust sessions. It exposes a single Store interface with two implementations:
// a Postgres-backed store (production + integration tests) and an in-memory
// store (unit tests) so business logic is covered without a database.
package registry

import (
	"context"
	"crypto/ed25519"
	"errors"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
)

// Common store errors.
var (
	ErrNotFound     = errors.New("registry: not found")
	ErrConflict     = errors.New("registry: conflict")
	ErrInvalidInput = errors.New("registry: invalid input")
	ErrReplay       = errors.New("registry: sequence replay")
)

// SigningKey is a tenant Ed25519 key pair in decrypted form. The Store handles
// envelope encryption of Private transparently.
type SigningKey struct {
	ID        string
	TenantID  string
	Algorithm string
	Public    ed25519.PublicKey
	Private   ed25519.PrivateKey
	IsActive  bool
	CreatedAt int64
}

// APIKeyRecord is the non-secret metadata persisted for an issued API key.
type APIKeyRecord struct {
	ID        string
	TenantID  string
	KeyID     string
	Name      string
	Scopes    []string
	Status    string
	CreatedAt int64
}

// WebhookSecret is a webhook plus its decrypted HMAC signing secret, used by the
// dispatcher to sign deliveries.
type WebhookSecret struct {
	Webhook *ksealv1.Webhook
	Secret  []byte
}

// TrustSession records a minted trust token for proof validation and replay
// defense.
type TrustSession struct {
	TokenID         string
	TenantID        string
	AppID           string
	BuildHash       string
	InstanceID      string
	PolicyHash      string
	RiskLevel       int32
	CapabilityScope []string
	SessionSecret   []byte
	LastSequence    int64
	Status          string
	IssuedAt        int64
	ExpiresAt       int64
}

// TrustSessionStats aggregates trust-session outcomes for a tenant over a time
// window. TokensIssued counts minting sessions (active/revoked);
// AttestationsFailed counts non-minting 'failed' records; ByRiskLevel buckets
// the issued sessions by their fused risk level (TrustLevel enum value).
type TrustSessionStats struct {
	TotalSessions      int64
	TokensIssued       int64
	AttestationsFailed int64
	ByRiskLevel        map[int32]int64
}

// TenantCounts are the registry cardinalities shown on the dashboard overview.
type TenantCounts struct {
	Apps           int64
	Builds         int64
	ActivePolicies int64
	Webhooks       int64
}

// CreateTenantInput carries the fields for creating a tenant.
type CreateTenantInput struct {
	Name string
	Slug string
	Tier string
}

// UpdateTenantInput carries mutable tenant fields. Empty fields are left as-is.
type UpdateTenantInput struct {
	ID     string
	Name   string
	Tier   string
	Status string
}

// CreateAppInput carries the fields for creating an app.
type CreateAppInput struct {
	TenantID          string
	Name              string
	Platform          ksealv1.Platform
	PackageID         string
	SigningIdentities []string
}

// CreateBuildInput carries the fields for creating a build.
type CreateBuildInput struct {
	TenantID            string
	AppID               string
	BuildHash           string
	VersionName         string
	VersionCode         int64
	ProtectionProfileID string
	Manifest            string
}

// CreatePolicyInput carries the fields for creating a policy version.
type CreatePolicyInput struct {
	TenantID        string
	AppID           string
	Name            string
	EnforcementMode ksealv1.EnforcementMode
	Rules           string
	RiskThresholds  string
	ModulesEnabled  []string
}

// CreateProtectionProfileInput carries the fields for a protection profile.
type CreateProtectionProfileInput struct {
	TenantID       string
	Name           string
	ModulesEnabled []string
	DefaultMode    ksealv1.EnforcementMode
}

// Page bounds a list query.
type Page struct {
	Size  int
	Token string
}

// Store is the full persistence surface of the control plane. Every
// tenant-scoped method enforces isolation both at the application layer and via
// Postgres row-level security (in the Postgres implementation).
type Store interface {
	// Tenants (admin-scoped).
	CreateTenant(ctx context.Context, in CreateTenantInput) (*ksealv1.Tenant, error)
	GetTenant(ctx context.Context, id string) (*ksealv1.Tenant, error)
	ListTenants(ctx context.Context, page Page) ([]*ksealv1.Tenant, string, error)
	UpdateTenant(ctx context.Context, in UpdateTenantInput) (*ksealv1.Tenant, error)

	// Apps.
	CreateApp(ctx context.Context, in CreateAppInput) (*ksealv1.App, error)
	GetApp(ctx context.Context, tenantID, id string) (*ksealv1.App, error)
	ListApps(ctx context.Context, tenantID string, page Page) ([]*ksealv1.App, string, error)

	// Builds.
	CreateBuild(ctx context.Context, in CreateBuildInput) (*ksealv1.Build, error)
	GetBuild(ctx context.Context, tenantID, id string) (*ksealv1.Build, error)
	ListBuilds(ctx context.Context, tenantID, appID string, page Page) ([]*ksealv1.Build, string, error)

	// Policies.
	CreatePolicy(ctx context.Context, in CreatePolicyInput) (*ksealv1.Policy, error)
	GetActivePolicy(ctx context.Context, tenantID, appID string) (*ksealv1.Policy, error)
	ListPolicies(ctx context.Context, tenantID, appID string) ([]*ksealv1.Policy, error)
	ActivatePolicy(ctx context.Context, tenantID, id string) (*ksealv1.Policy, error)

	// Protection profiles.
	CreateProtectionProfile(ctx context.Context, in CreateProtectionProfileInput) (*ksealv1.ProtectionProfile, error)
	ListProtectionProfiles(ctx context.Context, tenantID string) ([]*ksealv1.ProtectionProfile, error)

	// API keys.
	CreateAPIKey(ctx context.Context, tenantID, name string, scopes []string) (plaintext string, rec *APIKeyRecord, err error)
	ValidateAPIKey(ctx context.Context, plaintext string) (*auth.Principal, error)
	RevokeAPIKey(ctx context.Context, tenantID, keyID string) error

	// Signing keys.
	CreateSigningKey(ctx context.Context, tenantID string) (*SigningKey, error)
	GetActiveSigningKey(ctx context.Context, tenantID string) (*SigningKey, error)
	GetSigningKey(ctx context.Context, tenantID, id string) (*SigningKey, error)
	RotateSigningKey(ctx context.Context, tenantID string) (*SigningKey, error)

	// Webhooks.
	CreateWebhook(ctx context.Context, tenantID, url string, eventTypes []ksealv1.EventType) (*ksealv1.Webhook, error)
	ListWebhooks(ctx context.Context, tenantID string) ([]*ksealv1.Webhook, error)
	DeleteWebhook(ctx context.Context, tenantID, id string) (bool, error)
	ListWebhooksForEvent(ctx context.Context, tenantID string, eventType ksealv1.EventType) ([]WebhookSecret, error)

	// Trust sessions.
	CreateTrustSession(ctx context.Context, s *TrustSession) error
	GetTrustSession(ctx context.Context, tokenID string) (*TrustSession, error)
	ConsumeSequence(ctx context.Context, tokenID string, seq int64) error
	RevokeTrustSession(ctx context.Context, tenantID, tokenID string) error
	// RecordFailedAttestation persists a non-minting attestation outcome
	// (status 'failed') so the dashboard can report attestation failures. It is
	// reached only after the single-use nonce is consumed, so it is bounded by
	// the same rate limits as the trust flow.
	RecordFailedAttestation(ctx context.Context, s *TrustSession) error
	// GetTrustSessionStats aggregates trust-session outcomes for a tenant over
	// [fromSec, toSec] (unix seconds; 0 means unbounded).
	GetTrustSessionStats(ctx context.Context, tenantID string, fromSec, toSec int64) (*TrustSessionStats, error)
	// GetTenantCounts returns the registry cardinalities for the overview panel.
	GetTenantCounts(ctx context.Context, tenantID string) (*TenantCounts, error)

	// Close releases resources.
	Close()
}
