package compliance

import (
	"context"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// KeySource supplies the tenant's active Ed25519 signing key used to sign kill
// switches. The registry store satisfies it; kill switches are signed with the
// same per-tenant key that signs policy config, so the SDK verifies both with
// one trust anchor.
type KeySource interface {
	GetActiveSigningKey(ctx context.Context, tenantID string) (*registry.SigningKey, error)
	CreateSigningKey(ctx context.Context, tenantID string) (*registry.SigningKey, error)
}

// DataProcessingInput creates or replaces a tenant's per-app data-processing
// disclosure. AppID may be empty for a tenant-wide default record.
type DataProcessingInput struct {
	TenantID          string
	AppID             string
	DataCategories    []string
	Purpose           string
	RetentionDays     int32
	LegalBasis        string
	ThirdPartySharing bool
}

// KillSwitchInput issues a signed disable/enable command for a scope. AppID and
// BuildHash are optional (empty widens the scope).
type KillSwitchInput struct {
	TenantID   string
	AppID      string
	BuildHash  string
	Command    ksealv1.KillSwitchCommand
	Reason     string
	ActorKeyID string
}

// CanaryInput configures or updates a staged rollout. StablePolicyID is the
// last-known-good policy to revert to; the service resolves it from the
// currently active policy when a rollout is first created.
type CanaryInput struct {
	TenantID          string
	AppID             string
	CandidatePolicyID string
	StablePolicyID    string
	Percent           uint32
	RollbackThreshold float64
	ActorKeyID        string
}

// CanaryObservation is the guardrail health snapshot recorded alongside a
// rollout transition (e.g. an auto-rollback), so the status read surface and
// audit trail capture why a transition happened.
type CanaryObservation struct {
	BlockRate   float64
	SampleCount int64
}

// Store is the compliance persistence surface: the hash-chained audit trail,
// the data-processing registry, the signed kill switch, and canary rollout
// state. Every method is tenant-scoped and isolated by Postgres row-level
// security in the Postgres implementation.
type Store interface {
	// Audit trail.
	AppendAudit(ctx context.Context, tenantID string, e Entry) (*ksealv1.AuditEvent, error)
	ListAudit(ctx context.Context, tenantID string, f AuditFilter, pageSize int, pageToken string) ([]*ksealv1.AuditEvent, string, error)
	VerifyAudit(ctx context.Context, tenantID string) (VerifyResult, error)

	// Data-processing registry.
	PutDataProcessing(ctx context.Context, in DataProcessingInput) (*ksealv1.DataProcessingRecord, error)
	ListDataProcessing(ctx context.Context, tenantID string) ([]*ksealv1.DataProcessingRecord, error)

	// Signed kill switch. IssueKillSwitch signs the command, persists it, and
	// appends an audit event atomically.
	IssueKillSwitch(ctx context.Context, in KillSwitchInput) (*ksealv1.SignedKillSwitch, error)
	ListKillSwitches(ctx context.Context, tenantID string) ([]*ksealv1.SignedKillSwitch, error)

	// Canary rollout. SetCanary upserts a rollout; Promote/Rollback transition
	// it and append an audit event atomically.
	SetCanary(ctx context.Context, in CanaryInput) (*ksealv1.CanaryStatus, error)
	GetCanary(ctx context.Context, tenantID, appID string) (*ksealv1.CanaryStatus, error)
	ListActiveCanaries(ctx context.Context) ([]*ksealv1.CanaryStatus, error)
	PromoteCanary(ctx context.Context, tenantID, appID, actorKeyID string) (*ksealv1.CanaryStatus, error)
	RollbackCanary(ctx context.Context, tenantID, appID, reason, actorKeyID string, obs CanaryObservation) (*ksealv1.CanaryStatus, error)
}

var (
	_ Store = (*MemStore)(nil)
	_ Store = (*PostgresStore)(nil)
)

// GetKillSwitchState resolves the effective command for a query scope from a
// tenant's configured switches. It is a pure helper over ListKillSwitches so
// both store implementations and the data plane share one resolution rule.
func GetKillSwitchState(switches []*ksealv1.SignedKillSwitch, appID, buildHash string) (ksealv1.KillSwitchCommand, *ksealv1.SignedKillSwitch) {
	active := resolveEffective(switches, killSwitchScope{appID: appID, buildHash: buildHash})
	if active == nil {
		return ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_ENABLE, nil
	}
	return active.Command, active
}
