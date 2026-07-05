package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/kennguy3n/kseal/server/control-plane/compliance"
	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/data-plane/canary"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
	"github.com/kennguy3n/kseal/server/shared/auth"
	appconfig "github.com/kennguy3n/kseal/server/shared/config"
)

// KillSwitchSource supplies a tenant's signed kill switches for delivery in the
// config envelope. The compliance store satisfies it.
type KillSwitchSource interface {
	ListKillSwitches(ctx context.Context, tenantID string) ([]*ksealv1.SignedKillSwitch, error)
}

// Service implements the Connect ConfigService.
type Service struct {
	ksealv1connect.UnimplementedConfigServiceHandler

	store  registry.Store
	signer *Signer
	ttl    time.Duration

	// Optional enterprise wiring; nil disables the feature (default behavior).
	canary     *canary.Registry
	killSwitch KillSwitchSource
	flags      appconfig.FeatureFlags
}

// NewService builds a ConfigService with the given signed-config TTL.
func NewService(store registry.Store, signer *Signer, ttl time.Duration) *Service {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Service{store: store, signer: signer, ttl: ttl}
}

// AttachCompliance wires the optional canary rollout and signed kill-switch
// delivery into config assembly. Both are flag-gated per tenant
// (compliance.FlagCanaryRollout / FlagKillSwitch); when a flag is off the
// config served is identical to the baseline.
func (s *Service) AttachCompliance(reg *canary.Registry, killSwitch KillSwitchSource, flags appconfig.FeatureFlags) {
	s.canary = reg
	s.killSwitch = killSwitch
	s.flags = flags
}

// GetConfig assembles the active policy into a signed, cacheable config bundle.
func (s *Service) GetConfig(ctx context.Context, req *connect.Request[ksealv1.ConfigRequest]) (*connect.Response[ksealv1.ConfigResponse], error) {
	m := req.Msg
	if m.TenantId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("tenant_id required"))
	}
	if err := auth.EnforceTenant(ctx, m.TenantId); err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("device credential required"))
	}
	if _, err := s.store.GetApp(ctx, m.TenantId, m.AppId); err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("unknown tenant or app"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	policy, candidate, err := s.resolvePolicy(ctx, m)
	if errors.Is(err, registry.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no active policy"))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	killSwitch := s.resolveKillSwitch(ctx, m)

	pc := buildPolicyConfig(policy)
	// PolicyHash is a hex-encoded SHA-256 digest (registry.HashPolicy), so it
	// contains only token-safe characters. Fold in the kill-switch identity so a
	// newly issued/updated switch busts a cached config within the TTL rather
	// than waiting for it to expire. Wrap in literal double quotes per RFC 7232
	// (a strong ETag) rather than fmt.Sprintf("%q", ...), which would Go-escape
	// special characters and could confuse CDN ETag parsers.
	etag := `"` + pc.PolicyHash + killSwitchEtag(killSwitch) + `"`
	// If the client already holds this exact policy, advertise a cache hit by
	// returning the same ETag before doing any marshal/sign work; the SDK/CDN
	// compares against If-None-Match.
	if inm := req.Header().Get("If-None-Match"); inm != "" && inm == etag {
		resp := connect.NewResponse(&ksealv1.ConfigResponse{Etag: etag, LastModified: policy.UpdatedAt})
		resp.Header().Set("ETag", etag)
		return resp, nil
	}

	bytes, err := proto.Marshal(pc)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	sig, keyID, err := s.signer.Sign(ctx, m.TenantId, bytes)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := connect.NewResponse(&ksealv1.ConfigResponse{
		Config: &ksealv1.SignedConfig{
			ConfigBytes: bytes,
			Signature:   sig,
			KeyId:       keyID,
			Version:     int64(policy.Version),
			TtlSeconds:  int64(s.ttl.Seconds()),
		},
		Etag:         etag,
		LastModified: policy.UpdatedAt,
		KillSwitch:   killSwitch,
	})
	resp.Header().Set("ETag", etag)
	// A canary candidate or a kill switch makes the response vary within a
	// (tenant, app) by instance/build, so it must not be served from a shared
	// cache. Connect uses POST (not cached by default), but mark such responses
	// private defensively against aggressive proxies; the stable, shared config
	// stays publicly cacheable for the TTL.
	if candidate || killSwitch != nil {
		resp.Header().Set("Cache-Control", fmt.Sprintf("private, max-age=%d", int(s.ttl.Seconds())))
	} else {
		resp.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(s.ttl.Seconds())))
	}
	return resp, nil
}

// resolvePolicy returns the policy to serve: the candidate when the instance
// falls in an active canary cohort and the feature is enabled for the tenant,
// otherwise the active (stable) policy. It is fail-safe — any error resolving a
// candidate falls back to the active policy so a rollout misconfiguration never
// denies config.
func (s *Service) resolvePolicy(ctx context.Context, m *ksealv1.ConfigRequest) (policy *ksealv1.Policy, servedCandidate bool, err error) {
	active, err := s.store.GetActivePolicy(ctx, m.TenantId, m.AppId)
	if err != nil {
		return nil, false, err
	}
	if s.canary == nil || m.InstanceId == "" || !s.flags.Enabled(m.TenantId, compliance.FlagCanaryRollout) {
		return active, false, nil
	}
	policyID, candidate := s.canary.Cohort(m.TenantId, m.AppId, m.InstanceId)
	if !candidate || policyID == "" {
		return active, false, nil
	}
	cand, err := s.store.GetPolicy(ctx, m.TenantId, policyID)
	// Fail-safe: a canary lookup error degrades to the active policy rather
	// than failing the config response (same pattern as resolveKillSwitch).
	if err != nil || cand == nil {
		return active, false, nil
	}
	return cand, true, nil
}

// resolveKillSwitch returns the signed kill switch in effect for the scope when
// the feature is enabled for the tenant, or nil. It is fail-safe: any lookup
// error yields nil (no kill switch delivered) rather than failing the config.
func (s *Service) resolveKillSwitch(ctx context.Context, m *ksealv1.ConfigRequest) *ksealv1.SignedKillSwitch {
	if s.killSwitch == nil || !s.flags.Enabled(m.TenantId, compliance.FlagKillSwitch) {
		return nil
	}
	switches, err := s.killSwitch.ListKillSwitches(ctx, m.TenantId)
	if err != nil {
		return nil
	}
	// Pass the caller's build hash so a build-scoped switch (the most specific
	// scope) is delivered when present; empty falls back to app/tenant scope.
	_, active := compliance.GetKillSwitchState(switches, m.AppId, m.BuildHash)
	return active
}

// killSwitchEtag derives a short cache-busting suffix from the kill switch's
// scope and version so a changed switch invalidates a cached config.
func killSwitchEtag(ks *ksealv1.SignedKillSwitch) string {
	if ks == nil {
		return ""
	}
	return fmt.Sprintf(":ks%d.%d", int32(ks.Command), ks.Version)
}

// GetPolicy returns the raw assembled policy without signing — for dashboards
// and tooling that want to inspect the effective policy.
func (s *Service) GetPolicy(ctx context.Context, req *connect.Request[ksealv1.PolicyRequest]) (*connect.Response[ksealv1.PolicyResponse], error) {
	m := req.Msg
	if m.TenantId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("tenant_id required"))
	}
	policy, err := s.store.GetActivePolicy(ctx, m.TenantId, m.AppId)
	if errors.Is(err, registry.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no active policy"))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&ksealv1.PolicyResponse{Policy: buildPolicyConfig(policy)}), nil
}

// policyDoc is the authoring JSON stored in Policy.Rules. Both the array form
// ("[ {rule}, ... ]") and the object form ("{ rules: [...], signal_weights: {...} }")
// are accepted so the dashboard can evolve without breaking older policies.
type policyDoc struct {
	Rules         []ruleDoc         `json:"rules"`
	SignalWeights map[string]uint32 `json:"signal_weights"`
	// ReattestIntervalSecs opts the SDK into background re-attestation at this
	// cadence (seconds). 0 (the default / absent) keeps continuous mode off and
	// preserves the no-launch-time-network-call invariant.
	ReattestIntervalSecs uint32 `json:"reattest_interval_secs"`
}

type ruleDoc struct {
	ID          string `json:"id"`
	RiskMask    uint64 `json:"risk_mask"`
	MinScore    uint32 `json:"min_score"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

func parsePolicyDoc(rules string) policyDoc {
	var doc policyDoc
	if rules == "" {
		return doc
	}
	if err := json.Unmarshal([]byte(rules), &doc); err == nil && (doc.Rules != nil || doc.SignalWeights != nil || doc.ReattestIntervalSecs != 0) {
		return doc
	}
	var arr []ruleDoc
	if err := json.Unmarshal([]byte(rules), &arr); err == nil {
		doc.Rules = arr
	}
	return doc
}

func buildPolicyConfig(p *ksealv1.Policy) *ksealv1.PolicyConfig {
	doc := parsePolicyDoc(p.Rules)
	rules := make([]*ksealv1.PolicyRule, 0, len(doc.Rules))
	for _, r := range doc.Rules {
		rules = append(rules, &ksealv1.PolicyRule{
			Id:          r.ID,
			RiskMask:    r.RiskMask,
			MinScore:    r.MinScore,
			Action:      parseMode(r.Action, p.EnforcementMode),
			Description: r.Description,
		})
	}

	thresholds := map[string]uint32{}
	if p.RiskThresholds != "" {
		_ = json.Unmarshal([]byte(p.RiskThresholds), &thresholds)
	}

	weights := map[uint32]uint32{}
	for k, v := range doc.SignalWeights {
		var idx uint32
		if _, err := fmt.Sscanf(k, "%d", &idx); err == nil {
			weights[idx] = v
		}
	}

	return &ksealv1.PolicyConfig{
		Rules:                rules,
		RiskThresholds:       thresholds,
		DefaultMode:          p.EnforcementMode,
		ModulesEnabled:       p.ModulesEnabled,
		SignalWeights:        weights,
		PolicyHash:           registry.HashPolicy(p.AppId, p.EnforcementMode, p.Rules, p.RiskThresholds, p.ModulesEnabled),
		ReattestIntervalSecs: doc.ReattestIntervalSecs,
	}
}

func parseMode(s string, fallback ksealv1.EnforcementMode) ksealv1.EnforcementMode {
	switch s {
	case "observe", "OBSERVE", "ENFORCEMENT_MODE_OBSERVE":
		return ksealv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE
	case "step_up", "STEP_UP", "ENFORCEMENT_MODE_STEP_UP":
		return ksealv1.EnforcementMode_ENFORCEMENT_MODE_STEP_UP
	case "block", "BLOCK", "ENFORCEMENT_MODE_BLOCK":
		return ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK
	default:
		return fallback
	}
}
