package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
)

// Service implements the Connect ConfigService.
type Service struct {
	ksealv1connect.UnimplementedConfigServiceHandler

	store  registry.Store
	signer *Signer
	ttl    time.Duration
}

// NewService builds a ConfigService with the given signed-config TTL.
func NewService(store registry.Store, signer *Signer, ttl time.Duration) *Service {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Service{store: store, signer: signer, ttl: ttl}
}

// GetConfig assembles the active policy into a signed, cacheable config bundle.
func (s *Service) GetConfig(ctx context.Context, req *connect.Request[ksealv1.ConfigRequest]) (*connect.Response[ksealv1.ConfigResponse], error) {
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

	pc := buildPolicyConfig(policy)
	// PolicyHash is a hex-encoded SHA-256 digest (registry.HashPolicy), so it
	// contains only token-safe characters. Wrap it in literal double quotes per
	// RFC 7232 (a strong ETag) rather than fmt.Sprintf("%q", ...), which would
	// Go-escape any special characters and could confuse CDN ETag parsers.
	etag := `"` + pc.PolicyHash + `"`
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
	})
	resp.Header().Set("ETag", etag)
	resp.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(s.ttl.Seconds())))
	return resp, nil
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
	if err := json.Unmarshal([]byte(rules), &doc); err == nil && (doc.Rules != nil || doc.SignalWeights != nil) {
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
		Rules:          rules,
		RiskThresholds: thresholds,
		DefaultMode:    p.EnforcementMode,
		ModulesEnabled: p.ModulesEnabled,
		SignalWeights:  weights,
		PolicyHash:     registry.HashPolicy(p.AppId, p.EnforcementMode, p.Rules, p.RiskThresholds, p.ModulesEnabled),
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
