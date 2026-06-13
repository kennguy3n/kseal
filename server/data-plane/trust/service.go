package trust

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kennguy3n/kseal/server/control-plane/compliance"
	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/data-plane/attestation"
	"github.com/kennguy3n/kseal/server/data-plane/canary"
	"github.com/kennguy3n/kseal/server/data-plane/guardrails"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
	appconfig "github.com/kennguy3n/kseal/server/shared/config"
	"github.com/kennguy3n/kseal/server/shared/crypto"
	"github.com/kennguy3n/kseal/server/shared/risk"
)

// Service implements the Connect TrustService.
type Service struct {
	ksealv1connect.UnimplementedTrustServiceHandler

	store    registry.Store
	nonces   *NonceStore
	verifier *attestation.Verifier
	tokenTTL time.Duration

	// Optional canary health feed; nil disables it (default behavior).
	detector *guardrails.Detector
	canary   *canary.Registry
	flags    appconfig.FeatureFlags
}

// NewService builds a TrustService.
func NewService(store registry.Store, nonces *NonceStore, verifier *attestation.Verifier, tokenTTL time.Duration) *Service {
	if tokenTTL <= 0 {
		tokenTTL = 15 * time.Minute
	}
	return &Service{store: store, nonces: nonces, verifier: verifier, tokenTTL: tokenTTL}
}

// AttachCanaryHealth wires the guardrail health feed for canary auto-rollback.
// Each validated request's allow/deny outcome is recorded against the cohort's
// policy id (candidate or stable), so the controller can detect a candidate that
// degrades. Flag-gated per tenant (compliance.FlagCanaryRollout); a nil detector
// or registry disables it entirely.
func (s *Service) AttachCanaryHealth(detector *guardrails.Detector, reg *canary.Registry, flags appconfig.FeatureFlags) {
	s.detector = detector
	s.canary = reg
	s.flags = flags
}

// recordCanaryHealth attributes one decision to the instance's canary cohort.
// It is cheap (in-memory) and no-ops unless the feature is enabled and a rollout
// is active for the scope.
func (s *Service) recordCanaryHealth(tenantID, appID, instanceID string, decision ksealv1.RequestProofResult_Decision) {
	if s.detector == nil || s.canary == nil || instanceID == "" {
		return
	}
	if !s.flags.Enabled(tenantID, compliance.FlagCanaryRollout) {
		return
	}
	policyID, _ := s.canary.Cohort(tenantID, appID, instanceID)
	if policyID == "" {
		return
	}
	s.detector.RecordDecision(tenantID, appID, policyID, decision == ksealv1.RequestProofResult_DECISION_DENY)
}

// GetNonce issues a single-use challenge nonce for the attestation step.
func (s *Service) GetNonce(ctx context.Context, req *connect.Request[ksealv1.NonceRequest]) (*connect.Response[ksealv1.NonceResponse], error) {
	if req.Msg.TenantId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("tenant_id required"))
	}
	nonce, expires, err := s.nonces.Issue(ctx, req.Msg.TenantId, req.Msg.AppId)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	return connect.NewResponse(&ksealv1.NonceResponse{Nonce: nonce, ExpiresAt: expires}), nil
}

// VerifyAttestation consumes the nonce, verifies the platform attestation, fuses
// risk against the active policy, mints a trust token, and records a session.
func (s *Service) VerifyAttestation(ctx context.Context, req *connect.Request[ksealv1.AttestationRequest]) (*connect.Response[ksealv1.AttestationResponse], error) {
	m := req.Msg
	if m.TenantId == "" || m.AppId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("tenant_id and app_id required"))
	}

	// The nonce must have been issued for this exact app (anti cross-app replay).
	ok, err := s.nonces.Consume(ctx, m.TenantId, m.Nonce, m.AppId)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if !ok {
		return reject("invalid or expired nonce"), nil
	}

	// Resolve the expected platform app identity (package / bundle id).
	expectedAppID := ""
	if app, err := s.store.GetApp(ctx, m.TenantId, m.AppId); err == nil {
		expectedAppID = app.PackageId
	} else if !errors.Is(err, registry.ErrNotFound) {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	res, err := s.verifier.Verify(ctx, attestation.Input{
		Platform: m.Platform,
		Token:    m.PlatformAttestationToken,
		Nonce:    m.Nonce,
		AppID:    expectedAppID,
	})
	if err != nil {
		if errors.Is(err, attestation.ErrUnsupportedPlatform) {
			return reject("unsupported platform"), nil
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !res.Accepted {
		// Attestation parsed but failed cryptographic verification; do not mint.
		// Record the failure for dashboard stats (best-effort: a recording error
		// must not turn a clean rejection into a 500). Reached only after the
		// single-use nonce was consumed, so it is rate-limited like the flow.
		_ = s.store.RecordFailedAttestation(ctx, &registry.TrustSession{
			TenantID:   m.TenantId,
			AppID:      m.AppId,
			BuildHash:  m.BuildHash,
			InstanceID: m.InstanceId,
			IssuedAt:   time.Now().Unix(),
		})
		reason := res.Reason
		if reason == "" {
			reason = "attestation rejected"
		}
		return reject(reason), nil
	}

	// Fuse device-reported risk with attestation-derived risk and score against
	// the active policy.
	policy, _ := s.store.GetActivePolicy(ctx, m.TenantId, m.AppId)
	thresholds := parseThresholds(policy)
	fused := risk.Fuse(m.RiskBitset, res.RiskBits)
	score := risk.Score(fused, parseWeights(policy))
	level := risk.Level(score, thresholds)
	nextChecks := risk.NextChecks(level)
	scope := capabilityScope(level)

	policyHash := m.PolicyHash
	if policy != nil {
		policyHash = registry.HashPolicy(policy.AppId, policy.EnforcementMode, policy.Rules, policy.RiskThresholds, policy.ModulesEnabled)
	}

	sk, err := s.store.GetActiveSigningKey(ctx, m.TenantId)
	if errors.Is(err, registry.ErrNotFound) {
		sk, err = s.store.CreateSigningKey(ctx, m.TenantId)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	now := time.Now()
	expiry := now.Add(s.tokenTTL)
	tokenID := uuid.NewString()
	claims := TrustClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiry),
			Subject:   m.InstanceId,
		},
		TenantID:        m.TenantId,
		AppID:           m.AppId,
		BuildHash:       m.BuildHash,
		RiskLevel:       int32(level),
		CapabilityScope: scope,
		PolicyHash:      policyHash,
	}
	signed, err := MintToken(sk.ID, sk.Private, claims)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	if err := s.store.CreateTrustSession(ctx, &registry.TrustSession{
		TokenID:         tokenID,
		TenantID:        m.TenantId,
		AppID:           m.AppId,
		BuildHash:       m.BuildHash,
		InstanceID:      m.InstanceId,
		PolicyHash:      policyHash,
		RiskLevel:       int32(level),
		CapabilityScope: scope,
		SessionSecret:   DeriveProofKey([]byte(signed)),
		IssuedAt:        now.Unix(),
		ExpiresAt:       expiry.Unix(),
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&ksealv1.AttestationResponse{
		TrustToken:  tokenToProto(claims, nextChecks),
		SignedToken: []byte(signed),
		Accepted:    true,
	}), nil
}

// ValidateRequestProof verifies a per-request proof: token validity, proof
// signature, and a strictly-increasing sequence, then returns the policy
// decision for the bound risk level.
func (s *Service) ValidateRequestProof(ctx context.Context, req *connect.Request[ksealv1.RequestProof]) (*connect.Response[ksealv1.RequestProofResult], error) {
	m := req.Msg
	if m.TrustTokenId == "" {
		return deny("missing trust token id"), nil
	}
	// Token ids are minted as UUIDs, so a malformed id can never match a stored
	// session. Fail closed here without a DB round-trip; this also prevents a
	// uuid-typed column from raising a 22P02 error that would surface as a 500
	// for attacker-controlled input.
	if _, perr := uuid.Parse(m.TrustTokenId); perr != nil {
		return deny("unknown trust token"), nil
	}
	sess, err := s.store.GetTrustSession(ctx, m.TrustTokenId)
	if errors.Is(err, registry.ErrNotFound) {
		return deny("unknown trust token"), nil
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if sess.Status != "active" {
		return deny("revoked trust token"), nil
	}
	if time.Now().Unix() >= sess.ExpiresAt {
		return deny("expired trust token"), nil
	}

	expected := crypto.HMACSHA256(sess.SessionSecret, ProofMessage(m.TrustTokenId, m.RequestHash, m.Nonce, m.MonotonicSequence))
	if subtle.ConstantTimeCompare(expected, m.AppInstanceSignature) != 1 {
		return deny("invalid proof signature"), nil
	}

	if err := s.store.ConsumeSequence(ctx, m.TrustTokenId, m.MonotonicSequence); err != nil {
		if errors.Is(err, registry.ErrReplay) {
			return deny("sequence replay"), nil
		}
		if errors.Is(err, registry.ErrNotFound) {
			return deny("unknown trust token"), nil
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	mode := ksealv1.EnforcementMode_ENFORCEMENT_MODE_STEP_UP
	if policy, err := s.store.GetActivePolicy(ctx, sess.TenantID, sess.AppID); err == nil && policy != nil {
		mode = policy.EnforcementMode
	}
	decision := risk.Decision(ksealv1.TrustLevel(sess.RiskLevel), mode)
	s.recordCanaryHealth(sess.TenantID, sess.AppID, sess.InstanceID, decision)
	return connect.NewResponse(&ksealv1.RequestProofResult{
		Decision: decision,
		Reason:   decisionReason(decision),
	}), nil
}

func reject(reason string) *connect.Response[ksealv1.AttestationResponse] {
	return connect.NewResponse(&ksealv1.AttestationResponse{Accepted: false, RejectionReason: reason})
}

func deny(reason string) *connect.Response[ksealv1.RequestProofResult] {
	return connect.NewResponse(&ksealv1.RequestProofResult{Decision: ksealv1.RequestProofResult_DECISION_DENY, Reason: reason})
}

func decisionReason(d ksealv1.RequestProofResult_Decision) string {
	switch d {
	case ksealv1.RequestProofResult_DECISION_ALLOW:
		return "ok"
	case ksealv1.RequestProofResult_DECISION_STEP_UP:
		return "step-up required"
	case ksealv1.RequestProofResult_DECISION_DENY:
		return "denied"
	default:
		return ""
	}
}

func capabilityScope(level ksealv1.TrustLevel) []string {
	switch level {
	case ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED:
		return []string{"*"}
	case ksealv1.TrustLevel_TRUST_LEVEL_LOW_RISK:
		return []string{"read", "write"}
	case ksealv1.TrustLevel_TRUST_LEVEL_MEDIUM_RISK:
		return []string{"read"}
	case ksealv1.TrustLevel_TRUST_LEVEL_HIGH_RISK:
		return []string{"read"}
	default:
		return []string{}
	}
}

func parseThresholds(policy *ksealv1.Policy) map[string]uint32 {
	if policy == nil || policy.RiskThresholds == "" {
		return nil
	}
	out := map[string]uint32{}
	if err := json.Unmarshal([]byte(policy.RiskThresholds), &out); err != nil {
		return nil
	}
	return out
}

func parseWeights(policy *ksealv1.Policy) map[uint32]uint32 {
	if policy == nil || policy.Rules == "" {
		return nil
	}
	// Optional "signal_weights" object embedded in the rules JSON.
	var wrapper struct {
		SignalWeights map[string]uint32 `json:"signal_weights"`
	}
	if err := json.Unmarshal([]byte(policy.Rules), &wrapper); err != nil || wrapper.SignalWeights == nil {
		return nil
	}
	out := map[uint32]uint32{}
	for k, v := range wrapper.SignalWeights {
		if idx, err := strconv.ParseUint(k, 10, 32); err == nil {
			out[uint32(idx)] = v
		}
	}
	return out
}
