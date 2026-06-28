package trust

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/kennguy3n/kseal/server/control-plane/compliance"
	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/data-plane/attestation"
	"github.com/kennguy3n/kseal/server/data-plane/canary"
	"github.com/kennguy3n/kseal/server/data-plane/fleet"
	"github.com/kennguy3n/kseal/server/data-plane/guardrails"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
	"github.com/kennguy3n/kseal/server/shared/auth"
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
	tracer   trace.Tracer

	// Optional canary health feed; nil disables it (default behavior).
	detector *guardrails.Detector
	canary   *canary.Registry
	flags    appconfig.FeatureFlags

	// Optional population-level fleet-anomaly engine; nil disables it.
	fleet *fleet.Engine
	// trustEdgeRegion gates whether CDN-injected country headers are read as the
	// fleet cohort's region dimension. Off by default: these headers are
	// client-spoofable when the server is not behind a CDN that sets and
	// sanitizes them, so trusting them blindly would let an attacker fragment
	// their traffic across fabricated region cohorts (each staying under
	// MinSamples/VelocityMinVolume) to evade detection. Operators behind such a
	// trusted edge opt in explicitly.
	trustEdgeRegion bool
}

// NewService builds a TrustService. flags carries the per-tenant feature toggles
// that gate the optional subsystems (canary health, fleet anomaly); it is owned
// by the service for its lifetime, so the Attach* wirings never mutate it. The
// zero value disables every flag.
func NewService(store registry.Store, nonces *NonceStore, verifier *attestation.Verifier, tokenTTL time.Duration, flags appconfig.FeatureFlags) *Service {
	if tokenTTL <= 0 {
		tokenTTL = 15 * time.Minute
	}
	return &Service{
		store:    store,
		nonces:   nonces,
		verifier: verifier,
		tokenTTL: tokenTTL,
		tracer:   otel.Tracer("github.com/kennguy3n/kseal/server/data-plane/trust"),
		flags:    flags,
	}
}

// AttachCanaryHealth wires the guardrail health feed for canary auto-rollback.
// Each validated request's allow/deny outcome is recorded against the cohort's
// policy id (candidate or stable), so the controller can detect a candidate that
// degrades. Flag-gated per tenant (compliance.FlagCanaryRollout, supplied to
// NewService); a nil detector or registry disables it entirely.
func (s *Service) AttachCanaryHealth(detector *guardrails.Detector, reg *canary.Registry) {
	s.detector = detector
	s.canary = reg
}

// AttachFleetGuard wires the population-level fleet-anomaly engine. Each accepted
// attestation is observed into the engine, and when the (tenant, app, build,
// region) cohort is surging, a server-derived FLEET_ANOMALY risk bit is fused
// into the newly minted session's risk before scoring. Flag-gated per tenant
// (compliance.FlagFleetAnomaly, supplied to NewService); a nil engine disables
// it entirely.
func (s *Service) AttachFleetGuard(engine *fleet.Engine, trustEdgeRegionHeaders bool) {
	s.fleet = engine
	s.trustEdgeRegion = trustEdgeRegionHeaders
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

// applyFleetGuard observes the fused risk bits into the population engine and,
// when the (tenant, app, build, region) cohort is surging — either a signal
// surge or a volume-velocity spike — fuses the server-derived FLEET_ANOMALY bit
// into the returned bitset. It is a no-op (returning fused unchanged) unless the
// engine is wired and the feature is enabled for the tenant, so it adds zero
// overhead on the default path.
func (s *Service) applyFleetGuard(tenantID, appID, buildHash, region string, fused uint64, span trace.Span) uint64 {
	if s.fleet == nil || !s.flags.Enabled(tenantID, compliance.FlagFleetAnomaly) {
		return fused
	}
	// Observe and assess on the engine's own clock under a single shard-lock
	// acquisition, so the arrival time and the window assessment share one
	// (injectable) time source and the hot path locks the cohort's shard once.
	a := s.fleet.ObserveAndAssessNow(tenantID, appID, buildHash, region, fused)
	if !a.Anomalous {
		return fused
	}
	names := make([]string, 0, len(a.Signals))
	for _, sig := range a.Signals {
		names = append(names, sig.Name)
	}
	span.SetAttributes(
		attribute.Bool("fleet.anomaly", true),
		attribute.String("fleet.signals", strings.Join(names, ",")),
		attribute.Bool("fleet.velocity_surge", a.VelocitySurge),
		attribute.Int("fleet.observed", a.Observed),
	)
	return fused | risk.BitFleetAnomaly
}

// edgeCountryHeaders are the request headers a fronting CDN/edge commonly sets
// with the client's ISO country, used as the best-effort cohort region. When
// none are present the region is empty and the cohort is build-level.
var edgeCountryHeaders = []string{
	"Cf-Ipcountry",        // Cloudflare
	"X-Vercel-Ip-Country", // Vercel
	"X-Geo-Country",       // generic / Fastly
	"X-Country-Code",
	"X-Appengine-Country", // Google Cloud
}

// edgeRegion extracts a best-effort country/region from edge headers. An empty
// or sentinel value (e.g. Cloudflare's "XX"/"T1") collapses to "". It returns ""
// unless the operator has opted in via AttachFleetGuard, because these headers
// are client-spoofable absent a trusted CDN/edge that sets and strips them;
// collapsing to a build-level cohort is the safe default (an attacker cannot
// then shard traffic across fabricated regions to dodge the per-cohort floors).
func (s *Service) edgeRegion(h http.Header) string {
	if !s.trustEdgeRegion {
		return ""
	}
	for _, name := range edgeCountryHeaders {
		v := strings.ToUpper(strings.TrimSpace(h.Get(name)))
		if v == "" || v == "XX" || v == "T1" {
			continue
		}
		return v
	}
	return ""
}

// GetNonce issues a single-use challenge nonce for the attestation step.
func (s *Service) GetNonce(ctx context.Context, req *connect.Request[ksealv1.NonceRequest]) (*connect.Response[ksealv1.NonceResponse], error) {
	if req.Msg.TenantId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("tenant_id required"))
	}
	if req.Msg.AppId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("app_id required"))
	}
	if _, err := s.store.GetApp(ctx, req.Msg.TenantId, req.Msg.AppId); err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("unknown tenant or app"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
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

	ctx, span := s.tracer.Start(ctx, "trust.VerifyAttestation", trace.WithAttributes(
		attribute.String("tenant", m.TenantId),
		attribute.String("app", m.AppId),
		attribute.String("platform", m.Platform.String()),
	))
	defer span.End()

	// The nonce must have been issued for this exact app (anti cross-app replay).
	ok, err := s.nonces.Consume(ctx, m.TenantId, m.Nonce, m.AppId)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if !ok {
		return reject("invalid or expired nonce"), nil
	}

	// Resolve the expected platform app identity (package / bundle id).
	app, err := s.store.GetApp(ctx, m.TenantId, m.AppId)
	if errors.Is(err, registry.ErrNotFound) {
		return reject("unknown tenant or app"), nil
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if app.PackageId == "" {
		return reject("app identity is not configured"), nil
	}
	expectedAppID := app.PackageId

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
	policy, perr := s.store.GetActivePolicy(ctx, m.TenantId, m.AppId)
	if perr != nil && !errors.Is(perr, registry.ErrNotFound) {
		span.RecordError(perr)
		span.SetAttributes(attribute.String("policy_lookup", "degraded"))
	}
	thresholds := parseThresholds(policy)
	fused := risk.Fuse(risk.FromWire(m.RiskBitset), res.RiskBits)
	fused = s.applyFleetGuard(m.TenantId, m.AppId, m.BuildHash, s.edgeRegion(req.Header()), fused, span)
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
	if len(m.RequestHash) == 0 || len(m.Nonce) == 0 {
		return deny("invalid proof: missing request hash or nonce"), nil
	}
	if len(m.AppInstanceSignature) == 0 {
		return deny("invalid proof: missing signature"), nil
	}

	ctx, span := s.tracer.Start(ctx, "trust.ValidateRequestProof", trace.WithAttributes(
		attribute.String("trust_token_id", m.TrustTokenId),
	))
	defer span.End()

	// Token ids are minted as UUIDs, so a malformed id can never match a stored
	// session. Fail closed here without a DB round-trip; this also prevents a
	// uuid-typed column from raising a 22P02 error that would surface as a 500
	// for attacker-controlled input.
	if _, perr := uuid.Parse(m.TrustTokenId); perr != nil {
		return deny("unknown trust token"), nil
	}
	tenantID, terr := auth.TenantFrom(ctx)
	if terr != nil || tenantID == "" {
		return deny("tenant credential required"), nil
	}
	sess, err := s.store.GetTrustSession(ctx, tenantID, m.TrustTokenId)
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

	if err := s.store.ConsumeSequence(ctx, tenantID, m.TrustTokenId, m.MonotonicSequence); err != nil {
		if errors.Is(err, registry.ErrReplay) {
			return deny("sequence replay"), nil
		}
		if errors.Is(err, registry.ErrNotFound) {
			return deny("unknown trust token"), nil
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	mode := ksealv1.EnforcementMode_ENFORCEMENT_MODE_STEP_UP
	if policy, perr := s.store.GetActivePolicy(ctx, sess.TenantID, sess.AppID); perr == nil && policy != nil {
		mode = policy.EnforcementMode
	} else if perr != nil && !errors.Is(perr, registry.ErrNotFound) {
		span.RecordError(perr)
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
