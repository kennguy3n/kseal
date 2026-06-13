// Package flow holds the reusable steps of the backend quickstart: connecting
// to Postgres + Redis, seeding a tenant/app/build/policy/API key, driving the
// device trust flow, and reading back through QueryService. It is split out from
// main so the same code is covered by a real integration test (flow_test.go).
package flow

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"sync/atomic"

	"github.com/google/uuid"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"

	"github.com/kennguy3n/kseal/server/control-plane/migrations"
	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/data-plane/attestation"
	"github.com/kennguy3n/kseal/server/data-plane/ingest"
	"github.com/kennguy3n/kseal/server/data-plane/query"
	"github.com/kennguy3n/kseal/server/data-plane/trust"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
	kcrypto "github.com/kennguy3n/kseal/server/shared/crypto"
	"github.com/kennguy3n/kseal/server/shared/db"
)

// BuildHash is the registered build hash used by the seeded build; the trust
// token binds to it.
const BuildHash = "sha256:0000000000000000000000000000000000000000000000000000000000000001"

// devKEK is a fixed 32-byte key-encryption key for the local example database.
// It only protects signing-key material inside a throwaway dev database, so a
// constant is fine here (and never appears in production paths). Declared as a
// string const so it is truly immutable; converted to bytes at the use site.
const devKEK = "kseal-backend-quickstart-dev-kek"

// playKeyID is the fake Google JWKS key id our mock key source answers to.
const playKeyID = "kseal-quickstart-google-kid"

// Env holds the wired, real server services plus the mock attestation key.
type Env struct {
	db       *db.DB
	rdb      *redis.Client
	store    registry.Store
	trustSvc *trust.Service
	querySvc *query.Service

	playKeyID string
	playPriv  *rsa.PrivateKey
}

// Connect dials Postgres + Redis, runs migrations, and wires the registry,
// trust, and query services with a mock Play Integrity key source.
func Connect(ctx context.Context, dsn, redisAddr string) (*Env, error) {
	database, err := db.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect postgres (%s): %w", redactDSN(dsn), err)
	}
	if err := database.Migrate(ctx, migrations.FS); err != nil {
		database.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		database.Close()
		return nil, fmt.Errorf("connect redis (%s): %w", redisAddr, err)
	}

	enc, err := kcrypto.NewEncryptor([]byte(devKEK))
	if err != nil {
		_ = rdb.Close()
		database.Close()
		return nil, err
	}
	store := registry.NewPostgresStore(database, enc)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		_ = rdb.Close()
		database.Close()
		return nil, err
	}
	play := attestation.NewPlayIntegrityVerifier(staticKeySource{keyID: playKeyID, pub: priv.Public()})
	verifier := attestation.NewVerifier(play, nil)

	nonces := trust.NewNonceStore(rdb, 0)
	trustSvc := trust.NewService(store, nonces, verifier, 0)

	// QueryService reads tenant overview + trust-session stats from the store;
	// an in-memory analytics store satisfies the (unused-here) events path.
	querySvc := query.NewService(store, ingest.NewInMemoryAnalyticsStore())

	return &Env{
		db:        database,
		rdb:       rdb,
		store:     store,
		trustSvc:  trustSvc,
		querySvc:  querySvc,
		playKeyID: playKeyID,
		playPriv:  priv,
	}, nil
}

// Close releases the database pool and the Redis client, so callers (including
// t.Cleanup in the test) fully release every connection they opened.
func (e *Env) Close() {
	if e.rdb != nil {
		_ = e.rdb.Close()
	}
	if e.db != nil {
		e.db.Close()
	}
}

// SeedResult identifies the seeded tenant, app, build, and the bootstrap key.
type SeedResult struct {
	TenantID  string
	AppID     string
	PackageID string
	PolicyID  string
	APIKey    string
}

// Seed provisions one tenant with an Android app, a registered build, an active
// BLOCK-mode policy (so one policy exercises ALLOW/STEP_UP/DENY by trust level
// alone), and a control-plane API key. This is the documented out-of-band
// bootstrap path until a self-service onboarding RPC ships.
func (e *Env) Seed(ctx context.Context) (SeedResult, error) {
	tenant, err := e.store.CreateTenant(ctx, registry.CreateTenantInput{
		Name: "Quickstart", Slug: uniqueSlug("quickstart"), Tier: "growth",
	})
	if err != nil {
		return SeedResult{}, fmt.Errorf("create tenant: %w", err)
	}
	pkg := "com.kseal.quickstart"
	app, err := e.store.CreateApp(ctx, registry.CreateAppInput{
		TenantID: tenant.Id, Name: pkg, PackageID: pkg, Platform: ksealv1.Platform_PLATFORM_ANDROID,
	})
	if err != nil {
		return SeedResult{}, fmt.Errorf("create app: %w", err)
	}
	if _, err := e.store.CreateBuild(ctx, registry.CreateBuildInput{
		TenantID: tenant.Id, AppID: app.Id, BuildHash: BuildHash,
		VersionName: "1.0.0", VersionCode: 1, Manifest: "{}",
	}); err != nil {
		return SeedResult{}, fmt.Errorf("create build: %w", err)
	}
	policy, err := e.store.CreatePolicy(ctx, registry.CreatePolicyInput{
		TenantID: tenant.Id, AppID: app.Id, Name: uniqueSlug("policy"),
		EnforcementMode: ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK,
		Rules:           "{}", RiskThresholds: "",
		ModulesEnabled: []string{"root", "debugger", "integrity"},
	})
	if err != nil {
		return SeedResult{}, fmt.Errorf("create policy: %w", err)
	}
	if _, err := e.store.ActivatePolicy(ctx, tenant.Id, policy.Id); err != nil {
		return SeedResult{}, fmt.Errorf("activate policy: %w", err)
	}
	apiKey, _, err := e.store.CreateAPIKey(ctx, tenant.Id, "quickstart-admin", []string{"control:read", "control:write"})
	if err != nil {
		return SeedResult{}, fmt.Errorf("create api key: %w", err)
	}
	return SeedResult{
		TenantID: tenant.Id, AppID: app.Id, PackageID: pkg, PolicyID: policy.Id, APIKey: apiKey,
	}, nil
}

// Verdict is the (mocked) Play Integrity verdict that drives the real
// verdict->risk mapping in the verifier.
type Verdict struct {
	AppRecognition string
	Device         []string
	Licensing      string
}

// FlowResult captures the trust-flow outcome for one device profile.
type FlowResult struct {
	TokenID        string
	TrustLevel     string
	Decision       string
	ReplayDecision string
}

// RunTrustFlow drives GetNonce -> VerifyAttestation -> ValidateRequestProof for
// one device profile and returns the resulting decisions.
func (e *Env) RunTrustFlow(ctx context.Context, seed SeedResult, v Verdict) (FlowResult, error) {
	nonceResp, err := e.trustSvc.GetNonce(ctx, connect.NewRequest(&ksealv1.NonceRequest{
		TenantId: seed.TenantID, AppId: seed.AppID, Platform: ksealv1.Platform_PLATFORM_ANDROID,
	}))
	if err != nil {
		return FlowResult{}, fmt.Errorf("get nonce: %w", err)
	}
	nonce := nonceResp.Msg.Nonce

	token := e.playIntegrityToken(seed.PackageID, nonce, v)
	attResp, err := e.trustSvc.VerifyAttestation(ctx, connect.NewRequest(&ksealv1.AttestationRequest{
		TenantId: seed.TenantID, AppId: seed.AppID, Platform: ksealv1.Platform_PLATFORM_ANDROID,
		PlatformAttestationToken: token, Nonce: nonce, BuildHash: BuildHash, InstanceId: "quickstart-instance-1",
	}))
	if err != nil {
		return FlowResult{}, fmt.Errorf("verify attestation: %w", err)
	}
	if !attResp.Msg.Accepted {
		return FlowResult{}, fmt.Errorf("attestation rejected: %s", attResp.Msg.RejectionReason)
	}

	tokenID := attResp.Msg.TrustToken.TokenId
	proofKey := trust.DeriveProofKey(attResp.Msg.SignedToken)
	reqNonce := mustRandom(16)

	decision, err := e.validate(ctx, buildProof(tokenID, proofKey, reqNonce, 1))
	if err != nil {
		return FlowResult{}, err
	}
	// Replaying the exact same (token, seq) must be denied by anti-replay.
	replay, err := e.validate(ctx, buildProof(tokenID, proofKey, reqNonce, 1))
	if err != nil {
		return FlowResult{}, err
	}
	return FlowResult{
		TokenID:        tokenID,
		TrustLevel:     trustLevelName(attResp.Msg.TrustToken.RiskLevel),
		Decision:       decisionName(decision),
		ReplayDecision: decisionName(replay),
	}, nil
}

func (e *Env) validate(ctx context.Context, p *ksealv1.RequestProof) (ksealv1.RequestProofResult_Decision, error) {
	res, err := e.trustSvc.ValidateRequestProof(ctx, connect.NewRequest(p))
	if err != nil {
		return ksealv1.RequestProofResult_DECISION_UNSPECIFIED, fmt.Errorf("validate request proof: %w", err)
	}
	return res.Msg.Decision, nil
}

// Overview is the subset of GetTenantOverview the quickstart prints.
type Overview struct {
	AppCount          int32
	BuildCount        int32
	ActivePolicyCount int32
}

// TenantOverview performs a QueryService read for the tenant. The seeded API
// key is validated exactly as the server's auth middleware does, attaching the
// resolved principal to the context so tenant isolation is enforced.
func (e *Env) TenantOverview(ctx context.Context, seed SeedResult) (Overview, error) {
	authed, err := e.authContext(ctx, seed.APIKey)
	if err != nil {
		return Overview{}, err
	}
	resp, err := e.querySvc.GetTenantOverview(authed, connect.NewRequest(&ksealv1.GetTenantOverviewRequest{TenantId: seed.TenantID}))
	if err != nil {
		return Overview{}, fmt.Errorf("get tenant overview: %w", err)
	}
	return Overview{
		AppCount: resp.Msg.AppCount, BuildCount: resp.Msg.BuildCount, ActivePolicyCount: resp.Msg.ActivePolicyCount,
	}, nil
}

// SessionStats is the subset of GetTrustSessionStats the quickstart prints.
type SessionStats struct {
	Total              int64
	TokensIssued       int64
	AttestationsFailed int64
	ByTrustLevel       map[string]int64
}

// TrustSessionStats reads trust-session outcome counts via QueryService.
func (e *Env) TrustSessionStats(ctx context.Context, seed SeedResult) (SessionStats, error) {
	authed, err := e.authContext(ctx, seed.APIKey)
	if err != nil {
		return SessionStats{}, err
	}
	resp, err := e.querySvc.GetTrustSessionStats(authed, connect.NewRequest(&ksealv1.GetTrustSessionStatsRequest{TenantId: seed.TenantID}))
	if err != nil {
		return SessionStats{}, fmt.Errorf("get trust-session stats: %w", err)
	}
	m := resp.Msg
	return SessionStats{
		Total:              m.TotalSessions,
		TokensIssued:       m.TokensIssued,
		AttestationsFailed: m.AttestationsFailed,
		ByTrustLevel:       m.SessionsByTrustLevel,
	}, nil
}

// authContext validates the API key through the registry store (the same call
// the server's auth interceptor makes) and attaches the resolved principal, so
// QueryService reads run with a real, tenant-scoped identity.
func (e *Env) authContext(ctx context.Context, apiKey string) (context.Context, error) {
	principal, err := e.store.ValidateAPIKey(ctx, apiKey)
	if err != nil {
		return nil, fmt.Errorf("validate api key: %w", err)
	}
	return auth.WithPrincipal(ctx, principal), nil
}

// playIntegrityToken signs a Play Integrity verdict JWS (RS256) with the local
// test key, binding it to the issued nonce. This emulates the EXTERNAL Google
// Play Integrity service only; the real JWS parsing and verdict->risk mapping
// run unchanged in the verifier.
func (e *Env) playIntegrityToken(pkg string, nonce []byte, v Verdict) []byte {
	claims := jwt.MapClaims{
		"requestDetails": map[string]any{
			"requestPackageName": pkg,
			"nonce":              base64.StdEncoding.EncodeToString(nonce),
		},
		"appIntegrity":    map[string]any{"appRecognitionVerdict": v.AppRecognition},
		"deviceIntegrity": map[string]any{"deviceRecognitionVerdict": v.Device},
		"accountDetails":  map[string]any{"appLicensingVerdict": v.Licensing},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = e.playKeyID
	signed, err := tok.SignedString(e.playPriv)
	if err != nil {
		// Signing a locally generated key cannot fail in practice; panic keeps
		// the example honest rather than emitting an empty token.
		panic(fmt.Sprintf("sign play integrity token: %v", err))
	}
	return []byte(signed)
}

// buildProof constructs a request proof with the SAME canonical preimage and
// HMAC the SDK core uses (crypto.RequestProofPreimage keyed by the per-session
// proof key derived from the signed token).
func buildProof(tokenID string, proofKey, nonce []byte, seq int64) *ksealv1.RequestProof {
	requestHash := sha256.Sum256([]byte("POST /v1/orders"))
	sig := kcrypto.HMACSHA256(proofKey, trust.ProofMessage(tokenID, requestHash[:], nonce, seq))
	return &ksealv1.RequestProof{
		TrustTokenId:         tokenID,
		RequestHash:          requestHash[:],
		Nonce:                nonce,
		MonotonicSequence:    seq,
		AppInstanceSignature: sig,
	}
}

// staticKeySource resolves the locally generated RSA public key by key id,
// standing in for Google's JWKS endpoint (the only external dependency mocked).
type staticKeySource struct {
	keyID string
	pub   crypto.PublicKey
}

func (s staticKeySource) PublicKey(_ context.Context, keyID string) (crypto.PublicKey, error) {
	if keyID != s.keyID {
		return nil, fmt.Errorf("unknown key id: %s", keyID)
	}
	return s.pub, nil
}

func mustRandom(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("read random: %v", err))
	}
	return b
}

// slugCounter keeps seeded slugs unique across repeated runs against a persisted
// database without colliding.
var slugCounter atomic.Uint64

func uniqueSlug(prefix string) string {
	return fmt.Sprintf("%s-%s-%d", prefix, uuid.NewString()[:8], slugCounter.Add(1))
}

// redactDSN masks any password in a database DSN so it is safe to embed in
// errors/logs. url.URL.Redacted() replaces the password with "xxxxx"; if the
// DSN can't be parsed we drop it entirely rather than risk leaking it.
func redactDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "<unparseable dsn>"
	}
	return u.Redacted()
}

func trustLevelName(l ksealv1.TrustLevel) string {
	if name, ok := map[ksealv1.TrustLevel]string{
		ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED:     "TRUSTED",
		ksealv1.TrustLevel_TRUST_LEVEL_LOW_RISK:    "LOW_RISK",
		ksealv1.TrustLevel_TRUST_LEVEL_MEDIUM_RISK: "MEDIUM_RISK",
		ksealv1.TrustLevel_TRUST_LEVEL_HIGH_RISK:   "HIGH_RISK",
		ksealv1.TrustLevel_TRUST_LEVEL_CRITICAL:    "CRITICAL",
	}[l]; ok {
		return name
	}
	return l.String()
}

func decisionName(d ksealv1.RequestProofResult_Decision) string {
	switch d {
	case ksealv1.RequestProofResult_DECISION_ALLOW:
		return "ALLOW"
	case ksealv1.RequestProofResult_DECISION_STEP_UP:
		return "STEP_UP"
	case ksealv1.RequestProofResult_DECISION_DENY:
		return "DENY"
	default:
		return "UNSPECIFIED"
	}
}
