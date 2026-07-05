package trust

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/data-plane/attestation"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
	appconfig "github.com/kennguy3n/kseal/server/shared/config"
	"github.com/kennguy3n/kseal/server/shared/crypto"
)

type stubVerifier struct{ res *attestation.Result }

func (s stubVerifier) Verify(_ context.Context, _ attestation.Input) (*attestation.Result, error) {
	return s.res, nil
}

func newRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

func TestTokenMintValidate(t *testing.T) {
	kp, _ := crypto.GenerateEd25519()
	now := time.Now()
	claims := TrustClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "tok1",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
		TenantID: "t1", AppID: "a1", RiskLevel: int32(ksealv1.TrustLevel_TRUST_LEVEL_LOW_RISK),
	}
	signed, err := MintToken("kid1", kp.Private, claims)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ValidateToken(kp.Public, signed)
	if err != nil {
		t.Fatal(err)
	}
	if got.TenantID != "t1" || got.ID != "tok1" {
		t.Fatalf("claims mismatch: %+v", got)
	}

	// Expired token must fail.
	expired := claims
	expired.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Minute))
	es, _ := MintToken("kid1", kp.Private, expired)
	if _, err := ValidateToken(kp.Public, es); err == nil {
		t.Fatal("expired token accepted")
	}

	// Wrong key must fail.
	other, _ := crypto.GenerateEd25519()
	if _, err := ValidateToken(other.Public, signed); err == nil {
		t.Fatal("token verified under wrong key")
	}
}

func TestNonceSingleUse(t *testing.T) {
	store := NewNonceStore(newRedis(t), time.Minute)
	ctx := context.Background()
	nonce, exp, err := store.Issue(ctx, "t1", "a1")
	if err != nil || len(nonce) != crypto.NonceSize || exp == 0 {
		t.Fatalf("issue: %v len=%d", err, len(nonce))
	}
	// A nonce issued for app a1 must not be redeemable for a different app.
	if ok, err := store.Consume(ctx, "t1", nonce, "a2"); err != nil || ok {
		t.Fatalf("cross-app consume should fail: ok=%v err=%v", ok, err)
	}
	ok, err := store.Consume(ctx, "t1", nonce, "a1")
	if err != nil || !ok {
		t.Fatalf("first consume should succeed: %v %v", ok, err)
	}
	ok, _ = store.Consume(ctx, "t1", nonce, "a1")
	if ok {
		t.Fatal("nonce reused")
	}
}

func setupService(t *testing.T, res *attestation.Result) (*Service, registry.Store, *ksealv1.Tenant, *ksealv1.App) {
	return setupServiceWithFlags(t, res, appconfig.FeatureFlags{})
}

func setupServiceWithFlags(t *testing.T, res *attestation.Result, flags appconfig.FeatureFlags) (*Service, registry.Store, *ksealv1.Tenant, *ksealv1.App) {
	t.Helper()
	store := registry.NewMemStore()
	ctx := context.Background()
	tn, err := store.CreateTenant(ctx, registry.CreateTenantInput{Name: "T", Slug: "t-trust"})
	if err != nil {
		t.Fatal(err)
	}
	app, err := store.CreateApp(ctx, registry.CreateAppInput{TenantID: tn.Id, Name: "A", PackageID: "com.x", Platform: ksealv1.Platform_PLATFORM_ANDROID})
	if err != nil {
		t.Fatal(err)
	}
	verifier := attestation.NewVerifier(stubVerifier{res}, stubVerifier{res})
	svc := NewService(store, NewNonceStore(newRedis(t), time.Minute), verifier, time.Minute, flags)
	return svc, store, tn, app
}

func TestTrustFlowEndToEnd(t *testing.T) {
	svc, _, tn, app := setupService(t, &attestation.Result{Accepted: true, AppRecognized: true, DeviceIntegrity: true})
	ctx := context.Background()
	tenantCtx := auth.WithTenant(ctx, tn.Id)

	nonceResp, err := svc.GetNonce(ctx, connect.NewRequest(&ksealv1.NonceRequest{TenantId: tn.Id, AppId: app.Id, Platform: ksealv1.Platform_PLATFORM_ANDROID}))
	if err != nil {
		t.Fatal(err)
	}

	attResp, err := svc.VerifyAttestation(ctx, connect.NewRequest(&ksealv1.AttestationRequest{
		TenantId: tn.Id, AppId: app.Id, Platform: ksealv1.Platform_PLATFORM_ANDROID,
		Nonce: nonceResp.Msg.Nonce, BuildHash: "bh", InstanceId: "inst",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !attResp.Msg.Accepted || attResp.Msg.TrustToken == nil {
		t.Fatalf("attestation not accepted: %+v", attResp.Msg)
	}
	tokenID := attResp.Msg.TrustToken.TokenId
	proofKey := DeriveProofKey(attResp.Msg.SignedToken)

	// Valid proof with sequence 1 -> allow (level trusted, step-up default mode).
	proofNonce := []byte("proof-nonce-12345678")
	proof := func(seq int64) *ksealv1.RequestProof {
		reqHash := []byte("req")
		p := &ksealv1.RequestProof{TrustTokenId: tokenID, RequestHash: reqHash, Nonce: proofNonce, MonotonicSequence: seq}
		p.AppInstanceSignature = crypto.HMACSHA256(proofKey, ProofMessage(tokenID, reqHash, proofNonce, seq))
		return p
	}

	r1, err := svc.ValidateRequestProof(tenantCtx, connect.NewRequest(proof(1)))
	if err != nil {
		t.Fatal(err)
	}
	if r1.Msg.Decision == ksealv1.RequestProofResult_DECISION_DENY {
		t.Fatalf("clean device denied: %s", r1.Msg.Reason)
	}

	// Replay of sequence 1 -> deny.
	rReplay, err := svc.ValidateRequestProof(tenantCtx, connect.NewRequest(proof(1)))
	if err != nil {
		t.Fatal(err)
	}
	if rReplay.Msg.Decision != ksealv1.RequestProofResult_DECISION_DENY {
		t.Fatal("replay not denied")
	}

	// Bad signature -> deny.
	bad := proof(2)
	bad.AppInstanceSignature = []byte("garbage")
	rBad, _ := svc.ValidateRequestProof(tenantCtx, connect.NewRequest(bad))
	if rBad.Msg.Decision != ksealv1.RequestProofResult_DECISION_DENY {
		t.Fatal("bad signature not denied")
	}
}

// failingSessionStore embeds a real Store but makes GetTrustSession return a
// non-ErrNotFound error, mimicking the Postgres uuid-typed column raising a
// 22P02 (invalid_text_representation) for a malformed token id.
type failingSessionStore struct {
	registry.Store
}

func (failingSessionStore) GetTrustSession(context.Context, string, string) (*registry.TrustSession, error) {
	return nil, errors.New("simulated 22P02 invalid_text_representation")
}

// A malformed (non-UUID) trust token id must fail closed to a clean DENY rather
// than surfacing the store error as a Connect Internal (500). The UUID pre-check
// short-circuits before the store is consulted, so the simulated store error is
// never reached.
func TestValidateRequestProofMalformedTokenIDFailsClosed(t *testing.T) {
	verifier := attestation.NewVerifier(stubVerifier{nil}, stubVerifier{nil})
	svc := NewService(failingSessionStore{registry.NewMemStore()}, NewNonceStore(newRedis(t), time.Minute), verifier, time.Minute, appconfig.FeatureFlags{})
	ctx := context.Background()

	res, err := svc.ValidateRequestProof(ctx, connect.NewRequest(&ksealv1.RequestProof{
		TrustTokenId:         "not-a-uuid",
		RequestHash:          []byte("req"),
		MonotonicSequence:    1,
		AppInstanceSignature: []byte("irrelevant"),
	}))
	if err != nil {
		t.Fatalf("malformed token id must fail closed (DENY), got error %v", err)
	}
	if res.Msg.Decision != ksealv1.RequestProofResult_DECISION_DENY {
		t.Fatalf("expected DENY for malformed token id, got %v", res.Msg.Decision)
	}
}

func TestValidateRequestProofRejectsMissingFields(t *testing.T) {
	svc, _, tn, app := setupService(t, &attestation.Result{Accepted: true, AppRecognized: true, DeviceIntegrity: true})
	ctx := context.Background()

	nonceResp, err := svc.GetNonce(ctx, connect.NewRequest(&ksealv1.NonceRequest{TenantId: tn.Id, AppId: app.Id, Platform: ksealv1.Platform_PLATFORM_ANDROID}))
	if err != nil {
		t.Fatal(err)
	}
	attResp, err := svc.VerifyAttestation(ctx, connect.NewRequest(&ksealv1.AttestationRequest{
		TenantId: tn.Id, AppId: app.Id, Platform: ksealv1.Platform_PLATFORM_ANDROID,
		Nonce: nonceResp.Msg.Nonce, BuildHash: "bh", InstanceId: "inst",
	}))
	if err != nil || !attResp.Msg.Accepted {
		t.Fatal("attestation failed")
	}
	tokenID := attResp.Msg.TrustToken.TokenId

	cases := []struct {
		name  string
		proof *ksealv1.RequestProof
	}{
		{
			"empty_request_hash",
			&ksealv1.RequestProof{TrustTokenId: tokenID, Nonce: []byte("n"), MonotonicSequence: 1, AppInstanceSignature: []byte("sig")},
		},
		{
			"empty_nonce",
			&ksealv1.RequestProof{TrustTokenId: tokenID, RequestHash: []byte("rh"), MonotonicSequence: 1, AppInstanceSignature: []byte("sig")},
		},
		{
			"empty_signature",
			&ksealv1.RequestProof{TrustTokenId: tokenID, RequestHash: []byte("rh"), Nonce: []byte("n"), MonotonicSequence: 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := svc.ValidateRequestProof(ctx, connect.NewRequest(tc.proof))
			if err != nil {
				t.Fatalf("expected DENY not error: %v", err)
			}
			if res.Msg.Decision != ksealv1.RequestProofResult_DECISION_DENY {
				t.Fatalf("expected DENY for %s, got %v", tc.name, res.Msg.Decision)
			}
		})
	}
}

func TestVerifyAttestationRejectsConsumedNonce(t *testing.T) {
	svc, _, tn, app := setupService(t, &attestation.Result{Accepted: true})
	ctx := context.Background()
	resp, err := svc.VerifyAttestation(ctx, connect.NewRequest(&ksealv1.AttestationRequest{
		TenantId: tn.Id, AppId: app.Id, Platform: ksealv1.Platform_PLATFORM_ANDROID, Nonce: []byte("never-issued"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Accepted {
		t.Fatal("attestation accepted with invalid nonce")
	}
}

// A cryptographically failed attestation (verifier returns Accepted:false, nil)
// must not mint a token even though there is no transport error.
func TestVerifyAttestationRejectsFailedAttestation(t *testing.T) {
	svc, _, tn, app := setupService(t, &attestation.Result{Accepted: false, Reason: "bad signature"})
	ctx := context.Background()
	nonceResp, err := svc.GetNonce(ctx, connect.NewRequest(&ksealv1.NonceRequest{TenantId: tn.Id, AppId: app.Id, Platform: ksealv1.Platform_PLATFORM_ANDROID}))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.VerifyAttestation(ctx, connect.NewRequest(&ksealv1.AttestationRequest{
		TenantId: tn.Id, AppId: app.Id, Platform: ksealv1.Platform_PLATFORM_ANDROID, Nonce: nonceResp.Msg.Nonce,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Accepted || resp.Msg.SignedToken != nil || resp.Msg.TrustToken != nil {
		t.Fatalf("failed attestation minted a token: %+v", resp.Msg)
	}
	if resp.Msg.RejectionReason == "" {
		t.Fatal("expected rejection reason")
	}
}

func TestVerifyAttestationRejectsUnknownApp(t *testing.T) {
	svc, _, tn, _ := setupService(t, &attestation.Result{Accepted: true})
	ctx := context.Background()
	nonce, _, err := svc.nonces.Issue(ctx, tn.Id, "00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.VerifyAttestation(ctx, connect.NewRequest(&ksealv1.AttestationRequest{
		TenantId: tn.Id, AppId: "00000000-0000-0000-0000-000000000000", Platform: ksealv1.Platform_PLATFORM_ANDROID, Nonce: nonce,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Accepted || resp.Msg.RejectionReason == "" {
		t.Fatalf("expected unknown app rejection, got %+v", resp.Msg)
	}
}

type captureVerifier struct{ in attestation.Input }

func (c *captureVerifier) Verify(_ context.Context, in attestation.Input) (*attestation.Result, error) {
	c.in = in
	if in.AppID != "com.x" {
		return &attestation.Result{Accepted: false, Reason: "package mismatch"}, nil
	}
	return &attestation.Result{Accepted: true, AppRecognized: true, DeviceIntegrity: true}, nil
}

func TestVerifyAttestationBindsKnownAppIdentity(t *testing.T) {
	store := registry.NewMemStore()
	ctx := context.Background()
	tn, _ := store.CreateTenant(ctx, registry.CreateTenantInput{Name: "T", Slug: "t-bind"})
	app, _ := store.CreateApp(ctx, registry.CreateAppInput{TenantID: tn.Id, Name: "A", PackageID: "com.x", Platform: ksealv1.Platform_PLATFORM_ANDROID})
	cv := &captureVerifier{}
	svc := NewService(store, NewNonceStore(newRedis(t), time.Minute), attestation.NewVerifier(cv, cv), time.Minute, appconfig.FeatureFlags{})
	nonceResp, err := svc.GetNonce(ctx, connect.NewRequest(&ksealv1.NonceRequest{TenantId: tn.Id, AppId: app.Id, Platform: ksealv1.Platform_PLATFORM_ANDROID}))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.VerifyAttestation(ctx, connect.NewRequest(&ksealv1.AttestationRequest{TenantId: tn.Id, AppId: app.Id, Platform: ksealv1.Platform_PLATFORM_ANDROID, Nonce: nonceResp.Msg.Nonce}))
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Msg.Accepted || cv.in.AppID != "com.x" {
		t.Fatalf("expected app-bound acceptance, accepted=%v appID=%q", resp.Msg.Accepted, cv.in.AppID)
	}
}
