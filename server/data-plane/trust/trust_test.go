package trust

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/data-plane/attestation"
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
	ok, err := store.Consume(ctx, "t1", nonce)
	if err != nil || !ok {
		t.Fatalf("first consume should succeed: %v %v", ok, err)
	}
	ok, _ = store.Consume(ctx, "t1", nonce)
	if ok {
		t.Fatal("nonce reused")
	}
}

func setupService(t *testing.T, res *attestation.Result) (*Service, registry.Store, *ksealv1.Tenant, *ksealv1.App) {
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
	svc := NewService(store, NewNonceStore(newRedis(t), time.Minute), verifier, time.Minute)
	return svc, store, tn, app
}

func TestTrustFlowEndToEnd(t *testing.T) {
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
	if err != nil {
		t.Fatal(err)
	}
	if !attResp.Msg.Accepted || attResp.Msg.TrustToken == nil {
		t.Fatalf("attestation not accepted: %+v", attResp.Msg)
	}
	tokenID := attResp.Msg.TrustToken.TokenId
	proofKey := DeriveProofKey(attResp.Msg.SignedToken)

	// Valid proof with sequence 1 -> allow (level trusted, step-up default mode).
	proof := func(seq int64) *ksealv1.RequestProof {
		reqHash := []byte("req")
		p := &ksealv1.RequestProof{TrustTokenId: tokenID, RequestHash: reqHash, MonotonicSequence: seq}
		p.AppInstanceSignature = crypto.HMACSHA256(proofKey, ProofMessage(tokenID, reqHash, nil, seq))
		return p
	}

	r1, err := svc.ValidateRequestProof(ctx, connect.NewRequest(proof(1)))
	if err != nil {
		t.Fatal(err)
	}
	if r1.Msg.Decision == ksealv1.RequestProofResult_DECISION_DENY {
		t.Fatalf("clean device denied: %s", r1.Msg.Reason)
	}

	// Replay of sequence 1 -> deny.
	rReplay, err := svc.ValidateRequestProof(ctx, connect.NewRequest(proof(1)))
	if err != nil {
		t.Fatal(err)
	}
	if rReplay.Msg.Decision != ksealv1.RequestProofResult_DECISION_DENY {
		t.Fatal("replay not denied")
	}

	// Bad signature -> deny.
	bad := proof(2)
	bad.AppInstanceSignature = []byte("garbage")
	rBad, _ := svc.ValidateRequestProof(ctx, connect.NewRequest(bad))
	if rBad.Msg.Decision != ksealv1.RequestProofResult_DECISION_DENY {
		t.Fatal("bad signature not denied")
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
