package tests

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"

	"github.com/kennguy3n/kseal/server/data-plane/attestation"
	"github.com/kennguy3n/kseal/server/data-plane/trust"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	kcrypto "github.com/kennguy3n/kseal/server/shared/crypto"
)

// staticKeySource mocks the ONLY external dependency of the Play Integrity
// verifier — Google's JWKS endpoint — by resolving a locally generated RSA
// public key by key id. The JWS parsing, signature verification, nonce binding,
// package binding, and verdict→risk mapping all run for real.
type staticKeySource struct {
	keyID string
	pub   crypto.PublicKey
}

func (s staticKeySource) PublicKey(_ context.Context, keyID string) (crypto.PublicKey, error) {
	if keyID != s.keyID {
		return nil, &keyNotFoundError{keyID}
	}
	return s.pub, nil
}

type keyNotFoundError struct{ kid string }

func (e *keyNotFoundError) Error() string { return "unknown key id: " + e.kid }

// playIntegrityToken signs a Play Integrity verdict JWS (RS256) with the test
// signing key, binding it to the issued nonce. The verdict fields drive the
// real verdict→risk mapping in the verifier.
func playIntegrityToken(t *testing.T, priv *rsa.PrivateKey, keyID, pkg string, nonce []byte, appRecognition string, device []string, licensing string) []byte {
	t.Helper()
	claims := jwt.MapClaims{
		"requestDetails": map[string]any{
			"requestPackageName": pkg,
			"nonce":              base64.StdEncoding.EncodeToString(nonce),
		},
		"appIntegrity": map[string]any{
			"appRecognitionVerdict": appRecognition,
		},
		"deviceIntegrity": map[string]any{
			"deviceRecognitionVerdict": device,
		},
		"accountDetails": map[string]any{
			"appLicensingVerdict": licensing,
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = keyID
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign play integrity token: %v", err)
	}
	return []byte(signed)
}

// unknownTokenID is a well-formed UUID that is never minted, used to assert the
// "unknown trust token" DENY path.
const unknownTokenID = "00000000-0000-4000-8000-000000000000"

func TestE2ETrustFlow(t *testing.T) {
	requireHarness(t)
	ctx := context.Background()

	store := newStore(t)
	tenant := makeTenant(t, store, "trust")
	app := makeApp(t, store, tenant.Id, "com.kseal.trustflow")
	makeBuild(t, store, tenant.Id, app.Id)
	// BLOCK enforcement so a single policy exercises ALLOW / STEP_UP / DENY by
	// trust level alone.
	activatePolicy(t, store, tenant.Id, app.Id, ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK, "{}", "")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	const keyID = "test-google-kid"
	play := attestation.NewPlayIntegrityVerifier(staticKeySource{keyID: keyID, pub: priv.Public()})
	verifier := attestation.NewVerifier(play, nil)
	nonces := trust.NewNonceStore(newRedis(t), time.Minute)
	svc := trust.NewService(store, nonces, verifier, 15*time.Minute)

	// runFlow drives GetNonce -> sign verdict -> VerifyAttestation and returns
	// the accepted response (or the rejection).
	runFlow := func(t *testing.T, appRecognition string, device []string, licensing string) *ksealv1.AttestationResponse {
		t.Helper()
		nonceResp, err := svc.GetNonce(ctx, connect.NewRequest(&ksealv1.NonceRequest{TenantId: tenant.Id, AppId: app.Id}))
		if err != nil {
			t.Fatalf("get nonce: %v", err)
		}
		nonce := nonceResp.Msg.Nonce
		if len(nonce) == 0 {
			t.Fatal("empty nonce issued")
		}
		token := playIntegrityToken(t, priv, keyID, app.PackageId, nonce, appRecognition, device, licensing)
		attResp, err := svc.VerifyAttestation(ctx, connect.NewRequest(&ksealv1.AttestationRequest{
			TenantId:                 tenant.Id,
			AppId:                    app.Id,
			Platform:                 ksealv1.Platform_PLATFORM_ANDROID,
			PlatformAttestationToken: token,
			Nonce:                    nonce,
			BuildHash:                buildHash,
			InstanceId:               "instance-1",
		}))
		if err != nil {
			t.Fatalf("verify attestation: %v", err)
		}
		return attResp.Msg
	}

	t.Run("clean_device_allows_and_anti_replay", func(t *testing.T) {
		resp := runFlow(t, "PLAY_RECOGNIZED", []string{"MEETS_STRONG_INTEGRITY"}, "LICENSED")
		if !resp.Accepted {
			t.Fatalf("expected accepted attestation, got rejection: %q", resp.RejectionReason)
		}
		if resp.TrustToken.RiskLevel != ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED {
			t.Fatalf("expected TRUSTED, got %v", resp.TrustToken.RiskLevel)
		}
		if len(resp.SignedToken) == 0 {
			t.Fatal("expected a signed trust token")
		}
		tokenID := resp.TrustToken.TokenId
		proofKey := trust.DeriveProofKey(resp.SignedToken)
		nonce := mustRandom(t, 16)

		// seq=1 valid proof -> ALLOW.
		res := validate(t, ctx, svc, proof(tokenID, proofKey, nonce, 1))
		if res.Decision != ksealv1.RequestProofResult_DECISION_ALLOW {
			t.Fatalf("expected ALLOW, got %v (%s)", res.Decision, res.Reason)
		}

		// Replayed sequence (==last) -> DENY.
		res = validate(t, ctx, svc, proof(tokenID, proofKey, nonce, 1))
		if res.Decision != ksealv1.RequestProofResult_DECISION_DENY {
			t.Fatalf("expected DENY on replay, got %v", res.Decision)
		}

		// Decreasing sequence -> DENY.
		res = validate(t, ctx, svc, proof(tokenID, proofKey, nonce, 0))
		if res.Decision != ksealv1.RequestProofResult_DECISION_DENY {
			t.Fatalf("expected DENY on decreasing sequence, got %v", res.Decision)
		}

		// Advancing sequence with a valid proof still works.
		res = validate(t, ctx, svc, proof(tokenID, proofKey, nonce, 2))
		if res.Decision != ksealv1.RequestProofResult_DECISION_ALLOW {
			t.Fatalf("expected ALLOW on advancing sequence, got %v", res.Decision)
		}

		// Proof for the WRONG nonce fails the signature check (computed over a
		// different nonce than the one presented to the server).
		wrong := proof(tokenID, proofKey, nonce, 3)
		wrong.Nonce = mustRandom(t, 16)
		res = validate(t, ctx, svc, wrong)
		if res.Decision != ksealv1.RequestProofResult_DECISION_DENY {
			t.Fatalf("expected DENY for wrong nonce, got %v", res.Decision)
		}

		// Proof for an unknown (well-formed but nonexistent) trust token -> DENY.
		res = validate(t, ctx, svc, proof(unknownTokenID, proofKey, nonce, 1))
		if res.Decision != ksealv1.RequestProofResult_DECISION_DENY {
			t.Fatalf("expected DENY for unknown token, got %v", res.Decision)
		}

		// ROBUSTNESS GAP (reported to component owner): a malformed (non-UUID)
		// token id should fail closed as a clean DENY, but the Postgres store
		// currently surfaces the uuid parse error as a Connect Internal error
		// because registry.wrapPgErr only maps pgx.ErrNoRows to ErrNotFound. We
		// prove the gap here without locking in the wrong behavior: a future
		// fail-closed fix (DENY) is also accepted.
		if r, err := svc.ValidateRequestProof(ctx, connect.NewRequest(proof("not-a-uuid", proofKey, nonce, 1))); err != nil {
			if connect.CodeOf(err) != connect.CodeInternal {
				t.Fatalf("malformed token id: expected Internal (current) or DENY (fixed), got code %v", connect.CodeOf(err))
			}
		} else if r.Msg.Decision != ksealv1.RequestProofResult_DECISION_DENY {
			t.Fatalf("malformed token id: expected DENY once fixed, got %v", r.Msg.Decision)
		}

		// Proof signed with the WRONG key (attacker without the session secret) -> DENY.
		res = validate(t, ctx, svc, proof(tokenID, []byte("not-the-session-secret"), nonce, 4))
		if res.Decision != ksealv1.RequestProofResult_DECISION_DENY {
			t.Fatalf("expected DENY for forged signature, got %v", res.Decision)
		}
	})

	t.Run("medium_risk_steps_up", func(t *testing.T) {
		// Basic integrity (BitDeviceIntegrity=45) + unlicensed (BitAccountRisk=20)
		// = 65 -> MEDIUM_RISK -> STEP_UP.
		resp := runFlow(t, "PLAY_RECOGNIZED", []string{"MEETS_BASIC_INTEGRITY"}, "UNLICENSED")
		if !resp.Accepted {
			t.Fatalf("expected accepted, got %q", resp.RejectionReason)
		}
		if resp.TrustToken.RiskLevel != ksealv1.TrustLevel_TRUST_LEVEL_MEDIUM_RISK {
			t.Fatalf("expected MEDIUM_RISK, got %v", resp.TrustToken.RiskLevel)
		}
		proofKey := trust.DeriveProofKey(resp.SignedToken)
		res := validate(t, ctx, svc, proof(resp.TrustToken.TokenId, proofKey, mustRandom(t, 16), 1))
		if res.Decision != ksealv1.RequestProofResult_DECISION_STEP_UP {
			t.Fatalf("expected STEP_UP, got %v (%s)", res.Decision, res.Reason)
		}
	})

	t.Run("critical_risk_denies", func(t *testing.T) {
		// Tampered app (BitAppTamper|BitAppUnrecognized=125) + no device integrity
		// (BitDeviceIntegrity|BitRootJailbreak=85) = 210 -> CRITICAL -> DENY.
		resp := runFlow(t, "UNRECOGNIZED_VERSION", []string{}, "UNLICENSED")
		if !resp.Accepted {
			t.Fatalf("expected accepted (verdict parsed) but high risk, got %q", resp.RejectionReason)
		}
		if resp.TrustToken.RiskLevel != ksealv1.TrustLevel_TRUST_LEVEL_CRITICAL {
			t.Fatalf("expected CRITICAL, got %v", resp.TrustToken.RiskLevel)
		}
		proofKey := trust.DeriveProofKey(resp.SignedToken)
		res := validate(t, ctx, svc, proof(resp.TrustToken.TokenId, proofKey, mustRandom(t, 16), 1))
		if res.Decision != ksealv1.RequestProofResult_DECISION_DENY {
			t.Fatalf("expected DENY, got %v (%s)", res.Decision, res.Reason)
		}
	})

	t.Run("forged_attestation_signature_rejected", func(t *testing.T) {
		// Sign the verdict with a key the verifier's key source does not know:
		// the real JWS signature verification must reject it (no token minted).
		nonceResp, err := svc.GetNonce(ctx, connect.NewRequest(&ksealv1.NonceRequest{TenantId: tenant.Id, AppId: app.Id}))
		if err != nil {
			t.Fatalf("get nonce: %v", err)
		}
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa: %v", err)
		}
		token := playIntegrityToken(t, other, keyID, app.PackageId, nonceResp.Msg.Nonce, "PLAY_RECOGNIZED", []string{"MEETS_STRONG_INTEGRITY"}, "LICENSED")
		attResp, err := svc.VerifyAttestation(ctx, connect.NewRequest(&ksealv1.AttestationRequest{
			TenantId: tenant.Id, AppId: app.Id, Platform: ksealv1.Platform_PLATFORM_ANDROID,
			PlatformAttestationToken: token, Nonce: nonceResp.Msg.Nonce, BuildHash: buildHash, InstanceId: "instance-x",
		}))
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if attResp.Msg.Accepted {
			t.Fatal("expected rejection for forged JWS signature")
		}
		if len(attResp.Msg.SignedToken) != 0 {
			t.Fatal("no trust token must be minted on rejection")
		}
	})

	t.Run("consumed_nonce_cannot_be_replayed", func(t *testing.T) {
		nonceResp, err := svc.GetNonce(ctx, connect.NewRequest(&ksealv1.NonceRequest{TenantId: tenant.Id, AppId: app.Id}))
		if err != nil {
			t.Fatalf("get nonce: %v", err)
		}
		nonce := nonceResp.Msg.Nonce
		token := playIntegrityToken(t, priv, keyID, app.PackageId, nonce, "PLAY_RECOGNIZED", []string{"MEETS_STRONG_INTEGRITY"}, "LICENSED")
		req := func() *connect.Request[ksealv1.AttestationRequest] {
			return connect.NewRequest(&ksealv1.AttestationRequest{
				TenantId: tenant.Id, AppId: app.Id, Platform: ksealv1.Platform_PLATFORM_ANDROID,
				PlatformAttestationToken: token, Nonce: nonce, BuildHash: buildHash, InstanceId: "instance-r",
			})
		}
		first, err := svc.VerifyAttestation(ctx, req())
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !first.Msg.Accepted {
			t.Fatalf("first attestation should succeed: %q", first.Msg.RejectionReason)
		}
		second, err := svc.VerifyAttestation(ctx, req())
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if second.Msg.Accepted {
			t.Fatal("replayed nonce must be rejected (single-use)")
		}
	})
}

// proof builds a signed request proof for the given session secret using the
// SAME canonical preimage as the SDK core (crypto.RequestProofPreimage).
func proof(tokenID string, sessionSecret, nonce []byte, seq int64) *ksealv1.RequestProof {
	requestHash := sha256.Sum256([]byte("POST /v1/resource"))
	sig := kcrypto.HMACSHA256(sessionSecret, trust.ProofMessage(tokenID, requestHash[:], nonce, seq))
	return &ksealv1.RequestProof{
		TrustTokenId:         tokenID,
		RequestHash:          requestHash[:],
		Nonce:                nonce,
		MonotonicSequence:    seq,
		AppInstanceSignature: sig,
	}
}

func validate(t *testing.T, ctx context.Context, svc *trust.Service, p *ksealv1.RequestProof) *ksealv1.RequestProofResult {
	t.Helper()
	res, err := svc.ValidateRequestProof(ctx, connect.NewRequest(p))
	if err != nil {
		t.Fatalf("validate request proof: %v", err)
	}
	return res.Msg
}

func mustRandom(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}
