package trust

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"

	"github.com/kennguy3n/kseal/server/control-plane/compliance"
	"github.com/kennguy3n/kseal/server/data-plane/attestation"
	"github.com/kennguy3n/kseal/server/data-plane/fleet"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// wireEmulator is the device/wire RiskBitset emulator bit (Rust-core layout).
const wireEmulator = uint64(1) << 2

// verifyOnce issues a fresh nonce and runs one VerifyAttestation with the given
// device-reported wire risk bits, returning the minted token's risk level.
func verifyOnce(t *testing.T, svc *Service, tenant, app, build string, wireBits uint64) ksealv1.TrustLevel {
	t.Helper()
	ctx := context.Background()
	nonceResp, err := svc.GetNonce(ctx, connect.NewRequest(&ksealv1.NonceRequest{
		TenantId: tenant, AppId: app, Platform: ksealv1.Platform_PLATFORM_ANDROID,
	}))
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	resp, err := svc.VerifyAttestation(ctx, connect.NewRequest(&ksealv1.AttestationRequest{
		TenantId: tenant, AppId: app, Platform: ksealv1.Platform_PLATFORM_ANDROID,
		Nonce: nonceResp.Msg.Nonce, BuildHash: build, InstanceId: "inst", RiskBitset: wireBits,
	}))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !resp.Msg.Accepted || resp.Msg.TrustToken == nil {
		t.Fatalf("attestation not accepted: %+v", resp.Msg)
	}
	return resp.Msg.TrustToken.RiskLevel
}

// TestFleetGuardFusesAnomalyBitOnSurge drives a coordinated emulator surge for
// one build cohort, then verifies a *clean* device joining that cohort is
// elevated to MEDIUM_RISK by the fused FLEET_ANOMALY bit — the per-instance path
// alone would have minted it TRUSTED.
func TestFleetGuardFusesAnomalyBitOnSurge(t *testing.T) {
	svc, _, tn, app := setupServiceWithFlags(t, &attestation.Result{Accepted: true, AppRecognized: true, DeviceIntegrity: true}, flags(t, "*:"+compliance.FlagFleetAnomaly+"=true"))
	engine := fleet.New(fleet.DefaultConfig())
	svc.AttachFleetGuard(engine, false)

	const build = "bh-surge"

	// Control: with no surge yet, a clean device mints TRUSTED.
	if lvl := verifyOnce(t, svc, tn.Id, app.Id, build, 0); lvl != ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED {
		t.Fatalf("clean device pre-surge = %v, want TRUSTED", lvl)
	}

	// Surge: 80 emulator-reporting devices on this build cohort, past MinSamples.
	for i := 0; i < 80; i++ {
		verifyOnce(t, svc, tn.Id, app.Id, build, wireEmulator)
	}

	// A clean device joining the surging cohort is now elevated.
	lvl := verifyOnce(t, svc, tn.Id, app.Id, build, 0)
	if lvl != ksealv1.TrustLevel_TRUST_LEVEL_MEDIUM_RISK {
		t.Fatalf("clean device during surge = %v, want MEDIUM_RISK (fleet anomaly fused)", lvl)
	}
}

// TestFleetGuardFlagGated asserts the guard never fires when the feature flag is
// off for the tenant, even with the engine attached and a clear surge present.
func TestFleetGuardFlagGated(t *testing.T) {
	svc, _, tn, app := setupServiceWithFlags(t, &attestation.Result{Accepted: true, AppRecognized: true, DeviceIntegrity: true}, flags(t, "")) // flag off
	engine := fleet.New(fleet.DefaultConfig())
	svc.AttachFleetGuard(engine, false)

	const build = "bh-nogate"
	for i := 0; i < 80; i++ {
		verifyOnce(t, svc, tn.Id, app.Id, build, wireEmulator)
	}
	if lvl := verifyOnce(t, svc, tn.Id, app.Id, build, 0); lvl != ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED {
		t.Fatalf("flag off must not fuse fleet anomaly; clean device = %v, want TRUSTED", lvl)
	}
}

// TestFleetGuardDisabledWithoutAttach asserts that without AttachFleetGuard the
// trust path is unchanged (nil engine is a no-op).
func TestFleetGuardDisabledWithoutAttach(t *testing.T) {
	svc, _, tn, app := setupService(t, &attestation.Result{Accepted: true, AppRecognized: true, DeviceIntegrity: true})
	const build = "bh-noattach"
	for i := 0; i < 80; i++ {
		verifyOnce(t, svc, tn.Id, app.Id, build, wireEmulator)
	}
	if lvl := verifyOnce(t, svc, tn.Id, app.Id, build, 0); lvl != ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED {
		t.Fatalf("no engine attached must leave clean device TRUSTED, got %v", lvl)
	}
}

// TestEdgeRegionTrustGate asserts CDN country headers are honored only when the
// operator opts in, so a spoofable header cannot fragment cohorts by default.
func TestEdgeRegionTrustGate(t *testing.T) {
	h := http.Header{}
	h.Set("Cf-Ipcountry", "de")

	off := &Service{trustEdgeRegion: false}
	if got := off.edgeRegion(h); got != "" {
		t.Fatalf("edgeRegion with trust off = %q, want \"\" (spoofable header ignored)", got)
	}

	on := &Service{trustEdgeRegion: true}
	if got := on.edgeRegion(h); got != "DE" {
		t.Fatalf("edgeRegion with trust on = %q, want \"DE\"", got)
	}

	// Sentinel/unknown country collapses to "" even when trusted.
	sentinel := http.Header{}
	sentinel.Set("Cf-Ipcountry", "XX")
	if got := on.edgeRegion(sentinel); got != "" {
		t.Fatalf("edgeRegion sentinel = %q, want \"\"", got)
	}
}
