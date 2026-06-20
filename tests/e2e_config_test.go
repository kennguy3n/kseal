package tests

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	cfgsvc "github.com/kennguy3n/kseal/server/data-plane/config"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
	kcrypto "github.com/kennguy3n/kseal/server/shared/crypto"
)

func TestE2EConfig(t *testing.T) {
	requireHarness(t)
	ctx := context.Background()

	store := newStore(t)
	tenant := makeTenant(t, store, "config")
	app := makeApp(t, store, tenant.Id, "com.kseal.config")
	configCtx := auth.WithTenant(ctx, tenant.Id)
	const rulesV1 = `{"rules":[{"id":"r1","risk_mask":1,"min_score":40,"action":"step_up"}],"signal_weights":{"0":40}}`
	const thresholds = `{"HIGH_RISK":90,"MEDIUM_RISK":50}`
	activatePolicy(t, store, tenant.Id, app.Id, ksealv1.EnforcementMode_ENFORCEMENT_MODE_STEP_UP, rulesV1, thresholds)

	const ttl = 7 * time.Minute
	svc := cfgsvc.NewService(store, cfgsvc.NewSigner(store), ttl)

	get := func(t *testing.T, ifNoneMatch string) *connect.Response[ksealv1.ConfigResponse] {
		t.Helper()
		req := connect.NewRequest(&ksealv1.ConfigRequest{TenantId: tenant.Id, AppId: app.Id, Platform: ksealv1.Platform_PLATFORM_ANDROID})
		if ifNoneMatch != "" {
			req.Header().Set("If-None-Match", ifNoneMatch)
		}
		resp, err := svc.GetConfig(configCtx, req)
		if err != nil {
			t.Fatalf("get config: %v", err)
		}
		return resp
	}

	// First fetch: a fully signed config bundle.
	resp := get(t, "")
	cfg := resp.Msg.Config
	if cfg == nil {
		t.Fatal("expected a signed config on first fetch")
	}
	if cfg.TtlSeconds != int64(ttl.Seconds()) {
		t.Fatalf("expected ttl %d, got %d", int64(ttl.Seconds()), cfg.TtlSeconds)
	}
	if resp.Msg.Etag == "" || resp.Header().Get("ETag") != resp.Msg.Etag {
		t.Fatalf("expected ETag header to match body etag, got header=%q body=%q", resp.Header().Get("ETag"), resp.Msg.Etag)
	}

	// Verify the Ed25519 signature over the FULL envelope using the tenant's
	// active signing key — exactly what the SDK does offline.
	sk, err := store.GetActiveSigningKey(ctx, tenant.Id)
	if err != nil {
		t.Fatalf("get signing key: %v", err)
	}
	if sk.ID != cfg.KeyId {
		t.Fatalf("config signed by key %q but active key is %q", cfg.KeyId, sk.ID)
	}
	if !kcrypto.VerifyEd25519(sk.Public, cfg.ConfigBytes, cfg.Signature) {
		t.Fatal("config signature failed to verify against the active signing key")
	}

	// Tampering with the signed bytes must invalidate the signature.
	tampered := append([]byte(nil), cfg.ConfigBytes...)
	tampered[0] ^= 0xFF
	if kcrypto.VerifyEd25519(sk.Public, tampered, cfg.Signature) {
		t.Fatal("tampered config must not verify")
	}

	// The signed bytes decode to a PolicyConfig whose hash matches the ETag.
	var pc ksealv1.PolicyConfig
	if err := proto.Unmarshal(cfg.ConfigBytes, &pc); err != nil {
		t.Fatalf("unmarshal policy config: %v", err)
	}
	// Reconstruct the ETag exactly as the server does: a strong RFC 7232 ETag is
	// the hex policy hash wrapped in literal double quotes (config/service.go).
	if want := `"` + pc.PolicyHash + `"`; want != resp.Msg.Etag {
		t.Fatalf("etag %q does not match policy hash %q", resp.Msg.Etag, want)
	}
	if pc.RiskThresholds["HIGH_RISK"] != 90 || pc.RiskThresholds["MEDIUM_RISK"] != 50 {
		t.Fatalf("risk thresholds not propagated: %+v", pc.RiskThresholds)
	}

	// Conditional GET with the current ETag is a cache hit: same ETag, no body.
	notModified := get(t, resp.Msg.Etag)
	if notModified.Msg.Config != nil {
		t.Fatal("expected no config body on If-None-Match cache hit")
	}
	if notModified.Msg.Etag != resp.Msg.Etag {
		t.Fatalf("cache-hit etag changed: %q vs %q", notModified.Msg.Etag, resp.Msg.Etag)
	}

	// Activating a new policy version changes the ETag/version and resigns.
	const rulesV2 = `{"rules":[{"id":"r1","risk_mask":3,"min_score":60,"action":"block"}],"signal_weights":{"0":40,"1":25}}`
	activatePolicy(t, store, tenant.Id, app.Id, ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK, rulesV2, thresholds)
	updated := get(t, "")
	if updated.Msg.Etag == resp.Msg.Etag {
		t.Fatal("ETag must change after a new policy version is activated")
	}
	if updated.Msg.Config.Version <= cfg.Version {
		t.Fatalf("version must increase after reactivation: old=%d new=%d", cfg.Version, updated.Msg.Config.Version)
	}
	// The stale ETag is no longer a cache hit; the client receives fresh bytes.
	if stale := get(t, resp.Msg.Etag); stale.Msg.Config == nil {
		t.Fatal("a stale ETag must not produce a cache hit after the policy changed")
	}
}
