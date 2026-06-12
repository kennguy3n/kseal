package config

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/shared/crypto"
)

func setup(t *testing.T) (*Service, registry.Store, *ksealv1.Tenant, *ksealv1.App) {
	t.Helper()
	store := registry.NewMemStore()
	ctx := context.Background()
	tn, err := store.CreateTenant(ctx, registry.CreateTenantInput{Name: "T", Slug: "t-cfg"})
	if err != nil {
		t.Fatal(err)
	}
	app, err := store.CreateApp(ctx, registry.CreateAppInput{TenantID: tn.Id, Name: "A", PackageID: "com.cfg", Platform: ksealv1.Platform_PLATFORM_ANDROID})
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(store, NewSigner(store), time.Minute)
	return svc, store, tn, app
}

func activatePolicy(t *testing.T, store registry.Store, tenantID, appID, rules, thresholds string) {
	t.Helper()
	ctx := context.Background()
	p, err := store.CreatePolicy(ctx, registry.CreatePolicyInput{
		TenantID: tenantID, AppID: appID, Name: "v1",
		EnforcementMode: ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK,
		Rules:           rules, RiskThresholds: thresholds, ModulesEnabled: []string{"root"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActivatePolicy(ctx, tenantID, p.Id); err != nil {
		t.Fatal(err)
	}
}

func TestGetConfigSignsAssembledPolicy(t *testing.T) {
	svc, store, tn, app := setup(t)
	activatePolicy(t, store, tn.Id, app.Id,
		`{"rules":[{"id":"r1","risk_mask":1,"min_score":50,"action":"block","description":"root"}],"signal_weights":{"0":70}}`,
		`{"HIGH_RISK":90}`)

	resp, err := svc.GetConfig(context.Background(), connect.NewRequest(&ksealv1.ConfigRequest{TenantId: tn.Id, AppId: app.Id}))
	if err != nil {
		t.Fatal(err)
	}
	sc := resp.Msg.Config
	if sc == nil || len(sc.Signature) == 0 || sc.KeyId == "" {
		t.Fatalf("missing signed config: %+v", sc)
	}
	if resp.Msg.Etag == "" {
		t.Fatal("missing etag")
	}

	// Signature must verify against the tenant's active signing key.
	sk, err := store.GetActiveSigningKey(context.Background(), tn.Id)
	if err != nil {
		t.Fatal(err)
	}
	if !crypto.VerifyEd25519(sk.Public, sc.ConfigBytes, sc.Signature) {
		t.Fatal("signature does not verify")
	}

	// Config bytes decode to a PolicyConfig with the rule and weights present.
	var pc ksealv1.PolicyConfig
	if err := proto.Unmarshal(sc.ConfigBytes, &pc); err != nil {
		t.Fatal(err)
	}
	if len(pc.Rules) != 1 || pc.Rules[0].Id != "r1" {
		t.Fatalf("rules not assembled: %+v", pc.Rules)
	}
	if pc.SignalWeights[0] != 70 {
		t.Fatalf("weights not parsed: %+v", pc.SignalWeights)
	}
	if pc.Rules[0].Action != ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK {
		t.Fatalf("rule action mismatch: %v", pc.Rules[0].Action)
	}
}

func TestGetConfigNoPolicyIsNotFound(t *testing.T) {
	svc, _, tn, app := setup(t)
	_, err := svc.GetConfig(context.Background(), connect.NewRequest(&ksealv1.ConfigRequest{TenantId: tn.Id, AppId: app.Id}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestGetConfigETagShortCircuit(t *testing.T) {
	svc, store, tn, app := setup(t)
	activatePolicy(t, store, tn.Id, app.Id, "[]", "{}")
	first, err := svc.GetConfig(context.Background(), connect.NewRequest(&ksealv1.ConfigRequest{TenantId: tn.Id, AppId: app.Id}))
	if err != nil {
		t.Fatal(err)
	}
	req := connect.NewRequest(&ksealv1.ConfigRequest{TenantId: tn.Id, AppId: app.Id})
	req.Header().Set("If-None-Match", first.Msg.Etag)
	second, err := svc.GetConfig(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if second.Msg.Config != nil {
		t.Fatal("expected cache short-circuit with no config body")
	}
	if second.Msg.Etag != first.Msg.Etag {
		t.Fatal("etag changed for identical policy")
	}
}

func TestGetPolicyReturnsAssembled(t *testing.T) {
	svc, store, tn, app := setup(t)
	activatePolicy(t, store, tn.Id, app.Id, "[]", "{}")
	resp, err := svc.GetPolicy(context.Background(), connect.NewRequest(&ksealv1.PolicyRequest{TenantId: tn.Id, AppId: app.Id}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Policy == nil || resp.Msg.Policy.PolicyHash == "" {
		t.Fatalf("missing policy: %+v", resp.Msg.Policy)
	}
}
