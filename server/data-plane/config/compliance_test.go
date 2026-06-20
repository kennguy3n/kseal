package config

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	"github.com/kennguy3n/kseal/server/control-plane/compliance"
	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/data-plane/canary"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
	appconfig "github.com/kennguy3n/kseal/server/shared/config"
)

func mustFlags(t *testing.T, spec string) appconfig.FeatureFlags {
	t.Helper()
	ff, err := appconfig.ParseFeatureFlags(spec)
	if err != nil {
		t.Fatal(err)
	}
	return ff
}

func createPolicy(t *testing.T, store registry.Store, tenantID, appID, name string, activate bool) *ksealv1.Policy {
	t.Helper()
	ctx := context.Background()
	p, err := store.CreatePolicy(ctx, registry.CreatePolicyInput{
		TenantID: tenantID, AppID: appID, Name: name,
		EnforcementMode: ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK, Rules: "[]", RiskThresholds: "{}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if activate {
		if _, err := store.ActivatePolicy(ctx, tenantID, p.Id); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func servedVersion(t *testing.T, svc *Service, tenantID, appID, instanceID string) int64 {
	t.Helper()
	resp, err := svc.GetConfig(auth.WithTenant(context.Background(), tenantID), connect.NewRequest(&ksealv1.ConfigRequest{
		TenantId: tenantID, AppId: appID, InstanceId: instanceID,
	}))
	if err != nil {
		t.Fatal(err)
	}
	return resp.Msg.Config.Version
}

func TestCanarySelectionFlagGated(t *testing.T) {
	svc, store, tn, app := setup(t)
	stable := createPolicy(t, store, tn.Id, app.Id, "stable", true) // version 1
	cand := createPolicy(t, store, tn.Id, app.Id, "candidate", false)
	if cand.Version == stable.Version {
		t.Fatalf("expected distinct versions, both %d", cand.Version)
	}

	reg := canary.NewRegistry()
	reg.Replace([]*ksealv1.CanaryStatus{{
		TenantId: tn.Id, AppId: app.Id, CandidatePolicyId: cand.Id, StablePolicyId: stable.Id,
		Percent: 100, State: ksealv1.CanaryState_CANARY_STATE_ACTIVE,
	}})

	// Flag OFF: candidate cohort still served the stable policy.
	svc.AttachCompliance(reg, nil, mustFlags(t, ""))
	if v := servedVersion(t, svc, tn.Id, app.Id, "inst-1"); v != int64(stable.Version) {
		t.Fatalf("flag off must serve stable v%d, got v%d", stable.Version, v)
	}

	// Flag ON: 100%% cohort served the candidate policy.
	svc.AttachCompliance(reg, nil, mustFlags(t, tn.Id+":"+compliance.FlagCanaryRollout+"=true"))
	if v := servedVersion(t, svc, tn.Id, app.Id, "inst-1"); v != int64(cand.Version) {
		t.Fatalf("flag on must serve candidate v%d, got v%d", cand.Version, v)
	}

	// No instance id stays on stable even with the flag on (fail-safe).
	if v := servedVersion(t, svc, tn.Id, app.Id, ""); v != int64(stable.Version) {
		t.Fatalf("empty instance must serve stable v%d, got v%d", stable.Version, v)
	}
}

func TestKillSwitchDeliveryFlagGated(t *testing.T) {
	svc, store, tn, app := setup(t)
	createPolicy(t, store, tn.Id, app.Id, "stable", true)

	cs := compliance.NewMemStore(store)
	if _, err := cs.IssueKillSwitch(context.Background(), compliance.KillSwitchInput{
		TenantID: tn.Id, AppID: app.Id, Command: ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE,
	}); err != nil {
		t.Fatal(err)
	}

	// Flag OFF: no kill switch delivered.
	svc.AttachCompliance(nil, cs, mustFlags(t, ""))
	resp, err := svc.GetConfig(auth.WithTenant(context.Background(), tn.Id), connect.NewRequest(&ksealv1.ConfigRequest{TenantId: tn.Id, AppId: app.Id}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.KillSwitch != nil {
		t.Fatal("flag off must not deliver a kill switch")
	}

	// Flag ON: signed DISABLE delivered in the config envelope.
	svc.AttachCompliance(nil, cs, mustFlags(t, "*:"+compliance.FlagKillSwitch+"=true"))
	resp, err = svc.GetConfig(auth.WithTenant(context.Background(), tn.Id), connect.NewRequest(&ksealv1.ConfigRequest{TenantId: tn.Id, AppId: app.Id}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.KillSwitch == nil || resp.Msg.KillSwitch.Command != ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE {
		t.Fatalf("flag on must deliver signed DISABLE, got %+v", resp.Msg.KillSwitch)
	}
	// The kill switch must verify against the tenant key (fail-safe contract).
	sk, err := store.GetActiveSigningKey(context.Background(), tn.Id)
	if err != nil {
		t.Fatal(err)
	}
	if !compliance.VerifyKillSwitch(sk.Public, resp.Msg.KillSwitch) {
		t.Fatal("delivered kill switch must carry a valid signature")
	}
}

func TestKillSwitchChangesETag(t *testing.T) {
	svc, store, tn, app := setup(t)
	createPolicy(t, store, tn.Id, app.Id, "stable", true)
	cs := compliance.NewMemStore(store)
	svc.AttachCompliance(nil, cs, mustFlags(t, "*:"+compliance.FlagKillSwitch+"=true"))

	base, err := svc.GetConfig(auth.WithTenant(context.Background(), tn.Id), connect.NewRequest(&ksealv1.ConfigRequest{TenantId: tn.Id, AppId: app.Id}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.IssueKillSwitch(context.Background(), compliance.KillSwitchInput{
		TenantID: tn.Id, AppID: app.Id, Command: ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE,
	}); err != nil {
		t.Fatal(err)
	}
	after, err := svc.GetConfig(auth.WithTenant(context.Background(), tn.Id), connect.NewRequest(&ksealv1.ConfigRequest{TenantId: tn.Id, AppId: app.Id}))
	if err != nil {
		t.Fatal(err)
	}
	if base.Msg.Etag == after.Msg.Etag {
		t.Fatal("issuing a kill switch must bust the cached ETag")
	}
}

func TestBuildScopedKillSwitchDeliveredViaConfig(t *testing.T) {
	svc, store, tn, app := setup(t)
	createPolicy(t, store, tn.Id, app.Id, "stable", true)
	cs := compliance.NewMemStore(store)
	const build = "buildhash-abc"
	if _, err := cs.IssueKillSwitch(context.Background(), compliance.KillSwitchInput{
		TenantID: tn.Id, AppID: app.Id, BuildHash: build,
		Command: ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE,
	}); err != nil {
		t.Fatal(err)
	}
	svc.AttachCompliance(nil, cs, mustFlags(t, "*:"+compliance.FlagKillSwitch+"=true"))

	// No build hash: the build-scoped switch must not apply.
	resp, err := svc.GetConfig(auth.WithTenant(context.Background(), tn.Id), connect.NewRequest(&ksealv1.ConfigRequest{TenantId: tn.Id, AppId: app.Id}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.KillSwitch != nil {
		t.Fatalf("build-scoped switch must not apply to a request without build_hash, got %+v", resp.Msg.KillSwitch)
	}

	// Matching build hash: the build-scoped switch is delivered.
	resp, err = svc.GetConfig(auth.WithTenant(context.Background(), tn.Id), connect.NewRequest(&ksealv1.ConfigRequest{TenantId: tn.Id, AppId: app.Id, BuildHash: build}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.KillSwitch == nil || resp.Msg.KillSwitch.BuildHash != build {
		t.Fatalf("matching build_hash must deliver the build-scoped switch, got %+v", resp.Msg.KillSwitch)
	}
}

func TestCacheControlPrivateWhenInstanceSpecific(t *testing.T) {
	svc, store, tn, app := setup(t)
	stable := createPolicy(t, store, tn.Id, app.Id, "stable", true)
	cand := createPolicy(t, store, tn.Id, app.Id, "candidate", false)
	reg := canary.NewRegistry()
	reg.Replace([]*ksealv1.CanaryStatus{{
		TenantId: tn.Id, AppId: app.Id, CandidatePolicyId: cand.Id, StablePolicyId: stable.Id,
		Percent: 100, State: ksealv1.CanaryState_CANARY_STATE_ACTIVE,
	}})
	svc.AttachCompliance(reg, nil, mustFlags(t, tn.Id+":"+compliance.FlagCanaryRollout+"=true"))

	// Stable (no candidate, no kill switch) stays publicly cacheable.
	stableResp, err := svc.GetConfig(auth.WithTenant(context.Background(), tn.Id), connect.NewRequest(&ksealv1.ConfigRequest{TenantId: tn.Id, AppId: app.Id}))
	if err != nil {
		t.Fatal(err)
	}
	if cc := stableResp.Header().Get("Cache-Control"); cc == "" || cc[:6] != "public" {
		t.Fatalf("stable config must be public, got %q", cc)
	}

	// A served canary candidate is instance-specific and must be private.
	candResp, err := svc.GetConfig(auth.WithTenant(context.Background(), tn.Id), connect.NewRequest(&ksealv1.ConfigRequest{TenantId: tn.Id, AppId: app.Id, InstanceId: "inst-1"}))
	if err != nil {
		t.Fatal(err)
	}
	if cc := candResp.Header().Get("Cache-Control"); cc == "" || cc[:7] != "private" {
		t.Fatalf("canary candidate config must be private, got %q", cc)
	}
}
