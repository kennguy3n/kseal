package compliance

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
)

func authCtx(tenant, keyID string) context.Context {
	return auth.WithPrincipal(context.Background(), &auth.Principal{TenantID: tenant, APIKeyID: keyID})
}

func newService(t *testing.T) (*Service, *registry.MemStore) {
	t.Helper()
	reg := registry.NewMemStore()
	return NewService(NewMemStore(reg), reg), reg
}

func TestServiceRequiresTenantContext(t *testing.T) {
	svc, _ := newService(t)
	// No principal in context -> unauthenticated.
	_, err := svc.ListAuditEvents(context.Background(), connect.NewRequest(&ksealv1.ListAuditEventsRequest{TenantId: "t1"}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected unauthenticated, got %v", err)
	}
}

func TestServiceCrossTenantDenied(t *testing.T) {
	svc, _ := newService(t)
	ctx := authCtx("t1", "k1")
	_, err := svc.GetDataProcessingRegistry(ctx, connect.NewRequest(&ksealv1.GetDataProcessingRegistryRequest{TenantId: "t2"}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expected permission denied for cross-tenant, got %v", err)
	}
}

func TestServicePutAndListDataProcessing(t *testing.T) {
	svc, _ := newService(t)
	ctx := authCtx("t1", "k1")
	_, err := svc.PutDataProcessingRecord(ctx, connect.NewRequest(&ksealv1.PutDataProcessingRecordRequest{
		TenantId: "t1", AppId: "app1", Purpose: "fraud", RetentionDays: 30, DataCategories: []string{"device"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.GetDataProcessingRegistry(ctx, connect.NewRequest(&ksealv1.GetDataProcessingRegistryRequest{TenantId: "t1"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Records) != 1 || resp.Msg.Records[0].Purpose != "fraud" {
		t.Fatalf("unexpected records %+v", resp.Msg.Records)
	}
	// The disclosure change was audited.
	ev, _, err := svc.store.ListAudit(ctx, "t1", AuditFilter{Action: "dataprocessing.put"}, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(ev))
	}
}

func TestServiceKillSwitchFlow(t *testing.T) {
	svc, _ := newService(t)
	ctx := authCtx("t1", "k1")
	if _, err := svc.IssueKillSwitch(ctx, connect.NewRequest(&ksealv1.IssueKillSwitchRequest{
		TenantId: "t1", AppId: "app1", Command: ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE,
	})); err != nil {
		t.Fatal(err)
	}
	state, err := svc.GetKillSwitchState(ctx, connect.NewRequest(&ksealv1.GetKillSwitchStateRequest{TenantId: "t1", AppId: "app1"}))
	if err != nil {
		t.Fatal(err)
	}
	if state.Msg.EffectiveCommand != ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE || state.Msg.Active == nil {
		t.Fatalf("expected DISABLE active, got %+v", state.Msg)
	}
}

func TestServiceSetCanaryValidatesCandidate(t *testing.T) {
	svc, reg := newService(t)
	ctx := authCtx("t1", "k1")
	// Candidate policy id that doesn't exist -> NotFound.
	_, err := svc.SetCanaryRollout(ctx, connect.NewRequest(&ksealv1.SetCanaryRolloutRequest{
		TenantId: "t1", AppId: "app1", CandidatePolicyId: "missing", Percent: 10,
	}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("expected NotFound for missing candidate, got %v", err)
	}

	// Create a real candidate policy and an active stable policy.
	stable := mustPolicy(t, reg, "t1", "app1")
	if _, err := reg.ActivatePolicy(ctx, "t1", stable.Id); err != nil {
		t.Fatal(err)
	}
	cand := mustPolicy(t, reg, "t1", "app1")

	resp, err := svc.SetCanaryRollout(ctx, connect.NewRequest(&ksealv1.SetCanaryRolloutRequest{
		TenantId: "t1", AppId: "app1", CandidatePolicyId: cand.Id, Percent: 25,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Status.StablePolicyId != stable.Id {
		t.Fatalf("expected stable resolved to active policy %q, got %q", stable.Id, resp.Msg.Status.StablePolicyId)
	}

	// Promote activates the candidate as the new active policy.
	if _, err := svc.PromoteCanary(ctx, connect.NewRequest(&ksealv1.PromoteCanaryRequest{TenantId: "t1", AppId: "app1"})); err != nil {
		t.Fatal(err)
	}
	got, err := reg.GetActivePolicy(ctx, "t1", "app1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Id != cand.Id {
		t.Fatalf("promote should activate candidate %q, active is %q", cand.Id, got.Id)
	}
}

func mustPolicy(t *testing.T, reg *registry.MemStore, tenant, app string) *ksealv1.Policy {
	t.Helper()
	p, err := reg.CreatePolicy(context.Background(), registry.CreatePolicyInput{
		TenantID: tenant, AppID: app, Name: "p", EnforcementMode: ksealv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
