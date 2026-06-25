package compliance

import (
	"context"
	"testing"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

func newTestStore(t *testing.T) (*MemStore, *registry.MemStore) {
	t.Helper()
	reg := registry.NewMemStore()
	return NewMemStore(reg), reg
}

func TestAuditChainAppendAndVerify(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	const tenant = "t1"

	for i := 0; i < 5; i++ {
		if _, err := s.AppendAudit(ctx, tenant, Entry{Action: "policy.update", ResourceType: "policy"}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	res, err := s.VerifyAudit(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact || res.VerifiedCount != 5 || res.BrokenSeq != 0 {
		t.Fatalf("expected intact chain of 5, got %+v", res)
	}
	if res.HeadHash == "" {
		t.Fatal("expected non-empty head hash")
	}
}

func TestAuditChainTamperDetected(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	const tenant = "t1"
	for i := 0; i < 4; i++ {
		if _, err := s.AppendAudit(ctx, tenant, Entry{Action: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	// Tamper with the stored chain directly (simulating a malicious DB edit).
	s.audit[tenant][1].Action = "tampered"
	res, err := s.VerifyAudit(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if res.Intact {
		t.Fatal("expected tamper to break the chain")
	}
	if res.BrokenSeq != 2 {
		t.Fatalf("expected break at seq 2, got %d", res.BrokenSeq)
	}
}

func TestAuditTenantIsolationAndPaging(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	for i := 0; i < 3; i++ {
		mustAppend(t, s, "a", "act")
	}
	mustAppend(t, s, "b", "act")

	// Tenant b never sees tenant a's events.
	evb, _, err := s.ListAudit(ctx, "b", AuditFilter{}, 50, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(evb) != 1 {
		t.Fatalf("tenant b should have 1 event, got %d", len(evb))
	}

	// Keyset paging over tenant a, newest first.
	page1, next, err := s.ListAudit(ctx, "a", AuditFilter{}, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page1) != 2 || next == "" {
		t.Fatalf("page1=%d next=%q", len(page1), next)
	}
	if page1[0].Seq != 3 || page1[1].Seq != 2 {
		t.Fatalf("expected newest-first 3,2 got %d,%d", page1[0].Seq, page1[1].Seq)
	}
	page2, _, err := s.ListAudit(ctx, "a", AuditFilter{}, 2, next)
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 1 || page2[0].Seq != 1 {
		t.Fatalf("expected final event seq 1, got %+v", page2)
	}
}

func TestAuditFilterByAction(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	mustAppend(t, s, "t", "policy.update")
	mustAppend(t, s, "t", "key.rotate")
	mustAppend(t, s, "t", "policy.update")
	got, _, err := s.ListAudit(ctx, "t", AuditFilter{Action: "policy.update"}, 50, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 filtered events, got %d", len(got))
	}
}

func TestAuditRejectsEmptyAction(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.AppendAudit(context.Background(), "t", Entry{}); err == nil {
		t.Fatal("expected error for empty action")
	}
}

func TestDataProcessingUpsert(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	const tenant = "t1"
	if _, err := s.PutDataProcessing(ctx, DataProcessingInput{
		TenantID: tenant, AppID: "app1", DataCategories: []string{"device"}, Purpose: "fraud", RetentionDays: 30, LegalBasis: "legitimate_interest",
	}); err != nil {
		t.Fatal(err)
	}
	// Update same (tenant, app) -> still one record, new values.
	if _, err := s.PutDataProcessing(ctx, DataProcessingInput{
		TenantID: tenant, AppID: "app1", DataCategories: []string{" Device ", "network", "device"}, Purpose: "security", RetentionDays: 7, LegalBasis: "legitimate_interest",
	}); err != nil {
		t.Fatal(err)
	}
	recs, err := s.ListDataProcessing(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record after upsert, got %d", len(recs))
	}
	if recs[0].Purpose != "security" || recs[0].RetentionDays != 7 {
		t.Fatalf("upsert did not replace values: %+v", recs[0])
	}
	if got := recs[0].DataCategories; len(got) != 2 || got[0] != "device" || got[1] != "network" {
		t.Fatalf("categories should be normalized/deduped in input order, got %v", got)
	}
}

func TestDataProcessingValidation(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	cases := []DataProcessingInput{
		{TenantID: "t", DataCategories: []string{"device"}, Purpose: "fraud", LegalBasis: "legitimate_interest", RetentionDays: -1},
		{TenantID: "t", Purpose: "fraud", LegalBasis: "legitimate_interest"},
		{TenantID: "t", DataCategories: []string{"device"}, LegalBasis: "legitimate_interest"},
		{TenantID: "t", DataCategories: []string{"device"}, Purpose: "fraud"},
	}
	for i, tc := range cases {
		if _, err := s.PutDataProcessing(ctx, tc); err == nil {
			t.Fatalf("case %d: expected validation error", i)
		}
	}
}

func TestKillSwitchSignVerifyAndVersioning(t *testing.T) {
	ctx := context.Background()
	s, reg := newTestStore(t)
	const tenant = "t1"

	ks, err := s.IssueKillSwitch(ctx, KillSwitchInput{
		TenantID: tenant, AppID: "app1", Command: ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE, Reason: "incident",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ks.Version != 1 {
		t.Fatalf("expected version 1, got %d", ks.Version)
	}

	sk, err := reg.GetActiveSigningKey(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyKillSwitch(sk.Public, ks) {
		t.Fatal("issued kill switch must verify with the tenant key")
	}
	// Forgery: flip the command, signature must no longer verify.
	forged := cloneKillSwitch(ks)
	forged.Command = ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_ENABLE
	if VerifyKillSwitch(sk.Public, forged) {
		t.Fatal("tampered command must fail verification (fail-safe)")
	}

	// Re-issue same scope bumps version (anti-rollback).
	ks2, err := s.IssueKillSwitch(ctx, KillSwitchInput{
		TenantID: tenant, AppID: "app1", Command: ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_ENABLE,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ks2.Version != 2 {
		t.Fatalf("expected version 2 on re-issue, got %d", ks2.Version)
	}
}

func TestKillSwitchResolutionMostSpecificWins(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	const tenant = "t1"
	// Tenant-wide DISABLE...
	if _, err := s.IssueKillSwitch(ctx, KillSwitchInput{TenantID: tenant, Command: ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE}); err != nil {
		t.Fatal(err)
	}
	// ...overridden by an app-scoped ENABLE.
	if _, err := s.IssueKillSwitch(ctx, KillSwitchInput{TenantID: tenant, AppID: "app1", Command: ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_ENABLE}); err != nil {
		t.Fatal(err)
	}
	switches, err := s.ListKillSwitches(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	cmd, active := GetKillSwitchState(switches, "app1", "")
	if cmd != ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_ENABLE || active == nil {
		t.Fatalf("app1 should resolve to ENABLE, got %v", cmd)
	}
	// A different app falls back to the tenant-wide DISABLE.
	cmd2, _ := GetKillSwitchState(switches, "app2", "")
	if cmd2 != ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE {
		t.Fatalf("app2 should resolve to tenant-wide DISABLE, got %v", cmd2)
	}
	// No switch at all -> default ENABLE, nil active.
	cmd3, active3 := GetKillSwitchState(nil, "x", "")
	if cmd3 != ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_ENABLE || active3 != nil {
		t.Fatal("no switch must default to ENABLE with nil active")
	}
}

func TestCanaryLifecycle(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	const tenant, app = "t1", "app1"

	cs, err := s.SetCanary(ctx, CanaryInput{TenantID: tenant, AppID: app, CandidatePolicyID: "cand", StablePolicyID: "stable", Percent: 10})
	if err != nil {
		t.Fatal(err)
	}
	if cs.State != ksealv1.CanaryState_CANARY_STATE_ACTIVE || cs.Percent != 10 {
		t.Fatalf("unexpected initial canary %+v", cs)
	}
	if cs.RollbackThreshold != DefaultRollbackThreshold {
		t.Fatalf("expected default threshold, got %v", cs.RollbackThreshold)
	}

	active, err := s.ListActiveCanaries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 {
		t.Fatalf("expected 1 active canary, got %d", len(active))
	}

	rb, err := s.RollbackCanary(ctx, tenant, app, "guardrail breach", "actor", CanaryObservation{BlockRate: 0.2, SampleCount: 100})
	if err != nil {
		t.Fatal(err)
	}
	if rb.State != ksealv1.CanaryState_CANARY_STATE_ROLLED_BACK || rb.Percent != 0 {
		t.Fatalf("rollback should zero percent and mark rolled back: %+v", rb)
	}
	if rb.BlockRate != 0.2 || rb.SampleCount != 100 {
		t.Fatalf("rollback should record observation, got %+v", rb)
	}

	// Rolled-back rollouts drop out of the active set.
	active, _ = s.ListActiveCanaries(ctx)
	if len(active) != 0 {
		t.Fatalf("rolled-back canary must not be active, got %d", len(active))
	}

	// Verify the audit chain captured set + rollback and stays intact.
	res, _ := s.VerifyAudit(ctx, tenant)
	if !res.Intact || res.VerifiedCount != 2 {
		t.Fatalf("expected 2 intact audit events, got %+v", res)
	}
}

func TestCanaryPromotePreservesStable(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	const tenant, app = "t1", "app1"
	if _, err := s.SetCanary(ctx, CanaryInput{TenantID: tenant, AppID: app, CandidatePolicyID: "cand", StablePolicyID: "stable", Percent: 50}); err != nil {
		t.Fatal(err)
	}
	cs, err := s.PromoteCanary(ctx, tenant, app, "actor")
	if err != nil {
		t.Fatal(err)
	}
	if cs.State != ksealv1.CanaryState_CANARY_STATE_PROMOTED || cs.Percent != 100 {
		t.Fatalf("promote should set 100%% promoted, got %+v", cs)
	}
	if cs.StablePolicyId != "cand" {
		t.Fatalf("promote should make candidate the new stable, got %q", cs.StablePolicyId)
	}
}

func TestCanarySetHonorsNewStableAfterRollback(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	const tenant, app = "t1", "app1"

	// Initial rollout against stable "v1", then roll back.
	if _, err := s.SetCanary(ctx, CanaryInput{TenantID: tenant, AppID: app, CandidatePolicyID: "cand1", StablePolicyID: "v1", Percent: 50}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RollbackCanary(ctx, tenant, app, "breach", "actor", CanaryObservation{BlockRate: 0.5, SampleCount: 100}); err != nil {
		t.Fatal(err)
	}

	// Admin activated a new policy "v2"; re-canary must target v2 as stable,
	// not the stale "v1" preserved from the previous rollout.
	cs, err := s.SetCanary(ctx, CanaryInput{TenantID: tenant, AppID: app, CandidatePolicyID: "cand2", StablePolicyID: "v2", Percent: 10})
	if err != nil {
		t.Fatal(err)
	}
	if cs.StablePolicyId != "v2" {
		t.Fatalf("re-canary must adopt the new stable v2, got %q", cs.StablePolicyId)
	}

	// When the caller cannot resolve a stable (empty), fall back to last-known-good.
	cs, err = s.SetCanary(ctx, CanaryInput{TenantID: tenant, AppID: app, CandidatePolicyID: "cand3", StablePolicyID: "", Percent: 5})
	if err != nil {
		t.Fatal(err)
	}
	if cs.StablePolicyId != "v2" {
		t.Fatalf("empty stable must fall back to last-known-good v2, got %q", cs.StablePolicyId)
	}
}

func TestListAuditNoTrailingEmptyPage(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	const tenant = "t1"
	for i := 0; i < 4; i++ {
		mustAppend(t, s, tenant, "policy.update")
	}
	// Page size equal to the exact count: a token must NOT be emitted, so the
	// client never makes a follow-up request that returns zero results.
	page, next, err := s.ListAudit(ctx, tenant, AuditFilter{}, 4, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 4 {
		t.Fatalf("expected all 4 events, got %d", len(page))
	}
	if next != "" {
		t.Fatalf("exact-fill page must not emit a next token, got %q", next)
	}
}

func mustAppend(t *testing.T, s *MemStore, tenant, action string) {
	t.Helper()
	if _, err := s.AppendAudit(context.Background(), tenant, Entry{Action: action}); err != nil {
		t.Fatal(err)
	}
}
