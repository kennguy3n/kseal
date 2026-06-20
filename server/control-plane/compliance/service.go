package compliance

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
	"github.com/kennguy3n/kseal/server/shared/auth"
)

// Service implements the Connect ComplianceService over the compliance store
// and the registry store. Every RPC is tenant-scoped: the caller's
// authenticated tenant must match the request tenant_id, and all reads/writes
// filter on that tenant.
type Service struct {
	ksealv1connect.UnimplementedComplianceServiceHandler

	store    Store
	registry registry.Store
}

// NewService builds a ComplianceService handler. registry is used to resolve
// and activate policies for canary rollouts.
func NewService(store Store, reg registry.Store) *Service {
	return &Service{store: store, registry: reg}
}

// requireTenant authenticates the caller and enforces that the request tenant
// matches the caller's tenant, returning the resolved tenant id and the actor's
// API-key id for audit attribution.
func requireTenant(ctx context.Context, bodyTenant string) (tenant, actorKeyID string, err error) {
	p, ok := auth.PrincipalFrom(ctx)
	if !ok || p.TenantID == "" {
		return "", "", connect.NewError(connect.CodeUnauthenticated, errors.New("missing tenant context"))
	}
	if bodyTenant != "" && bodyTenant != p.TenantID {
		return "", "", connect.NewError(connect.CodePermissionDenied, errors.New("cross-tenant request denied"))
	}
	return p.TenantID, p.APIKeyID, nil
}

func toConnectErr(err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, ErrNotFound), errors.Is(err, registry.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

// ListAuditEvents returns a newest-first, keyset-paginated page of audit events
// for the caller's tenant.
func (s *Service) ListAuditEvents(ctx context.Context, req *connect.Request[ksealv1.ListAuditEventsRequest]) (*connect.Response[ksealv1.ListAuditEventsResponse], error) {
	m := req.Msg
	tenant, _, err := requireTenant(ctx, m.TenantId)
	if err != nil {
		return nil, err
	}
	events, next, err := s.store.ListAudit(ctx, tenant, AuditFilter{
		Action:       m.Action,
		ResourceType: m.ResourceType,
		FromMillis:   m.StartTime,
		ToMillis:     m.EndTime,
	}, int(m.PageSize), m.PageToken)
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.ListAuditEventsResponse{Events: events, NextPageToken: next}), nil
}

// VerifyAuditChain recomputes the tenant's hash chain and reports integrity.
func (s *Service) VerifyAuditChain(ctx context.Context, req *connect.Request[ksealv1.VerifyAuditChainRequest]) (*connect.Response[ksealv1.VerifyAuditChainResponse], error) {
	tenant, _, err := requireTenant(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	res, err := s.store.VerifyAudit(ctx, tenant)
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.VerifyAuditChainResponse{
		Intact:        res.Intact,
		VerifiedCount: res.VerifiedCount,
		BrokenSeq:     res.BrokenSeq,
		HeadHash:      res.HeadHash,
	}), nil
}

// GetDataProcessingRegistry returns every data-processing record for a tenant.
func (s *Service) GetDataProcessingRegistry(ctx context.Context, req *connect.Request[ksealv1.GetDataProcessingRegistryRequest]) (*connect.Response[ksealv1.GetDataProcessingRegistryResponse], error) {
	tenant, _, err := requireTenant(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	recs, err := s.store.ListDataProcessing(ctx, tenant)
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.GetDataProcessingRegistryResponse{Records: recs}), nil
}

// PutDataProcessingRecord creates or updates a tenant's per-app disclosure.
func (s *Service) PutDataProcessingRecord(ctx context.Context, req *connect.Request[ksealv1.PutDataProcessingRecordRequest]) (*connect.Response[ksealv1.PutDataProcessingRecordResponse], error) {
	m := req.Msg
	tenant, actor, err := requireTenant(ctx, m.TenantId)
	if err != nil {
		return nil, err
	}
	rec, err := s.store.PutDataProcessing(ctx, DataProcessingInput{
		TenantID:          tenant,
		AppID:             m.AppId,
		DataCategories:    m.DataCategories,
		Purpose:           m.Purpose,
		RetentionDays:     m.RetentionDays,
		LegalBasis:        m.LegalBasis,
		ThirdPartySharing: m.ThirdPartySharing,
	})
	if err != nil {
		return nil, toConnectErr(err)
	}
	// Best-effort audit of the disclosure change; never blocks the write.
	_, _ = s.store.AppendAudit(ctx, tenant, dataProcessingAuditEntry(DataProcessingInput{
		TenantID:          rec.TenantId,
		AppID:             rec.AppId,
		DataCategories:    rec.DataCategories,
		Purpose:           rec.Purpose,
		RetentionDays:     rec.RetentionDays,
		LegalBasis:        rec.LegalBasis,
		ThirdPartySharing: rec.ThirdPartySharing,
	}, actor))
	return connect.NewResponse(&ksealv1.PutDataProcessingRecordResponse{Record: rec}), nil
}

// IssueKillSwitch signs and stores a remote disable/enable command for a scope.
func (s *Service) IssueKillSwitch(ctx context.Context, req *connect.Request[ksealv1.IssueKillSwitchRequest]) (*connect.Response[ksealv1.IssueKillSwitchResponse], error) {
	m := req.Msg
	tenant, actor, err := requireTenant(ctx, m.TenantId)
	if err != nil {
		return nil, err
	}
	ks, err := s.store.IssueKillSwitch(ctx, KillSwitchInput{
		TenantID:   tenant,
		AppID:      m.AppId,
		BuildHash:  m.BuildHash,
		Command:    m.Command,
		Reason:     m.Reason,
		ActorKeyID: actor,
	})
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.IssueKillSwitchResponse{KillSwitch: ks}), nil
}

// GetKillSwitchState resolves the effective command for a scope and returns the
// signed command in effect.
func (s *Service) GetKillSwitchState(ctx context.Context, req *connect.Request[ksealv1.GetKillSwitchStateRequest]) (*connect.Response[ksealv1.GetKillSwitchStateResponse], error) {
	m := req.Msg
	tenant, _, err := requireTenant(ctx, m.TenantId)
	if err != nil {
		return nil, err
	}
	switches, err := s.store.ListKillSwitches(ctx, tenant)
	if err != nil {
		return nil, toConnectErr(err)
	}
	cmd, active := GetKillSwitchState(switches, m.AppId, m.BuildHash)
	return connect.NewResponse(&ksealv1.GetKillSwitchStateResponse{EffectiveCommand: cmd, Active: active}), nil
}

// ListKillSwitches returns every kill switch configured for a tenant.
func (s *Service) ListKillSwitches(ctx context.Context, req *connect.Request[ksealv1.ListKillSwitchesRequest]) (*connect.Response[ksealv1.ListKillSwitchesResponse], error) {
	tenant, _, err := requireTenant(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	switches, err := s.store.ListKillSwitches(ctx, tenant)
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.ListKillSwitchesResponse{KillSwitches: switches}), nil
}

// SetCanaryRollout configures or updates a staged rollout. The last-known-good
// (stable) policy is resolved from the currently active policy, and the
// candidate policy is validated to belong to the tenant/app.
func (s *Service) SetCanaryRollout(ctx context.Context, req *connect.Request[ksealv1.SetCanaryRolloutRequest]) (*connect.Response[ksealv1.SetCanaryRolloutResponse], error) {
	m := req.Msg
	tenant, actor, err := requireTenant(ctx, m.TenantId)
	if err != nil {
		return nil, err
	}
	if m.AppId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("app_id required"))
	}
	candidate, err := s.registry.GetPolicy(ctx, tenant, m.CandidatePolicyId)
	if err != nil {
		return nil, toConnectErr(err)
	}
	if candidate.AppId != "" && candidate.AppId != m.AppId {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("candidate policy does not belong to app"))
	}
	stable := ""
	if active, err := s.registry.GetActivePolicy(ctx, tenant, m.AppId); err == nil && active != nil {
		stable = active.Id
	} else if err != nil && !errors.Is(err, registry.ErrNotFound) {
		return nil, toConnectErr(err)
	}
	status, err := s.store.SetCanary(ctx, CanaryInput{
		TenantID:          tenant,
		AppID:             m.AppId,
		CandidatePolicyID: m.CandidatePolicyId,
		StablePolicyID:    stable,
		Percent:           m.Percent,
		RollbackThreshold: m.RollbackThreshold,
		ActorKeyID:        actor,
	})
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.SetCanaryRolloutResponse{Status: status}), nil
}

// GetCanaryStatus returns the current rollout state and observed health.
func (s *Service) GetCanaryStatus(ctx context.Context, req *connect.Request[ksealv1.GetCanaryStatusRequest]) (*connect.Response[ksealv1.GetCanaryStatusResponse], error) {
	m := req.Msg
	tenant, _, err := requireTenant(ctx, m.TenantId)
	if err != nil {
		return nil, err
	}
	status, err := s.store.GetCanary(ctx, tenant, m.AppId)
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.GetCanaryStatusResponse{Status: status}), nil
}

// PromoteCanary promotes the candidate to the active policy and marks the
// rollout promoted.
func (s *Service) PromoteCanary(ctx context.Context, req *connect.Request[ksealv1.PromoteCanaryRequest]) (*connect.Response[ksealv1.PromoteCanaryResponse], error) {
	m := req.Msg
	tenant, actor, err := requireTenant(ctx, m.TenantId)
	if err != nil {
		return nil, err
	}
	cur, err := s.store.GetCanary(ctx, tenant, m.AppId)
	if err != nil {
		return nil, toConnectErr(err)
	}
	if _, err := s.registry.ActivatePolicy(ctx, tenant, cur.CandidatePolicyId); err != nil {
		return nil, toConnectErr(err)
	}
	status, err := s.store.PromoteCanary(ctx, tenant, m.AppId, actor)
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.PromoteCanaryResponse{Status: status}), nil
}

// RollbackCanary withdraws the candidate, reverting to last-known-good.
func (s *Service) RollbackCanary(ctx context.Context, req *connect.Request[ksealv1.RollbackCanaryRequest]) (*connect.Response[ksealv1.RollbackCanaryResponse], error) {
	m := req.Msg
	tenant, actor, err := requireTenant(ctx, m.TenantId)
	if err != nil {
		return nil, err
	}
	status, err := s.store.RollbackCanary(ctx, tenant, m.AppId, m.Reason, actor, CanaryObservation{})
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.RollbackCanaryResponse{Status: status}), nil
}
