package registry

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
	"github.com/kennguy3n/kseal/server/shared/auth"
)

// Service implements the Connect RegistryService over a Store. It validates
// inputs, enforces tenant context, and delegates persistence to the store.
type Service struct {
	ksealv1connect.UnimplementedRegistryServiceHandler
	store Store
}

// NewService builds a RegistryService handler.
func NewService(store Store) *Service { return &Service{store: store} }

// requireTenant ensures the caller's authenticated tenant matches the tenant id
// carried in the request body, closing the cross-tenant access path at the edge.
func requireTenant(ctx context.Context, bodyTenant string) error {
	tenant, err := auth.TenantFrom(ctx)
	if err != nil {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("missing tenant context"))
	}
	if bodyTenant != "" && bodyTenant != tenant {
		return connect.NewError(connect.CodePermissionDenied, errors.New("cross-tenant request denied"))
	}
	return nil
}

func toConnectErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, ErrConflict):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, ErrInvalidInput):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, ErrReplay):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, auth.ErrCrossTenant):
		return connect.NewError(connect.CodePermissionDenied, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

// ---- Tenants ----

func (s *Service) CreateTenant(ctx context.Context, req *connect.Request[ksealv1.CreateTenantRequest]) (*connect.Response[ksealv1.CreateTenantResponse], error) {
	t, err := s.store.CreateTenant(ctx, CreateTenantInput{Name: req.Msg.Name, Slug: req.Msg.Slug, Tier: req.Msg.Tier})
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.CreateTenantResponse{Tenant: t}), nil
}

func (s *Service) GetTenant(ctx context.Context, req *connect.Request[ksealv1.GetTenantRequest]) (*connect.Response[ksealv1.GetTenantResponse], error) {
	if err := requireTenant(ctx, req.Msg.Id); err != nil {
		return nil, err
	}
	t, err := s.store.GetTenant(ctx, req.Msg.Id)
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.GetTenantResponse{Tenant: t}), nil
}

func (s *Service) ListTenants(ctx context.Context, req *connect.Request[ksealv1.ListTenantsRequest]) (*connect.Response[ksealv1.ListTenantsResponse], error) {
	tenants, next, err := s.store.ListTenants(ctx, Page{Size: int(req.Msg.PageSize), Token: req.Msg.PageToken})
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.ListTenantsResponse{Tenants: tenants, NextPageToken: next}), nil
}

func (s *Service) UpdateTenant(ctx context.Context, req *connect.Request[ksealv1.UpdateTenantRequest]) (*connect.Response[ksealv1.UpdateTenantResponse], error) {
	if err := requireTenant(ctx, req.Msg.Id); err != nil {
		return nil, err
	}
	t, err := s.store.UpdateTenant(ctx, UpdateTenantInput{ID: req.Msg.Id, Name: req.Msg.Name, Tier: req.Msg.Tier, Status: req.Msg.Status})
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.UpdateTenantResponse{Tenant: t}), nil
}

// ---- Apps ----

func (s *Service) CreateApp(ctx context.Context, req *connect.Request[ksealv1.CreateAppRequest]) (*connect.Response[ksealv1.CreateAppResponse], error) {
	if err := requireTenant(ctx, req.Msg.TenantId); err != nil {
		return nil, err
	}
	a, err := s.store.CreateApp(ctx, CreateAppInput{
		TenantID: req.Msg.TenantId, Name: req.Msg.Name, Platform: req.Msg.Platform,
		PackageID: req.Msg.PackageId, SigningIdentities: req.Msg.SigningIdentities,
	})
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.CreateAppResponse{App: a}), nil
}

func (s *Service) GetApp(ctx context.Context, req *connect.Request[ksealv1.GetAppRequest]) (*connect.Response[ksealv1.GetAppResponse], error) {
	if err := requireTenant(ctx, req.Msg.TenantId); err != nil {
		return nil, err
	}
	a, err := s.store.GetApp(ctx, req.Msg.TenantId, req.Msg.Id)
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.GetAppResponse{App: a}), nil
}

func (s *Service) ListApps(ctx context.Context, req *connect.Request[ksealv1.ListAppsRequest]) (*connect.Response[ksealv1.ListAppsResponse], error) {
	if err := requireTenant(ctx, req.Msg.TenantId); err != nil {
		return nil, err
	}
	apps, next, err := s.store.ListApps(ctx, req.Msg.TenantId, Page{Size: int(req.Msg.PageSize), Token: req.Msg.PageToken})
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.ListAppsResponse{Apps: apps, NextPageToken: next}), nil
}

// ---- Builds ----

func (s *Service) CreateBuild(ctx context.Context, req *connect.Request[ksealv1.CreateBuildRequest]) (*connect.Response[ksealv1.CreateBuildResponse], error) {
	if err := requireTenant(ctx, req.Msg.TenantId); err != nil {
		return nil, err
	}
	b, err := s.store.CreateBuild(ctx, CreateBuildInput{
		TenantID: req.Msg.TenantId, AppID: req.Msg.AppId, BuildHash: req.Msg.BuildHash,
		VersionName: req.Msg.VersionName, VersionCode: req.Msg.VersionCode,
		ProtectionProfileID: req.Msg.ProtectionProfileId, Manifest: req.Msg.Manifest,
	})
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.CreateBuildResponse{Build: b}), nil
}

func (s *Service) GetBuild(ctx context.Context, req *connect.Request[ksealv1.GetBuildRequest]) (*connect.Response[ksealv1.GetBuildResponse], error) {
	if err := requireTenant(ctx, req.Msg.TenantId); err != nil {
		return nil, err
	}
	b, err := s.store.GetBuild(ctx, req.Msg.TenantId, req.Msg.Id)
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.GetBuildResponse{Build: b}), nil
}

func (s *Service) ListBuilds(ctx context.Context, req *connect.Request[ksealv1.ListBuildsRequest]) (*connect.Response[ksealv1.ListBuildsResponse], error) {
	if err := requireTenant(ctx, req.Msg.TenantId); err != nil {
		return nil, err
	}
	builds, next, err := s.store.ListBuilds(ctx, req.Msg.TenantId, req.Msg.AppId, Page{Size: int(req.Msg.PageSize), Token: req.Msg.PageToken})
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.ListBuildsResponse{Builds: builds, NextPageToken: next}), nil
}

// ---- Policies ----

func (s *Service) CreatePolicy(ctx context.Context, req *connect.Request[ksealv1.CreatePolicyRequest]) (*connect.Response[ksealv1.CreatePolicyResponse], error) {
	if err := requireTenant(ctx, req.Msg.TenantId); err != nil {
		return nil, err
	}
	p, err := s.store.CreatePolicy(ctx, CreatePolicyInput{
		TenantID: req.Msg.TenantId, AppID: req.Msg.AppId, Name: req.Msg.Name,
		EnforcementMode: req.Msg.EnforcementMode, Rules: req.Msg.Rules,
		RiskThresholds: req.Msg.RiskThresholds, ModulesEnabled: req.Msg.ModulesEnabled,
	})
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.CreatePolicyResponse{Policy: p}), nil
}

func (s *Service) GetActivePolicy(ctx context.Context, req *connect.Request[ksealv1.GetActivePolicyRequest]) (*connect.Response[ksealv1.GetActivePolicyResponse], error) {
	if err := requireTenant(ctx, req.Msg.TenantId); err != nil {
		return nil, err
	}
	p, err := s.store.GetActivePolicy(ctx, req.Msg.TenantId, req.Msg.AppId)
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.GetActivePolicyResponse{Policy: p}), nil
}

func (s *Service) ListPolicies(ctx context.Context, req *connect.Request[ksealv1.ListPoliciesRequest]) (*connect.Response[ksealv1.ListPoliciesResponse], error) {
	if err := requireTenant(ctx, req.Msg.TenantId); err != nil {
		return nil, err
	}
	policies, err := s.store.ListPolicies(ctx, req.Msg.TenantId, req.Msg.AppId)
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.ListPoliciesResponse{Policies: policies}), nil
}

func (s *Service) ActivatePolicy(ctx context.Context, req *connect.Request[ksealv1.ActivatePolicyRequest]) (*connect.Response[ksealv1.ActivatePolicyResponse], error) {
	if err := requireTenant(ctx, req.Msg.TenantId); err != nil {
		return nil, err
	}
	p, err := s.store.ActivatePolicy(ctx, req.Msg.TenantId, req.Msg.Id)
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.ActivatePolicyResponse{Policy: p}), nil
}

// ---- Protection profiles ----

func (s *Service) CreateProtectionProfile(ctx context.Context, req *connect.Request[ksealv1.CreateProtectionProfileRequest]) (*connect.Response[ksealv1.CreateProtectionProfileResponse], error) {
	if err := requireTenant(ctx, req.Msg.TenantId); err != nil {
		return nil, err
	}
	pp, err := s.store.CreateProtectionProfile(ctx, CreateProtectionProfileInput{
		TenantID: req.Msg.TenantId, Name: req.Msg.Name,
		ModulesEnabled: req.Msg.ModulesEnabled, DefaultMode: req.Msg.DefaultMode,
	})
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.CreateProtectionProfileResponse{Profile: pp}), nil
}

func (s *Service) ListProtectionProfiles(ctx context.Context, req *connect.Request[ksealv1.ListProtectionProfilesRequest]) (*connect.Response[ksealv1.ListProtectionProfilesResponse], error) {
	if err := requireTenant(ctx, req.Msg.TenantId); err != nil {
		return nil, err
	}
	profiles, err := s.store.ListProtectionProfiles(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, toConnectErr(err)
	}
	return connect.NewResponse(&ksealv1.ListProtectionProfilesResponse{Profiles: profiles}), nil
}
