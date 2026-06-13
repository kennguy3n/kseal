package siem

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
	"github.com/kennguy3n/kseal/server/shared/auth"
)

// Service implements the Connect SiemService: register, list, and delete
// per-tenant SIEM connectors. It is a control-plane surface (API-key gated) and
// is the sole writer of connector auth secrets, which it seals before storage
// and never returns.
type Service struct {
	ksealv1connect.UnimplementedSiemServiceHandler
	store ConnectorStore
}

// NewService builds a SiemService over the given connector store.
func NewService(store ConnectorStore) *Service { return &Service{store: store} }

func requireTenant(ctx context.Context, bodyTenant string) (string, error) {
	tenant, err := auth.TenantFrom(ctx)
	if err != nil {
		return "", connect.NewError(connect.CodeUnauthenticated, errors.New("missing tenant context"))
	}
	if bodyTenant != "" && bodyTenant != tenant {
		return "", connect.NewError(connect.CodePermissionDenied, errors.New("cross-tenant request denied"))
	}
	return tenant, nil
}

func mapErr(err error) error {
	var disallowed *DisallowedFieldError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, ErrInvalidInput), errors.As(err, &disallowed):
		return connect.NewError(connect.CodeInvalidArgument, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

// RegisterConnector seals the supplied auth secret and persists a new connector.
func (s *Service) RegisterConnector(ctx context.Context, req *connect.Request[ksealv1.RegisterSiemConnectorRequest]) (*connect.Response[ksealv1.RegisterSiemConnectorResponse], error) {
	tenant, err := requireTenant(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	if req.Msg.AuthSecret == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("auth_secret required"))
	}
	c, err := s.store.CreateConnector(ctx, CreateConnectorInput{
		TenantID:               tenant,
		Kind:                   req.Msg.Kind,
		Endpoint:               req.Msg.Endpoint,
		Secret:                 []byte(req.Msg.AuthSecret),
		Format:                 req.Msg.Format,
		FieldAllowList:         req.Msg.FieldAllowList,
		SentinelDcrImmutableID: req.Msg.SentinelDcrImmutableId,
		SentinelStreamName:     req.Msg.SentinelStreamName,
		ElasticIndex:           req.Msg.ElasticIndex,
		SplunkIndex:            req.Msg.SplunkIndex,
		SplunkSourcetype:       req.Msg.SplunkSourcetype,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(&ksealv1.RegisterSiemConnectorResponse{Connector: c}), nil
}

// ListConnectors returns the tenant's connectors. Secret values are never
// included — only the opaque auth_secret_ref.
func (s *Service) ListConnectors(ctx context.Context, req *connect.Request[ksealv1.ListSiemConnectorsRequest]) (*connect.Response[ksealv1.ListSiemConnectorsResponse], error) {
	tenant, err := requireTenant(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	conns, err := s.store.ListConnectors(ctx, tenant)
	if err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(&ksealv1.ListSiemConnectorsResponse{Connectors: conns}), nil
}

// DeleteConnector removes a connector by id.
func (s *Service) DeleteConnector(ctx context.Context, req *connect.Request[ksealv1.DeleteSiemConnectorRequest]) (*connect.Response[ksealv1.DeleteSiemConnectorResponse], error) {
	tenant, err := requireTenant(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	deleted, err := s.store.DeleteConnector(ctx, tenant, req.Msg.Id)
	if err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(&ksealv1.DeleteSiemConnectorResponse{Deleted: deleted}), nil
}
