// Package webhook manages tenant webhook registrations and asynchronously
// delivers HMAC-signed events with retries and per-endpoint circuit breaking.
package webhook

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/shared/auth"
)

// Service implements the Connect WebhookService.
type Service struct {
	ksealv1connect.UnimplementedWebhookServiceHandler
	store registry.Store
}

// NewService builds a WebhookService.
func NewService(store registry.Store) *Service { return &Service{store: store} }

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

func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, registry.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, registry.ErrInvalidInput):
		return connect.NewError(connect.CodeInvalidArgument, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

// RegisterWebhook creates a webhook subscription for the tenant.
func (s *Service) RegisterWebhook(ctx context.Context, req *connect.Request[ksealv1.RegisterWebhookRequest]) (*connect.Response[ksealv1.RegisterWebhookResponse], error) {
	if err := requireTenant(ctx, req.Msg.TenantId); err != nil {
		return nil, err
	}
	wh, err := s.store.CreateWebhook(ctx, req.Msg.TenantId, req.Msg.Url, req.Msg.EventTypes)
	if err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(&ksealv1.RegisterWebhookResponse{Webhook: wh}), nil
}

// ListWebhooks lists the tenant's webhooks.
func (s *Service) ListWebhooks(ctx context.Context, req *connect.Request[ksealv1.ListWebhooksRequest]) (*connect.Response[ksealv1.ListWebhooksResponse], error) {
	if err := requireTenant(ctx, req.Msg.TenantId); err != nil {
		return nil, err
	}
	whs, err := s.store.ListWebhooks(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(&ksealv1.ListWebhooksResponse{Webhooks: whs}), nil
}

// DeleteWebhook removes a webhook by id.
func (s *Service) DeleteWebhook(ctx context.Context, req *connect.Request[ksealv1.DeleteWebhookRequest]) (*connect.Response[ksealv1.DeleteWebhookResponse], error) {
	if err := requireTenant(ctx, req.Msg.TenantId); err != nil {
		return nil, err
	}
	deleted, err := s.store.DeleteWebhook(ctx, req.Msg.TenantId, req.Msg.Id)
	if err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(&ksealv1.DeleteWebhookResponse{Deleted: deleted}), nil
}
