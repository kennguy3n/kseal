package registry

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
)

func TestCreateTenantRejectsTenantPrincipal(t *testing.T) {
	svc := NewService(NewMemStore())
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{TenantID: "t1", APIKeyID: "k1", Scopes: []string{"tenant:admin"}})
	_, err := svc.CreateTenant(ctx, connect.NewRequest(&ksealv1.CreateTenantRequest{Name: "Nope", Slug: "nope"}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expected permission denied, got %v", err)
	}
}

func TestListTenantsRejectsTenantPrincipal(t *testing.T) {
	svc := NewService(NewMemStore())
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{TenantID: "t1", APIKeyID: "k1", Scopes: []string{"tenant:admin"}})
	_, err := svc.ListTenants(ctx, connect.NewRequest(&ksealv1.ListTenantsRequest{}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expected permission denied, got %v", err)
	}
}

func TestPlatformAdminCanCreateAndListTenants(t *testing.T) {
	svc := NewService(NewMemStore())
	ctx := auth.WithPrincipal(context.Background(), &auth.Principal{APIKeyID: "platform", PlatformAdmin: true, Scopes: []string{"platform:*"}})
	created, err := svc.CreateTenant(ctx, connect.NewRequest(&ksealv1.CreateTenantRequest{Name: "Acme", Slug: "acme"}))
	if err != nil {
		t.Fatal(err)
	}
	listed, err := svc.ListTenants(ctx, connect.NewRequest(&ksealv1.ListTenantsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Msg.Tenants) != 1 || listed.Msg.Tenants[0].Id != created.Msg.Tenant.Id {
		t.Fatalf("unexpected tenants: %+v", listed.Msg.Tenants)
	}
}
