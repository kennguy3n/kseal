package siem

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
)

func newSvc(t *testing.T) *Service {
	t.Helper()
	return NewService(NewMemConnectorStore(testEncryptor(t)))
}

func registerReq() *connect.Request[ksealv1.RegisterSiemConnectorRequest] {
	return connect.NewRequest(&ksealv1.RegisterSiemConnectorRequest{
		Kind:             ksealv1.SiemKind_SIEM_KIND_SPLUNK_HEC,
		Endpoint:         "https://splunk.example:8088",
		AuthSecret:       "hec-token",
		SplunkIndex:      "kseal",
		SplunkSourcetype: "kseal:trust",
	})
}

func TestServiceRegisterListDelete(t *testing.T) {
	svc := newSvc(t)
	ctx := auth.WithTenant(context.Background(), "t-1")

	resp, err := svc.RegisterConnector(ctx, registerReq())
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	c := resp.Msg.Connector
	if c.TenantId != "t-1" {
		t.Fatalf("tenant not bound from context: %q", c.TenantId)
	}
	if c.AuthSecretRef == "" {
		t.Fatal("auth_secret_ref missing")
	}
	// The response must never echo the secret.
	if got := c.String(); contains(got, "hec-token") {
		t.Fatalf("secret leaked in response: %s", got)
	}

	listResp, err := svc.ListConnectors(ctx, connect.NewRequest(&ksealv1.ListSiemConnectorsRequest{}))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(listResp.Msg.Connectors) != 1 {
		t.Fatalf("expected 1 connector, got %d", len(listResp.Msg.Connectors))
	}

	delResp, err := svc.DeleteConnector(ctx, connect.NewRequest(&ksealv1.DeleteSiemConnectorRequest{Id: c.Id}))
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !delResp.Msg.Deleted {
		t.Fatal("expected Deleted = true")
	}
}

func TestServiceRequiresTenantContext(t *testing.T) {
	svc := newSvc(t)
	_, err := svc.RegisterConnector(context.Background(), registerReq())
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestServiceRejectsCrossTenant(t *testing.T) {
	svc := newSvc(t)
	ctx := auth.WithTenant(context.Background(), "t-1")
	req := registerReq()
	req.Msg.TenantId = "t-2"
	_, err := svc.RegisterConnector(ctx, req)
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestServiceRejectsMissingSecret(t *testing.T) {
	svc := newSvc(t)
	ctx := auth.WithTenant(context.Background(), "t-1")
	req := registerReq()
	req.Msg.AuthSecret = ""
	_, err := svc.RegisterConnector(ctx, req)
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestServiceRejectsNonHTTPEndpoint(t *testing.T) {
	svc := newSvc(t)
	ctx := auth.WithTenant(context.Background(), "t-1")
	for _, ep := range []string{"file:///etc/passwd", "ftp://splunk", "splunk.example", "http://splunk.example:8088"} {
		req := registerReq()
		req.Msg.Endpoint = ep
		_, err := svc.RegisterConnector(ctx, req)
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("Endpoint=%q: expected InvalidArgument, got %v", ep, err)
		}
	}
}

func TestServiceRejectsDisallowedField(t *testing.T) {
	svc := newSvc(t)
	ctx := auth.WithTenant(context.Background(), "t-1")
	req := registerReq()
	req.Msg.FieldAllowList = []string{FieldRiskBits, "user_id"}
	_, err := svc.RegisterConnector(ctx, req)
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expected InvalidArgument for disallowed field, got %v", err)
	}
}
