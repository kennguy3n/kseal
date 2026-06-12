package auth

import (
	"context"
	"testing"
)

func TestAPIKeyLifecycle(t *testing.T) {
	gen, err := GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	keyID, secret, err := ParseAPIKey(gen.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if keyID != gen.KeyID {
		t.Fatalf("parsed key id %q != %q", keyID, gen.KeyID)
	}
	ok, err := VerifySecret(secret, gen.Hash)
	if err != nil || !ok {
		t.Fatalf("verify failed: ok=%v err=%v", ok, err)
	}
	bad, _ := VerifySecret("wrong", gen.Hash)
	if bad {
		t.Fatal("wrong secret verified")
	}
}

func TestParseAPIKeyRejectsMalformed(t *testing.T) {
	for _, k := range []string{"", "nope", "ksk_only", "x_y_z"} {
		if _, _, err := ParseAPIKey(k); err == nil {
			t.Errorf("expected error parsing %q", k)
		}
	}
}

func TestTenantContext(t *testing.T) {
	ctx := WithTenant(context.Background(), "t1")
	got, err := TenantFrom(ctx)
	if err != nil || got != "t1" {
		t.Fatalf("tenant from ctx: %q err=%v", got, err)
	}
	if err := EnforceTenant(ctx, "t1"); err != nil {
		t.Fatal("same tenant should be allowed")
	}
	if err := EnforceTenant(ctx, "t2"); err == nil {
		t.Fatal("cross tenant must be denied")
	}
}

func TestPrincipalScopes(t *testing.T) {
	p := &Principal{TenantID: "t1", Scopes: []string{"read"}}
	if !p.HasScope("read") {
		t.Fatal("expected read scope")
	}
	if p.HasScope("admin") {
		t.Fatal("unexpected admin scope")
	}
	ctx := WithPrincipal(context.Background(), p)
	if got, ok := PrincipalFrom(ctx); !ok || got.TenantID != "t1" {
		t.Fatal("principal round trip failed")
	}
}
