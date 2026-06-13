package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestTenantCreateAndGet_HappyPath(t *testing.T) {
	ts := newTestServer(t)

	out, _, code := ts.run(t, nil, "-o", "json", "tenant", "create", "--name", "Beta Corp", "--slug", "beta", "--tier", "growth")
	if code != ExitOK {
		t.Fatalf("create exit=%d out=%s", code, out)
	}
	var created tenantView
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("decode create: %v\n%s", err, out)
	}
	if created.Slug != "beta" || created.Name != "Beta Corp" || created.Tier != "growth" {
		t.Fatalf("unexpected tenant: %+v", created)
	}
	if created.ID == "" {
		t.Fatalf("expected server-assigned id")
	}

	// GetTenant is scoped to the principal's own tenant. The API key belongs to
	// the seeded tenant, so fetching it succeeds; fetching the just-created
	// foreign tenant must NOT (covered by TestTenantGet_CrossTenantDenied).
	getOut, _, code := ts.run(t, nil, "-o", "json", "tenant", "get", ts.TenantID)
	if code != ExitOK {
		t.Fatalf("get exit=%d out=%s", code, getOut)
	}
	var got tenantView
	if err := json.Unmarshal([]byte(getOut), &got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if got.ID != ts.TenantID {
		t.Fatalf("get returned different id: %s vs %s", got.ID, ts.TenantID)
	}
}

func TestTenantGet_CrossTenantDenied(t *testing.T) {
	ts := newTestServer(t)
	// Create a second tenant, then attempt to read it with the first tenant's
	// key. Strict tenant scoping on the server must reject this.
	out, _, code := ts.run(t, nil, "-o", "json", "tenant", "create", "--name", "Other", "--slug", "other")
	if code != ExitOK {
		t.Fatalf("create exit=%d out=%s", code, out)
	}
	var other tenantView
	if err := json.Unmarshal([]byte(out), &other); err != nil {
		t.Fatalf("decode: %v", err)
	}
	_, _, code = ts.run(t, nil, "tenant", "get", other.ID)
	if code == ExitOK {
		t.Fatalf("expected cross-tenant get to be denied, got exit 0")
	}
}

func TestTenantCreate_GoldenJSON(t *testing.T) {
	ts := newTestServer(t)
	out, _, code := ts.run(t, nil, "-o", "json", "tenant", "create", "--name", "Beta Corp", "--slug", "beta", "--tier", "growth")
	if code != ExitOK {
		t.Fatalf("exit=%d out=%s", code, out)
	}
	assertGoldenJSON(t, "tenant_create.json", out)
}

func TestTenantList_HappyPath(t *testing.T) {
	ts := newTestServer(t)
	// Seed tenant already exists ("Acme"); add one more.
	if _, _, code := ts.run(t, nil, "tenant", "create", "--name", "Beta", "--slug", "beta"); code != ExitOK {
		t.Fatalf("seed create exit=%d", code)
	}
	out, _, code := ts.run(t, nil, "-o", "json", "tenant", "list")
	if code != ExitOK {
		t.Fatalf("list exit=%d out=%s", code, out)
	}
	var env struct {
		Tenants []tenantView `json:"tenants"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("decode list: %v\n%s", err, out)
	}
	if len(env.Tenants) < 2 {
		t.Fatalf("expected >=2 tenants, got %d", len(env.Tenants))
	}
}

func TestAuthFailure_401(t *testing.T) {
	ts := newTestServer(t)
	// Override the API key env with an invalid value.
	out, errOut, code := ts.run(t, map[string]string{defaultAPIKeyEnv: "kseal_invalid.deadbeef"}, "tenant", "list")
	if code != ExitAuth {
		t.Fatalf("expected ExitAuth(%d), got %d (out=%q err=%q)", ExitAuth, code, out, errOut)
	}
	if !strings.Contains(errOut, "error:") {
		t.Fatalf("expected error banner, got %q", errOut)
	}
}

func TestMissingAPIKey_Errors(t *testing.T) {
	ts := newTestServer(t)
	// Unset the key entirely; resolution should fail before any network call.
	out, _, code := ts.run(t, map[string]string{defaultAPIKeyEnv: ""}, "tenant", "list")
	if code == ExitOK {
		t.Fatalf("expected failure with no API key, out=%s", out)
	}
}

func TestAppCreate_DryRun_NoMutation(t *testing.T) {
	ts := newTestServer(t)
	tenant := ts.TenantID

	// Dry-run create must not persist anything.
	out, errOut, code := ts.run(t, nil, "--tenant", tenant, "--dry-run", "-o", "json",
		"app", "create", "--name", "Wallet", "--platform", "android", "--package-id", "com.acme.wallet")
	if code != ExitOK {
		t.Fatalf("dry-run exit=%d out=%s", code, out)
	}
	if !strings.Contains(errOut, "dry-run") {
		t.Fatalf("expected dry-run notice on stderr, got %q", errOut)
	}
	apps, _, err := ts.Store.ListApps(context.Background(), tenant, anyPage())
	if err != nil {
		t.Fatalf("list apps: %v", err)
	}
	if len(apps) != 0 {
		t.Fatalf("dry-run created %d apps; want 0", len(apps))
	}

	// Real create persists.
	out, _, code = ts.run(t, nil, "--tenant", tenant, "-o", "json",
		"app", "create", "--name", "Wallet", "--platform", "android", "--package-id", "com.acme.wallet")
	if code != ExitOK {
		t.Fatalf("create exit=%d out=%s", code, out)
	}
	apps, _, err = ts.Store.ListApps(context.Background(), tenant, anyPage())
	if err != nil {
		t.Fatalf("list apps: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("expected 1 app after create, got %d", len(apps))
	}
}

func TestTenantScoping_RequiresTenant(t *testing.T) {
	ts := newTestServer(t)
	// No --tenant and no profile tenant: app commands must refuse with a usage
	// error (exit 2) before any RPC.
	_, errOut, code := ts.run(t, nil, "app", "list")
	if code != ExitUsage {
		t.Fatalf("expected ExitUsage(%d), got %d err=%q", ExitUsage, code, errOut)
	}
	if !strings.Contains(errOut, "tenant") {
		t.Fatalf("expected tenant-scope error, got %q", errOut)
	}
}
