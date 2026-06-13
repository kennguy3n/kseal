package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/data-plane/ingest"
	"github.com/kennguy3n/kseal/server/data-plane/query"
	"github.com/kennguy3n/kseal/server/data-plane/webhook"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
	"github.com/kennguy3n/kseal/server/shared/middleware"
	"github.com/kennguy3n/kseal/server/shared/telemetry"
	"github.com/rs/zerolog"
)

// testLogger returns a no-op logger so test output stays clean.
func testLogger() zerolog.Logger { return zerolog.Nop() }

// testServer is an in-process kseal Connect server backed by the real service
// handlers and the in-memory store, fronted by the real interceptor chain
// (including API-key auth). It mirrors server/cmd/kseal-server/main.go closely
// enough that CLI commands exercise the genuine request path.
type testServer struct {
	URL       string
	APIKey    string
	TenantID  string
	Store     *registry.MemStore
	Analytics *ingest.InMemoryAnalyticsStore
}

// newTestServer builds the harness, seeding one tenant + API key so control
// -plane calls authenticate. t.Cleanup stops the server.
func newTestServer(t *testing.T) *testServer {
	t.Helper()
	ctx := context.Background()

	store := registry.NewMemStore()
	tenant, err := store.CreateTenant(ctx, registry.CreateTenantInput{Name: "Acme", Slug: "acme", Tier: "growth"})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	apiKey, _, err := store.CreateAPIKey(ctx, tenant.Id, "cli-test", []string{"admin"})
	if err != nil {
		t.Fatalf("seed api key: %v", err)
	}

	analytics := ingest.NewInMemoryAnalyticsStore()

	registrySvc := registry.NewService(store)
	webhookSvc := webhook.NewService(store)
	querySvc := query.NewService(store, analytics)

	tel, err := telemetry.Setup("kseal-cli-test", "test")
	if err != nil {
		t.Fatalf("telemetry setup: %v", err)
	}
	t.Cleanup(func() { _ = tel.Shutdown(context.Background()) })

	ic := &middleware.Interceptors{
		Logger:      testLogger(),
		Metrics:     tel.Metrics,
		Tracer:      *tel,
		Validator:   store,
		RequireAuth: requireAuthProcedures(),
	}
	opts := ic.Chain()

	mux := http.NewServeMux()
	mux.Handle(ksealv1connect.NewRegistryServiceHandler(registrySvc, opts))
	mux.Handle(ksealv1connect.NewWebhookServiceHandler(webhookSvc, opts))
	mux.Handle(ksealv1connect.NewQueryServiceHandler(querySvc, opts))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &testServer{
		URL: srv.URL, APIKey: apiKey, TenantID: tenant.Id,
		Store: store, Analytics: analytics,
	}
}

// requireAuthProcedures mirrors the server's controlPlaneProcedures set.
func requireAuthProcedures() map[string]bool {
	return map[string]bool{
		ksealv1connect.RegistryServiceCreateTenantProcedure:            true,
		ksealv1connect.RegistryServiceGetTenantProcedure:               true,
		ksealv1connect.RegistryServiceListTenantsProcedure:             true,
		ksealv1connect.RegistryServiceUpdateTenantProcedure:            true,
		ksealv1connect.RegistryServiceCreateAppProcedure:               true,
		ksealv1connect.RegistryServiceGetAppProcedure:                  true,
		ksealv1connect.RegistryServiceListAppsProcedure:                true,
		ksealv1connect.RegistryServiceCreateBuildProcedure:             true,
		ksealv1connect.RegistryServiceGetBuildProcedure:                true,
		ksealv1connect.RegistryServiceListBuildsProcedure:              true,
		ksealv1connect.RegistryServiceCreatePolicyProcedure:            true,
		ksealv1connect.RegistryServiceGetActivePolicyProcedure:         true,
		ksealv1connect.RegistryServiceListPoliciesProcedure:            true,
		ksealv1connect.RegistryServiceActivatePolicyProcedure:          true,
		ksealv1connect.RegistryServiceCreateProtectionProfileProcedure: true,
		ksealv1connect.RegistryServiceListProtectionProfilesProcedure:  true,
		ksealv1connect.WebhookServiceRegisterWebhookProcedure:          true,
		ksealv1connect.WebhookServiceListWebhooksProcedure:             true,
		ksealv1connect.WebhookServiceDeleteWebhookProcedure:            true,
		ksealv1connect.QueryServiceListEventsProcedure:                 true,
		ksealv1connect.QueryServiceGetTenantOverviewProcedure:          true,
		ksealv1connect.QueryServiceGetTrustSessionStatsProcedure:       true,
	}
}

// seedEvents writes risk events into the analytics store for events/simulate
// tests.
func (ts *testServer) seedEvents(t *testing.T, appID string, riskBits ...uint64) {
	t.Helper()
	events := make([]ingest.StoredEvent, 0, len(riskBits))
	for i, bits := range riskBits {
		events = append(events, ingest.StoredEvent{
			ID:         idForIndex(i),
			TenantID:   ts.TenantID,
			AppID:      appID,
			EventType:  ksealv1.EventType_EVENT_TYPE_POLICY_DECISION,
			RiskLevel:  ksealv1.TrustLevel_TRUST_LEVEL_LOW_RISK,
			RiskBits:   bits,
			TimeBucket: int64(1000 + i),
			ReceivedAt: int64(1000 + i),
		})
	}
	if err := ts.Analytics.Write(context.Background(), events); err != nil {
		t.Fatalf("seed events: %v", err)
	}
}

func idForIndex(i int) string {
	return "evt-" + string(rune('a'+i))
}

// anyPage returns a zero-value page for direct store assertions in tests.
func anyPage() registry.Page { return registry.Page{} }

// newCLI builds a *CLI wired to the test server for direct method tests (e.g.
// tailEvents) that can't go through the blocking Execute path.
func (ts *testServer) newCLI(out, errOut *bytes.Buffer, format outputFormat) *CLI {
	return &CLI{
		endpoint: ts.URL,
		apiKey:   ts.APIKey,
		output:   format,
		out:      out,
		errOut:   errOut,
	}
}

// run invokes the CLI in-process against the test server with the given args,
// returning stdout, stderr, and the exit code. Auth and endpoint are injected
// via flags so each test is hermetic.
func (ts *testServer) run(t *testing.T, extraEnv map[string]string, args ...string) (string, string, int) {
	t.Helper()
	t.Setenv(defaultAPIKeyEnv, ts.APIKey)
	// Isolate config to a temp path so tests never touch a real config file.
	t.Setenv(configEnvVar, t.TempDir()+"/config.json")
	for k, v := range extraEnv {
		t.Setenv(k, v)
	}
	full := append([]string{"--endpoint", ts.URL}, args...)
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), full, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}
