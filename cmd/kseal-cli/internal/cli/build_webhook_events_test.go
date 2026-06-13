package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// createApp is a helper that registers an app and returns its id.
func createApp(t *testing.T, ts *testServer) string {
	t.Helper()
	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json",
		"app", "create", "--name", "Wallet", "--platform", "android", "--package-id", "com.acme.wallet")
	if code != ExitOK {
		t.Fatalf("create app exit=%d out=%s", code, out)
	}
	var a appView
	if err := json.Unmarshal([]byte(out), &a); err != nil {
		t.Fatalf("decode app: %v", err)
	}
	return a.ID
}

func TestBuildRegister_FromManifest(t *testing.T) {
	ts := newTestServer(t)
	appID := createApp(t, ts)

	manifest := `{
  "app_id": "` + appID + `",
  "build_hash": "sha256:abc123",
  "version_name": "1.2.3",
  "version_code": 42,
  "manifest": {"modules": ["rasp", "integrity"], "tool": "gradle-plugin@1.0"}
}`
	mf := writeFile(t, "build.json", manifest)

	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "build", "register", "--manifest-file", mf)
	if code != ExitOK {
		t.Fatalf("register exit=%d out=%s", code, out)
	}
	var b buildView
	if err := json.Unmarshal([]byte(out), &b); err != nil {
		t.Fatalf("decode build: %v\n%s", err, out)
	}
	if b.BuildHash != "sha256:abc123" || b.VersionName != "1.2.3" || b.VersionCode != 42 {
		t.Fatalf("unexpected build: %+v", b)
	}
	if !strings.Contains(b.Manifest, "gradle-plugin") {
		t.Fatalf("manifest provenance not stored: %q", b.Manifest)
	}

	// Verify it persisted via list.
	builds, _, err := ts.Store.ListBuilds(context.Background(), ts.TenantID, "", anyPage())
	if err != nil {
		t.Fatalf("list builds: %v", err)
	}
	if len(builds) != 1 {
		t.Fatalf("expected 1 build, got %d", len(builds))
	}
}

func TestBuildRegister_DryRun_NoMutation(t *testing.T) {
	ts := newTestServer(t)
	appID := createApp(t, ts)
	manifest := `{"app_id":"` + appID + `","build_hash":"sha256:zzz","version_name":"9.9.9"}`
	mf := writeFile(t, "build.json", manifest)

	_, errOut, code := ts.run(t, nil, "--tenant", ts.TenantID, "--dry-run", "build", "register", "--manifest-file", mf)
	if code != ExitOK {
		t.Fatalf("dry-run exit=%d err=%s", code, errOut)
	}
	builds, _, err := ts.Store.ListBuilds(context.Background(), ts.TenantID, "", anyPage())
	if err != nil {
		t.Fatalf("list builds: %v", err)
	}
	if len(builds) != 0 {
		t.Fatalf("dry-run created %d builds; want 0", len(builds))
	}
}

func TestBuildRegister_MissingRequired(t *testing.T) {
	ts := newTestServer(t)
	// Empty manifest and no flags -> usage error before any RPC.
	mf := writeFile(t, "empty.json", `{}`)
	_, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "build", "register", "--manifest-file", mf)
	if code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %d", code)
	}
}

func TestWebhookLifecycle(t *testing.T) {
	ts := newTestServer(t)

	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json",
		"webhook", "register", "--url", "https://hooks.acme.test/kseal", "--event-type", "ROOT_RISK", "--event-type", "DEBUGGER")
	if code != ExitOK {
		t.Fatalf("register exit=%d out=%s", code, out)
	}
	var w webhookView
	if err := json.Unmarshal([]byte(out), &w); err != nil {
		t.Fatalf("decode webhook: %v\n%s", err, out)
	}
	if w.URL != "https://hooks.acme.test/kseal" || len(w.EventTypes) != 2 {
		t.Fatalf("unexpected webhook: %+v", w)
	}

	listOut, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "webhook", "list")
	if code != ExitOK {
		t.Fatalf("list exit=%d", code)
	}
	var env struct {
		Webhooks []webhookView `json:"webhooks"`
	}
	if err := json.Unmarshal([]byte(listOut), &env); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(env.Webhooks) != 1 {
		t.Fatalf("expected 1 webhook, got %d", len(env.Webhooks))
	}

	delOut, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "webhook", "delete", w.ID)
	if code != ExitOK {
		t.Fatalf("delete exit=%d out=%s", code, delOut)
	}
	var del struct {
		Deleted bool `json:"deleted"`
	}
	if err := json.Unmarshal([]byte(delOut), &del); err != nil {
		t.Fatalf("decode delete: %v", err)
	}
	if !del.Deleted {
		t.Fatalf("expected deleted=true")
	}
}

func TestWebhookRegister_DryRun_NoMutation(t *testing.T) {
	ts := newTestServer(t)
	_, errOut, code := ts.run(t, nil, "--tenant", ts.TenantID, "--dry-run",
		"webhook", "register", "--url", "https://hooks.acme.test/x")
	if code != ExitOK {
		t.Fatalf("dry-run exit=%d err=%s", code, errOut)
	}
	listOut, _, _ := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "webhook", "list")
	var env struct {
		Webhooks []webhookView `json:"webhooks"`
	}
	_ = json.Unmarshal([]byte(listOut), &env)
	if len(env.Webhooks) != 0 {
		t.Fatalf("dry-run created %d webhooks; want 0", len(env.Webhooks))
	}
}

func TestEventsQuery_Golden(t *testing.T) {
	ts := newTestServer(t)
	ts.seedEvents(t, "", 0b1, 0b0)
	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "events", "query")
	if code != ExitOK {
		t.Fatalf("query exit=%d out=%s", code, out)
	}
	assertGoldenJSON(t, "events_query.json", out)
}

func TestEventsQuery_FilterByRiskLevel(t *testing.T) {
	ts := newTestServer(t)
	ts.seedEvents(t, "", 0b1, 0b0)
	// All seeded events are LOW_RISK; filtering for CRITICAL yields none.
	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "events", "query", "--risk-level", "CRITICAL")
	if code != ExitOK {
		t.Fatalf("query exit=%d out=%s", code, out)
	}
	var env struct {
		Events []eventView `json:"events"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(env.Events) != 0 {
		t.Fatalf("expected 0 CRITICAL events, got %d", len(env.Events))
	}
}

func TestEventsTail_EmitsSeededThenStops(t *testing.T) {
	ts := newTestServer(t)
	ts.seedEvents(t, "", 0b1, 0b0)

	var out, errOut bytes.Buffer
	c := ts.newCLI(&out, &errOut, outputJSON)

	// Allow one poll to complete, then let the context deadline stop the tail.
	// The deadline is generous so the assertion is timing-independent (e.g.
	// under -race), since tail only emits on its first poll here.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := c.tailEvents(ctx, ts.TenantID, &eventFilterFlags{}, 100, 50*time.Millisecond); err != nil {
		t.Fatalf("tailEvents: %v", err)
	}
	if !strings.Contains(out.String(), "evt-") {
		t.Fatalf("expected seeded events in tail output, got %q", out.String())
	}
}
