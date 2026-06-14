package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
)

// fakeComplianceService implements the canonical ComplianceService read RPCs
// the CLI consumes; all other procedures stay Unimplemented.
type fakeComplianceService struct {
	ksealv1connect.UnimplementedComplianceServiceHandler
}

func (fakeComplianceService) ListAuditEvents(_ context.Context, req *connect.Request[ksealv1.ListAuditEventsRequest]) (*connect.Response[ksealv1.ListAuditEventsResponse], error) {
	return connect.NewResponse(&ksealv1.ListAuditEventsResponse{
		Events: []*ksealv1.AuditEvent{{
			Seq: 2, CreatedAt: 1_700_000_000_002, ActorKeyId: "key-ops",
			Action: req.Msg.GetAction(), ResourceType: "policy", ResourceId: "pol-1",
			Hash: "hash2", PrevHash: "hash1", Metadata: map[string]string{"to": "BLOCK"},
		}},
	}), nil
}

func (fakeComplianceService) GetKillSwitchState(context.Context, *connect.Request[ksealv1.GetKillSwitchStateRequest]) (*connect.Response[ksealv1.GetKillSwitchStateResponse], error) {
	return connect.NewResponse(&ksealv1.GetKillSwitchStateResponse{
		EffectiveCommand: ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE,
		Active: &ksealv1.SignedKillSwitch{
			Command: ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE,
			Version: 7, KeyId: "ks-key-1", Reason: "INC-42",
		},
	}), nil
}

func (fakeComplianceService) GetDataProcessingRegistry(context.Context, *connect.Request[ksealv1.GetDataProcessingRegistryRequest]) (*connect.Response[ksealv1.GetDataProcessingRegistryResponse], error) {
	return connect.NewResponse(&ksealv1.GetDataProcessingRegistryResponse{
		Records: []*ksealv1.DataProcessingRecord{{
			AppId: "app-1", Purpose: "Runtime risk scoring",
			DataCategories: []string{"device_integrity", "os_version"},
			LegalBasis:     "Legitimate interest", RetentionDays: 30,
			ThirdPartySharing: false,
		}},
	}), nil
}

// complianceServer mounts the canonical ComplianceService fake and returns its
// base URL for CLI --endpoint wiring.
func complianceServer(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(ksealv1connect.NewComplianceServiceHandler(fakeComplianceService{}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// localRun executes the CLI for an offline (local-only) command: it isolates
// the config path and runs from the given working directory so generators that
// locate repo files (e.g. the MASVS catalog) resolve deterministically.
func localRun(t *testing.T, workdir string, args ...string) (string, string, int) {
	t.Helper()
	t.Setenv(configEnvVar, filepath.Join(t.TempDir(), "config.json"))
	if workdir != "" {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir(workdir); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chdir(cwd) })
	}
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func TestCompliancePrivacyManifest_Local(t *testing.T) {
	out, _, code := localRun(t, "", "compliance", "privacy-manifest")
	if code != ExitOK {
		t.Fatalf("exit=%d out=%s", code, out)
	}
	for _, want := range []string{"NSPrivacyTracking", "NSPrivacyAccessedAPITypes", "<plist version=\"1.0\">"} {
		if !strings.Contains(out, want) {
			t.Errorf("plist missing %q", want)
		}
	}

	jsonOut, _, code := localRun(t, "", "compliance", "privacy-manifest", "--format", "json")
	if code != ExitOK {
		t.Fatalf("json exit=%d", code)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(jsonOut), &m); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, jsonOut)
	}
	if _, ok := m["collected_data_types"]; !ok {
		t.Errorf("summary missing collected_data_types: %v", m)
	}
}

func TestComplianceDataSafety_Local(t *testing.T) {
	md, _, code := localRun(t, "", "compliance", "data-safety")
	if code != ExitOK {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(md, "Google Play Data Safety") {
		t.Errorf("markdown missing heading:\n%s", md)
	}

	jsonOut, _, code := localRun(t, "", "compliance", "data-safety", "--format", "json")
	if code != ExitOK {
		t.Fatalf("json exit=%d", code)
	}
	var form map[string]any
	if err := json.Unmarshal([]byte(jsonOut), &form); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if _, ok := form["data_types"]; !ok {
		t.Errorf("form missing data_types: %v", form)
	}
}

func TestComplianceMASTG_LocalGatingExit(t *testing.T) {
	catalog := filepath.Join("testdata", "mastg_catalog.md")
	// No evidence: fail-safe, exits 0.
	_, _, code := localRun(t, "", "compliance", "mastg", "--catalog", catalog)
	if code != ExitOK {
		t.Fatalf("no-evidence exit=%d, want 0", code)
	}

	// A failing assertion blocks the release -> ExitBlocked.
	ev := filepath.Join(t.TempDir(), "ev.json")
	writeFileJSON(t, ev, map[string]any{
		"release": "1.0",
		"results": []map[string]any{
			{"match": "No sensitive data in logs", "status": "fail", "note": "leak"},
		},
	})
	out, _, code := localRun(t, "", "compliance", "mastg", "--catalog", catalog, "--evidence", ev, "--format", "json")
	if code != ExitBlocked {
		t.Fatalf("blocked exit=%d, want %d\n%s", code, ExitBlocked, out)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
}

func TestComplianceMASTG_BadFormat(t *testing.T) {
	_, _, code := localRun(t, "", "compliance", "mastg", "--catalog", filepath.Join("testdata", "mastg_catalog.md"), "--format", "yaml")
	if code != ExitUsage {
		t.Fatalf("bad-format exit=%d, want %d", code, ExitUsage)
	}
}

func TestComplianceServerCapabilityUnavailable(t *testing.T) {
	ts := newTestServer(t)
	// The test server registers no ComplianceService handler, so the RPC is
	// Unimplemented and the command must degrade gracefully (exit 0).
	for _, sub := range []string{"audit-trail", "kill-switch", "data-processing-registry"} {
		out, errOut, code := ts.run(t, nil, "--tenant", ts.TenantID, "compliance", sub)
		if code != ExitOK {
			t.Errorf("%s exit=%d, want 0 (graceful)\nstderr=%s", sub, code, errOut)
		}
		if !strings.Contains(errOut, "server capability unavailable") {
			t.Errorf("%s missing unavailable notice, stderr=%s out=%s", sub, errOut, out)
		}
		// Table mode still emits a machine-parseable one-liner on stdout so
		// scripts get consistent output across formats.
		if !strings.Contains(out, "AVAILABLE") || !strings.Contains(out, "false") {
			t.Errorf("%s table mode should emit an availability row, out=%q", sub, out)
		}
	}

	// JSON mode reports available:false so scripts can detect it.
	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "compliance", "kill-switch")
	if code != ExitOK {
		t.Fatalf("json exit=%d", code)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out)
	}
	if res["available"] != false {
		t.Errorf("expected available:false, got %v", res)
	}
}

func TestComplianceReadsCanonicalService(t *testing.T) {
	endpoint := complianceServer(t)
	t.Setenv(defaultAPIKeyEnv, "k")
	t.Setenv(configEnvVar, t.TempDir()+"/config.json")

	run := func(args ...string) map[string]any {
		t.Helper()
		var out, errOut bytes.Buffer
		full := append([]string{"--endpoint", endpoint, "--tenant", "t-1", "-o", "json"}, args...)
		if code := Execute(context.Background(), full, &out, &errOut); code != ExitOK {
			t.Fatalf("args=%v exit=%d stderr=%s", args, code, errOut.String())
		}
		var m map[string]any
		if err := json.Unmarshal(out.Bytes(), &m); err != nil {
			t.Fatalf("invalid json for %v: %v\n%s", args, err, out.String())
		}
		return m
	}

	audit := run("compliance", "audit-trail", "--action", "policy.activate")
	if audit["available"] != true {
		t.Fatalf("audit not available: %v", audit)
	}
	entries, ok := audit["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %v", audit["entries"])
	}
	e0 := entries[0].(map[string]any)
	if e0["seq"].(float64) != 2 || e0["actor_key_id"] != "key-ops" || e0["action"] != "policy.activate" {
		t.Errorf("canonical audit fields not mapped: %v", e0)
	}

	ks := run("compliance", "kill-switch", "--app", "app-1")
	if ks["effective_command"] != "disable" || ks["enforcing"] != false {
		t.Errorf("kill-switch canonical mapping wrong: %v", ks)
	}

	dpr := run("compliance", "data-processing-registry")
	recs := dpr["records"].([]any)
	if len(recs) != 1 {
		t.Fatalf("expected 1 dpr record, got %v", dpr["records"])
	}
	r0 := recs[0].(map[string]any)
	if r0["app_id"] != "app-1" || r0["retention_days"].(float64) != 30 || r0["third_party_sharing"] != false {
		t.Errorf("dpr canonical fields not mapped: %v", r0)
	}
}

func TestComplianceRequiresTenant(t *testing.T) {
	ts := newTestServer(t)
	_, _, code := ts.run(t, nil, "compliance", "audit-trail")
	if code != ExitUsage {
		t.Fatalf("missing-tenant exit=%d, want %d", code, ExitUsage)
	}
}

func writeFileJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
