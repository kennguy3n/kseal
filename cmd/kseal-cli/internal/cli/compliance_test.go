package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
