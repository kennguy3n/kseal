package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// statusOf returns the status recorded for the named check, or "" if absent.
func statusOf(r doctorReport, name string) checkStatus {
	for _, ch := range r.Checks {
		if ch.Name == name {
			return ch.Status
		}
	}
	return ""
}

func decodeDoctor(t *testing.T, out string) doctorReport {
	t.Helper()
	var r doctorReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("doctor json not parseable: %v\n%s", err, out)
	}
	return r
}

// TestDoctorFreshTenant: connected + authed, but no app/policy/build yet. These
// are warnings (setup gaps), so the command still exits 0.
func TestDoctorFreshTenant(t *testing.T) {
	ts := newTestServer(t)
	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "doctor")
	if code != ExitOK {
		t.Fatalf("doctor exit=%d out=%s", code, out)
	}
	r := decodeDoctor(t, out)
	if statusOf(r, "configuration") != statusPass ||
		statusOf(r, "credentials") != statusPass ||
		statusOf(r, "connectivity") != statusPass ||
		statusOf(r, "tenant-scope") != statusPass {
		t.Fatalf("expected core checks to pass: %+v", r.Checks)
	}
	if statusOf(r, "app-registration") != statusWarn {
		t.Fatalf("expected app-registration warning on a fresh tenant: %+v", r.Checks)
	}
	if !r.Healthy {
		t.Fatalf("fresh tenant with only warnings should be healthy (exit 0)")
	}
}

// TestDoctorStrictFailsOnWarn: --strict promotes setup gaps to failures.
func TestDoctorStrictFailsOnWarn(t *testing.T) {
	ts := newTestServer(t)
	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "doctor", "--strict")
	if code != ExitBlocked {
		t.Fatalf("doctor --strict on a fresh tenant should exit %d, got %d\n%s", ExitBlocked, code, out)
	}
}

// TestDoctorProgressesWithSetup: once an app, an active policy, and a build are
// in place, those checks pass.
func TestDoctorProgressesWithSetup(t *testing.T) {
	ts := newTestServer(t)
	appID := createAppForDoctor(t, ts)

	// Apply + activate a curated pack so the app has an active policy.
	if _, errOut, code := ts.run(t, nil, "--tenant", ts.TenantID,
		"policy", "pack", "apply", "fintech", "--app-id", appID, "--activate"); code != ExitOK {
		t.Fatalf("pack apply exit=%d err=%s", code, errOut)
	}
	registerBuildForDoctor(t, ts, appID)

	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "doctor")
	if code != ExitOK {
		t.Fatalf("doctor exit=%d out=%s", code, out)
	}
	r := decodeDoctor(t, out)
	if statusOf(r, "app-registration") != statusPass {
		t.Fatalf("app-registration should pass: %+v", r.Checks)
	}
	if statusOf(r, "protection-policy") != statusPass {
		t.Fatalf("protection-policy should pass after applying a pack: %+v", r.Checks)
	}
	if statusOf(r, "build-proof") != statusPass {
		t.Fatalf("build-proof should pass after registering a build: %+v", r.Checks)
	}
	if !r.Healthy {
		t.Fatalf("fully set up tenant should be healthy: %+v", r.Checks)
	}
}

// TestDoctorBadCredentials: a rejected key fails connectivity with ExitAuth and
// still prints a full report.
func TestDoctorBadCredentials(t *testing.T) {
	ts := newTestServer(t)
	out, _, code := ts.run(t, map[string]string{defaultAPIKeyEnv: "not-a-real-key"},
		"--tenant", ts.TenantID, "-o", "json", "doctor")
	if code != ExitAuth {
		t.Fatalf("doctor with bad key should exit %d, got %d", ExitAuth, code)
	}
	r := decodeDoctor(t, out)
	if statusOf(r, "connectivity") != statusFail {
		t.Fatalf("connectivity should fail with a bad key: %+v", r.Checks)
	}
	// The report must never carry a check name twice (regression: a failed
	// connectivity check used to also be appended as a skipped one).
	seen := map[string]bool{}
	for _, ch := range r.Checks {
		if seen[ch.Name] {
			t.Fatalf("duplicate check %q in report: %+v", ch.Name, r.Checks)
		}
		seen[ch.Name] = true
	}
}

// TestDoctorMissingKey: no key at all fails the credentials check (ExitAuth)
// before any server call, and never prints a secret.
func TestDoctorMissingKey(t *testing.T) {
	ts := newTestServer(t)
	out, errOut, code := ts.run(t, map[string]string{defaultAPIKeyEnv: ""},
		"--tenant", ts.TenantID, "doctor")
	if code != ExitAuth {
		t.Fatalf("doctor without a key should exit %d, got %d", ExitAuth, code)
	}
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "credentials") {
		t.Fatalf("expected a failing credentials check in the report:\n%s", out)
	}
	if !strings.Contains(errOut, "hint:") {
		t.Fatalf("expected an actionable hint on stderr:\n%s", errOut)
	}
}

func registerBuildForDoctor(t *testing.T, ts *testServer, appID string) {
	t.Helper()
	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID,
		"build", "register", "--app-id", appID,
		"--build-hash", "sha256:deadbeef", "--version-name", "1.0.0", "--version-code", "1")
	if code != ExitOK {
		t.Fatalf("build register exit=%d out=%s", code, out)
	}
}

func createAppForDoctor(t *testing.T, ts *testServer) string {
	t.Helper()
	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json",
		"app", "create", "--name", "Wallet", "--platform", "android", "--package-id", "com.acme.wallet")
	if code != ExitOK {
		t.Fatalf("app create exit=%d out=%s", code, out)
	}
	var app struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &app); err != nil {
		t.Fatalf("decode app: %v\n%s", err, out)
	}
	return app.ID
}
