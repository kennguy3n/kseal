package cli

import (
	"strings"
	"testing"
)

// TestEnvPrecedenceTenant verifies the flag > env > profile precedence for the
// tenant scope: $KSEAL_TENANT is used when no --tenant flag is given, and the
// flag overrides the env.
func TestEnvPrecedenceTenant(t *testing.T) {
	ts := newTestServer(t)

	// No --tenant flag: the env var supplies the scope.
	out, _, code := ts.run(t, map[string]string{tenantEnvVar: ts.TenantID}, "-o", "json", "app", "list")
	if code != ExitOK {
		t.Fatalf("app list via $%s exit=%d out=%s", tenantEnvVar, code, out)
	}

	// A bogus env tenant with an explicit --tenant flag: the flag wins, so the
	// command still succeeds against the real tenant.
	out, _, code = ts.run(t, map[string]string{tenantEnvVar: "ten_wrong"},
		"--tenant", ts.TenantID, "-o", "json", "app", "list")
	if code != ExitOK {
		t.Fatalf("--tenant should override $%s, exit=%d out=%s", tenantEnvVar, code, out)
	}
}

// TestEnvPrecedenceOutput verifies $KSEAL_OUTPUT selects the format and the
// --output flag overrides it.
func TestEnvPrecedenceOutput(t *testing.T) {
	ts := newTestServer(t)

	out, _, code := ts.run(t, map[string]string{outputEnvVar: "json"}, "--tenant", ts.TenantID, "app", "list")
	if code != ExitOK {
		t.Fatalf("app list exit=%d", code)
	}
	if !strings.Contains(out, "\"apps\"") {
		t.Fatalf("$%s=json should produce JSON, got:\n%s", outputEnvVar, out)
	}

	// Flag overrides env: table output has no JSON braces.
	out, _, code = ts.run(t, map[string]string{outputEnvVar: "json"}, "--tenant", ts.TenantID, "-o", "table", "app", "list")
	if code != ExitOK {
		t.Fatalf("app list exit=%d", code)
	}
	if strings.Contains(out, "\"apps\"") {
		t.Fatalf("--output table should override $%s=json, got:\n%s", outputEnvVar, out)
	}
}
