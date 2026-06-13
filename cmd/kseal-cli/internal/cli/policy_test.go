package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

const validPolicyJSON = `{
  "name": "baseline",
  "enforcement_mode": "block",
  "rules": {"rules": [], "signal_weights": {"0": 100}},
  "risk_thresholds": {"HIGH_RISK": 90, "CRITICAL": 130},
  "modules_enabled": ["rasp", "attestation"]
}`

const invalidPolicyJSON = `{
  "name": "",
  "enforcement_mode": "panic",
  "rules": {"rules": [], "signal_weights": {"99": 10}},
  "risk_thresholds": {"NONSENSE": 10}
}`

func TestPolicyValidate_Valid_Golden(t *testing.T) {
	ts := newTestServer(t)
	file := writeFile(t, "policy.json", validPolicyJSON)
	out, _, code := ts.run(t, nil, "-o", "json", "policy", "validate", "--file", file)
	if code != ExitOK {
		t.Fatalf("validate exit=%d out=%s", code, out)
	}
	assertGoldenJSON(t, "policy_validate_valid.json", out)
}

func TestPolicyValidate_Invalid_NonZeroExit(t *testing.T) {
	ts := newTestServer(t)
	file := writeFile(t, "bad.json", invalidPolicyJSON)
	out, _, code := ts.run(t, nil, "-o", "json", "policy", "validate", "--file", file)
	if code == ExitOK {
		t.Fatalf("expected non-zero exit for invalid policy")
	}
	var res struct {
		Valid    bool     `json:"valid"`
		Problems []string `json:"problems"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if res.Valid {
		t.Fatalf("expected valid=false")
	}
	if len(res.Problems) < 3 {
		t.Fatalf("expected multiple problems, got %v", res.Problems)
	}
}

// TestPolicyValidate_LocalOnly_NoCredentials verifies "policy validate" runs
// purely locally: it must succeed with no API key and no endpoint configured,
// so it is usable in CI lint stages without credentials.
func TestPolicyValidate_LocalOnly_NoCredentials(t *testing.T) {
	t.Setenv(defaultAPIKeyEnv, "")
	t.Setenv(configEnvVar, filepath.Join(t.TempDir(), "config.json"))
	file := writeFile(t, "policy.json", validPolicyJSON)

	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{"-o", "json", "policy", "validate", "--file", file}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("validate without credentials exit=%d stderr=%s", code, stderr.String())
	}
}

// TestPolicyValidate_Invalid_ExitUsage pins the exit-code contract: an invalid
// policy file is an input error and must map to ExitUsage (2), matching the
// documented contract and "policy author"'s invalid-file path.
func TestPolicyValidate_Invalid_ExitUsage(t *testing.T) {
	t.Setenv(defaultAPIKeyEnv, "")
	t.Setenv(configEnvVar, filepath.Join(t.TempDir(), "config.json"))
	file := writeFile(t, "bad.json", invalidPolicyJSON)

	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{"-o", "json", "policy", "validate", "--file", file}, &stdout, &stderr)
	if code != ExitUsage {
		t.Fatalf("invalid policy exit=%d, want ExitUsage(%d) stderr=%s", code, ExitUsage, stderr.String())
	}
}

func TestPolicyAuthorActivateGetActive(t *testing.T) {
	ts := newTestServer(t)
	file := writeFile(t, "policy.json", validPolicyJSON)

	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "policy", "author", "--file", file)
	if code != ExitOK {
		t.Fatalf("author exit=%d out=%s", code, out)
	}
	var created policyView
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("decode author: %v\n%s", err, out)
	}
	if created.ID == "" || created.IsActive {
		t.Fatalf("unexpected new policy: %+v", created)
	}

	actOut, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "policy", "activate", created.ID)
	if code != ExitOK {
		t.Fatalf("activate exit=%d out=%s", code, actOut)
	}
	var activated policyView
	if err := json.Unmarshal([]byte(actOut), &activated); err != nil {
		t.Fatalf("decode activate: %v", err)
	}
	if !activated.IsActive {
		t.Fatalf("policy should be active after activate")
	}

	getOut, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "policy", "get-active")
	if code != ExitOK {
		t.Fatalf("get-active exit=%d out=%s", code, getOut)
	}
	var active policyView
	if err := json.Unmarshal([]byte(getOut), &active); err != nil {
		t.Fatalf("decode get-active: %v", err)
	}
	if active.ID != created.ID {
		t.Fatalf("active policy id mismatch: %s vs %s", active.ID, created.ID)
	}
}

func TestPolicyAuthor_DryRun_NoMutation(t *testing.T) {
	ts := newTestServer(t)
	file := writeFile(t, "policy.json", validPolicyJSON)
	_, errOut, code := ts.run(t, nil, "--tenant", ts.TenantID, "--dry-run", "policy", "author", "--file", file)
	if code != ExitOK {
		t.Fatalf("dry-run exit=%d", code)
	}
	if errOut == "" {
		t.Fatalf("expected dry-run notice")
	}
	// List should show no policies.
	listOut, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "policy", "list")
	if code != ExitOK {
		t.Fatalf("list exit=%d", code)
	}
	var env struct {
		Policies []policyView `json:"policies"`
	}
	if err := json.Unmarshal([]byte(listOut), &env); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(env.Policies) != 0 {
		t.Fatalf("dry-run created %d policies; want 0", len(env.Policies))
	}
}

func TestPolicySimulate_Golden(t *testing.T) {
	ts := newTestServer(t)

	// Current active policy: observe mode => every decision is ALLOW.
	current := `{"name":"current","enforcement_mode":"observe","rules":{"rules":[]}}`
	curFile := writeFile(t, "current.json", current)
	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "policy", "author", "--file", curFile)
	if code != ExitOK {
		t.Fatalf("author current exit=%d out=%s", code, out)
	}
	var cur policyView
	if err := json.Unmarshal([]byte(out), &cur); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "policy", "activate", cur.ID); code != ExitOK {
		t.Fatalf("activate current exit=%d", code)
	}

	// Seed two events: one high-risk (bit0 -> score 100 -> HIGH_RISK), one clean.
	ts.seedEvents(t, "", 0b1, 0b0)

	// Candidate blocks high-risk.
	candFile := writeFile(t, "candidate.json", validPolicyJSON)
	simOut, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "json", "policy", "simulate", "--candidate-file", candFile)
	if code != ExitOK {
		t.Fatalf("simulate exit=%d out=%s", code, simOut)
	}
	assertGoldenJSON(t, "policy_simulate.json", simOut)
}
