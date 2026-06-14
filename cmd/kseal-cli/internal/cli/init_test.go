package cli

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// runLocal runs the CLI in-process with an isolated config and no server,
// returning stdout/stderr/exit. It is for local-only commands (init, doctor,
// man) that should work without a live endpoint.
func runLocal(t *testing.T, cfgPath string, env map[string]string, args ...string) (string, string, int) {
	t.Helper()
	t.Setenv(configEnvVar, cfgPath)
	for k, v := range env {
		t.Setenv(k, v)
	}
	var stdout, stderr strings.Builder
	code := Execute(context.Background(), args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func TestInitNonInteractiveWritesProfile(t *testing.T) {
	cfg := t.TempDir() + "/config.json"
	out, _, code := runLocal(t, cfg, nil, "init",
		"--name", "prod", "--endpoint", "https://api.example.com",
		"--tenant-id", "ten_123", "--non-interactive")
	if code != ExitOK {
		t.Fatalf("init exit=%d out=%s", code, out)
	}
	if !strings.Contains(out, "Next steps to get secure fast") {
		t.Fatalf("init should print the guided next steps, got:\n%s", out)
	}

	// Profile must be persisted and selected as current.
	loaded, err := LoadConfig(cfg)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.CurrentProfile != "prod" {
		t.Fatalf("current profile = %q, want prod", loaded.CurrentProfile)
	}
	prof := loaded.Profiles["prod"]
	if prof == nil || prof.Endpoint != "https://api.example.com" || prof.Tenant != "ten_123" {
		t.Fatalf("unexpected profile: %+v", prof)
	}
}

func TestInitJSONOutputAndNoSecret(t *testing.T) {
	cfg := t.TempDir() + "/config.json"
	t.Setenv(defaultAPIKeyEnv, "super-secret-key")
	out, _, code := runLocal(t, cfg, nil, "-o", "json", "init",
		"--name", "dev", "--endpoint", "https://api.example.com", "--tenant-id", "ten_x", "--non-interactive")
	if code != ExitOK {
		t.Fatalf("init json exit=%d", code)
	}
	if strings.Contains(out, "super-secret-key") {
		t.Fatalf("init must never print the API key value:\n%s", out)
	}
	var res initResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("init json not parseable: %v\n%s", err, out)
	}
	if res.Profile != "dev" || !res.APIKeySet || res.APIKeyEnv != defaultAPIKeyEnv {
		t.Fatalf("unexpected init result: %+v", res)
	}
	if len(res.NextSteps) == 0 {
		t.Fatalf("init result should carry next steps")
	}
	// With a key already present, the first step should not be "provide key".
	if strings.Contains(res.NextSteps[0].Title, "API key") {
		t.Fatalf("with key set, first step should be doctor/app, got %q", res.NextSteps[0].Title)
	}
}

func TestInitDryRunWritesNothing(t *testing.T) {
	cfg := t.TempDir() + "/config.json"
	_, errOut, code := runLocal(t, cfg, nil, "--dry-run", "init",
		"--name", "prod", "--endpoint", "https://api.example.com", "--non-interactive")
	if code != ExitOK {
		t.Fatalf("init dry-run exit=%d", code)
	}
	if !strings.Contains(errOut, "dry-run") {
		t.Fatalf("expected a dry-run notice, got %q", errOut)
	}
	if _, err := os.Stat(cfg); !os.IsNotExist(err) {
		t.Fatalf("dry-run must not write the config file (stat err=%v)", err)
	}
}

func TestInitIsLocalOnly(t *testing.T) {
	// init must work with no endpoint and no API key available.
	cfg := t.TempDir() + "/config.json"
	t.Setenv(defaultAPIKeyEnv, "")
	_, _, code := runLocal(t, cfg, nil, "init", "--non-interactive", "--endpoint", "https://api.example.com")
	if code != ExitOK {
		t.Fatalf("init should not require server/credentials, exit=%d", code)
	}
}
