package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestConfigProfileLifecycle(t *testing.T) {
	ts := newTestServer(t)
	cfgPath := t.TempDir() + "/config.json"
	env := map[string]string{configEnvVar: cfgPath}

	// Create a profile that references the API key by env var name (never value).
	out, _, code := ts.run(t, env, "config", "set-profile",
		"--name", "prod", "--endpoint", ts.URL, "--tenant-id", ts.TenantID,
		"--api-key-env", "KSEAL_API_KEY", "--use")
	if code != ExitOK {
		t.Fatalf("set-profile exit=%d out=%s", code, out)
	}

	// The persisted config must NOT contain the API key value anywhere.
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if strings.Contains(string(raw), ts.APIKey) {
		t.Fatalf("config file leaked API key value")
	}

	// current should report the profile.
	curOut, _, code := ts.run(t, env, "-o", "json", "config", "current")
	if code != ExitOK {
		t.Fatalf("current exit=%d", code)
	}
	var prof struct {
		Name      string `json:"name"`
		Endpoint  string `json:"endpoint"`
		Tenant    string `json:"tenant"`
		APIKeyEnv string `json:"api_key_env"`
	}
	if err := json.Unmarshal([]byte(curOut), &prof); err != nil {
		t.Fatalf("decode current: %v\n%s", err, curOut)
	}
	if prof.Name != "prod" || prof.Tenant != ts.TenantID {
		t.Fatalf("unexpected profile: %+v", prof)
	}

	// With the profile active, a tenant-scoped command needs no --tenant flag.
	listOut, _, code := ts.run(t, env, "-o", "json", "app", "list")
	if code != ExitOK {
		t.Fatalf("app list via profile exit=%d out=%s", code, listOut)
	}

	// Remove the profile.
	if _, _, code := ts.run(t, env, "config", "remove", "prod"); code != ExitOK {
		t.Fatalf("remove exit=%d", code)
	}
}

func TestConfigProfile_NeverEchoesSecret(t *testing.T) {
	ts := newTestServer(t)
	cfgPath := t.TempDir() + "/config.json"
	env := map[string]string{configEnvVar: cfgPath}

	if _, _, code := ts.run(t, env, "config", "set-profile", "--name", "prod", "--endpoint", ts.URL, "--use"); code != ExitOK {
		t.Fatalf("set-profile exit=%d", code)
	}
	out, _, code := ts.run(t, env, "-o", "json", "config", "list")
	if code != ExitOK {
		t.Fatalf("list exit=%d", code)
	}
	if strings.Contains(out, ts.APIKey) {
		t.Fatalf("config list leaked API key")
	}
}
