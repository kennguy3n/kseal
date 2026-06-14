package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v3"
)

func TestParseOutputFormat(t *testing.T) {
	cases := map[string]struct {
		want    outputFormat
		wantErr bool
	}{
		"":       {outputTable, false},
		"table":  {outputTable, false},
		"json":   {outputJSON, false},
		"JSON":   {outputJSON, false},
		"yaml":   {outputYAML, false},
		"yml":    {outputYAML, false},
		" yaml ": {outputYAML, false},
		"xml":    {"", true},
	}
	for in, want := range cases {
		got, err := parseOutputFormat(in)
		if want.wantErr {
			if err == nil {
				t.Errorf("parseOutputFormat(%q) = %q, want error", in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseOutputFormat(%q) error: %v", in, err)
			continue
		}
		if got != want.want {
			t.Errorf("parseOutputFormat(%q) = %q, want %q", in, got, want.want)
		}
	}
}

// TestRenderYAMLMatchesJSON verifies the YAML projection carries the same
// fields/values as the JSON projection (YAML is a re-encoding of the documented
// JSON shape) and that it is emitted as readable block style, not flow style.
func TestRenderYAMLMatchesJSON(t *testing.T) {
	type sample struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Modules []string `json:"modules"`
		Active  bool     `json:"active"`
	}
	v := sample{ID: "app_1", Name: "Acme Wallet", Modules: []string{"rasp", "attest"}, Active: true}

	var yb bytes.Buffer
	if err := renderYAML(&yb, v); err != nil {
		t.Fatalf("renderYAML: %v", err)
	}
	// Block style: keys appear at the start of a line, not wrapped in braces.
	if strings.Contains(yb.String(), "{") || strings.Contains(yb.String(), "[") {
		t.Fatalf("yaml should be block style, got flow:\n%s", yb.String())
	}

	// Round-trip both encodings into maps and compare for semantic equality.
	jb, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON, fromYAML map[string]any
	if err := json.Unmarshal(jb, &fromJSON); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(yb.Bytes(), &fromYAML); err != nil {
		t.Fatalf("yaml is not parseable: %v\n%s", err, yb.String())
	}
	if fromYAML["id"] != fromJSON["id"] || fromYAML["name"] != fromJSON["name"] || fromYAML["active"] != fromJSON["active"] {
		t.Fatalf("yaml/json mismatch:\njson=%v\nyaml=%v", fromJSON, fromYAML)
	}
}

// TestAppListYAML exercises the full command path with --output yaml and checks
// the documented top-level "apps" key is present and parseable.
func TestAppListYAML(t *testing.T) {
	ts := newTestServer(t)
	if _, _, code := ts.run(t, nil, "--tenant", ts.TenantID,
		"app", "create", "--name", "Acme", "--platform", "android", "--package-id", "com.acme.app"); code != ExitOK {
		t.Fatalf("app create exit=%d", code)
	}

	out, _, code := ts.run(t, nil, "--tenant", ts.TenantID, "-o", "yaml", "app", "list")
	if code != ExitOK {
		t.Fatalf("app list yaml exit=%d out=%s", code, out)
	}
	var doc struct {
		Apps []map[string]any `yaml:"apps"`
	}
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("app list yaml not parseable: %v\n%s", err, out)
	}
	if len(doc.Apps) != 1 || doc.Apps[0]["name"] != "Acme" {
		t.Fatalf("unexpected yaml apps: %v", doc.Apps)
	}
}
