package siem

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

func minimizedRecords(allow []string, evs ...Event) []map[string]any {
	set := allowSet(allow)
	out := make([]map[string]any, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.minimized(set))
	}
	return out
}

func TestRenderSplunk(t *testing.T) {
	c := &ksealv1.SiemConnector{
		Kind:             ksealv1.SiemKind_SIEM_KIND_SPLUNK_HEC,
		Format:           ksealv1.SiemPayloadFormat_SIEM_PAYLOAD_FORMAT_SPLUNK_HEC,
		Endpoint:         "https://splunk.example:8088",
		SplunkIndex:      "kseal",
		SplunkSourcetype: "kseal:trust",
	}
	rr, err := renderSplunk(c, []byte("hectoken"), minimizedRecords(DefaultAllowList(), sampleEvent()), "idem")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(rr.url, "/services/collector/event") {
		t.Fatalf("unexpected url: %s", rr.url)
	}
	if got := rr.headers["Authorization"]; got != "Splunk hectoken" {
		t.Fatalf("auth header = %q", got)
	}
	if rr.headers["X-Splunk-Request-Channel"] == "" {
		t.Fatal("missing splunk channel header")
	}
	// One JSON object per line, each with an "event" envelope.
	var env map[string]any
	if err := json.Unmarshal(firstLine(rr.body), &env); err != nil {
		t.Fatalf("body not json: %v", err)
	}
	if env["index"] != "kseal" || env["sourcetype"] != "kseal:trust" {
		t.Fatalf("routing metadata missing: %v", env)
	}
	ev, ok := env["event"].(map[string]any)
	if !ok {
		t.Fatalf("event object missing: %v", env)
	}
	if ev[FieldEventType] == nil || ev[FieldRiskBits] == nil {
		t.Fatalf("canonical fields missing: %v", ev)
	}
	assertNoPIIKeys(t, rr.body)
}

func TestRenderSentinel(t *testing.T) {
	c := &ksealv1.SiemConnector{
		Kind:                   ksealv1.SiemKind_SIEM_KIND_SENTINEL,
		Format:                 ksealv1.SiemPayloadFormat_SIEM_PAYLOAD_FORMAT_SENTINEL,
		Endpoint:               "https://dce.example",
		SentinelDcrImmutableId: "dcr-abc",
		SentinelStreamName:     "Custom-KsealTrust_CL",
	}
	rr, err := renderSentinel(c, []byte("bearer123"), minimizedRecords(DefaultAllowList(), sampleEvent()), "idem")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"dataCollectionRules/dcr-abc", "streams/Custom-KsealTrust_CL", "api-version="} {
		if !strings.Contains(rr.url, want) {
			t.Fatalf("url %q missing %q", rr.url, want)
		}
	}
	if got := rr.headers["Authorization"]; got != "Bearer bearer123" {
		t.Fatalf("auth header = %q", got)
	}
	var rows []map[string]any
	if err := json.Unmarshal(rr.body, &rows); err != nil {
		t.Fatalf("body not json array: %v", err)
	}
	if len(rows) != 1 || rows[0]["TimeGenerated"] == nil {
		t.Fatalf("expected one row with TimeGenerated: %v", rows)
	}
	assertNoPIIKeys(t, rr.body)
}

func TestRenderSentinelRequiresDCR(t *testing.T) {
	c := &ksealv1.SiemConnector{
		Kind:     ksealv1.SiemKind_SIEM_KIND_SENTINEL,
		Format:   ksealv1.SiemPayloadFormat_SIEM_PAYLOAD_FORMAT_SENTINEL,
		Endpoint: "https://dce.example",
	}
	if _, err := renderSentinel(c, []byte("x"), minimizedRecords(DefaultAllowList(), sampleEvent()), "i"); err == nil {
		t.Fatal("expected error when dcr/stream missing")
	}
}

func TestRenderElastic(t *testing.T) {
	c := &ksealv1.SiemConnector{
		Kind:         ksealv1.SiemKind_SIEM_KIND_ELASTIC,
		Format:       ksealv1.SiemPayloadFormat_SIEM_PAYLOAD_FORMAT_ECS,
		Endpoint:     "https://elastic.example",
		ElasticIndex: "kseal-trust-000001",
	}
	rr, err := renderElastic(c, []byte("apikeyXYZ"), minimizedRecords(DefaultAllowList(), sampleEvent()), "idem")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(rr.url, "/_bulk") {
		t.Fatalf("unexpected url: %s", rr.url)
	}
	if got := rr.headers["Authorization"]; got != "ApiKey apikeyXYZ" {
		t.Fatalf("auth header = %q", got)
	}
	// NDJSON: action line then doc line.
	sc := bufio.NewScanner(bytes.NewReader(rr.body))
	sc.Scan()
	var action map[string]any
	if err := json.Unmarshal(sc.Bytes(), &action); err != nil {
		t.Fatalf("action not json: %v", err)
	}
	if _, ok := action["create"]; !ok {
		t.Fatalf("missing bulk create action: %v", action)
	}
	sc.Scan()
	var doc map[string]any
	if err := json.Unmarshal(sc.Bytes(), &doc); err != nil {
		t.Fatalf("doc not json: %v", err)
	}
	labels, ok := doc["labels"].(map[string]any)
	if !ok || labels[FieldInstallKeyHash] == nil {
		t.Fatalf("ecs labels missing canonical fields: %v", doc)
	}
	if doc["@timestamp"] == nil {
		t.Fatal("ecs doc missing @timestamp")
	}
	assertNoPIIKeys(t, rr.body)
}

func firstLine(b []byte) []byte {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return b[:i]
	}
	return b
}

// assertNoPIIKeys parses every JSON object in body (supporting NDJSON) and
// recursively asserts no key contains a forbidden PII substring.
func assertNoPIIKeys(t *testing.T, body []byte) {
	t.Helper()
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var v any
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatalf("invalid json line: %v", err)
		}
		walkKeys(t, v)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
}

func walkKeys(t *testing.T, v any) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for k, sub := range x {
			lk := strings.ToLower(k)
			for _, bad := range forbiddenSubstrings {
				if strings.Contains(lk, bad) {
					t.Fatalf("PII key %q (matches %q) found in export payload", k, bad)
				}
			}
			walkKeys(t, sub)
		}
	case []any:
		for _, sub := range x {
			walkKeys(t, sub)
		}
	}
}
