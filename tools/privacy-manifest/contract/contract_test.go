package contract

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"testing"
)

func TestCanonicalParsesAndValidates(t *testing.T) {
	c, err := Canonical()
	if err != nil {
		t.Fatalf("canonical contract did not load: %v", err)
	}
	if c.Schema != "kseal.data-contract/v1" {
		t.Errorf("schema = %q", c.Schema)
	}
	if !c.Transport.EncryptedInTransit {
		t.Error("kseal telemetry must be declared encrypted in transit")
	}
	if c.DataSharing.SharedWithThirdParties || c.DataSharing.UsedForTracking || c.DataSharing.Sold {
		t.Error("contract must declare no third-party sharing/selling/tracking")
	}
	if len(c.NotCollected) == 0 {
		t.Error("contract must enumerate the default-exclusions list")
	}
}

func TestPersonalDataItemsExcludeArtifactMetadata(t *testing.T) {
	c, err := Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range c.PersonalDataItems() {
		if it.ID == "app_build_identity" || it.ID == "coarse_event_time" {
			t.Errorf("%q must not be classified as personal data", it.ID)
		}
		if it.IOS == nil && it.Android == nil {
			t.Errorf("personal-data item %q is missing a store mapping", it.ID)
		}
	}
}

// TestContractMatchesTelemetryProto pins the contract to the wire schema: every
// field of kseal.v1.TelemetryEvent must be mapped by exactly one collected
// item, and no item may reference a field that does not exist on the message.
// This makes silent drift between the data contract and the SDK's actual
// telemetry impossible.
func TestContractMatchesTelemetryProto(t *testing.T) {
	protoFields := telemetryEventFields(t)
	c, err := Canonical()
	if err != nil {
		t.Fatal(err)
	}
	got := c.ProtoFields()
	sort.Strings(protoFields)
	if !reflect.DeepEqual(got, protoFields) {
		t.Fatalf("contract proto fields drift from telemetry.proto\n contract: %v\n    proto: %v", got, protoFields)
	}
}

// telemetryEventFields extracts the field names of the TelemetryEvent message
// from the checked-in proto. The repo root is three levels up from this package.
func telemetryEventFields(t *testing.T) []string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "proto", "kseal", "v1", "telemetry.proto")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read telemetry.proto (%s): %v", path, err)
	}
	msg := regexp.MustCompile(`(?s)message\s+TelemetryEvent\s*\{(.*?)\}`).FindSubmatch(data)
	if msg == nil {
		t.Fatal("TelemetryEvent message not found in telemetry.proto")
	}
	// Match scalar/enum/message fields: optional? Type name = N;
	field := regexp.MustCompile(`(?m)^\s*(?:optional\s+)?[A-Za-z0-9_.]+\s+([a-z][A-Za-z0-9_]*)\s*=\s*\d+\s*;`)
	var names []string
	for _, m := range field.FindAllSubmatch(msg[1], -1) {
		names = append(names, string(m[1]))
	}
	if len(names) == 0 {
		t.Fatal("no fields parsed from TelemetryEvent")
	}
	return names
}

func TestLoadFromFileRoundTrips(t *testing.T) {
	c, err := Canonical()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(p, canonicalJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(p)
	if err != nil {
		t.Fatalf("load from file: %v", err)
	}
	if len(loaded.Collected) != len(c.Collected) {
		t.Errorf("round-trip item count = %d, want %d", len(loaded.Collected), len(c.Collected))
	}
}

func TestValidateRejectsBrokenContract(t *testing.T) {
	bad := []byte(`{"schema":"x","sdk":"kseal","transport":{},"data_sharing":{},"collected":[{"id":"a","name":"A","proto_fields":["f"],"personal_data":true}],"not_collected":[],"ios_required_reason_apis":[]}`)
	if _, err := parse(bad, "test"); err == nil {
		t.Fatal("expected validation error for personal-data item with no store mapping")
	}
}
