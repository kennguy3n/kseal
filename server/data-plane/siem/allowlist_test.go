package siem

import (
	"strings"
	"testing"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// forbiddenSubstrings mirrors tests/privacy_contract_test.go: any export key
// containing one of these is a PII leak and must never appear.
var forbiddenSubstrings = []string{
	"email", "phone", "msisdn", "imei", "imsi", "mac", "ip_address",
	"latitude", "longitude", "device_id", "advertising_id", "user_id",
	"serial", "name", "address", "fingerprint",
}

func TestCanonicalFieldsHaveNoPII(t *testing.T) {
	for f := range canonicalFields {
		for _, bad := range forbiddenSubstrings {
			if strings.Contains(f, bad) {
				t.Fatalf("canonical field %q contains forbidden substring %q", f, bad)
			}
		}
	}
}

func TestNormalizeAllowListDefaults(t *testing.T) {
	got, err := NormalizeAllowList(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(canonicalFields) {
		t.Fatalf("default allow-list = %d fields, want %d", len(got), len(canonicalFields))
	}
	// Sorted + deduplicated.
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("allow-list not strictly sorted: %v", got)
		}
	}
}

func TestNormalizeAllowListSubsetAndDedup(t *testing.T) {
	got, err := NormalizeAllowList([]string{FieldRiskBits, FieldRiskBits, FieldEventType})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{FieldEventType, FieldRiskBits}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestNormalizeAllowListRejectsUnknown(t *testing.T) {
	_, err := NormalizeAllowList([]string{FieldRiskBits, "device_id"})
	if err == nil {
		t.Fatal("expected rejection of disallowed field, got nil")
	}
	var d *DisallowedFieldError
	if !asDisallowed(err, &d) || d.Field != "device_id" {
		t.Fatalf("expected DisallowedFieldError for device_id, got %v", err)
	}
}

func TestMinimizedRespectsAllowList(t *testing.T) {
	ev := sampleEvent()
	// Only allow two fields.
	allow := allowSet([]string{FieldRiskBits, FieldEventType})
	m := ev.minimized(allow)
	if len(m) != 2 {
		t.Fatalf("expected 2 fields, got %d (%v)", len(m), m)
	}
	if _, ok := m[FieldInstallKeyHash]; ok {
		t.Fatal("install_key_hash leaked despite not being allow-listed")
	}
}

func TestMinimizedOmitsEmptyCountry(t *testing.T) {
	ev := sampleEvent()
	ev.Country = ""
	m := ev.minimized(allowSet(DefaultAllowList()))
	if _, ok := m[FieldCountryOrRegion]; ok {
		t.Fatal("country_or_region present despite being empty")
	}
}

func sampleEvent() Event {
	return Event{
		TenantID:         "t-1",
		AppID:            "app-1",
		EventType:        ksealv1.EventType_EVENT_TYPE_ROOT_RISK,
		RiskLevel:        ksealv1.TrustLevel_TRUST_LEVEL_HIGH_RISK,
		RiskBits:         0b1011,
		Confidence:       ksealv1.Confidence_CONFIDENCE_HIGH,
		BuildHash:        "bh_abc",
		PolicyHash:       "ph_def",
		InstallKeyHash:   "ikh_123",
		CoarseTimeBucket: 1_700_000_000,
		Country:          "US",
	}
}

// asDisallowed is a tiny errors.As wrapper to avoid importing errors in every test.
func asDisallowed(err error, target **DisallowedFieldError) bool {
	for err != nil {
		if d, ok := err.(*DisallowedFieldError); ok {
			*target = d
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
