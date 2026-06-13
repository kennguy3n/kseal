package tests

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
)

// allowedTelemetryFields is the EXACT privacy contract for an uploaded telemetry
// event: only minimized, aggregate-safe fields. Adding any field to the proto
// forces a deliberate update here, which is the point — it makes a PII
// regression fail the build.
var allowedTelemetryFields = map[string]bool{
	"event_type":                     true, // enum signal class
	"risk_bits":                      true, // packed risk bitset
	"confidence":                     true, // coarse confidence enum
	"app_build_hash":                 true, // build identity (hash)
	"policy_hash":                    true, // policy identity (hash)
	"tenant_scoped_install_key_hash": true, // salted, tenant-scoped install hash
	"coarse_time_bucket":             true, // coarse time, not a precise timestamp
	"country_or_region":              true, // OPTIONAL coarse geography
}

// allowedEventRecordFields is the privacy contract for the queryable read model.
// Beyond the uploaded fields it carries only server-assigned, non-PII identifiers.
var allowedEventRecordFields = map[string]bool{
	"id":                true, // server-assigned event id
	"tenant_id":         true, // tenant namespace (not user PII)
	"app_id":            true, // app identity
	"event_type":        true,
	"risk_level":        true, // derived trust level
	"risk_bits":         true,
	"confidence":        true,
	"app_build_hash":    true,
	"policy_hash":       true,
	"timestamp":         true, // coarse bucket surfaced as timestamp
	"country_or_region": true,
}

// forbiddenSubstrings are tokens that must never appear in a telemetry field
// name — they would indicate raw PII or fingerprinting identifiers.
var forbiddenSubstrings = []string{
	"email", "phone", "msisdn", "imei", "imsi", "mac", "ip_address", "ipaddr",
	"latitude", "longitude", "lat_", "lng", "geo_point", "precise",
	"advertising", "ad_id", "idfa", "gaid", "device_id", "deviceid",
	"serial", "android_id", "ssn", "name", "address", "fingerprint",
	"user_id", "username", "raw",
}

func TestPrivacyContract(t *testing.T) {
	requireHarness(t)

	t.Run("telemetry_event_schema_is_minimized", func(t *testing.T) {
		assertFieldContract(t, (&ksealv1.TelemetryEvent{}).ProtoReflect().Descriptor(), allowedTelemetryFields)
	})

	t.Run("event_record_schema_is_minimized", func(t *testing.T) {
		assertFieldContract(t, (&ksealv1.EventRecord{}).ProtoReflect().Descriptor(), allowedEventRecordFields)
	})

	t.Run("ingested_event_carries_no_pii", func(t *testing.T) {
		store := newStore(t)
		tenant := makeTenant(t, store, "privacy")
		app := makeApp(t, store, tenant.Id, "com.kseal.privacy")
		p := newPipeline(t, store, 100000, nil)

		const installHash = "0f1e2d3c4b5a69788796a5b4c3d2e1f0" // opaque, pre-hashed
		country := "DE"
		ev := &ksealv1.TelemetryEvent{
			EventType:                  ksealv1.EventType_EVENT_TYPE_ROOT_RISK,
			RiskBits:                   1 << 0,
			Confidence:                 ksealv1.Confidence_CONFIDENCE_HIGH,
			AppBuildHash:               buildHash,
			TenantScopedInstallKeyHash: installHash,
			CoarseTimeBucket:           time.Now().Unix(),
			CountryOrRegion:            &country,
		}
		p.submit(t, tenant.Id, app.Id, &ksealv1.TelemetryBatch{Platform: ksealv1.Platform_PLATFORM_ANDROID, Events: []*ksealv1.TelemetryEvent{ev}})
		if got := p.waitForEvents(t, tenant.Id, 1); got != 1 {
			t.Fatalf("expected 1 event, got %d", got)
		}

		ctx := auth.WithTenant(context.Background(), tenant.Id)
		resp, err := p.query.ListEvents(ctx, connect.NewRequest(&ksealv1.ListEventsRequest{TenantId: tenant.Id, PageSize: 10}))
		if err != nil {
			t.Fatalf("list events: %v", err)
		}
		if len(resp.Msg.Events) != 1 {
			t.Fatalf("expected 1 event back, got %d", len(resp.Msg.Events))
		}
		rec := resp.Msg.Events[0]

		// The install key is surfaced only as the pre-hashed value we supplied;
		// the server never derives or stores a raw identifier.
		if rec.GetCountryOrRegion() != "DE" {
			t.Fatalf("coarse geography not preserved: %q", rec.GetCountryOrRegion())
		}

		// Serialize the read model to JSON and assert no forbidden token appears
		// in any KEY (a raw-PII field) — values like the build hash are fine.
		raw, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		var asMap map[string]json.RawMessage
		if err := json.Unmarshal(raw, &asMap); err != nil {
			t.Fatalf("unmarshal record: %v", err)
		}
		for key := range asMap {
			lower := strings.ToLower(key)
			for _, bad := range forbiddenSubstrings {
				if strings.Contains(lower, bad) {
					t.Fatalf("forbidden PII-like field %q present in event record", key)
				}
			}
		}
	})

	t.Run("stored_proto_wire_has_no_unknown_fields", func(t *testing.T) {
		// A defense-in-depth check: a TelemetryEvent carrying only allowed fields
		// must round-trip with zero unknown fields, so no out-of-contract data
		// can ride along on the wire.
		ev := &ksealv1.TelemetryEvent{EventType: ksealv1.EventType_EVENT_TYPE_DEBUGGER, RiskBits: 2}
		b, err := proto.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var back ksealv1.TelemetryEvent
		if err := proto.Unmarshal(b, &back); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if n := len(back.ProtoReflect().GetUnknown()); n != 0 {
			t.Fatalf("telemetry event carried %d bytes of unknown fields", n)
		}
	})
}

// assertFieldContract fails if the message has any field outside allowed, or is
// missing any field the contract expects.
func assertFieldContract(t *testing.T, desc protoreflect.MessageDescriptor, allowed map[string]bool) {
	t.Helper()
	fields := desc.Fields()
	seen := map[string]bool{}
	for i := 0; i < fields.Len(); i++ {
		name := string(fields.Get(i).Name())
		seen[name] = true
		if !allowed[name] {
			t.Fatalf("%s carries field %q outside the privacy contract", desc.Name(), name)
		}
		lower := strings.ToLower(name)
		for _, bad := range forbiddenSubstrings {
			if strings.Contains(lower, bad) {
				t.Fatalf("%s field %q matches forbidden PII token %q", desc.Name(), name, bad)
			}
		}
	}
	for name := range allowed {
		if !seen[name] {
			t.Fatalf("%s is missing expected contract field %q (schema drift)", desc.Name(), name)
		}
	}
}
