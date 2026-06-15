package ingest

import (
	"encoding/binary"
	"strings"
	"testing"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/risk"
)

func sampleEvent() StoredEvent {
	return StoredEvent{
		ID:             "11111111-2222-3333-4444-555555555555",
		TenantID:       "tenant-a",
		AppID:          "com.example.app",
		EventType:      ksealv1.EventType_EVENT_TYPE_ROOT_RISK,
		RiskLevel:      ksealv1.TrustLevel_TRUST_LEVEL_HIGH_RISK,
		RiskBits:       0xDEADBEEFCAFE,
		RiskBitsLayout: risk.LayoutServer,
		Confidence:     ksealv1.Confidence_CONFIDENCE_HIGH,
		BuildHash:      "sha256:abc123",
		PolicyHash:     "sha256:def456",
		InstallKeyHash: "ikh-789",
		TimeBucket:     1_700_000_000,
		Country:        "US",
		Platform:       ksealv1.Platform_PLATFORM_ANDROID,
		ReceivedAt:     1_700_000_123,
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := sampleEvent()
	out, err := decodeStoredEvent(encodeStoredEvent(in))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestEncodeDecodeEmptyStrings(t *testing.T) {
	// Zero-value strings (e.g. no country / no policy hash) must round-trip,
	// since the privacy allow-list legitimately omits coarse fields.
	in := StoredEvent{TenantID: "t", ID: "id", TimeBucket: 1, ReceivedAt: 2}
	out, err := decodeStoredEvent(encodeStoredEvent(in))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestEncodeIsDeterministic(t *testing.T) {
	in := sampleEvent()
	a := encodeStoredEvent(in)
	b := encodeStoredEvent(in)
	if string(a) != string(b) {
		t.Fatal("encoding is not deterministic for identical input")
	}
}

func TestDecodeRejectsEmpty(t *testing.T) {
	if _, err := decodeStoredEvent(nil); err != errTruncatedEvent {
		t.Fatalf("want errTruncatedEvent, got %v", err)
	}
}

// encodeStoredEventV1 reproduces the pre-layout (v1) on-the-wire format so the
// decoder's backward compatibility can be tested: a v1 record has no
// RiskBitsLayout byte and must decode as risk.LayoutUnknown.
func encodeStoredEventV1(e StoredEvent) []byte {
	buf := []byte{eventCodecVersionV1}
	buf = appendString(buf, e.ID)
	buf = appendString(buf, e.TenantID)
	buf = appendString(buf, e.AppID)
	buf = binary.AppendVarint(buf, int64(e.EventType))
	buf = binary.AppendVarint(buf, int64(e.RiskLevel))
	buf = binary.AppendUvarint(buf, e.RiskBits)
	buf = binary.AppendVarint(buf, int64(e.Confidence))
	buf = appendString(buf, e.BuildHash)
	buf = appendString(buf, e.PolicyHash)
	buf = appendString(buf, e.InstallKeyHash)
	buf = binary.AppendVarint(buf, e.TimeBucket)
	buf = appendString(buf, e.Country)
	buf = binary.AppendVarint(buf, int64(e.Platform))
	buf = binary.AppendVarint(buf, e.ReceivedAt)
	return buf
}

// TestDecodeV1RecordDefaultsLayoutUnknown asserts a v1 record (no layout byte)
// still decodes during a rolling upgrade and the missing field defaults to
// LayoutUnknown — which NormalizeStored treats as the server layout.
func TestDecodeV1RecordDefaultsLayoutUnknown(t *testing.T) {
	in := sampleEvent()
	out, err := decodeStoredEvent(encodeStoredEventV1(in))
	if err != nil {
		t.Fatalf("decode v1: %v", err)
	}
	if out.RiskBitsLayout != risk.LayoutUnknown {
		t.Fatalf("v1 layout = %d, want LayoutUnknown(%d)", out.RiskBitsLayout, risk.LayoutUnknown)
	}
	want := in
	want.RiskBitsLayout = risk.LayoutUnknown
	if out != want {
		t.Fatalf("v1 round-trip mismatch:\n got %+v\nwant %+v", out, want)
	}
}

func TestDecodeRejectsBadVersion(t *testing.T) {
	enc := encodeStoredEvent(sampleEvent())
	enc[0] = 0xFF // corrupt the version byte
	if _, err := decodeStoredEvent(enc); err != errBadEventVersion {
		t.Fatalf("want errBadEventVersion, got %v", err)
	}
}

func TestDecodeRejectsTruncation(t *testing.T) {
	enc := encodeStoredEvent(sampleEvent())
	// Drop the final byte: a length prefix or scalar will now run past the end.
	if _, err := decodeStoredEvent(enc[:len(enc)-1]); err != errTruncatedEvent {
		t.Fatalf("want errTruncatedEvent, got %v", err)
	}
}

func TestDecodeRejectsTrailingGarbage(t *testing.T) {
	enc := append(encodeStoredEvent(sampleEvent()), 0x00)
	if _, err := decodeStoredEvent(enc); err != errTrailingGarbage {
		t.Fatalf("want errTrailingGarbage, got %v", err)
	}
}

func TestDecodeRejectsOversizedString(t *testing.T) {
	// Hand-craft a record whose first string claims a length above the bound.
	buf := []byte{eventCodecVersion}
	buf = binary.AppendUvarint(buf, uint64(maxEncodedStringLen+1))
	buf = append(buf, []byte(strings.Repeat("x", 16))...)
	if _, err := decodeStoredEvent(buf); err != errStringTooLong {
		t.Fatalf("want errStringTooLong, got %v", err)
	}
}
