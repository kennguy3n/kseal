package ingest

import (
	"encoding/binary"
	"errors"
	"math"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/risk"
)

// eventCodecVersion is the wire version of the broker-internal StoredEvent
// encoding written by this build. v2 appends the RiskBitsLayout byte after
// RiskBits. The decoder still accepts v1 (older in-flight records during a
// rolling upgrade decode with RiskBitsLayout == risk.LayoutUnknown); any
// version newer than this build is rejected so a forward record is never
// silently misread.
const (
	eventCodecVersion   byte = 2
	eventCodecVersionV1 byte = 1
)

// maxEncodedStringLen guards the decoder against a corrupt/forged length prefix
// claiming a multi-gigabyte string. No legitimate StoredEvent field approaches
// this, so it is a cheap anti-DoS bound on broker-sourced bytes.
const maxEncodedStringLen = 1 << 20 // 1 MiB

var (
	errTruncatedEvent  = errors.New("ingest: truncated encoded event")
	errBadEventVersion = errors.New("ingest: unknown encoded event version")
	errStringTooLong   = errors.New("ingest: encoded string exceeds bound")
	errTrailingGarbage = errors.New("ingest: trailing bytes after encoded event")
)

// encodeStoredEvent serializes a StoredEvent into a compact, deterministic,
// versioned binary form for transport through a durable broker. It is
// allocation-light (a single buffer grown to a generous estimate) so it stays
// cheap on the ingest hot path. The format is internal to the data plane and
// independent of the RPC wire shapes, so it never constrains proto evolution.
func encodeStoredEvent(e StoredEvent) []byte {
	// Estimate: version + 5 varint-ish scalars + 6 length-prefixed strings.
	buf := make([]byte, 0, 64+len(e.ID)+len(e.TenantID)+len(e.AppID)+len(e.BuildHash)+len(e.PolicyHash)+len(e.InstallKeyHash)+len(e.Country))
	buf = append(buf, eventCodecVersion)
	buf = appendString(buf, e.ID)
	buf = appendString(buf, e.TenantID)
	buf = appendString(buf, e.AppID)
	buf = binary.AppendVarint(buf, int64(e.EventType))
	buf = binary.AppendVarint(buf, int64(e.RiskLevel))
	buf = binary.AppendUvarint(buf, e.RiskBits)
	buf = binary.AppendUvarint(buf, uint64(e.RiskBitsLayout)) // v2+
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

// decodeStoredEvent is the exact inverse of encodeStoredEvent. It validates the
// version, every length prefix, and that no trailing bytes remain, so a
// malformed or truncated broker record is rejected rather than yielding a
// partially-populated event.
func decodeStoredEvent(b []byte) (StoredEvent, error) {
	var e StoredEvent
	if len(b) == 0 {
		return e, errTruncatedEvent
	}
	ver := b[0]
	if ver != eventCodecVersion && ver != eventCodecVersionV1 {
		return e, errBadEventVersion
	}
	d := decoder{b: b[1:]}

	e.ID = d.string()
	e.TenantID = d.string()
	e.AppID = d.string()
	e.EventType = ksealv1.EventType(d.varint())
	e.RiskLevel = ksealv1.TrustLevel(d.varint())
	e.RiskBits = d.uvarint()
	// v1 records predate the layout byte; they decode as LayoutUnknown, which
	// NormalizeStored treats as the (steady-state) server layout.
	if ver >= eventCodecVersion {
		e.RiskBitsLayout = risk.Layout(d.uvarint())
	}
	e.Confidence = ksealv1.Confidence(d.varint())
	e.BuildHash = d.string()
	e.PolicyHash = d.string()
	e.InstallKeyHash = d.string()
	e.TimeBucket = d.varint()
	e.Country = d.string()
	e.Platform = ksealv1.Platform(d.varint())
	e.ReceivedAt = d.varint()

	if d.err != nil {
		return StoredEvent{}, d.err
	}
	if len(d.b) != 0 {
		return StoredEvent{}, errTrailingGarbage
	}
	return e, nil
}

func appendString(buf []byte, s string) []byte {
	buf = binary.AppendUvarint(buf, uint64(len(s)))
	return append(buf, s...)
}

// decoder is a tiny sticky-error reader over the remaining bytes: once any read
// fails it records the error and every subsequent read is a no-op, so callers
// can decode the whole struct and check err once.
type decoder struct {
	b   []byte
	err error
}

func (d *decoder) uvarint() uint64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Uvarint(d.b)
	if n <= 0 {
		d.err = errTruncatedEvent
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *decoder) varint() int64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Varint(d.b)
	if n <= 0 {
		d.err = errTruncatedEvent
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *decoder) string() string {
	n := d.uvarint()
	if d.err != nil {
		return ""
	}
	if n > maxEncodedStringLen {
		d.err = errStringTooLong
		return ""
	}
	if uint64(len(d.b)) < n {
		d.err = errTruncatedEvent
		return ""
	}
	// math.MaxInt guard keeps the slice conversion safe on 32-bit builds.
	if n > math.MaxInt {
		d.err = errStringTooLong
		return ""
	}
	s := string(d.b[:n])
	d.b = d.b[n:]
	return s
}
