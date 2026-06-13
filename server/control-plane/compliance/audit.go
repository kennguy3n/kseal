// Package compliance is the control-plane source of truth for enterprise trust
// & compliance state: a tamper-evident, hash-chained audit trail of
// control-plane mutations, a machine-readable data-processing registry, a
// signed remote kill switch, and canary rollout state. Every record is
// tenant-scoped and free of PII.
//
// It exposes a single Store interface with two implementations — a
// Postgres-backed store (production + integration tests, row-level-security
// isolated) and an in-memory store (unit tests) — held to identical semantics
// by a shared suite.
package compliance

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// Store errors.
var (
	ErrNotFound     = errors.New("compliance: not found")
	ErrInvalidInput = errors.New("compliance: invalid input")
)

// auditDomain is the domain-separation tag prefixed to every audit-event hash
// preimage. It is distinct from the config/proof domains so an audit hash can
// never collide with another signed structure.
const auditDomain = "kseal/v1/audit-event"

// Entry is the caller-supplied content of an audit event. The chaining fields
// (seq, prev_hash, hash, created_at) are assigned by the store at append time.
// Metadata must contain only coarse, non-PII attributes.
type Entry struct {
	Action       string
	ResourceType string
	ResourceID   string
	ActorKeyID   string
	Metadata     map[string]string
}

// AuditFilter narrows an audit-event listing. Zero-valued fields are ignored.
type AuditFilter struct {
	Action       string
	ResourceType string
	// FromMillis/ToMillis bound created_at inclusively (0 means unbounded).
	FromMillis int64
	ToMillis   int64
}

// VerifyResult reports the outcome of recomputing a tenant's audit chain.
type VerifyResult struct {
	Intact        bool
	VerifiedCount int64
	// BrokenSeq is the first sequence whose stored hash does not match its
	// recomputed value or whose prev_hash does not link to its predecessor
	// (0 when intact).
	BrokenSeq int64
	HeadHash  string
}

// appendUint64 appends v as 8 big-endian bytes.
func appendUint64(buf []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(buf, b[:]...)
}

// appendLP appends a 4-byte big-endian length prefix followed by field. Audit
// fields (action, ids, metadata) are bounded far below MaxUint32 in practice;
// values are validated at the service edge, so a plain uint32 prefix is safe.
func appendLP(buf, field []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(field)))
	buf = append(buf, n[:]...)
	return append(buf, field...)
}

// canonicalMetadata serializes metadata deterministically: keys sorted, each
// encoded as len-prefixed key followed by len-prefixed value. Equal maps always
// produce identical bytes regardless of Go map iteration order.
func canonicalMetadata(md map[string]string) []byte {
	if len(md) == 0 {
		return nil
	}
	keys := make([]string, 0, len(md))
	for k := range md {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf []byte
	for _, k := range keys {
		buf = appendLP(buf, []byte(k))
		buf = appendLP(buf, []byte(md[k]))
	}
	return buf
}

// auditPreimage builds the canonical, domain-separated, length-prefixed bytes a
// single audit event commits to. The layout is fixed:
//
//	lp(DOMAIN) || lp(tenant_id) || u64(seq) || lp(action) || lp(resource_type)
//	|| lp(resource_id) || lp(actor_key_id) || lp(canonicalMetadata)
//	|| u64(created_at_millis) || lp(prev_hash_hex)
//
// Including prev_hash chains each event to its predecessor: editing, dropping,
// or reordering any event changes a downstream hash and breaks verification.
func auditPreimage(tenantID string, seq int64, e Entry, createdAtMillis int64, prevHash string) []byte {
	buf := make([]byte, 0, 64+len(tenantID)+len(e.Action)+len(e.ResourceType)+len(e.ResourceID)+len(e.ActorKeyID)+len(prevHash))
	buf = appendLP(buf, []byte(auditDomain))
	buf = appendLP(buf, []byte(tenantID))
	buf = appendUint64(buf, uint64(seq))
	buf = appendLP(buf, []byte(e.Action))
	buf = appendLP(buf, []byte(e.ResourceType))
	buf = appendLP(buf, []byte(e.ResourceID))
	buf = appendLP(buf, []byte(e.ActorKeyID))
	buf = appendLP(buf, canonicalMetadata(e.Metadata))
	buf = appendUint64(buf, uint64(createdAtMillis))
	buf = appendLP(buf, []byte(prevHash))
	return buf
}

// hashAuditEvent returns the hex SHA-256 of an event's canonical preimage.
func hashAuditEvent(tenantID string, seq int64, e Entry, createdAtMillis int64, prevHash string) string {
	sum := sha256.Sum256(auditPreimage(tenantID, seq, e, createdAtMillis, prevHash))
	return hex.EncodeToString(sum[:])
}

// validateEntry rejects an audit entry that is missing required fields. The
// action is mandatory; everything else is optional but, when present, must be
// non-PII (enforced by callers — the store never logs raw values).
func validateEntry(e Entry) error {
	if e.Action == "" {
		return errors.New("compliance: audit action required")
	}
	return nil
}

// recompute verifies an ordered slice of events forms an intact chain. Events
// must be ascending by seq starting at 1 with no gaps.
func recompute(tenantID string, events []*ksealv1.AuditEvent) VerifyResult {
	res := VerifyResult{Intact: true}
	prevHash := ""
	expectSeq := int64(1)
	for _, ev := range events {
		if ev.Seq != expectSeq {
			res.Intact = false
			res.BrokenSeq = ev.Seq
			return res
		}
		want := hashAuditEvent(tenantID, ev.Seq, Entry{
			Action:       ev.Action,
			ResourceType: ev.ResourceType,
			ResourceID:   ev.ResourceId,
			ActorKeyID:   ev.ActorKeyId,
			Metadata:     ev.Metadata,
		}, ev.CreatedAt, prevHash)
		if ev.PrevHash != prevHash || ev.Hash != want {
			res.Intact = false
			res.BrokenSeq = ev.Seq
			return res
		}
		prevHash = ev.Hash
		res.VerifiedCount++
		res.HeadHash = ev.Hash
		expectSeq++
	}
	return res
}
