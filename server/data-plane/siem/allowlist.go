// Package siem streams privacy-minimized trust/risk events to per-tenant
// external SIEM sinks (Splunk HEC, Microsoft Sentinel, Elastic) reliably and
// without ever egressing PII.
//
// The package is split into:
//
//   - allowlist.go — the canonical, non-PII export field contract and its
//     enforcement (the privacy boundary).
//   - event.go     — the neutral, minimized Event the exporter consumes.
//   - mapping.go   — per-sink payload + auth/header rendering (Splunk/Sentinel/
//     Elastic), driven only by allow-listed fields.
//   - store.go     — the ConnectorStore interface + in-memory implementation.
//   - postgres.go  — the Postgres-backed, RLS-isolated connector store.
//   - exporter.go  — the async, backpressured, batched, at-least-once exporter
//     with per-tenant queues, circuit breakers, idempotency, and metrics.
//   - service.go   — the Connect SiemService (register/list/delete connectors).
//   - metrics.go   — Prometheus instruments (dead-letter counter, export-lag
//     gauge, queue depth) exposed on the existing /metrics surface.
package siem

import "sort"

// Canonical minimized export field names. These are the ONLY field keys an
// exporter may ever emit. They mirror the platform privacy contract enforced by
// tests/privacy_contract_test.go: a salted tenant-scoped install-key hash, a
// coarse time bucket, optional coarse geography, packed risk bits, a coarse
// confidence, and policy/build identity hashes — plus the tenant/app namespaces
// (identifiers, not user PII). No raw identifier, precise location, or device
// fingerprint is representable here.
const (
	FieldTenantID         = "tenant_id"
	FieldAppID            = "app_id"
	FieldEventType        = "event_type"
	FieldRiskLevel        = "risk_level"
	FieldRiskBits         = "risk_bits"
	FieldConfidence       = "confidence"
	FieldBuildHash        = "build_hash"
	FieldPolicyHash       = "policy_hash"
	FieldInstallKeyHash   = "install_key_hash"
	FieldCoarseTimeBucket = "coarse_time_bucket"
	FieldCountryOrRegion  = "country_or_region"
)

// canonicalFields is the complete export contract. A connector's field
// allow-list must be a subset of this set; the exporter intersects requested
// fields with it so a future proto change can never silently widen egress.
var canonicalFields = map[string]struct{}{
	FieldTenantID:         {},
	FieldAppID:            {},
	FieldEventType:        {},
	FieldRiskLevel:        {},
	FieldRiskBits:         {},
	FieldConfidence:       {},
	FieldBuildHash:        {},
	FieldPolicyHash:       {},
	FieldInstallKeyHash:   {},
	FieldCoarseTimeBucket: {},
	FieldCountryOrRegion:  {},
}

// DefaultAllowList returns the full minimized contract, sorted for stable
// output. Used when a connector specifies no explicit allow-list.
func DefaultAllowList() []string {
	out := make([]string, 0, len(canonicalFields))
	for f := range canonicalFields {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// IsCanonicalField reports whether name is part of the export contract.
func IsCanonicalField(name string) bool {
	_, ok := canonicalFields[name]
	return ok
}

// NormalizeAllowList validates and canonicalizes a requested allow-list. An
// empty request yields the full contract. Unknown fields are rejected (rather
// than silently dropped) so a misconfiguration surfaces at registration time.
// The result is deduplicated and sorted for deterministic storage and tests.
func NormalizeAllowList(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return DefaultAllowList(), nil
	}
	seen := make(map[string]struct{}, len(requested))
	out := make([]string, 0, len(requested))
	for _, f := range requested {
		if !IsCanonicalField(f) {
			return nil, &DisallowedFieldError{Field: f}
		}
		if _, dup := seen[f]; dup {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	sort.Strings(out)
	return out, nil
}

// DisallowedFieldError is returned when an allow-list references a field outside
// the canonical privacy contract.
type DisallowedFieldError struct{ Field string }

func (e *DisallowedFieldError) Error() string {
	return "siem: field not in privacy contract: " + e.Field
}
