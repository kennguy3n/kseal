package siem

import (
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/risk"
)

// Event is the neutral, already-minimized risk/trust event the exporter
// consumes. It is intentionally decoupled from the ingest package's StoredEvent
// so the SIEM subsystem has no dependency on the ingest hot path; main.go
// adapts one to the other. It carries ONLY non-PII, aggregate-safe fields.
type Event struct {
	TenantID  string
	AppID     string
	EventType ksealv1.EventType
	RiskLevel ksealv1.TrustLevel
	RiskBits  uint64
	// Confidence is the coarse confidence enum.
	Confidence ksealv1.Confidence
	BuildHash  string
	PolicyHash string
	// InstallKeyHash is the salted, tenant-scoped install-key HMAC. Never a raw
	// install identifier.
	InstallKeyHash string
	// CoarseTimeBucket is unix seconds, coarsened upstream for k-anonymity.
	CoarseTimeBucket int64
	// Country is OPTIONAL coarse geography (ISO country/region); empty when the
	// privacy policy disallows it.
	Country string
}

// minimized projects an Event onto the canonical contract, then filters to the
// allow-listed subset. Fields outside the contract are unrepresentable. The
// optional country field is emitted only when present AND allow-listed.
//
// Values are concrete types (strings, uint64, int64) so every formatter renders
// identical, well-typed JSON regardless of sink. The returned map's keys are
// always a subset of canonicalFields ∩ allow, which is what the privacy test
// asserts can never be violated.
func (e Event) minimized(allow map[string]struct{}) map[string]any {
	full := map[string]any{
		FieldTenantID:         e.TenantID,
		FieldAppID:            e.AppID,
		FieldEventType:        e.EventType.String(),
		FieldRiskLevel:        e.RiskLevel.String(),
		FieldRiskBits:         e.RiskBits,
		FieldRiskSignals:      riskSignalsOf(e.RiskBits),
		FieldConfidence:       e.Confidence.String(),
		FieldBuildHash:        e.BuildHash,
		FieldPolicyHash:       e.PolicyHash,
		FieldInstallKeyHash:   e.InstallKeyHash,
		FieldCoarseTimeBucket: e.CoarseTimeBucket,
	}
	if e.Country != "" {
		full[FieldCountryOrRegion] = e.Country
	}
	out := make(map[string]any, len(full))
	for k, v := range full {
		if _, ok := allow[k]; ok {
			out[k] = v
		}
	}
	return out
}

// riskSignalsOf returns the stable per-signal names for the (server-layout)
// risk bits, always as a non-nil slice so the field serializes as a JSON array
// (never null) even when no signal is set. RiskBits MUST already be in the
// server layout; main.go normalizes via risk.NormalizeStored before adapting.
func riskSignalsOf(bits uint64) []string {
	names := risk.SignalNames(bits)
	if names == nil {
		return []string{}
	}
	return names
}

// allowSet builds a lookup set from an allow-list slice, intersected with the
// canonical contract as a defense-in-depth backstop: even if a malformed
// allow-list reaches the exporter, only canonical fields can pass.
func allowSet(allow []string) map[string]struct{} {
	s := make(map[string]struct{}, len(allow))
	for _, f := range allow {
		if IsCanonicalField(f) {
			s[f] = struct{}{}
		}
	}
	if len(s) == 0 {
		for f := range canonicalFields {
			s[f] = struct{}{}
		}
	}
	return s
}
