// Package risk defines the packed risk-signal bit layout and the fusion/scoring
// helpers shared by the trust, attestation, config, simulator, and guardrails
// components. These constants are the *server* layout — the authority for
// interpreting telemetry and attestation outcomes and for scoring.
//
// This layout is deliberately NOT identical to the device/wire layout carried
// in proto RiskBitset (the Rust core's RiskBitset, bits 0..20): the same numeric
// position can mean different things on each side (e.g. wire bit 4 is DEBUGGER
// but server bit 4 is BitAppTamper). Device-reported bits must therefore be
// translated with FromWire before they are fused or scored against this layout;
// never OR a raw wire bitset into a server bitset. See wireToServer / FromWire
// and the pinned wire_contract_test.go for the mapping.
package risk

import (
	"math"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// Server risk-signal bit positions (packed into a uint64). This is the server
// layout used for scoring; it is distinct from the device/wire layout (see the
// package doc and FromWire). Renumbering here is pinned by wire_contract_test.go
// so the wire→server mapping can't silently drift.
//
// NOTE: these positions are NOT a mirror of the Rust core's wire RiskBitset.
// Device-reported bits arrive in the wire layout and are remapped via FromWire.
const (
	BitRootJailbreak   uint64 = 1 << 0
	BitDebugger        uint64 = 1 << 1
	BitEmulator        uint64 = 1 << 2
	BitHooking         uint64 = 1 << 3
	BitAppTamper       uint64 = 1 << 4
	BitAttestationFail uint64 = 1 << 5
	BitNetworkMITM     uint64 = 1 << 6
	BitAccountRisk     uint64 = 1 << 7
	BitDeviceIntegrity uint64 = 1 << 8 // device integrity could not be established
	BitAppUnrecognized uint64 = 1 << 9 // app not recognized by the platform
	BitEnvironmentRisk uint64 = 1 << 10

	// Fraud-vector RASP signals. These are device-reported (translated from the
	// wire layout via FromWire) and sit in the free server range below
	// BitFleetAnomaly. Append-only: never renumber.
	BitScreenCapture      uint64 = 1 << 11 // screen capture / recording in progress
	BitOverlayAbuse       uint64 = 1 << 12 // tapjacking / overlay window over the app
	BitAccessibilityAbuse uint64 = 1 << 13 // abusive accessibility service active
	BitMaliciousIME       uint64 = 1 << 14 // malicious / untrusted input method active
	BitRemoteAccess       uint64 = 1 << 15 // remote-access / screen-sharing tool active

	// BitFleetAnomaly is a server-derived signal: the (tenant, app) population
	// is currently showing a coordinated surge of an abuse signal above its
	// learned baseline (see server/data-plane/fleet). It is never reported by a
	// device — devices cannot see the fleet — so it is placed well clear of the
	// device-reported bit range (0..20) to avoid colliding with any wire bit.
	BitFleetAnomaly uint64 = 1 << 32
)

// defaultWeights assigns a severity weight to each known bit. Higher means more
// dangerous. Used when a policy does not specify per-bit weights.
var defaultWeights = map[uint64]uint32{
	BitRootJailbreak:      40,
	BitDebugger:           25,
	BitEmulator:           20,
	BitHooking:            35,
	BitAppTamper:          60,
	BitAttestationFail:    70,
	BitNetworkMITM:        30,
	BitAccountRisk:        20,
	BitDeviceIntegrity:    45,
	BitAppUnrecognized:    65,
	BitEnvironmentRisk:    15,
	BitScreenCapture:      30,
	BitOverlayAbuse:       35,
	BitAccessibilityAbuse: 40,
	BitMaliciousIME:       25,
	BitRemoteAccess:       45,
	// A fleet surge alone lands an otherwise-clean instance at MEDIUM_RISK
	// (step-up), the graduated response; combined with any device signal it
	// escalates further. Override per policy via signal_weights["32"].
	BitFleetAnomaly: 50,
}

// Wire bit positions as packed by the device SDKs / Rust trust core's
// RiskBitset (the layout carried on the wire in proto RiskBitset and
// TelemetryEvent.risk_bits). These are a DIFFERENT, finer-grained namespace
// than the server bits above — keep them in sync with
// sdk/rust-core/kseal-core/src/risk.rs. Do not renumber; only append.
const (
	wireRoot            = 0
	wireJailbreak       = 1
	wireEmulator        = 2
	wireSimulator       = 3
	wireDebugger        = 4
	wireHooking         = 5
	wireTamper          = 6
	wireAppIntegrity    = 7
	wireNetworkMITM     = 8
	wireEnvironment     = 9
	wireProxy           = 10
	wireUserCA          = 11
	wirePinningFailure  = 12
	wireAttestationFail = 13
	wireSecureHWMissing = 14
	wireRepackaged      = 15
	wireScreenCapture   = 16
	wireOverlayAbuse    = 17
	wireAccessibility   = 18
	wireMaliciousIME    = 19
	wireRemoteAccess    = 20

	// maxWireBit is the highest meaningful wire bit (see MAX_SIGNAL_BIT in the
	// Rust core). Wire bits above this carry no server meaning and are dropped
	// by FromWire rather than being scored against an unrelated server weight.
	maxWireBit = wireRemoteAccess
)

// wireToServer maps each device/wire RiskBitset bit (index) to the server-side
// bit mask it means. The two layouts are distinct (e.g. wire bit 4 is DEBUGGER
// but server bit 4 is APP_TAMPER), so the device bitset MUST be translated
// through this table before it is fused or scored — never fused raw. This table
// is the single source of truth for that contract; see TestWireToServerContract
// and the Rust-side TestRiskBitLayoutContract.
var wireToServer = [maxWireBit + 1]uint64{
	wireRoot:            BitRootJailbreak,
	wireJailbreak:       BitRootJailbreak,
	wireEmulator:        BitEmulator,
	wireSimulator:       BitEmulator,
	wireDebugger:        BitDebugger,
	wireHooking:         BitHooking,
	wireTamper:          BitAppTamper,
	wireAppIntegrity:    BitAppTamper,
	wireNetworkMITM:     BitNetworkMITM,
	wireEnvironment:     BitEnvironmentRisk,
	wireProxy:           BitEnvironmentRisk,
	wireUserCA:          BitNetworkMITM,
	wirePinningFailure:  BitNetworkMITM,
	wireAttestationFail: BitAttestationFail,
	wireSecureHWMissing: BitDeviceIntegrity,
	wireRepackaged:      BitAppTamper,
	wireScreenCapture:   BitScreenCapture,
	wireOverlayAbuse:    BitOverlayAbuse,
	wireAccessibility:   BitAccessibilityAbuse,
	wireMaliciousIME:    BitMaliciousIME,
	wireRemoteAccess:    BitRemoteAccess,
}

// FromWire translates a device-reported RiskBitset (wire/Rust-core layout) into
// the server-side risk-bit layout that Score, Level, and the policy weights all
// speak. Every wire bit is remapped through wireToServer; wire bits with no
// server meaning (and any bit above maxWireBit) are dropped. Callers at the
// device→server boundary (trust attestation, telemetry ingest) MUST run device
// bits through FromWire before Fuse/Score so a single uint64 is never
// interpreted under two different bit namespaces.
func FromWire(wire uint64) uint64 {
	var out uint64
	for i := 0; i <= maxWireBit; i++ {
		if wire&(uint64(1)<<uint(i)) != 0 {
			out |= wireToServer[i]
		}
	}
	return out
}

// Fuse combines locally-reported risk bits with bits derived from server-side
// attestation. Both inputs must already be in the server bit layout (run device
// bits through FromWire first). Fusion is a union: any source asserting a risk
// keeps it set.
func Fuse(reported, attestation uint64) uint64 {
	return reported | attestation
}

// Score computes a weighted severity score for the set bits. weights maps a bit
// index (0..63) to a weight; bits absent from the map fall back to the default
// severity table. Addition saturates at uint32 max so a hostile policy (or a
// future large signal set) can never overflow the score and wrap to a low,
// misleading value — matching the Rust core's saturating weighted_score.
func Score(bits uint64, weights map[uint32]uint32) uint32 {
	var total uint32
	for i := uint32(0); i < 64; i++ {
		bit := uint64(1) << i
		if bits&bit == 0 {
			continue
		}
		w := defaultWeights[bit]
		if weights != nil {
			if pw, ok := weights[i]; ok {
				w = pw
			}
		}
		total = addSat(total, w)
	}
	return total
}

// addSat returns a + b clamped to math.MaxUint32 instead of wrapping on
// overflow, mirroring Rust's u32::saturating_add.
func addSat(a, b uint32) uint32 {
	if a > math.MaxUint32-b {
		return math.MaxUint32
	}
	return a + b
}

// defaultThresholds map a TrustLevel to the minimum score that reaches it.
var defaultThresholds = []struct {
	min   uint32
	level ksealv1.TrustLevel
}{
	{min: 130, level: ksealv1.TrustLevel_TRUST_LEVEL_CRITICAL},
	{min: 90, level: ksealv1.TrustLevel_TRUST_LEVEL_HIGH_RISK},
	{min: 50, level: ksealv1.TrustLevel_TRUST_LEVEL_MEDIUM_RISK},
	{min: 20, level: ksealv1.TrustLevel_TRUST_LEVEL_LOW_RISK},
}

// Level maps a score to a TrustLevel. Optional thresholds (keyed by TrustLevel
// name, e.g. "HIGH_RISK") override the defaults.
func Level(score uint32, thresholds map[string]uint32) ksealv1.TrustLevel {
	if len(thresholds) > 0 {
		best := ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED
		bestMin := int64(-1)
		for name, min := range thresholds {
			lvl := levelByName(name)
			if lvl == ksealv1.TrustLevel_TRUST_LEVEL_UNSPECIFIED {
				continue
			}
			if score >= min && int64(min) > bestMin {
				best = lvl
				bestMin = int64(min)
			}
		}
		return best
	}
	for _, t := range defaultThresholds {
		if score >= t.min {
			return t.level
		}
	}
	return ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED
}

func levelByName(name string) ksealv1.TrustLevel {
	switch name {
	case "TRUSTED", "TRUST_LEVEL_TRUSTED":
		return ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED
	case "LOW_RISK", "TRUST_LEVEL_LOW_RISK":
		return ksealv1.TrustLevel_TRUST_LEVEL_LOW_RISK
	case "MEDIUM_RISK", "TRUST_LEVEL_MEDIUM_RISK":
		return ksealv1.TrustLevel_TRUST_LEVEL_MEDIUM_RISK
	case "HIGH_RISK", "TRUST_LEVEL_HIGH_RISK":
		return ksealv1.TrustLevel_TRUST_LEVEL_HIGH_RISK
	case "CRITICAL", "TRUST_LEVEL_CRITICAL":
		return ksealv1.TrustLevel_TRUST_LEVEL_CRITICAL
	default:
		return ksealv1.TrustLevel_TRUST_LEVEL_UNSPECIFIED
	}
}

// Decision maps a TrustLevel to the default enforcement posture, following the
// product rule "observe -> step-up -> block". block is reserved for the most
// severe levels; everything else degrades gracefully.
func Decision(level ksealv1.TrustLevel, mode ksealv1.EnforcementMode) ksealv1.RequestProofResult_Decision {
	// In observe mode nothing is ever denied; risk is only recorded.
	if mode == ksealv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE {
		return ksealv1.RequestProofResult_DECISION_ALLOW
	}
	switch level {
	case ksealv1.TrustLevel_TRUST_LEVEL_CRITICAL:
		return ksealv1.RequestProofResult_DECISION_DENY
	case ksealv1.TrustLevel_TRUST_LEVEL_HIGH_RISK:
		if mode == ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK {
			return ksealv1.RequestProofResult_DECISION_DENY
		}
		return ksealv1.RequestProofResult_DECISION_STEP_UP
	case ksealv1.TrustLevel_TRUST_LEVEL_MEDIUM_RISK:
		return ksealv1.RequestProofResult_DECISION_STEP_UP
	default:
		return ksealv1.RequestProofResult_DECISION_ALLOW
	}
}

// NextChecks recommends which probes the SDK should run before its next refresh,
// escalating coverage as risk rises.
func NextChecks(level ksealv1.TrustLevel) []ksealv1.EventType {
	switch level {
	case ksealv1.TrustLevel_TRUST_LEVEL_TRUSTED, ksealv1.TrustLevel_TRUST_LEVEL_LOW_RISK:
		return nil
	case ksealv1.TrustLevel_TRUST_LEVEL_MEDIUM_RISK:
		return []ksealv1.EventType{
			ksealv1.EventType_EVENT_TYPE_ROOT_RISK,
			ksealv1.EventType_EVENT_TYPE_DEBUGGER,
		}
	default:
		return []ksealv1.EventType{
			ksealv1.EventType_EVENT_TYPE_ROOT_RISK,
			ksealv1.EventType_EVENT_TYPE_DEBUGGER,
			ksealv1.EventType_EVENT_TYPE_HOOKING_DETECTED,
			ksealv1.EventType_EVENT_TYPE_APP_INTEGRITY_FAIL,
		}
	}
}
