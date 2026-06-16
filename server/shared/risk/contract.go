package risk

// This file holds the externally-facing risk-bit contract: the stable signal
// names emitted to consumers (SIEM, webhooks, dashboard) and the layout version
// that makes a stored/transported risk bitset self-describing. Both are kept
// here, decoupled from scoring, because they are the parts other systems pin
// against — renumbering a bit must not silently change what an external rule or
// a historical row means.

// signalNames pairs each server risk bit with its stable, external snake_case
// name. These names are part of the egress contract: external SIEM correlation
// rules and webhook consumers key on them, so they MUST stay stable even if the
// underlying bit position is ever renumbered (that is the whole point of
// emitting names instead of raw bit indices). The table is ordered ascending by
// bit so SignalNames produces deterministic output. Coupling the names to the
// Bit* constants (not literal masks) keeps them in lockstep with the layout.
var signalNames = []struct {
	bit  uint64
	name string
}{
	{BitRootJailbreak, "root_jailbreak"},
	{BitDebugger, "debugger"},
	{BitEmulator, "emulator"},
	{BitHooking, "hooking"},
	{BitAppTamper, "app_tamper"},
	{BitAttestationFail, "attestation_fail"},
	{BitNetworkMITM, "network_mitm"},
	{BitAccountRisk, "account_risk"},
	{BitDeviceIntegrity, "device_integrity"},
	{BitAppUnrecognized, "app_unrecognized"},
	{BitEnvironmentRisk, "environment_risk"},
	{BitScreenCapture, "screen_capture"},
	{BitOverlayAbuse, "overlay_abuse"},
	{BitAccessibilityAbuse, "accessibility_abuse"},
	{BitMaliciousIME, "malicious_ime"},
	{BitRemoteAccess, "remote_access"},
	{BitFleetAnomaly, "fleet_anomaly"},
}

// SignalNames returns the stable external names of every known server risk bit
// set in bits, in ascending bit order. Inputs MUST be in the server layout (run
// device bits through FromWire / NormalizeStored first). Unknown bits carry no
// contract name and are skipped, so a forward-compatible reader never emits a
// meaningless token. The result is nil when no known bit is set; callers that
// serialize it can treat nil as the empty list.
func SignalNames(bits uint64) []string {
	var out []string
	for _, s := range signalNames {
		if bits&s.bit != 0 {
			out = append(out, s.name)
		}
	}
	return out
}

// Layout identifies which risk-bit namespace a packed uint64 is expressed in.
// It is persisted alongside stored telemetry so a row is self-describing: a
// reader (simulator, exporter, a future migration) can always tell whether the
// bits are in the device/wire layout or the server scoring layout. This is the
// durable fix for the dual-namespace foot-gun — instead of inferring a row's
// layout from when it was written, the row states it, so any future renumber of
// either layout stays unambiguous rather than silently mis-scoring old rows.
type Layout uint8

const (
	// LayoutUnknown marks a bitset written before layout versioning existed (or
	// by a producer that did not set it). It is treated as the server layout on
	// read: since the wire->server translation landed, stored bits are already
	// server-layout, and the brief pre-translation window self-heals within the
	// tenant's retention horizon. Tagging it distinctly (rather than forcing
	// LayoutServer) keeps "we know it is server" separate from "we assume it is".
	LayoutUnknown Layout = 0
	// LayoutWire marks bits in the device/Rust-core wire layout (see FromWire).
	// Persisted wire-layout bits are translated on read via NormalizeStored.
	LayoutWire Layout = 1
	// LayoutServer marks bits already in the server scoring layout that Score,
	// Level, and the policy weights all speak. Ingest tags stored events with
	// this because it applies FromWire before persisting.
	LayoutServer Layout = 2
)

// NormalizeStored returns bits in the server scoring layout regardless of the
// layout they were stored under. Wire-layout bits are translated through
// FromWire; server-layout and unknown bits are returned unchanged (unknown is
// assumed server — see LayoutUnknown). Every read path that scores stored bits
// should pass them through this so a mislabeled or future-layout row is scored
// correctly instead of under the wrong namespace.
func NormalizeStored(bits uint64, layout Layout) uint64 {
	if layout == LayoutWire {
		return FromWire(bits)
	}
	return bits
}
