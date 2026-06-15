package risk

import (
	"reflect"
	"testing"
)

// TestSignalNamesContract pins the stable external names emitted to SIEM and
// webhook consumers. These names are an external API: renumbering a bit must
// keep the name attached to the same meaning, so a deliberate change here is
// required to break this test.
func TestSignalNamesContract(t *testing.T) {
	cases := []struct {
		bits uint64
		want []string
	}{
		{0, nil},
		{BitRootJailbreak, []string{"root_jailbreak"}},
		{BitAppTamper, []string{"app_tamper"}},
		{BitFleetAnomaly, []string{"fleet_anomaly"}},
		// Ascending bit order, regardless of set order.
		{BitFleetAnomaly | BitDebugger | BitRootJailbreak, []string{"root_jailbreak", "debugger", "fleet_anomaly"}},
		// Every known bit, in order.
		{
			BitRootJailbreak | BitDebugger | BitEmulator | BitHooking | BitAppTamper |
				BitAttestationFail | BitNetworkMITM | BitAccountRisk | BitDeviceIntegrity |
				BitAppUnrecognized | BitEnvironmentRisk | BitFleetAnomaly,
			[]string{
				"root_jailbreak", "debugger", "emulator", "hooking", "app_tamper",
				"attestation_fail", "network_mitm", "account_risk", "device_integrity",
				"app_unrecognized", "environment_risk", "fleet_anomaly",
			},
		},
	}
	for _, c := range cases {
		if got := SignalNames(c.bits); !reflect.DeepEqual(got, c.want) {
			t.Fatalf("SignalNames(%#x) = %v, want %v", c.bits, got, c.want)
		}
	}
}

// TestSignalNamesSkipsUnknownBits asserts a bit with no contract name is
// silently skipped (forward compatibility) rather than emitting a placeholder.
func TestSignalNamesSkipsUnknownBits(t *testing.T) {
	unknown := uint64(1) << 40 // no name assigned
	if got := SignalNames(unknown); got != nil {
		t.Fatalf("unknown bit must produce no names, got %v", got)
	}
	if got := SignalNames(unknown | BitEmulator); !reflect.DeepEqual(got, []string{"emulator"}) {
		t.Fatalf("mixed known/unknown = %v, want [emulator]", got)
	}
}

// TestSignalNamesCoversEveryWeightedBit guards against a new scored bit being
// added to defaultWeights without a matching egress name — which would let a
// signal influence the score yet be invisible to external consumers.
func TestSignalNamesCoversEveryWeightedBit(t *testing.T) {
	named := make(map[uint64]struct{}, len(signalNames))
	for _, s := range signalNames {
		named[s.bit] = struct{}{}
	}
	for bit := range defaultWeights {
		if _, ok := named[bit]; !ok {
			t.Fatalf("weighted bit %#x has no egress signal name", bit)
		}
	}
}

// TestNormalizeStoredLayouts pins the self-describing translation: wire-layout
// rows are remapped to the server layout, server/unknown rows pass through.
func TestNormalizeStoredLayouts(t *testing.T) {
	const wireDebugger = uint64(1) << 4 // wire bit 4 == DEBUGGER
	// Stored under the wire layout, it must translate to server DEBUGGER (not
	// be left as server bit 4 == APP_TAMPER).
	if got := NormalizeStored(wireDebugger, LayoutWire); got != BitDebugger {
		t.Fatalf("NormalizeStored(wire DEBUGGER, LayoutWire) = %#x, want %#x", got, BitDebugger)
	}
	// Already server layout: unchanged.
	if got := NormalizeStored(BitAppTamper, LayoutServer); got != BitAppTamper {
		t.Fatalf("NormalizeStored(server, LayoutServer) = %#x, want %#x", got, BitAppTamper)
	}
	// Unknown is assumed already-server (steady state), so unchanged.
	if got := NormalizeStored(BitAppTamper, LayoutUnknown); got != BitAppTamper {
		t.Fatalf("NormalizeStored(bits, LayoutUnknown) = %#x, want %#x", got, BitAppTamper)
	}
}
