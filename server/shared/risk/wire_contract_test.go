package risk

import "testing"

// TestServerBitLayoutContract pins the server-side risk-bit positions. The
// device/wire layout, the policy weight table, the simulator, and the SIEM
// field mapping all assume these exact positions; a silent renumber here is a
// latent foot-gun (a single uint64 being interpreted under two layouts), so any
// change must break this test deliberately.
func TestServerBitLayoutContract(t *testing.T) {
	want := map[string]uint64{
		"root_jailbreak":      1 << 0,
		"debugger":            1 << 1,
		"emulator":            1 << 2,
		"hooking":             1 << 3,
		"app_tamper":          1 << 4,
		"attestation_fail":    1 << 5,
		"network_mitm":        1 << 6,
		"account_risk":        1 << 7,
		"device_integrity":    1 << 8,
		"app_unrecognized":    1 << 9,
		"environment_risk":    1 << 10,
		"screen_capture":      1 << 11,
		"overlay_abuse":       1 << 12,
		"accessibility_abuse": 1 << 13,
		"malicious_ime":       1 << 14,
		"remote_access":       1 << 15,
		"fleet_anomaly":       1 << 32,
	}
	got := map[string]uint64{
		"root_jailbreak":      BitRootJailbreak,
		"debugger":            BitDebugger,
		"emulator":            BitEmulator,
		"hooking":             BitHooking,
		"app_tamper":          BitAppTamper,
		"attestation_fail":    BitAttestationFail,
		"network_mitm":        BitNetworkMITM,
		"account_risk":        BitAccountRisk,
		"device_integrity":    BitDeviceIntegrity,
		"app_unrecognized":    BitAppUnrecognized,
		"environment_risk":    BitEnvironmentRisk,
		"screen_capture":      BitScreenCapture,
		"overlay_abuse":       BitOverlayAbuse,
		"accessibility_abuse": BitAccessibilityAbuse,
		"malicious_ime":       BitMaliciousIME,
		"remote_access":       BitRemoteAccess,
		"fleet_anomaly":       BitFleetAnomaly,
	}
	for name, w := range want {
		if got[name] != w {
			t.Fatalf("server bit %q = %#x, want %#x", name, got[name], w)
		}
	}
}

// TestFleetAnomalyBitClearOfWireRange asserts the server-derived fleet bit lives
// well above the device-reported wire range (0..20), so a device can never
// forge it and it can never collide with a translated wire bit.
func TestFleetAnomalyBitClearOfWireRange(t *testing.T) {
	if BitFleetAnomaly <= (uint64(1) << maxWireBit) {
		t.Fatalf("BitFleetAnomaly %#x must sit above the wire range (<= 1<<%d)", BitFleetAnomaly, maxWireBit)
	}
	// It must also not coincide with any server bit a wire bit maps onto.
	for i := 0; i <= maxWireBit; i++ {
		if wireToServer[i]&BitFleetAnomaly != 0 {
			t.Fatalf("wire bit %d maps onto BitFleetAnomaly", i)
		}
	}
}

// TestWireToServerContract pins the full device/wire -> server translation. The
// two namespaces are distinct (the canonical example: wire bit 4 is DEBUGGER
// but server bit 4 is APP_TAMPER), so FromWire MUST remap rather than fuse raw.
// Keep this table in lockstep with sdk/rust-core/kseal-core/src/risk.rs
// (pinned there by test_risk_bit_layout_contract).
func TestWireToServerContract(t *testing.T) {
	cases := []struct {
		name     string
		wireBit  int
		wantMask uint64
	}{
		{"ROOT", 0, BitRootJailbreak},
		{"JAILBREAK", 1, BitRootJailbreak},
		{"EMULATOR", 2, BitEmulator},
		{"SIMULATOR", 3, BitEmulator},
		{"DEBUGGER", 4, BitDebugger},
		{"HOOKING", 5, BitHooking},
		{"TAMPER", 6, BitAppTamper},
		{"APP_INTEGRITY", 7, BitAppTamper},
		{"NETWORK_MITM", 8, BitNetworkMITM},
		{"ENVIRONMENT", 9, BitEnvironmentRisk},
		{"PROXY", 10, BitEnvironmentRisk},
		{"USER_CA", 11, BitNetworkMITM},
		{"PINNING_FAILURE", 12, BitNetworkMITM},
		{"ATTESTATION_FAIL", 13, BitAttestationFail},
		{"SECURE_HW_MISSING", 14, BitDeviceIntegrity},
		{"REPACKAGED", 15, BitAppTamper},
		{"SCREEN_CAPTURE", 16, BitScreenCapture},
		{"OVERLAY_ABUSE", 17, BitOverlayAbuse},
		{"ACCESSIBILITY_ABUSE", 18, BitAccessibilityAbuse},
		{"MALICIOUS_IME", 19, BitMaliciousIME},
		{"REMOTE_ACCESS", 20, BitRemoteAccess},
	}
	if len(cases) != maxWireBit+1 {
		t.Fatalf("contract covers %d wire bits, expected %d", len(cases), maxWireBit+1)
	}
	for _, c := range cases {
		got := FromWire(uint64(1) << uint(c.wireBit))
		if got != c.wantMask {
			t.Fatalf("FromWire(wire %s, bit %d) = %#x, want %#x", c.name, c.wireBit, got, c.wantMask)
		}
	}

	// The foot-gun guard: raw fusion of the wire DEBUGGER bit would have meant
	// server APP_TAMPER. Translation must prevent that.
	const wireDebugger = uint64(1) << 4
	if FromWire(wireDebugger)&BitAppTamper != 0 {
		t.Fatal("wire DEBUGGER bit must not translate to server APP_TAMPER")
	}
	if FromWire(wireDebugger) != BitDebugger {
		t.Fatalf("wire DEBUGGER must map to BitDebugger, got %#x", FromWire(wireDebugger))
	}
}

// TestFromWireDropsUnknownBits asserts wire bits above the known range carry no
// server meaning and are dropped rather than scored against an unrelated bit.
func TestFromWireDropsUnknownBits(t *testing.T) {
	above := uint64(1) << (maxWireBit + 1)
	if got := FromWire(above); got != 0 {
		t.Fatalf("unknown wire bit must drop to 0, got %#x", got)
	}
	// A mix of a known and an unknown bit keeps only the known translation.
	if got := FromWire(above | (uint64(1) << 2)); got != BitEmulator {
		t.Fatalf("mixed known/unknown wire bits = %#x, want %#x", got, BitEmulator)
	}
}

// TestFromWireUnionOfBits asserts multiple set wire bits union their server
// masks (e.g. ROOT+ATTESTATION_FAIL).
func TestFromWireUnionOfBits(t *testing.T) {
	wire := (uint64(1) << 0) | (uint64(1) << 13) // ROOT | ATTESTATION_FAIL
	want := BitRootJailbreak | BitAttestationFail
	if got := FromWire(wire); got != want {
		t.Fatalf("FromWire union = %#x, want %#x", got, want)
	}
}
