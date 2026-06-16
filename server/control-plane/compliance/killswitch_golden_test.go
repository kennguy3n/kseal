package compliance

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// TestKillSwitchPreimageGoldenVector pins the exact canonical byte layout of the
// signed kill-switch preimage. The Rust SDK core
// (crypto::kill_switch_preimage) asserts this identical vector, so an Ed25519
// signature produced on either side verifies on the other. Layout:
//
//	u32_be(len)||DOMAIN || u32_be(len)||tenant_id || u32_be(len)||app_id ||
//	u32_be(len)||build_hash || u64_be(command) || u64_be(version) ||
//	u64_be(issued_at) || u32_be(len)||reason
func TestKillSwitchPreimageGoldenVector(t *testing.T) {
	ks := &ksealv1.SignedKillSwitch{
		TenantId:  "t1", // 2 bytes: 74 31
		AppId:     "a1", // 2 bytes: 61 31
		BuildHash: "b1", // 2 bytes: 62 31
		Command:   ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE,
		Version:   7,
		IssuedAt:  3600, // 0x0E10
		Reason:    "x",  // 1 byte: 78
	}

	want := []byte{
		// u32_be(20) || "kseal/v1/kill-switch"
		0x00, 0x00, 0x00, 0x14,
		'k', 's', 'e', 'a', 'l', '/', 'v', '1', '/', 'k', 'i', 'l', 'l', '-', 's', 'w', 'i', 't', 'c', 'h',
		// u32_be(2) || "t1"
		0x00, 0x00, 0x00, 0x02, 0x74, 0x31,
		// u32_be(2) || "a1"
		0x00, 0x00, 0x00, 0x02, 0x61, 0x31,
		// u32_be(2) || "b1"
		0x00, 0x00, 0x00, 0x02, 0x62, 0x31,
		// u64_be(2) command
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		// u64_be(7) version
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
		// u64_be(3600) issued_at
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x10,
		// u32_be(1) || "x"
		0x00, 0x00, 0x00, 0x01, 0x78,
	}

	got := killSwitchPreimage(ks)
	if !bytes.Equal(got, want) {
		t.Fatalf("preimage byte layout mismatch:\n got=%x\nwant=%x", got, want)
	}
	if len(got) != 4+20+6+6+6+8+8+8+5 {
		t.Fatalf("unexpected preimage length %d", len(got))
	}
}

// TestKillSwitchSignVerifyRoundTrip exercises the sign/verify path and confirms
// tampering invalidates the signature (the fail-safe gate).
func TestKillSwitchSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ks := &ksealv1.SignedKillSwitch{
		TenantId:  "tenant",
		AppId:     "app",
		BuildHash: "build",
		Command:   ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_DISABLE,
		Version:   9,
		IssuedAt:  1_700_000_000,
		Reason:    "incident",
	}
	signKillSwitch(priv, ks)
	if !VerifyKillSwitch(pub, ks) {
		t.Fatal("expected valid signature to verify")
	}

	tampered := &ksealv1.SignedKillSwitch{
		TenantId:  ks.TenantId,
		AppId:     ks.AppId,
		BuildHash: ks.BuildHash,
		Command:   ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_ENABLE,
		Version:   ks.Version,
		IssuedAt:  ks.IssuedAt,
		Reason:    ks.Reason,
		Signature: ks.Signature,
	}
	if VerifyKillSwitch(pub, tampered) {
		t.Fatal("tampered command must not verify")
	}
}
