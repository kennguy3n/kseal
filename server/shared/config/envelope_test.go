package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// goldenSeed is the fixed Ed25519 seed shared with the Rust device core
// (SigningKey::from_bytes(&[7u8; 32])). ed25519.NewKeyFromSeed consumes the
// same 32-byte seed, so both sides derive the identical key pair.
func goldenSeed() []byte { return bytes.Repeat([]byte{7}, ed25519.SeedSize) }

// goldenSignedConfigSigHex is the deterministic Ed25519 signature the Rust core
// pins in signed_config_preimage_exact_byte_layout. The Go signer must
// reproduce it byte-for-byte.
const goldenSignedConfigSigHex = "8fe81cf02eb57b7fdba657b35cfb5b9cbc33c0325e1dbca3c8f46765b837ab8645e02f7074f57bbfbb1c9c690b7a06803529ad6a43624f119c52015d71f40a09"

// TestSignedConfigPreimageExactByteLayout pins the canonical preimage bytes to
// the same fixed vector asserted on the Rust side, so the cross-platform
// contract is checked from both ends.
func TestSignedConfigPreimageExactByteLayout(t *testing.T) {
	const (
		version    int64 = 7
		ttlSeconds int64 = 3600 // 0x0E10
		keyID            = "k1" // 6b 31
	)
	configBytes := []byte{0x01, 0x02, 0x03}

	var want []byte
	// u32_be(22) || "kseal/v1/signed-config"
	want = append(want, 0x00, 0x00, 0x00, 0x16)
	want = append(want, []byte("kseal/v1/signed-config")...)
	// i64_be(7)
	want = append(want, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07)
	// i64_be(3600)
	want = append(want, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x10)
	// u32_be(2) || "k1"
	want = append(want, 0x00, 0x00, 0x00, 0x02, 0x6b, 0x31)
	// u32_be(3) || 01 02 03
	want = append(want, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03)

	got := SignedConfigPreimage(version, ttlSeconds, keyID, configBytes)
	if !bytes.Equal(got, want) {
		t.Fatalf("preimage mismatch:\n got=%x\nwant=%x", got, want)
	}
	if wantLen := 4 + 22 + 8 + 8 + 4 + 2 + 4 + 3; len(got) != wantLen {
		t.Fatalf("preimage length = %d, want %d", len(got), wantLen)
	}

	// Deterministic Ed25519 signature must equal the shared golden vector.
	priv := ed25519.NewKeyFromSeed(goldenSeed())
	sigHex := hex.EncodeToString(SignConfigEnvelope(priv, version, ttlSeconds, keyID, configBytes))
	if sigHex != goldenSignedConfigSigHex {
		t.Fatalf("golden signature mismatch:\n got=%s\nwant=%s", sigHex, goldenSignedConfigSigHex)
	}

	pub := priv.Public().(ed25519.PublicKey)
	if !VerifyConfigEnvelope(pub, version, ttlSeconds, keyID, configBytes, SignConfigEnvelope(priv, version, ttlSeconds, keyID, configBytes)) {
		t.Fatal("envelope must verify against its own signature")
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)

	sc := SignConfig(priv, 12, 600, "key-2024", []byte("serialized-policy"))
	if !VerifySignedConfig(pub, sc) {
		t.Fatal("freshly signed config must verify")
	}
}

// TestTamperedEnvelopeFieldsFailVerification proves the envelope authenticates
// version, ttl_seconds and key_id — not just config_bytes — closing the
// CDN/cache tamper vector.
func TestTamperedEnvelopeFieldsFailVerification(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x09}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	sc := SignConfig(priv, 5, 3600, "k1", []byte{0xde, 0xad})

	cases := []struct {
		name   string
		mutate func(c *ksealv1.SignedConfig)
	}{
		{"version", func(c *ksealv1.SignedConfig) { c.Version = 6 }},
		{"ttl_seconds", func(c *ksealv1.SignedConfig) { c.TtlSeconds = 86400 }},
		{"key_id", func(c *ksealv1.SignedConfig) { c.KeyId = "k2" }},
		{"config_bytes", func(c *ksealv1.SignedConfig) { c.ConfigBytes = []byte{0xbe, 0xef} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := &ksealv1.SignedConfig{
				ConfigBytes: append([]byte(nil), sc.ConfigBytes...),
				Signature:   append([]byte(nil), sc.Signature...),
				KeyId:       sc.KeyId,
				Version:     sc.Version,
				TtlSeconds:  sc.TtlSeconds,
			}
			tc.mutate(tampered)
			if VerifySignedConfig(pub, tampered) {
				t.Fatalf("tampering %s must fail verification", tc.name)
			}
		})
	}
}

func TestVerifyRejectsMalformedInputs(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(goldenSeed())
	good := SignConfigEnvelope(priv, 1, 1, "k", nil)
	pub := priv.Public().(ed25519.PublicKey)

	if VerifyConfigEnvelope([]byte{0x00}, 1, 1, "k", nil, good) {
		t.Fatal("short public key must not verify")
	}
	if VerifyConfigEnvelope(pub, 1, 1, "k", nil, []byte{0x00}) {
		t.Fatal("short signature must not verify")
	}
	if VerifySignedConfig(pub, nil) {
		t.Fatal("nil SignedConfig must not verify")
	}
}
