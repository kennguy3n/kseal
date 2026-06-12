package proof

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// goldenProofTagHex is the deterministic HMAC-SHA256 tag the Rust core pins in
// proof_preimage_exact_byte_layout. The Go signer must reproduce it.
const goldenProofTagHex = "718bb06df45dc4bbc5bf483bd65acf7609429966adba8baff66fa965857ebd0d"

// TestRequestProofPreimageExactByteLayout pins the canonical preimage bytes and
// the golden HMAC tag to the same fixed vector asserted on the Rust side, so the
// cross-platform contract is checked from both ends.
func TestRequestProofPreimageExactByteLayout(t *testing.T) {
	const (
		tokenID       = "tok" // 74 6f 6b
		seq     int64 = 1
	)
	requestHash := []byte{0x01, 0x02, 0x03, 0x04}
	nonce := []byte{0xAA, 0xBB}

	var want []byte
	// u32_be(22) || "kseal/v1/request-proof"
	want = append(want, 0x00, 0x00, 0x00, 0x16)
	want = append(want, []byte("kseal/v1/request-proof")...)
	// u32_be(3) || "tok"
	want = append(want, 0x00, 0x00, 0x00, 0x03, 0x74, 0x6f, 0x6b)
	// u32_be(4) || 01 02 03 04
	want = append(want, 0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04)
	// u32_be(2) || AA BB
	want = append(want, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB)
	// i64_be(1)
	want = append(want, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)

	got := RequestProofPreimage(tokenID, requestHash, nonce, seq)
	if !bytes.Equal(got, want) {
		t.Fatalf("preimage mismatch:\n got=%x\nwant=%x", got, want)
	}
	if wantLen := 16 + 22 + 3 + 4 + 2 + 8; len(got) != wantLen {
		t.Fatalf("preimage length = %d, want %d", len(got), wantLen)
	}

	key := []byte("kseal-test-instance-key")
	tagHex := hex.EncodeToString(RequestProofTag(key, tokenID, requestHash, nonce, seq))
	if tagHex != goldenProofTagHex {
		t.Fatalf("golden HMAC tag mismatch:\n got=%s\nwant=%s", tagHex, goldenProofTagHex)
	}
}

func TestGenerateAndVerifyRoundTrip(t *testing.T) {
	key := []byte("hw-bound-instance-key")
	rh := sha256.Sum256([]byte("POST /pay {amount:100}"))
	nonce := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33}

	p := GenerateRequestProof(key, "tok-1", rh[:], nonce, 1)
	if !VerifyRequestProof(key, p) {
		t.Fatal("freshly generated proof must verify")
	}

	// A different sequence number yields a different tag.
	replay := &ksealv1.RequestProof{
		TrustTokenId:         p.TrustTokenId,
		RequestHash:          p.RequestHash,
		Nonce:                p.Nonce,
		AppInstanceSignature: p.AppInstanceSignature,
		MonotonicSequence:    2,
	}
	if VerifyRequestProof(key, replay) {
		t.Fatal("sequence tampering must fail verification")
	}

	// A different key fails.
	if VerifyRequestProof([]byte("other-key"), p) {
		t.Fatal("wrong key must fail verification")
	}
}

// TestTamperedProofFieldsFailVerification proves every authenticated field is
// bound by the tag.
func TestTamperedProofFieldsFailVerification(t *testing.T) {
	key := []byte("k")
	p := GenerateRequestProof(key, "tok", []byte{0x01, 0x02}, []byte{0x09}, 5)

	cases := []struct {
		name   string
		mutate func(c *ksealv1.RequestProof)
	}{
		{"token_id", func(c *ksealv1.RequestProof) { c.TrustTokenId = "tok2" }},
		{"request_hash", func(c *ksealv1.RequestProof) { c.RequestHash = []byte{0x01, 0x03} }},
		{"nonce", func(c *ksealv1.RequestProof) { c.Nonce = []byte{0x0A} }},
		{"monotonic_sequence", func(c *ksealv1.RequestProof) { c.MonotonicSequence = 6 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := &ksealv1.RequestProof{
				TrustTokenId:         p.TrustTokenId,
				RequestHash:          append([]byte(nil), p.RequestHash...),
				Nonce:                append([]byte(nil), p.Nonce...),
				AppInstanceSignature: append([]byte(nil), p.AppInstanceSignature...),
				MonotonicSequence:    p.MonotonicSequence,
			}
			tc.mutate(tampered)
			if VerifyRequestProof(key, tampered) {
				t.Fatalf("tampering %s must fail verification", tc.name)
			}
		})
	}
}

func TestVerifyRejectsNil(t *testing.T) {
	if VerifyRequestProof([]byte("k"), nil) {
		t.Fatal("nil proof must not verify")
	}
}
