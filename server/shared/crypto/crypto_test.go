package crypto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestRequestProofPreimageFixedVector pins the exact byte layout shared with the
// Rust SDK core (S2). The hex vector below is the canonical fixed vector; S2
// asserts the identical bytes so generate/validate are proven byte-identical.
func TestRequestProofPreimageFixedVector(t *testing.T) {
	const (
		tokenID = "tok_123"
		seq     = int64(7)
	)
	requestHash := []byte{0x01, 0x02, 0x03, 0x04}
	nonce := []byte{0xaa, 0xbb}

	got := RequestProofPreimage(tokenID, requestHash, nonce, seq)

	// Independent reconstruction of the documented layout.
	var want bytes.Buffer
	writeLP := func(b []byte) {
		_ = binary.Write(&want, binary.BigEndian, uint32(len(b)))
		want.Write(b)
	}
	writeLP([]byte("kseal/v1/request-proof"))
	writeLP([]byte(tokenID))
	writeLP(requestHash)
	writeLP(nonce)
	_ = binary.Write(&want, binary.BigEndian, seq)

	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("preimage mismatch:\n got=%x\nwant=%x", got, want.Bytes())
	}

	const fixedVector = "00000016" + // u32 len(domain)=22
		"6b7365616c2f76312f726571756573742d70726f6f66" + // "kseal/v1/request-proof"
		"00000007" + "746f6b5f313233" + // u32 len(token)=7, "tok_123"
		"00000004" + "01020304" + // u32 len(reqHash)=4, bytes
		"00000002" + "aabb" + // u32 len(nonce)=2, bytes
		"0000000000000007" // i64 sequence=7
	if h := hex.EncodeToString(got); h != fixedVector {
		t.Fatalf("fixed vector mismatch:\n got=%s\nwant=%s", h, fixedVector)
	}
}

// TestRequestProofGoldenHMACVector asserts the full HMAC-SHA256 tag over the
// request-proof preimage matches S2's locked golden vector. Matching the tag
// (not just the preimage) proves the two implementations are byte-identical end
// to end, including the keyed hash.
func TestRequestProofGoldenHMACVector(t *testing.T) {
	key := []byte("kseal-test-instance-key")
	const (
		tokenID = "tok"
		seq     = int64(1)
	)
	requestHash := []byte{0x01, 0x02, 0x03, 0x04}
	nonce := []byte{0xAA, 0xBB}

	const wantHex = "718bb06df45dc4bbc5bf483bd65acf7609429966adba8baff66fa965857ebd0d"
	tag := HMACSHA256(key, RequestProofPreimage(tokenID, requestHash, nonce, seq))
	if h := hex.EncodeToString(tag); h != wantHex {
		t.Fatalf("golden HMAC mismatch:\n got=%s\nwant=%s", h, wantHex)
	}
	if !VerifyHMACSHA256(key, RequestProofPreimage(tokenID, requestHash, nonce, seq), tag) {
		t.Fatal("constant-time verify rejected the golden tag")
	}
}

func TestEd25519SignVerify(t *testing.T) {
	kp, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("attest-this")
	sig := SignEd25519(kp.Private, msg)
	if !VerifyEd25519(kp.Public, msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if VerifyEd25519(kp.Public, []byte("tampered"), sig) {
		t.Fatal("tampered message accepted")
	}
}

func TestHMAC(t *testing.T) {
	key := []byte("k")
	tag := HMACSHA256(key, []byte("m"))
	if !VerifyHMACSHA256(key, []byte("m"), tag) {
		t.Fatal("valid hmac rejected")
	}
	if VerifyHMACSHA256(key, []byte("m2"), tag) {
		t.Fatal("wrong message accepted")
	}
}

func TestRandomNonce(t *testing.T) {
	a, err := RandomNonce()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != NonceSize {
		t.Fatalf("nonce len %d", len(a))
	}
	b, _ := RandomNonce()
	if bytes.Equal(a, b) {
		t.Fatal("nonces should differ")
	}
}

func TestEncryptorRoundTrip(t *testing.T) {
	kek := bytes.Repeat([]byte{7}, 32)
	enc, err := NewEncryptor(kek)
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("private-key-material")
	sealed, err := enc.Seal(pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, pt) {
		t.Fatal("plaintext leaked into ciphertext")
	}
	out, err := enc.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatal("round trip mismatch")
	}
}

func TestEncryptorRejectsBadKEK(t *testing.T) {
	if _, err := NewEncryptor([]byte("short")); err == nil {
		t.Fatal("expected error for short KEK")
	}
}
