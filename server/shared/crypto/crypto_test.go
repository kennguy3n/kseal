package crypto

import (
	"bytes"
	"testing"
)

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
