// Package config provides the canonical signed-config envelope crypto shared by
// every Go service that issues or validates a SignedConfig.
//
// # Envelope signing
//
// The Ed25519 signature authenticates the whole envelope, not just the policy
// bytes. The signed preimage is canonical, domain-separated and
// length-prefixed:
//
//	preimage =
//	    u32_be(len(DOMAIN))        || DOMAIN
//	  || i64_be(version)
//	  || i64_be(ttl_seconds)
//	  || u32_be(len(key_id_utf8))  || key_id_utf8
//	  || u32_be(len(config_bytes)) || config_bytes
//
// DOMAIN = "kseal/v1/signed-config". The two scalars are fixed-width 8-byte
// big-endian int64 (no length prefix); the variable-length key_id and
// config_bytes are length-prefixed so the framing is unambiguous.
//
// This is the byte-for-byte mirror of the Rust device core
// (sdk/rust-core/kseal-core/src/crypto.rs: signed_config_preimage /
// verify_config_envelope). The two implementations are pinned together by a
// shared golden vector (see envelope_test.go and the Rust
// signed_config_preimage_exact_byte_layout test): version=7, ttl=3600,
// key_id="k1", config_bytes=01 02 03, seed=[7u8;32] yields signature
// 8fe81cf0…f40a09. Any divergence in field order, length-prefix encoding or
// domain string breaks offline verification on device, so do not change the
// layout without updating both sides and the golden vector.
package config

import (
	"crypto/ed25519"
	"encoding/binary"
	"math"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// SignedConfigDomain is the domain-separation tag for the signed-config
// envelope preimage (ASCII, 22 bytes, no NUL). It is distinct from the
// request-proof domain so a request proof can never be mistaken for a config
// signature and vice versa.
const SignedConfigDomain = "kseal/v1/signed-config"

// pushLP appends a 4-byte big-endian length prefix followed by field.
//
// The length prefix is a uint32, so a field longer than math.MaxUint32 bytes
// would truncate the prefix and silently diverge from the peer's preimage,
// breaking cross-platform verification. Every real field (the 22-byte domain,
// key_id, and the serialized config bytes) is orders of magnitude smaller, so
// this is structurally impossible with well-formed input; we still panic rather
// than emit a corrupt signature, the fail-loud analogue of the Rust side's
// debug_assert guard.
func pushLP(buf []byte, field []byte) []byte {
	if uint64(len(field)) > math.MaxUint32 {
		panic("kseal/config: length-prefixed field exceeds u32 prefix")
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(field)))
	buf = append(buf, prefix[:]...)
	return append(buf, field...)
}

// SignedConfigPreimage builds the canonical, domain-separated, length-prefixed
// signing preimage for a SignedConfig envelope. The returned bytes are exactly
// what is fed to Ed25519 sign/verify on both server and device.
func SignedConfigPreimage(version, ttlSeconds int64, keyID string, configBytes []byte) []byte {
	// 4 + len(DOMAIN) + 8 + 8 + 4 + len(keyID) + 4 + len(configBytes).
	buf := make([]byte, 0, 4+len(SignedConfigDomain)+8+8+4+len(keyID)+4+len(configBytes))
	buf = pushLP(buf, []byte(SignedConfigDomain))
	// uint64(int64) preserves the two's-complement bit pattern for all values
	// (incl. negatives), so these bytes are identical to Rust's i64::to_be_bytes.
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], uint64(version))
	buf = append(buf, scalar[:]...)
	binary.BigEndian.PutUint64(scalar[:], uint64(ttlSeconds))
	buf = append(buf, scalar[:]...)
	buf = pushLP(buf, []byte(keyID))
	buf = pushLP(buf, configBytes)
	return buf
}

// SignConfigEnvelope signs the canonical envelope preimage with priv and
// returns the raw 64-byte Ed25519 signature. Ed25519 is deterministic
// (RFC 8032), so a given (key, preimage) pair always yields the same signature.
func SignConfigEnvelope(priv ed25519.PrivateKey, version, ttlSeconds int64, keyID string, configBytes []byte) []byte {
	return ed25519.Sign(priv, SignedConfigPreimage(version, ttlSeconds, keyID, configBytes))
}

// VerifyConfigEnvelope reports whether signature is a valid Ed25519 signature
// by pub over the canonical envelope preimage. It returns false (never panics)
// for a malformed public key or signature length.
//
// Verification direction matters. In this architecture the server is the sole
// signer and the Rust device core is the verifier, where it uses the stricter
// verify_strict (rejects non-canonical points and a non-canonical scalar S).
// This Go path uses stdlib ed25519.Verify (RFC 8032 cofactored), which is
// correct here because the server's own ed25519.Sign always produces canonical
// signatures — so any signature this package accepts, the device also accepts.
// The asymmetry only matters if the direction were reversed (device-signed,
// Go-verified): Go's more permissive check could then accept signatures the
// device's verify_strict would reject. Do not verify externally-produced
// signatures with this function without switching to a strict verifier.
func VerifyConfigEnvelope(pub ed25519.PublicKey, version, ttlSeconds int64, keyID string, configBytes, signature []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, SignedConfigPreimage(version, ttlSeconds, keyID, configBytes), signature)
}

// SignConfig assembles a fully-populated SignedConfig: it signs the envelope
// over (version, ttlSeconds, keyID, configBytes) and returns the proto the SDK
// fetches from the CDN. This is the drop-in entry point for the control plane's
// config signer.
//
// configBytes is retained by reference in the returned proto (standard protobuf
// convention; no copy), and the signature is computed over its contents at call
// time. The caller must not mutate configBytes afterwards, or the proto's bytes
// would diverge from its signature and fail verification on device. Pass an
// owned/immutable slice.
func SignConfig(priv ed25519.PrivateKey, version, ttlSeconds int64, keyID string, configBytes []byte) *ksealv1.SignedConfig {
	return &ksealv1.SignedConfig{
		ConfigBytes: configBytes,
		Signature:   SignConfigEnvelope(priv, version, ttlSeconds, keyID, configBytes),
		KeyId:       keyID,
		Version:     version,
		TtlSeconds:  ttlSeconds,
	}
}

// VerifySignedConfig verifies the envelope signature carried by a SignedConfig
// proto against pub. It is the inverse of SignConfig and mirrors the device
// core's verify_and_decode entry point.
func VerifySignedConfig(pub ed25519.PublicKey, sc *ksealv1.SignedConfig) bool {
	if sc == nil {
		return false
	}
	return VerifyConfigEnvelope(pub, sc.Version, sc.TtlSeconds, sc.KeyId, sc.ConfigBytes, sc.Signature)
}
