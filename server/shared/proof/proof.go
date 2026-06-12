// Package proof provides the canonical request-proof HMAC shared by every Go
// service that issues or verifies a RequestProof.
//
// # Request proofs
//
// A request proof binds an API request to a trust token using an HMAC-SHA256
// tag keyed by the app instance's hardware-bound key. The tag is computed over
// a canonical, domain-separated, length-prefixed preimage:
//
//	preimage =
//	    u32_be(len(DOMAIN))           || DOMAIN
//	  || u32_be(len(token_id_utf8))   || token_id_utf8
//	  || u32_be(len(request_hash))    || request_hash
//	  || u32_be(len(nonce))           || nonce
//	  || i64_be(monotonic_sequence)
//
// DOMAIN = "kseal/v1/request-proof". The trailing sequence is a fixed-width
// 8-byte big-endian int64 with no length prefix; the three variable-length
// fields are length-prefixed so the framing is unambiguous.
//
// This is the byte-for-byte mirror of the Rust device core
// (sdk/rust-core/kseal-core/src/crypto.rs: proof_preimage / generate_request_proof
// / verify_request_proof). The two implementations are pinned together by a
// shared golden vector (see proof_test.go and the Rust
// proof_preimage_exact_byte_layout test): token_id="tok",
// request_hash=01 02 03 04, nonce=AA BB, seq=1, key="kseal-test-instance-key"
// yields tag 718bb06d…857ebd0d. Any divergence in field order, length-prefix
// encoding or domain string breaks proof verification, so do not change the
// layout without updating both sides and the golden vector.
package proof

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// RequestProofDomain is the domain-separation tag for the request-proof
// preimage (ASCII, 22 bytes, no NUL). It is distinct from the signed-config
// domain so a config signature can never be mistaken for a request proof and
// vice versa.
const RequestProofDomain = "kseal/v1/request-proof"

// pushLP appends a 4-byte big-endian length prefix followed by field.
//
// The length prefix is a uint32, so a field longer than math.MaxUint32 bytes
// would truncate the prefix and silently diverge from the peer's preimage,
// breaking verification. Every real field (the 22-byte domain, token id, a
// 32-byte request hash, a short nonce) is orders of magnitude smaller, so this
// is structurally impossible with well-formed input; we still panic rather than
// emit a corrupt tag, the fail-loud analogue of the Rust side's debug_assert.
func pushLP(buf []byte, field []byte) []byte {
	if uint64(len(field)) > math.MaxUint32 {
		panic("kseal/proof: length-prefixed field exceeds u32 prefix")
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(field)))
	buf = append(buf, prefix[:]...)
	return append(buf, field...)
}

// RequestProofPreimage builds the canonical, domain-separated, length-prefixed
// proof preimage. The returned bytes are exactly what is fed to HMAC-SHA256 on
// both server and device.
func RequestProofPreimage(tokenID string, requestHash, nonce []byte, seq int64) []byte {
	// 4 length-prefixed fields (4 bytes each) + payloads + 8-byte seq.
	buf := make([]byte, 0, 4*4+len(RequestProofDomain)+len(tokenID)+len(requestHash)+len(nonce)+8)
	buf = pushLP(buf, []byte(RequestProofDomain))
	buf = pushLP(buf, []byte(tokenID))
	buf = pushLP(buf, requestHash)
	buf = pushLP(buf, nonce)
	// uint64(int64) preserves the two's-complement bit pattern for all values
	// (incl. negatives), so these bytes are identical to Rust's i64::to_be_bytes.
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], uint64(seq))
	return append(buf, seqBytes[:]...)
}

// RequestProofTag computes the HMAC-SHA256 tag over the canonical preimage with
// the instance key. Mirrors the device core's generate_request_proof tag.
func RequestProofTag(key []byte, tokenID string, requestHash, nonce []byte, seq int64) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(RequestProofPreimage(tokenID, requestHash, nonce, seq))
	return mac.Sum(nil)
}

// GenerateRequestProof assembles a fully-populated RequestProof proto, binding
// the request to the trust token with an HMAC-SHA256 tag over the canonical
// preimage. This is the drop-in entry point for issuing proofs server-side.
//
// requestHash and nonce are retained by reference in the returned proto
// (standard protobuf convention; no copy) and the tag is computed over their
// contents at call time. The caller must not mutate them afterwards, or the
// proto's fields would diverge from app_instance_signature. Pass owned slices.
func GenerateRequestProof(key []byte, tokenID string, requestHash, nonce []byte, seq int64) *ksealv1.RequestProof {
	return &ksealv1.RequestProof{
		TrustTokenId:         tokenID,
		RequestHash:          requestHash,
		Nonce:                nonce,
		AppInstanceSignature: RequestProofTag(key, tokenID, requestHash, nonce, seq),
		MonotonicSequence:    seq,
	}
}

// VerifyRequestProof recomputes the tag for proof's fields under key and
// compares it to proof.AppInstanceSignature in constant time (hmac.Equal). It
// returns false for a nil proof. Callers remain responsible for anti-replay
// (the monotonic_sequence must strictly increase per token).
func VerifyRequestProof(key []byte, proof *ksealv1.RequestProof) bool {
	if proof == nil {
		return false
	}
	want := RequestProofTag(key, proof.TrustTokenId, proof.RequestHash, proof.Nonce, proof.MonotonicSequence)
	return hmac.Equal(want, proof.AppInstanceSignature)
}
