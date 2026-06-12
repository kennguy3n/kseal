// Package trust implements the device trust flow: nonce issuance, attestation
// verification + trust-token minting, and per-request proof validation with
// monotonic anti-replay. Trust tokens are Ed25519-signed JWTs bound to a tenant
// signing key; request proofs are HMACs keyed by a per-session secret derived
// from the issued token.
package trust

import (
	"crypto/ed25519"
	"encoding/binary"
	"time"

	"github.com/golang-jwt/jwt/v5"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/crypto"
)

const proofKeyLabel = "kseal/v1/proof-key"

// TrustClaims is the JWT payload for a trust token.
type TrustClaims struct {
	jwt.RegisteredClaims
	TenantID        string   `json:"tid"`
	AppID           string   `json:"aid"`
	BuildHash       string   `json:"bh"`
	RiskLevel       int32    `json:"rl"`
	CapabilityScope []string `json:"cap"`
	PolicyHash      string   `json:"ph"`
}

// MintToken signs the claims with the tenant's Ed25519 private key.
func MintToken(keyID string, priv ed25519.PrivateKey, claims TrustClaims) (string, error) {
	return crypto.MintJWT(priv, keyID, claims)
}

// ValidateToken verifies a trust token's signature and standard time claims and
// returns the parsed claims. This is the hot path and avoids any I/O.
func ValidateToken(pub ed25519.PublicKey, tokenStr string) (*TrustClaims, error) {
	claims := &TrustClaims{}
	if _, err := crypto.ParseJWT(pub, tokenStr, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// DeriveProofKey derives the per-session HMAC key from the issued (signed) trust
// token. Both the server (at mint time) and the SDK derive the same key, so the
// request proof binds possession of the token without an extra shared secret.
func DeriveProofKey(signedToken []byte) []byte {
	return crypto.HMACSHA256(signedToken, []byte(proofKeyLabel))
}

// ProofMessage is the canonical byte string a request proof signs over.
func ProofMessage(tokenID string, requestHash, nonce []byte, sequence int64) []byte {
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, uint64(sequence))
	msg := make([]byte, 0, len(tokenID)+len(requestHash)+len(nonce)+8)
	msg = append(msg, tokenID...)
	msg = append(msg, requestHash...)
	msg = append(msg, nonce...)
	msg = append(msg, seq...)
	return msg
}

// tokenToProto builds the wire TrustToken from claims.
func tokenToProto(claims TrustClaims, requiredChecks []ksealv1.EventType) *ksealv1.TrustToken {
	var ttl int64
	if claims.ExpiresAt != nil && claims.IssuedAt != nil {
		ttl = int64(claims.ExpiresAt.Sub(claims.IssuedAt.Time) / time.Second)
	}
	tt := &ksealv1.TrustToken{
		TokenId:            claims.ID,
		TenantId:           claims.TenantID,
		AppId:              claims.AppID,
		BuildHash:          claims.BuildHash,
		CapabilityScope:    claims.CapabilityScope,
		TtlSeconds:         ttl,
		RiskLevel:          ksealv1.TrustLevel(claims.RiskLevel),
		PolicyHash:         claims.PolicyHash,
		RequiredNextChecks: requiredChecks,
	}
	if claims.IssuedAt != nil {
		tt.IssuedAt = claims.IssuedAt.Unix()
	}
	if claims.ExpiresAt != nil {
		tt.ExpiresAt = claims.ExpiresAt.Unix()
	}
	return tt
}
