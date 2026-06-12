package crypto

import (
	"crypto/ed25519"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// MintJWT signs claims into a compact JWS using EdDSA (Ed25519). keyID is set as
// the "kid" header so verifiers can select the right public key during rotation.
func MintJWT(priv ed25519.PrivateKey, keyID string, claims jwt.Claims) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	if keyID != "" {
		tok.Header["kid"] = keyID
	}
	signed, err := tok.SignedString(priv)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signed, nil
}

// ParseJWT verifies tokenStr against pub and decodes it into claims. It enforces
// the EdDSA algorithm to prevent algorithm-confusion attacks.
func ParseJWT(pub ed25519.PublicKey, tokenStr string, claims jwt.Claims) (*jwt.Token, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	return parser.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pub, nil
	})
}
