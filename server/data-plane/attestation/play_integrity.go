package attestation

import (
	"context"
	"crypto"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/risk"
)

// KeySource resolves the public key used to verify a Play Integrity token by
// key id. In production this is backed by Google's JWKS endpoint; THIS is the
// only external dependency and it is mocked in tests with a static key set. The
// JWS parsing and signature verification below are fully real.
type KeySource interface {
	PublicKey(ctx context.Context, keyID string) (crypto.PublicKey, error)
}

// PlayIntegrityVerifier verifies Android Play Integrity verdict tokens.
type PlayIntegrityVerifier struct {
	keys KeySource
}

// NewPlayIntegrityVerifier builds a verifier over the given key source.
func NewPlayIntegrityVerifier(keys KeySource) *PlayIntegrityVerifier {
	return &PlayIntegrityVerifier{keys: keys}
}

// Verify parses and cryptographically verifies the Play Integrity JWS, binds it
// to the issued nonce and expected package, and maps the verdict to risk signals.
func (v *PlayIntegrityVerifier) Verify(ctx context.Context, in Input) (*Result, error) {
	if len(in.Token) == 0 {
		return rejected("empty play integrity token"), nil
	}
	keyfunc := func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		return v.keys.PublicKey(ctx, kid)
	}
	claims := jwt.MapClaims{}
	_, err := jwt.NewParser(jwt.WithValidMethods([]string{"RS256", "PS256", "ES256"})).
		ParseWithClaims(string(in.Token), claims, keyfunc)
	if err != nil {
		return rejected(fmt.Sprintf("jws verification failed: %v", err)), nil
	}

	// Bind the verdict to the server-issued nonce (anti-replay).
	if err := checkNonce(claims, in.Nonce); err != nil {
		return rejected(err.Error()), nil
	}
	// Bind to the expected package name when present.
	if in.AppID != "" {
		if pkg := nestedString(claims, "requestDetails", "requestPackageName"); pkg != "" && pkg != in.AppID {
			return rejected(fmt.Sprintf("package mismatch: got %q want %q", pkg, in.AppID)), nil
		}
	}

	res := &Result{Accepted: true, Confidence: ksealv1.Confidence_CONFIDENCE_MEDIUM}

	switch nestedString(claims, "appIntegrity", "appRecognitionVerdict") {
	case "PLAY_RECOGNIZED":
		res.AppRecognized = true
	case "UNRECOGNIZED_VERSION":
		res.RiskBits |= risk.BitAppTamper | risk.BitAppUnrecognized
	default:
		res.RiskBits |= risk.BitAppUnrecognized
	}

	device := nestedStringSlice(claims, "deviceIntegrity", "deviceRecognitionVerdict")
	switch {
	case containsStr(device, "MEETS_STRONG_INTEGRITY"):
		res.DeviceIntegrity = true
		res.Confidence = ksealv1.Confidence_CONFIDENCE_HIGH
	case containsStr(device, "MEETS_DEVICE_INTEGRITY"):
		res.DeviceIntegrity = true
	case containsStr(device, "MEETS_BASIC_INTEGRITY"):
		// Basic only: rooting/integrity could not be strongly established.
		res.RiskBits |= risk.BitDeviceIntegrity
	default:
		res.RiskBits |= risk.BitDeviceIntegrity | risk.BitRootJailbreak
	}
	if containsStr(device, "MEETS_VIRTUAL_INTEGRITY") {
		res.RiskBits |= risk.BitEmulator
	}

	switch nestedString(claims, "accountDetails", "appLicensingVerdict") {
	case "LICENSED":
		res.AccountValid = true
	case "UNLICENSED":
		res.RiskBits |= risk.BitAccountRisk
	}

	return res, nil
}

func checkNonce(claims jwt.MapClaims, nonce []byte) error {
	got := nestedString(claims, "requestDetails", "nonce")
	if got == "" {
		return errors.New("missing nonce in verdict")
	}
	// Play Integrity nonces are base64 (standard or URL). Accept either.
	want := nonce
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := enc.DecodeString(got); err == nil {
			if subtle.ConstantTimeCompare(decoded, want) == 1 {
				return nil
			}
		}
	}
	return errors.New("nonce mismatch")
}

func nestedString(claims jwt.MapClaims, path ...string) string {
	cur := map[string]interface{}(claims)
	for i, key := range path {
		val, ok := cur[key]
		if !ok {
			return ""
		}
		if i == len(path)-1 {
			s, _ := val.(string)
			return s
		}
		next, ok := val.(map[string]interface{})
		if !ok {
			return ""
		}
		cur = next
	}
	return ""
}

func nestedStringSlice(claims jwt.MapClaims, path ...string) []string {
	cur := map[string]interface{}(claims)
	for i, key := range path {
		val, ok := cur[key]
		if !ok {
			return nil
		}
		if i == len(path)-1 {
			arr, ok := val.([]interface{})
			if !ok {
				return nil
			}
			out := make([]string, 0, len(arr))
			for _, e := range arr {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
			return out
		}
		next, ok := val.(map[string]interface{})
		if !ok {
			return nil
		}
		cur = next
	}
	return nil
}

func containsStr(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
