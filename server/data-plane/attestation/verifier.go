// Package attestation verifies platform attestations (Android Play Integrity,
// iOS App Attest) and maps their verdicts onto kseal risk signals. The JWS/CBOR
// parsing and signature/cert-chain verification are real; only the *external*
// trust-material sources (Google's JWKS endpoint and Apple's root CA / receipt
// endpoint) are abstracted behind injectable sources so tests can supply locally
// generated equivalents instead of calling out to Google/Apple.
package attestation

import (
	"context"
	"errors"
	"fmt"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/risk"
)

// Input is the data needed to verify one attestation.
type Input struct {
	Platform ksealv1.Platform
	// Token is the raw platform attestation: a Play Integrity JWS (Android) or a
	// CBOR App Attest attestation object (iOS).
	Token []byte
	// Nonce is the server-issued challenge the attestation must be bound to.
	Nonce []byte
	// AppID is the expected application identity: the Android package name or the
	// iOS app id "TEAMID.bundle.id".
	AppID string
}

// Result is the normalized outcome of an attestation verification.
type Result struct {
	// Accepted is true when the attestation parsed and verified cryptographically.
	Accepted bool
	// AppRecognized reports whether the platform recognized a genuine app binary.
	AppRecognized bool
	// DeviceIntegrity reports whether basic/strong device integrity was met.
	DeviceIntegrity bool
	// AccountValid reports whether the account/licensing signal was satisfactory.
	AccountValid bool
	// RiskBits are the risk signals derived from the verdict, to be fused with
	// the device-reported bits.
	RiskBits uint64
	// Confidence expresses how strongly the platform supports the verdict.
	Confidence ksealv1.Confidence
	// Reason describes a rejection or notable condition.
	Reason string
}

// PlatformVerifier verifies a single platform's attestation.
type PlatformVerifier interface {
	Verify(ctx context.Context, in Input) (*Result, error)
}

// Verifier dispatches to the correct platform verifier.
type Verifier struct {
	play      PlatformVerifier
	appAttest PlatformVerifier
}

// NewVerifier builds a dispatching verifier from platform implementations.
func NewVerifier(play, appAttest PlatformVerifier) *Verifier {
	return &Verifier{play: play, appAttest: appAttest}
}

// ErrUnsupportedPlatform indicates no verifier is configured for the platform.
var ErrUnsupportedPlatform = errors.New("attestation: unsupported platform")

// Verify dispatches to the platform verifier and never panics on bad input: a
// parse/verify failure is returned as a non-accepted Result with the attestation
// risk bit set, so the trust service can still fuse risk and respond.
func (v *Verifier) Verify(ctx context.Context, in Input) (*Result, error) {
	switch in.Platform {
	case ksealv1.Platform_PLATFORM_ANDROID:
		if v.play == nil {
			return nil, ErrUnsupportedPlatform
		}
		return v.play.Verify(ctx, in)
	case ksealv1.Platform_PLATFORM_IOS:
		if v.appAttest == nil {
			return nil, ErrUnsupportedPlatform
		}
		return v.appAttest.Verify(ctx, in)
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedPlatform, in.Platform)
	}
}

// rejected builds a non-accepted result that flags an attestation failure.
func rejected(reason string) *Result {
	return &Result{
		Accepted:   false,
		RiskBits:   risk.BitAttestationFail,
		Confidence: ksealv1.Confidence_CONFIDENCE_HIGH,
		Reason:     reason,
	}
}
