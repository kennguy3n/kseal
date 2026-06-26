package attestation

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

const devTokenPrefix = "dev-attestation:"

// DevVerifier accepts the fake token emitted by the mobile/desktop SDK's
// DevAttestationTokenProvider ("dev-attestation:<base64-nonce>"). It verifies
// that the nonce embedded in the token matches the server-issued one so
// anti-replay is still exercised end-to-end; it does not perform any
// cryptographic signature check.
//
// Never use this in production — it is gated behind the KSEAL_ENV=development
// check in main.go.
type DevVerifier struct{}

func (DevVerifier) Verify(_ context.Context, in Input) (*Result, error) {
	s := strings.TrimPrefix(string(in.Token), devTokenPrefix)
	if s == string(in.Token) {
		return rejected("dev verifier: missing dev-attestation prefix"), nil
	}
	// The app encodes the nonce with base64 StdEncoding (with or without padding).
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return rejected("dev verifier: invalid base64 nonce"), nil
		}
	}
	if len(in.Nonce) > 0 && !bytes.Equal(decoded, in.Nonce) {
		return rejected("dev verifier: nonce mismatch"), nil
	}
	return &Result{
		Accepted:        true,
		AppRecognized:   false,
		DeviceIntegrity: false,
		AccountValid:    false,
		Confidence:      ksealv1.Confidence_CONFIDENCE_LOW,
	}, nil
}

// NewDevVerifier builds a Verifier that accepts the SDK's dev attestation
// tokens on both Android and iOS platforms.
func NewDevVerifier() *Verifier {
	v := DevVerifier{}
	return NewVerifier(v, v)
}
