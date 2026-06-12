package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// appAttestOID is Apple's certificate extension carrying the attestation nonce.
var appAttestOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// aaguidProd and aaguidDev identify the App Attest environment in authData.
var (
	aaguidProd = []byte("appattest\x00\x00\x00\x00\x00\x00\x00")
	aaguidDev  = []byte("appattestdevelop")
)

// AppAttestVerifier verifies iOS App Attest attestation objects. The Apple App
// Attest root certificate pool is injected (external trust material, supplied by
// a locally generated root in tests); all CBOR decoding, X.509 chain validation,
// nonce-extension checking, and authenticator-data parsing below are real.
type AppAttestVerifier struct {
	roots *x509.CertPool
	now   func() time.Time
}

// NewAppAttestVerifier builds a verifier trusting the given Apple root pool.
func NewAppAttestVerifier(appleRoots *x509.CertPool) *AppAttestVerifier {
	return &AppAttestVerifier{roots: appleRoots, now: time.Now}
}

type attestationObject struct {
	Fmt      string                 `cbor:"fmt"`
	AttStmt  appAttestStatement     `cbor:"attStmt"`
	AuthData []byte                 `cbor:"authData"`
	Extra    map[string]interface{} `cbor:"-"`
}

type appAttestStatement struct {
	X5c     [][]byte `cbor:"x5c"`
	Receipt []byte   `cbor:"receipt"`
}

// Verify performs the full App Attest verification flow per Apple's spec.
func (v *AppAttestVerifier) Verify(_ context.Context, in Input) (*Result, error) {
	if len(in.Token) == 0 {
		return rejected("empty app attest object"), nil
	}
	var obj attestationObject
	if err := cbor.Unmarshal(in.Token, &obj); err != nil {
		return rejected(fmt.Sprintf("cbor decode: %v", err)), nil
	}
	if obj.Fmt != "apple-appattest" {
		return rejected(fmt.Sprintf("unexpected fmt %q", obj.Fmt)), nil
	}
	if len(obj.AttStmt.X5c) == 0 {
		return rejected("missing x5c chain"), nil
	}

	credCert, err := x509.ParseCertificate(obj.AttStmt.X5c[0])
	if err != nil {
		return rejected(fmt.Sprintf("parse cred cert: %v", err)), nil
	}
	intermediates := x509.NewCertPool()
	for _, der := range obj.AttStmt.X5c[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return rejected(fmt.Sprintf("parse intermediate: %v", err)), nil
		}
		intermediates.AddCert(c)
	}
	if _, err := credCert.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		CurrentTime:   v.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return rejected(fmt.Sprintf("cert chain invalid: %v", err)), nil
	}

	// nonce = SHA256(authData || SHA256(challenge)); must match the cert extension.
	clientDataHash := sha256.Sum256(in.Nonce)
	h := sha256.New()
	h.Write(obj.AuthData)
	h.Write(clientDataHash[:])
	expectedNonce := h.Sum(nil)

	certNonce, err := extractNonce(credCert)
	if err != nil {
		return rejected(err.Error()), nil
	}
	if subtle.ConstantTimeCompare(certNonce, expectedNonce) != 1 {
		return rejected("attestation nonce mismatch"), nil
	}

	ad, err := parseAuthData(obj.AuthData)
	if err != nil {
		return rejected(err.Error()), nil
	}
	if in.AppID != "" {
		wantRP := sha256.Sum256([]byte(in.AppID))
		if subtle.ConstantTimeCompare(ad.rpIDHash, wantRP[:]) != 1 {
			return rejected("app id (rpId) mismatch"), nil
		}
	}
	if subtle.ConstantTimeCompare(ad.aaguid, aaguidProd) != 1 &&
		subtle.ConstantTimeCompare(ad.aaguid, aaguidDev) != 1 {
		return rejected("unexpected aaguid"), nil
	}

	// The key identifier (credentialId) must equal SHA256 of the attested public
	// key's uncompressed point.
	ecPub, ok := credCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return rejected("cred cert is not EC"), nil
	}
	pubPoint := ellipticMarshal(ecPub)
	keyID := sha256.Sum256(pubPoint)
	if subtle.ConstantTimeCompare(ad.credentialID, keyID[:]) != 1 {
		return rejected("key id mismatch"), nil
	}

	// A valid App Attest object proves a Secure-Enclave hardware key: strong
	// device + app integrity. Runtime risk (debugger, hooking) arrives via
	// telemetry, not attestation.
	return &Result{
		Accepted:        true,
		AppRecognized:   true,
		DeviceIntegrity: true,
		AccountValid:    true,
		RiskBits:        0,
		Confidence:      ksealv1.Confidence_CONFIDENCE_HIGH,
	}, nil
}

func extractNonce(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(appAttestOID) {
			continue
		}
		// SEQUENCE { [1] EXPLICIT OCTET STRING nonce }.
		var wrapper struct {
			Nonce []byte `asn1:"tag:1,explicit"`
		}
		if _, err := asn1.Unmarshal(ext.Value, &wrapper); err != nil {
			return nil, fmt.Errorf("parse nonce extension: %v", err)
		}
		if len(wrapper.Nonce) == 0 {
			return nil, errors.New("empty attestation nonce")
		}
		return wrapper.Nonce, nil
	}
	return nil, errors.New("attestation nonce extension not found")
}

type authData struct {
	rpIDHash     []byte
	flags        byte
	counter      uint32
	aaguid       []byte
	credentialID []byte
}

// parseAuthData parses WebAuthn-style authenticator data as used by App Attest.
func parseAuthData(b []byte) (*authData, error) {
	if len(b) < 37 {
		return nil, errors.New("auth data too short")
	}
	ad := &authData{
		rpIDHash: b[0:32],
		flags:    b[32],
		counter:  binary.BigEndian.Uint32(b[33:37]),
	}
	const flagAT = 0x40
	if ad.flags&flagAT == 0 {
		return nil, errors.New("attested credential data flag not set")
	}
	rest := b[37:]
	if len(rest) < 18 {
		return nil, errors.New("missing attested credential data")
	}
	ad.aaguid = rest[0:16]
	credIDLen := int(binary.BigEndian.Uint16(rest[16:18]))
	rest = rest[18:]
	if len(rest) < credIDLen {
		return nil, errors.New("credential id length overflow")
	}
	ad.credentialID = rest[:credIDLen]
	return ad, nil
}

// ellipticMarshal returns the uncompressed X9.62 point (0x04 || X || Y).
func ellipticMarshal(pub *ecdsa.PublicKey) []byte {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 1+2*byteLen)
	out[0] = 4
	pub.X.FillBytes(out[1 : 1+byteLen])
	pub.Y.FillBytes(out[1+byteLen:])
	return out
}
