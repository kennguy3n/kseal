package attestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v5"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/risk"
)

// ---- Play Integrity (Android) ----

type fakeKeySource map[string]crypto.PublicKey

func (f fakeKeySource) PublicKey(_ context.Context, kid string) (crypto.PublicKey, error) {
	if k, ok := f[kid]; ok {
		return k, nil
	}
	return nil, errUnknownKey
}

var errUnknownKey = asn1.StructuralError{Msg: "unknown key"}

func signPlayToken(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) []byte {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(s)
}

func TestPlayIntegrityAcceptsGenuineDevice(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := fakeKeySource{"k1": &priv.PublicKey}
	v := NewPlayIntegrityVerifier(keys)

	nonce := []byte("server-issued-nonce-bytes-32!!!!")
	claims := jwt.MapClaims{
		"requestDetails": map[string]interface{}{
			"requestPackageName": "com.x",
			"nonce":              base64.StdEncoding.EncodeToString(nonce),
		},
		"appIntegrity":    map[string]interface{}{"appRecognitionVerdict": "PLAY_RECOGNIZED"},
		"deviceIntegrity": map[string]interface{}{"deviceRecognitionVerdict": []interface{}{"MEETS_STRONG_INTEGRITY"}},
		"accountDetails":  map[string]interface{}{"appLicensingVerdict": "LICENSED"},
	}
	token := signPlayToken(t, priv, "k1", claims)

	res, err := v.Verify(context.Background(), Input{Platform: ksealv1.Platform_PLATFORM_ANDROID, Token: token, Nonce: nonce, AppID: "com.x"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Accepted || !res.AppRecognized || !res.DeviceIntegrity || !res.AccountValid {
		t.Fatalf("genuine device not fully trusted: %+v", res)
	}
	if res.RiskBits != 0 {
		t.Fatalf("unexpected risk bits %b", res.RiskBits)
	}
}

func TestPlayIntegrityFlagsCompromisedDevice(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := NewPlayIntegrityVerifier(fakeKeySource{"k1": &priv.PublicKey})
	nonce := []byte("server-issued-nonce-bytes-32!!!!")
	claims := jwt.MapClaims{
		"requestDetails":  map[string]interface{}{"nonce": base64.StdEncoding.EncodeToString(nonce)},
		"appIntegrity":    map[string]interface{}{"appRecognitionVerdict": "UNRECOGNIZED_VERSION"},
		"deviceIntegrity": map[string]interface{}{"deviceRecognitionVerdict": []interface{}{}},
		"accountDetails":  map[string]interface{}{"appLicensingVerdict": "UNLICENSED"},
	}
	res, err := v.Verify(context.Background(), Input{Platform: ksealv1.Platform_PLATFORM_ANDROID, Token: signPlayToken(t, priv, "k1", claims), Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	if res.RiskBits&risk.BitAppTamper == 0 || res.RiskBits&risk.BitDeviceIntegrity == 0 || res.RiskBits&risk.BitAccountRisk == 0 {
		t.Fatalf("expected tamper+device+account risk, got %b", res.RiskBits)
	}
}

func TestPlayIntegrityRejectsNonceMismatch(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := NewPlayIntegrityVerifier(fakeKeySource{"k1": &priv.PublicKey})
	claims := jwt.MapClaims{
		"requestDetails": map[string]interface{}{"nonce": base64.StdEncoding.EncodeToString([]byte("different"))},
	}
	res, err := v.Verify(context.Background(), Input{Platform: ksealv1.Platform_PLATFORM_ANDROID, Token: signPlayToken(t, priv, "k1", claims), Nonce: []byte("expected-nonce")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Accepted {
		t.Fatal("nonce mismatch accepted")
	}
}

func TestPlayIntegrityRejectsUnknownKey(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := NewPlayIntegrityVerifier(fakeKeySource{}) // no keys registered
	claims := jwt.MapClaims{"requestDetails": map[string]interface{}{"nonce": base64.StdEncoding.EncodeToString([]byte("n"))}}
	res, _ := v.Verify(context.Background(), Input{Platform: ksealv1.Platform_PLATFORM_ANDROID, Token: signPlayToken(t, priv, "missing", claims), Nonce: []byte("n")})
	if res.Accepted {
		t.Fatal("token with unresolved key accepted")
	}
}

// ---- App Attest (iOS) ----

func buildAuthData(appID string, credID []byte) []byte {
	rp := sha256.Sum256([]byte(appID))
	buf := make([]byte, 0, 37+18+len(credID))
	buf = append(buf, rp[:]...)
	buf = append(buf, 0x40) // AT flag set
	ctr := make([]byte, 4)
	binary.BigEndian.PutUint32(ctr, 0)
	buf = append(buf, ctr...)
	buf = append(buf, aaguidProd...)
	clen := make([]byte, 2)
	binary.BigEndian.PutUint16(clen, uint16(len(credID)))
	buf = append(buf, clen...)
	buf = append(buf, credID...)
	return buf
}

func TestAppAttestAcceptsGenuineKey(t *testing.T) {
	// Locally generated stand-in for Apple's root + attestation CA.
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Apple App Attestation Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	// Attested per-app key in the Secure Enclave.
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafPoint := elliptic.Marshal(elliptic.P256(), leafKey.PublicKey.X, leafKey.PublicKey.Y) //nolint:staticcheck // SA1019: test helper, elliptic.Marshal is fine for test fixtures
	credID := sha256.Sum256(leafPoint)

	appID := "TEAMID.com.x"
	challenge := []byte("server-challenge")
	authData := buildAuthData(appID, credID[:])

	clientDataHash := sha256.Sum256(challenge)
	h := sha256.New()
	h.Write(authData)
	h.Write(clientDataHash[:])
	expectedNonce := h.Sum(nil)

	extVal, err := asn1.Marshal(struct {
		Nonce []byte `asn1:"tag:1,explicit"`
	}{Nonce: expectedNonce})
	if err != nil {
		t.Fatal(err)
	}

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "credCert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: appAttestOID, Value: extVal},
		},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	obj := attestationObject{
		Fmt:      "apple-appattest",
		AttStmt:  appAttestStatement{X5c: [][]byte{leafDER}, Receipt: []byte("receipt")},
		AuthData: authData,
	}
	token, err := cbor.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}

	v := NewAppAttestVerifier(roots)
	res, err := v.Verify(context.Background(), Input{Platform: ksealv1.Platform_PLATFORM_IOS, Token: token, Nonce: challenge, AppID: appID})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Accepted || !res.DeviceIntegrity {
		t.Fatalf("genuine app attest not accepted: %+v", res)
	}

	// Tampering the authData breaks the nonce binding.
	bad := obj
	tampered := append([]byte(nil), authData...)
	tampered[40] ^= 0xFF
	bad.AuthData = tampered
	badToken, _ := cbor.Marshal(bad)
	badRes, _ := v.Verify(context.Background(), Input{Platform: ksealv1.Platform_PLATFORM_IOS, Token: badToken, Nonce: challenge, AppID: appID})
	if badRes.Accepted {
		t.Fatal("tampered attestation accepted")
	}
}

func TestAppAttestRejectsUntrustedRoot(t *testing.T) {
	v := NewAppAttestVerifier(x509.NewCertPool()) // empty pool trusts nothing
	res, _ := v.Verify(context.Background(), Input{Platform: ksealv1.Platform_PLATFORM_IOS, Token: []byte{0xA1}, Nonce: []byte("n"), AppID: "x"})
	if res.Accepted {
		t.Fatal("accepted with empty trust store")
	}
}

func TestVerifierUnsupportedPlatform(t *testing.T) {
	v := NewVerifier(nil, nil)
	if _, err := v.Verify(context.Background(), Input{Platform: ksealv1.Platform_PLATFORM_ANDROID}); err == nil {
		t.Fatal("expected unsupported platform error")
	}
}
