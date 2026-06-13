package siem

import (
	"context"
	"testing"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/crypto"
)

func testEncryptor(t *testing.T) *crypto.Encryptor {
	t.Helper()
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	enc, err := crypto.NewEncryptor(kek)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func splunkInput(tenant string) CreateConnectorInput {
	return CreateConnectorInput{
		TenantID:         tenant,
		Kind:             ksealv1.SiemKind_SIEM_KIND_SPLUNK_HEC,
		Endpoint:         "https://splunk.example:8088",
		Secret:           []byte("hec-token"),
		SplunkIndex:      "kseal",
		SplunkSourcetype: "kseal:trust",
	}
}

func TestMemStoreCreateListDelete(t *testing.T) {
	ctx := context.Background()
	st := NewMemConnectorStore(testEncryptor(t))

	c, err := st.CreateConnector(ctx, splunkInput("t-1"))
	if err != nil {
		t.Fatal(err)
	}
	if c.AuthSecretRef == "" {
		t.Fatal("expected auth_secret_ref to be set")
	}
	if c.Format != ksealv1.SiemPayloadFormat_SIEM_PAYLOAD_FORMAT_SPLUNK_HEC {
		t.Fatalf("format not defaulted from kind: %v", c.Format)
	}
	// The connector proto must NEVER carry the secret value.
	if got := c.String(); contains(got, "hec-token") {
		t.Fatalf("secret leaked into connector proto: %s", got)
	}

	list, err := st.ListConnectors(ctx, "t-1")
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, err = %v", list, err)
	}

	// Tenant isolation: another tenant sees nothing.
	other, _ := st.ListConnectors(ctx, "t-2")
	if len(other) != 0 {
		t.Fatalf("tenant isolation breached: %v", other)
	}

	withSecret, err := st.ListActiveWithSecrets(ctx, "t-1")
	if err != nil || len(withSecret) != 1 {
		t.Fatalf("active = %v, err = %v", withSecret, err)
	}
	if string(withSecret[0].Secret) != "hec-token" {
		t.Fatalf("decrypted secret mismatch: %q", withSecret[0].Secret)
	}

	deleted, err := st.DeleteConnector(ctx, "t-1", c.Id)
	if err != nil || !deleted {
		t.Fatalf("delete = %v, err = %v", deleted, err)
	}
	deleted, _ = st.DeleteConnector(ctx, "t-1", c.Id)
	if deleted {
		t.Fatal("second delete should report false")
	}
}

func TestMemStoreRejectsDisallowedAllowList(t *testing.T) {
	in := splunkInput("t-1")
	in.FieldAllowList = []string{FieldRiskBits, "device_id"}
	_, err := NewMemConnectorStore(testEncryptor(t)).CreateConnector(context.Background(), in)
	if err == nil {
		t.Fatal("expected rejection of disallowed allow-list field")
	}
}

func TestMemStoreValidatesSentinel(t *testing.T) {
	in := CreateConnectorInput{
		TenantID: "t-1",
		Kind:     ksealv1.SiemKind_SIEM_KIND_SENTINEL,
		Endpoint: "https://dce.example",
		Secret:   []byte("bearer"),
	}
	_, err := NewMemConnectorStore(testEncryptor(t)).CreateConnector(context.Background(), in)
	if err == nil {
		t.Fatal("expected sentinel connector without dcr/stream to be rejected")
	}
}

func TestMemStoreRequiresSecretAndEndpoint(t *testing.T) {
	st := NewMemConnectorStore(testEncryptor(t))
	in := splunkInput("t-1")
	in.Secret = nil
	if _, err := st.CreateConnector(context.Background(), in); err == nil {
		t.Fatal("expected error when secret missing")
	}
	in = splunkInput("t-1")
	in.Endpoint = ""
	if _, err := st.CreateConnector(context.Background(), in); err == nil {
		t.Fatal("expected error when endpoint missing")
	}
}

func TestMemStoreRejectsInvalidEndpoint(t *testing.T) {
	st := NewMemConnectorStore(testEncryptor(t))
	for _, ep := range []string{
		"not-a-url",                 // no scheme/host
		"ftp://splunk.example:8088", // wrong scheme
		"https://",                  // missing host
		"//splunk.example",          // scheme-relative, no scheme
	} {
		in := splunkInput("t-1")
		in.Endpoint = ep
		if _, err := st.CreateConnector(context.Background(), in); err == nil {
			t.Fatalf("expected rejection of invalid endpoint %q", ep)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
