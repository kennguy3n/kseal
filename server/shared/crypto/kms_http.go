package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPKMSClient is the production KMSClient. It talks to a cloud KMS over a
// small envelope-encryption JSON API (the same shape AWS KMS Encrypt/Decrypt,
// GCP KMS encrypt/decrypt, and Azure Key Vault wrapKey/unwrapKey expose): it
// POSTs the DEK to be wrapped/unwrapped and never transmits or stores the
// customer key itself.
//
// Requests:
//
//	POST {endpoint}/v1/wrap     {"key_uri":..,"plaintext":b64}  -> {"ciphertext":b64}
//	POST {endpoint}/v1/unwrap   {"key_uri":..,"ciphertext":b64} -> {"plaintext":b64}
type HTTPKMSClient struct {
	endpoint   string
	httpClient *http.Client
	authHeader string
}

// HTTPKMSOption configures an HTTPKMSClient.
type HTTPKMSOption func(*HTTPKMSClient)

// WithHTTPClient overrides the default http.Client (e.g. to inject mTLS or a
// custom transport).
func WithHTTPClient(c *http.Client) HTTPKMSOption {
	return func(k *HTTPKMSClient) {
		if c != nil {
			k.httpClient = c
		}
	}
}

// WithAuthToken sets a bearer token sent on every KMS request.
func WithAuthToken(token string) HTTPKMSOption {
	return func(k *HTTPKMSClient) {
		if token != "" {
			k.authHeader = "Bearer " + token
		}
	}
}

// NewHTTPKMSClient builds an HTTPKMSClient for the given endpoint base URL.
func NewHTTPKMSClient(endpoint string, opts ...HTTPKMSOption) (*HTTPKMSClient, error) {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if endpoint == "" {
		return nil, fmt.Errorf("crypto: empty kms endpoint")
	}
	k := &HTTPKMSClient{
		endpoint:   endpoint,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
	for _, opt := range opts {
		opt(k)
	}
	return k, nil
}

type kmsWrapRequest struct {
	KeyURI    string `json:"key_uri"`
	Plaintext string `json:"plaintext"`
}

type kmsWrapResponse struct {
	Ciphertext string `json:"ciphertext"`
}

type kmsUnwrapRequest struct {
	KeyURI     string `json:"key_uri"`
	Ciphertext string `json:"ciphertext"`
}

type kmsUnwrapResponse struct {
	Plaintext string `json:"plaintext"`
}

// Wrap encrypts plaintextDEK under keyURI via the KMS.
func (k *HTTPKMSClient) Wrap(ctx context.Context, keyURI string, plaintextDEK []byte) ([]byte, error) {
	if keyURI == "" {
		return nil, fmt.Errorf("crypto: empty key uri")
	}
	var resp kmsWrapResponse
	err := k.do(ctx, "/v1/wrap", kmsWrapRequest{
		KeyURI:    keyURI,
		Plaintext: base64.StdEncoding.EncodeToString(plaintextDEK),
	}, &resp)
	if err != nil {
		return nil, err
	}
	wrapped, err := base64.StdEncoding.DecodeString(resp.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("kms wrap: decode ciphertext: %w", err)
	}
	if len(wrapped) == 0 {
		return nil, fmt.Errorf("kms wrap: empty ciphertext")
	}
	return wrapped, nil
}

// Unwrap decrypts wrappedDEK under keyURI via the KMS.
func (k *HTTPKMSClient) Unwrap(ctx context.Context, keyURI string, wrappedDEK []byte) ([]byte, error) {
	if keyURI == "" {
		return nil, fmt.Errorf("crypto: empty key uri")
	}
	var resp kmsUnwrapResponse
	err := k.do(ctx, "/v1/unwrap", kmsUnwrapRequest{
		KeyURI:     keyURI,
		Ciphertext: base64.StdEncoding.EncodeToString(wrappedDEK),
	}, &resp)
	if err != nil {
		return nil, err
	}
	plaintext, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("kms unwrap: decode plaintext: %w", err)
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("kms unwrap: empty plaintext")
	}
	return plaintext, nil
}

func (k *HTTPKMSClient) do(ctx context.Context, path string, reqBody, respBody interface{}) error {
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("kms encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.endpoint+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("kms new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if k.authHeader != "" {
		req.Header.Set("Authorization", k.authHeader)
	}
	resp, err := k.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("kms request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("kms read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kms %s: status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, respBody); err != nil {
		return fmt.Errorf("kms decode response: %w", err)
	}
	return nil
}
