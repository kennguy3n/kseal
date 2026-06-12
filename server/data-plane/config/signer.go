// Package config assembles and signs the per-app SignedConfig that the SDK
// fetches at runtime: it projects the active policy into the wire PolicyConfig,
// marshals it, and signs it with the tenant's Ed25519 signing key so the device
// can verify authenticity offline.
package config

import (
	"context"
	"errors"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/shared/crypto"
)

// Signer signs config bytes with a tenant's active Ed25519 signing key.
type Signer struct {
	store registry.Store
}

// NewSigner builds a config signer over the registry store.
func NewSigner(store registry.Store) *Signer { return &Signer{store: store} }

// Sign returns the signature and the signing key id for configBytes. If the
// tenant has no signing key yet, one is created so first-fetch succeeds.
func (s *Signer) Sign(ctx context.Context, tenantID string, configBytes []byte) ([]byte, string, error) {
	sk, err := s.store.GetActiveSigningKey(ctx, tenantID)
	if errors.Is(err, registry.ErrNotFound) {
		sk, err = s.store.CreateSigningKey(ctx, tenantID)
	}
	if err != nil {
		return nil, "", err
	}
	return crypto.SignEd25519(sk.Private, configBytes), sk.ID, nil
}
