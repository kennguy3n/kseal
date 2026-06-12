package trust

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/kennguy3n/kseal/server/shared/crypto"
)

// consumeScript atomically reads and deletes a nonce, returning 1 if it existed.
// Single-use consumption is the anti-replay guard for the attestation step.
var consumeScript = redis.NewScript(`
local v = redis.call('get', KEYS[1])
if v then
  redis.call('del', KEYS[1])
  return 1
end
return 0
`)

// NonceStore issues and consumes single-use, short-lived nonces in Redis.
type NonceStore struct {
	client *redis.Client
	ttl    time.Duration
}

// NewNonceStore builds a nonce store with the given TTL (e.g. 5 minutes).
func NewNonceStore(client *redis.Client, ttl time.Duration) *NonceStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &NonceStore{client: client, ttl: ttl}
}

func nonceKey(tenantID string, nonce []byte) string {
	// {tenant} hash-tag keeps a tenant's keys co-located in Redis Cluster.
	return fmt.Sprintf("nonce:{%s}:%x", tenantID, nonce)
}

// Issue generates a 32-byte crypto-random nonce, stores it with the configured
// TTL, and returns it plus its absolute expiry (unix seconds).
func (n *NonceStore) Issue(ctx context.Context, tenantID, appID string) ([]byte, int64, error) {
	nonce, err := crypto.RandomNonce()
	if err != nil {
		return nil, 0, err
	}
	key := nonceKey(tenantID, nonce)
	// Value records the bound app so a nonce can only be redeemed for its app.
	if err := n.client.Set(ctx, key, appID, n.ttl).Err(); err != nil {
		return nil, 0, fmt.Errorf("store nonce: %w", err)
	}
	return nonce, time.Now().Add(n.ttl).Unix(), nil
}

// Consume atomically validates and removes a nonce, returning true if it was
// present (and therefore valid and unused). A second attempt returns false.
func (n *NonceStore) Consume(ctx context.Context, tenantID string, nonce []byte) (bool, error) {
	key := nonceKey(tenantID, nonce)
	res, err := consumeScript.Run(ctx, n.client, []string{key}).Int()
	if err != nil {
		return false, fmt.Errorf("consume nonce: %w", err)
	}
	return res == 1, nil
}
