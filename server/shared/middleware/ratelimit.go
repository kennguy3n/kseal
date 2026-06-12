package middleware

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// tokenBucketScript atomically refills and consumes from a token bucket stored
// in two Redis keys (tokens + last-refill timestamp). It returns 1 when a token
// was granted and 0 when the bucket is empty. Doing this in a single Lua script
// keeps the operation race-free across replicas.
var tokenBucketScript = redis.NewScript(`
local tokens_key = KEYS[1]
local ts_key = KEYS[2]
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

local tokens = tonumber(redis.call('get', tokens_key))
local last = tonumber(redis.call('get', ts_key))
if tokens == nil then
  tokens = capacity
  last = now
end

local delta = math.max(0, now - last)
local refilled = math.min(capacity, tokens + delta * rate)

local allowed = 0
if refilled >= cost then
  refilled = refilled - cost
  allowed = 1
end

local ttl = math.ceil(capacity / rate) + 1
redis.call('set', tokens_key, refilled, 'EX', ttl)
redis.call('set', ts_key, now, 'EX', ttl)
return allowed
`)

// RedisRateLimiter is a per-key token-bucket limiter backed by Redis.
type RedisRateLimiter struct {
	client   *redis.Client
	rate     float64 // tokens per second
	capacity int
	prefix   string
}

// NewRedisRateLimiter builds a limiter refilling at ratePerSecond up to capacity.
func NewRedisRateLimiter(client *redis.Client, ratePerSecond float64, capacity int, prefix string) *RedisRateLimiter {
	if prefix == "" {
		prefix = "rl"
	}
	return &RedisRateLimiter{client: client, rate: ratePerSecond, capacity: capacity, prefix: prefix}
}

// Allow reports whether one unit may proceed for key. It fails open on Redis
// errors so a limiter outage degrades to "no limiting" rather than an outage of
// the whole API — the data plane must shed load gracefully, not hard-fail.
func (l *RedisRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return l.AllowN(ctx, key, 1)
}

// AllowN consumes cost tokens for key.
func (l *RedisRateLimiter) AllowN(ctx context.Context, key string, cost int) (bool, error) {
	now := float64(time.Now().UnixNano()) / 1e9
	tokensKey := fmt.Sprintf("%s:{%s}:tokens", l.prefix, key)
	tsKey := fmt.Sprintf("%s:{%s}:ts", l.prefix, key)
	res, err := tokenBucketScript.Run(ctx, l.client,
		[]string{tokensKey, tsKey},
		l.rate, l.capacity, now, cost).Int()
	if err != nil {
		return true, fmt.Errorf("rate limit eval: %w", err)
	}
	return res == 1, nil
}
