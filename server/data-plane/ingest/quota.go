package ingest

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// quotaScript increments a per-tenant fixed-window counter and reports whether
// the request fits within the window budget. Doing the increment+limit check in
// one Lua call keeps it atomic under concurrency.
var quotaScript = redis.NewScript(`
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local cost = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])

local current = tonumber(redis.call('get', key)) or 0
if current + cost > limit then
  return -1
end
local newval = redis.call('incrby', key, cost)
if newval == cost then
  redis.call('expire', key, ttl)
end
return limit - newval
`)

// Quota enforces a per-tenant per-minute event budget in Redis.
type Quota struct {
	client     *redis.Client
	perMinute  int
	windowSecs int
}

// NewQuota builds a per-minute quota enforcer.
func NewQuota(client *redis.Client, perMinute int) *Quota {
	if perMinute <= 0 {
		perMinute = 60000
	}
	return &Quota{client: client, perMinute: perMinute, windowSecs: 60}
}

// Allow attempts to consume cost units from the tenant's current window. It
// returns whether the batch fits and the remaining budget. On Redis errors it
// fails open (allows) so telemetry loss never cascades into request failures.
func (q *Quota) Allow(ctx context.Context, tenantID string, cost int) (bool, int, error) {
	window := time.Now().Unix() / int64(q.windowSecs)
	key := fmt.Sprintf("quota:{%s}:%d", tenantID, window)
	res, err := quotaScript.Run(ctx, q.client, []string{key}, q.perMinute, cost, q.windowSecs+1).Int()
	if err != nil {
		return true, 0, fmt.Errorf("quota eval: %w", err)
	}
	if res < 0 {
		return false, 0, nil
	}
	return true, res, nil
}
