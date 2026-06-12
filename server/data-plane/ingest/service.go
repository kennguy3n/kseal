package ingest

import (
	"context"
	"errors"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
	"github.com/kennguy3n/kseal/server/shared/risk"
)

const maxDecompressedBytes = 16 << 20 // 16 MiB ceiling guards against zip bombs.

// maxAppCacheEntries caps the validator cache so adversarial traffic spraying
// distinct (tenant, app) pairs cannot grow it without bound.
const maxAppCacheEntries = 50_000

// AppValidator reports whether a (tenant, app) pair is registered. It is backed
// by a short-TTL cache over the registry so the hot ingest path avoids a DB hit
// per request.
type AppValidator interface {
	Valid(ctx context.Context, tenantID, appID string) (bool, error)
}

type cacheEntry struct {
	valid   bool
	expires time.Time
}

// CachedAppValidator caches both positive and negative registry lookups for a
// short TTL. The negative cache bounds DB load when a high-volume stream targets
// an unknown or deleted app (misconfiguration or abuse), capping it at one DB
// hit per (tenant, app) per negTTL.
type CachedAppValidator struct {
	store      registry.Store
	ttl        time.Duration
	negTTL     time.Duration
	maxEntries int

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// NewCachedAppValidator builds a validator with the given positive cache TTL.
// Negative results are cached for a shorter window (min(ttl, 5s)) so a newly
// registered app becomes visible quickly.
func NewCachedAppValidator(store registry.Store, ttl time.Duration) *CachedAppValidator {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	negTTL := 5 * time.Second
	if ttl < negTTL {
		negTTL = ttl
	}
	return &CachedAppValidator{store: store, ttl: ttl, negTTL: negTTL, maxEntries: maxAppCacheEntries, cache: map[string]cacheEntry{}}
}

// Valid returns whether the app exists for the tenant.
func (v *CachedAppValidator) Valid(ctx context.Context, tenantID, appID string) (bool, error) {
	key := tenantID + "/" + appID
	v.mu.Lock()
	if e, ok := v.cache[key]; ok && time.Now().Before(e.expires) {
		v.mu.Unlock()
		return e.valid, nil
	}
	v.mu.Unlock()

	_, err := v.store.GetApp(ctx, tenantID, appID)
	switch {
	case errors.Is(err, registry.ErrNotFound):
		v.put(key, cacheEntry{valid: false, expires: time.Now().Add(v.negTTL)})
		return false, nil
	case err != nil:
		return false, err
	default:
		v.put(key, cacheEntry{valid: true, expires: time.Now().Add(v.ttl)})
		return true, nil
	}
}

func (v *CachedAppValidator) put(key string, e cacheEntry) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.cache[key] = e
	if len(v.cache) <= v.maxEntries {
		return
	}
	// Over the cap: drop expired entries first, then evict arbitrary live ones
	// (map iteration order is randomized) until back under the cap.
	now := time.Now()
	for k, c := range v.cache {
		if !now.Before(c.expires) {
			delete(v.cache, k)
		}
	}
	for k := range v.cache {
		if len(v.cache) <= v.maxEntries {
			break
		}
		if k == key {
			continue
		}
		delete(v.cache, k)
	}
}

// Service implements the Connect IngestService.
type Service struct {
	ksealv1connect.UnimplementedIngestServiceHandler

	validator AppValidator
	quota     *Quota
	broker    Broker
	decoder   *zstd.Decoder
}

// NewService builds an IngestService. The zstd decoder is shared and safe for
// concurrent use via DecodeAll.
func NewService(validator AppValidator, quota *Quota, broker Broker) (*Service, error) {
	dec, err := zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(0),
		zstd.WithDecoderMaxMemory(maxDecompressedBytes), // cap output to guard against zip bombs
	)
	if err != nil {
		return nil, err
	}
	return &Service{validator: validator, quota: quota, broker: broker, decoder: dec}, nil
}

// SubmitTelemetry decompresses and validates a batch, enforces the tenant quota
// at the edge, and enqueues accepted events for asynchronous write.
func (s *Service) SubmitTelemetry(ctx context.Context, req *connect.Request[ksealv1.SubmitTelemetryRequest]) (*connect.Response[ksealv1.SubmitTelemetryResponse], error) {
	m := req.Msg
	if m.TenantId == "" || m.AppId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("tenant_id and app_id required"))
	}

	valid, err := s.validator.Valid(ctx, m.TenantId, m.AppId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !valid {
		return connect.NewResponse(&ksealv1.SubmitTelemetryResponse{
			Rejected: 1, RejectionReason: "unknown tenant or app",
		}), nil
	}

	raw, err := s.decompress(m.Compression, m.CompressedBatch)
	if err != nil {
		return connect.NewResponse(&ksealv1.SubmitTelemetryResponse{
			Rejected: 1, RejectionReason: "decompression failed",
		}), nil
	}
	var batch ksealv1.TelemetryBatch
	if err := proto.Unmarshal(raw, &batch); err != nil {
		return connect.NewResponse(&ksealv1.SubmitTelemetryResponse{
			Rejected: 1, RejectionReason: "malformed batch",
		}), nil
	}
	if len(batch.Events) == 0 {
		return connect.NewResponse(&ksealv1.SubmitTelemetryResponse{}), nil
	}

	allowed, _, err := s.quota.Allow(ctx, m.TenantId, len(batch.Events))
	if err == nil && !allowed {
		return connect.NewResponse(&ksealv1.SubmitTelemetryResponse{
			Rejected:        int32(len(batch.Events)),
			QuotaExceeded:   true,
			RejectionReason: "per-tenant quota exceeded",
		}), nil
	}

	now := time.Now().Unix()
	var accepted, rejected int32
	for _, ev := range batch.Events {
		if ev == nil || ev.EventType == ksealv1.EventType_EVENT_TYPE_UNSPECIFIED {
			rejected++
			continue
		}
		stored := StoredEvent{
			ID:             uuid.NewString(),
			TenantID:       m.TenantId,
			AppID:          m.AppId,
			EventType:      ev.EventType,
			RiskLevel:      risk.Level(risk.Score(ev.RiskBits, nil), nil),
			RiskBits:       ev.RiskBits,
			Confidence:     ev.Confidence,
			BuildHash:      ev.AppBuildHash,
			PolicyHash:     ev.PolicyHash,
			InstallKeyHash: ev.TenantScopedInstallKeyHash,
			TimeBucket:     coalesce(ev.CoarseTimeBucket, now),
			Country:        derefStr(ev.CountryOrRegion),
			Platform:       batch.Platform,
			ReceivedAt:     now,
		}
		if err := s.broker.Publish(ctx, stored); err != nil {
			rejected++
			continue
		}
		accepted++
	}

	return connect.NewResponse(&ksealv1.SubmitTelemetryResponse{Accepted: accepted, Rejected: rejected}), nil
}

func (s *Service) decompress(c ksealv1.Compression, data []byte) ([]byte, error) {
	switch c {
	case ksealv1.Compression_COMPRESSION_ZSTD:
		out, err := s.decoder.DecodeAll(data, make([]byte, 0, len(data)*3))
		if err != nil {
			return nil, err
		}
		if len(out) > maxDecompressedBytes {
			return nil, errors.New("payload too large")
		}
		return out, nil
	default:
		if len(data) > maxDecompressedBytes {
			return nil, errors.New("payload too large")
		}
		return data, nil
	}
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func coalesce(v, fallback int64) int64 {
	if v == 0 {
		return fallback
	}
	return v
}
