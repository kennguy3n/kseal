package ingest

import (
	"context"
	"errors"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
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

	tracer     trace.Tracer
	acceptedC  metric.Int64Counter
	rejectedC  metric.Int64Counter
	batchSizeH metric.Int64Histogram
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
	s := &Service{validator: validator, quota: quota, broker: broker, decoder: dec}
	s.tracer = otel.Tracer(instrumentationScope)
	meter := otel.Meter(instrumentationScope)
	// Instrument construction errors are non-fatal: a nil counter is simply not
	// recorded, so a metrics misconfiguration never breaks the ingest path.
	s.acceptedC, _ = meter.Int64Counter("kseal.ingest.events.accepted",
		metric.WithDescription("Telemetry events accepted into the broker"))
	s.rejectedC, _ = meter.Int64Counter("kseal.ingest.events.rejected",
		metric.WithDescription("Telemetry events rejected (invalid, quota, or broker shed)"))
	s.batchSizeH, _ = meter.Int64Histogram("kseal.ingest.batch.events",
		metric.WithDescription("Number of events per accepted SubmitTelemetry batch"))
	return s, nil
}

// instrumentationScope is the OpenTelemetry instrumentation scope shared by the
// ingest service and the data-plane backends.
const instrumentationScope = "github.com/kennguy3n/kseal/server/data-plane/ingest"

// SubmitTelemetry decompresses and validates a batch, enforces the tenant quota
// at the edge, and enqueues accepted events for asynchronous write.
func (s *Service) SubmitTelemetry(ctx context.Context, req *connect.Request[ksealv1.SubmitTelemetryRequest]) (*connect.Response[ksealv1.SubmitTelemetryResponse], error) {
	m := req.Msg
	if m.TenantId == "" || m.AppId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("tenant_id and app_id required"))
	}

	ctx, span := s.tracer.Start(ctx, "ingest.SubmitTelemetry", trace.WithAttributes(
		attribute.String("tenant", m.TenantId),
		attribute.String("app", m.AppId),
	))
	defer span.End()
	// tenantAttr scopes per-tenant metric series; reused across the call.
	tenantAttr := metric.WithAttributes(attribute.String("tenant", m.TenantId))

	valid, err := s.validator.Valid(ctx, m.TenantId, m.AppId)
	if err != nil {
		span.RecordError(err)
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !valid {
		s.reject(ctx, tenantAttr, 1)
		span.SetAttributes(attribute.String("outcome", "unknown_app"))
		return connect.NewResponse(&ksealv1.SubmitTelemetryResponse{
			Rejected: 1, RejectionReason: "unknown tenant or app",
		}), nil
	}

	raw, err := s.decompress(m.Compression, m.CompressedBatch)
	if err != nil {
		s.reject(ctx, tenantAttr, 1)
		span.SetAttributes(attribute.String("outcome", "decompression_failed"))
		return connect.NewResponse(&ksealv1.SubmitTelemetryResponse{
			Rejected: 1, RejectionReason: "decompression failed",
		}), nil
	}
	var batch ksealv1.TelemetryBatch
	if err := proto.Unmarshal(raw, &batch); err != nil {
		s.reject(ctx, tenantAttr, 1)
		span.SetAttributes(attribute.String("outcome", "malformed_batch"))
		return connect.NewResponse(&ksealv1.SubmitTelemetryResponse{
			Rejected: 1, RejectionReason: "malformed batch",
		}), nil
	}
	if len(batch.Events) == 0 {
		return connect.NewResponse(&ksealv1.SubmitTelemetryResponse{}), nil
	}
	span.SetAttributes(attribute.Int("events", len(batch.Events)))
	if s.batchSizeH != nil {
		s.batchSizeH.Record(ctx, int64(len(batch.Events)), tenantAttr)
	}

	allowed, _, err := s.quota.Allow(ctx, m.TenantId, len(batch.Events))
	if err == nil && !allowed {
		s.reject(ctx, tenantAttr, int64(len(batch.Events)))
		span.SetAttributes(attribute.String("outcome", "quota_exceeded"))
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
		// Translate the device-reported wire bitset into the server bit layout
		// so stored bits and the derived risk level speak the same namespace as
		// the trust path, the simulator, and policy weights.
		serverBits := risk.FromWire(ev.RiskBits)
		stored := StoredEvent{
			ID:             uuid.NewString(),
			TenantID:       m.TenantId,
			AppID:          m.AppId,
			EventType:      ev.EventType,
			RiskLevel:      risk.Level(risk.Score(serverBits, nil), nil),
			RiskBits:       serverBits,
			RiskBitsLayout: risk.LayoutServer,
			Confidence:     ev.Confidence,
			BuildHash:      ev.AppBuildHash,
			PolicyHash:     ev.PolicyHash,
			InstallKeyHash: ev.TenantScopedInstallKeyHash,
			TimeBucket:     normalizeTimeBucketSec(ev.CoarseTimeBucket, now),
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

	s.accept(ctx, tenantAttr, int64(accepted))
	s.reject(ctx, tenantAttr, int64(rejected))
	span.SetAttributes(
		attribute.Int("accepted", int(accepted)),
		attribute.Int("rejected", int(rejected)),
	)
	return connect.NewResponse(&ksealv1.SubmitTelemetryResponse{Accepted: accepted, Rejected: rejected}), nil
}

// accept records n accepted events (no-op for n<=0 or unconfigured metrics).
func (s *Service) accept(ctx context.Context, attrs metric.MeasurementOption, n int64) {
	if n > 0 && s.acceptedC != nil {
		s.acceptedC.Add(ctx, n, attrs)
	}
}

// reject records n rejected events (no-op for n<=0 or unconfigured metrics).
func (s *Service) reject(ctx context.Context, attrs metric.MeasurementOption, n int64) {
	if n > 0 && s.rejectedC != nil {
		s.rejectedC.Add(ctx, n, attrs)
	}
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

const (
	// millisCutoffSec separates a unix-seconds value from a unix-millis value
	// by magnitude: a seconds timestamp stays below this until the year ~5138,
	// while a millis timestamp is already ~1.7e12 today. Any value at or above
	// it is treated as millis and scaled down.
	millisCutoffSec = int64(1e11)
	// maxClockSkewSec bounds how far ahead of the server clock a coarse bucket
	// may sit before it is rejected as bogus (generous, to tolerate coarse
	// hour-bucketing and client clock skew).
	maxClockSkewSec = int64(25 * 3600)
)

// normalizeTimeBucketSec collapses a client-supplied coarse time bucket to
// canonical unix seconds. The wire contract (telemetry.proto coarse_time_bucket)
// is unix-millis, but normalizing by magnitude also absorbs a misbehaving SDK
// that sends seconds, so storage is always seconds and the millis<->seconds
// conversions at the query boundary can never be fed an ambiguous unit.
// Non-positive or implausibly-future values fall back to nowSec.
func normalizeTimeBucketSec(v, nowSec int64) int64 {
	if v <= 0 {
		return nowSec
	}
	if v >= millisCutoffSec {
		v /= 1000
	}
	if v > nowSec+maxClockSkewSec {
		return nowSec
	}
	return v
}
