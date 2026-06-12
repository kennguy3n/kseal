package ingest

import (
	"context"
	"errors"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/gen/kseal/v1/ksealv1connect"
	"github.com/kennguy3n/kseal/server/control-plane/registry"
)

const maxDecompressedBytes = 16 << 20 // 16 MiB ceiling guards against zip bombs.

// AppValidator reports whether a (tenant, app) pair is registered. It is backed
// by a short-TTL cache over the registry so the hot ingest path avoids a DB hit
// per request.
type AppValidator interface {
	Valid(ctx context.Context, tenantID, appID string) (bool, error)
}

// CachedAppValidator caches positive registry lookups for a short TTL.
type CachedAppValidator struct {
	store registry.Store
	ttl   time.Duration

	mu    sync.Mutex
	cache map[string]time.Time
}

// NewCachedAppValidator builds a validator with the given cache TTL.
func NewCachedAppValidator(store registry.Store, ttl time.Duration) *CachedAppValidator {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &CachedAppValidator{store: store, ttl: ttl, cache: map[string]time.Time{}}
}

// Valid returns whether the app exists for the tenant.
func (v *CachedAppValidator) Valid(ctx context.Context, tenantID, appID string) (bool, error) {
	key := tenantID + "/" + appID
	v.mu.Lock()
	if exp, ok := v.cache[key]; ok && time.Now().Before(exp) {
		v.mu.Unlock()
		return true, nil
	}
	v.mu.Unlock()

	_, err := v.store.GetApp(ctx, tenantID, appID)
	if errors.Is(err, registry.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	v.mu.Lock()
	v.cache[key] = time.Now().Add(v.ttl)
	v.mu.Unlock()
	return true, nil
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
	dec, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(0))
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
			Rejected:      int32(len(batch.Events)),
			QuotaExceeded: true,
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
			TenantID:       m.TenantId,
			AppID:          m.AppId,
			EventType:      ev.EventType,
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
		return s.decoder.DecodeAll(data, make([]byte, 0, len(data)*3))
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
