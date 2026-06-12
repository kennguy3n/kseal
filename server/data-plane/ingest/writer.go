// Package ingest accepts compressed telemetry batches at the edge, enforces
// per-tenant quotas, and forwards validated events through a swappable broker to
// an analytics store. The in-process channel broker and in-memory analytics
// store are the MVP backends; the interfaces let Kafka and ClickHouse drop in
// later without touching the service.
package ingest

import (
	"context"
	"sort"
	"sync"
	"time"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// StoredEvent is the normalized, tenant-scoped telemetry record persisted by the
// analytics store. It deliberately carries no PII — only coarse, aggregate-safe
// fields.
type StoredEvent struct {
	TenantID       string
	AppID          string
	EventType      ksealv1.EventType
	RiskBits       uint64
	Confidence     ksealv1.Confidence
	BuildHash      string
	PolicyHash     string
	InstallKeyHash string
	TimeBucket     int64
	Country        string
	Platform       ksealv1.Platform
	ReceivedAt     int64
}

// Query selects events for aggregation and replay.
type Query struct {
	TenantID   string
	AppID      string
	EventTypes []ksealv1.EventType
	PolicyHash string
	From       int64
	To         int64
}

// AnalyticsStore is the clean interface over event storage. ClickHouse can
// implement this later; the MVP uses InMemoryAnalyticsStore.
type AnalyticsStore interface {
	Write(ctx context.Context, events []StoredEvent) error
	Query(ctx context.Context, q Query) ([]StoredEvent, error)
	Count(ctx context.Context, q Query) (int, error)
}

// InMemoryAnalyticsStore is a concurrency-safe slice-backed analytics store.
type InMemoryAnalyticsStore struct {
	mu     sync.RWMutex
	events []StoredEvent
}

// NewInMemoryAnalyticsStore builds an empty store.
func NewInMemoryAnalyticsStore() *InMemoryAnalyticsStore {
	return &InMemoryAnalyticsStore{}
}

// Write appends events.
func (s *InMemoryAnalyticsStore) Write(_ context.Context, events []StoredEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, events...)
	return nil
}

func (q Query) matches(e StoredEvent) bool {
	if q.TenantID != "" && e.TenantID != q.TenantID {
		return false
	}
	if q.AppID != "" && e.AppID != q.AppID {
		return false
	}
	if q.PolicyHash != "" && e.PolicyHash != q.PolicyHash {
		return false
	}
	if q.From != 0 && e.TimeBucket < q.From {
		return false
	}
	if q.To != 0 && e.TimeBucket > q.To {
		return false
	}
	if len(q.EventTypes) > 0 {
		found := false
		for _, t := range q.EventTypes {
			if e.EventType == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Query returns matching events ordered by time bucket.
func (s *InMemoryAnalyticsStore) Query(_ context.Context, q Query) ([]StoredEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []StoredEvent
	for _, e := range s.events {
		if q.matches(e) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TimeBucket < out[j].TimeBucket })
	return out, nil
}

// Count returns the number of matching events.
func (s *InMemoryAnalyticsStore) Count(_ context.Context, q Query) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, e := range s.events {
		if q.matches(e) {
			n++
		}
	}
	return n, nil
}

// Writer drains the broker and flushes events to the analytics store in batches.
type Writer struct {
	broker    Broker
	store     AnalyticsStore
	batchSize int
	interval  time.Duration
}

// NewWriter builds a writer with batching parameters.
func NewWriter(broker Broker, store AnalyticsStore, batchSize int, interval time.Duration) *Writer {
	if batchSize <= 0 {
		batchSize = 256
	}
	if interval <= 0 {
		interval = time.Second
	}
	return &Writer{broker: broker, store: store, batchSize: batchSize, interval: interval}
}

// Run consumes until the context is cancelled, flushing on batch-size or tick.
// Remaining buffered events are flushed on shutdown.
func (w *Writer) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	batch := make([]StoredEvent, 0, w.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		_ = w.store.Write(ctx, batch)
		batch = batch[:0]
	}
	ch := w.broker.Consume()
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case <-ticker.C:
			flush()
		case e, ok := <-ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= w.batchSize {
				flush()
			}
		}
	}
}
