// Package ingest accepts compressed telemetry batches at the edge, enforces
// per-tenant quotas, and forwards validated events through a swappable broker to
// an analytics store. The in-process channel broker and in-memory analytics
// store are the MVP backends; the interfaces let Kafka and ClickHouse drop in
// later without touching the service.
package ingest

import (
	"context"
	"encoding/base64"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/risk"
)

var errBadCursor = errors.New("invalid page cursor")

// StoredEvent is the normalized, tenant-scoped telemetry record persisted by the
// analytics store. It deliberately carries no PII — only coarse, aggregate-safe
// fields.
type StoredEvent struct {
	// ID is a stable, unique identifier assigned at ingest, used as the keyset
	// pagination tiebreaker and the dashboard EventRecord id.
	ID        string
	TenantID  string
	AppID     string
	EventType ksealv1.EventType
	// RiskLevel is the fused trust classification derived from RiskBits at
	// ingest, so reads need no policy lookup to render risk.
	RiskLevel ksealv1.TrustLevel
	RiskBits  uint64
	// RiskBitsLayout records which namespace RiskBits is expressed in, making
	// the row self-describing. Ingest applies risk.FromWire before storing, so
	// rows it writes are tagged risk.LayoutServer; rows predating this field
	// decode as risk.LayoutUnknown (assumed server). Readers that score the
	// bits pass them through risk.NormalizeStored, so a future layout change
	// stays unambiguous instead of silently mis-scoring historical rows.
	RiskBitsLayout risk.Layout
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
	RiskLevels []ksealv1.TrustLevel
	PolicyHash string
	From       int64
	To         int64
}

// Page is one keyset-paginated window of events. NextCursor is empty when the
// window is the last one.
type Page struct {
	Events     []StoredEvent
	NextCursor string
}

// AnalyticsStore is the clean interface over event storage. ClickHouse can
// implement this later; the MVP uses InMemoryAnalyticsStore.
type AnalyticsStore interface {
	Write(ctx context.Context, events []StoredEvent) error
	Query(ctx context.Context, q Query) ([]StoredEvent, error)
	Count(ctx context.Context, q Query) (int, error)
	// ListEvents returns a recent-first (TimeBucket desc, ID desc) page of
	// matching events with an opaque keyset cursor. limit <= 0 uses a default.
	ListEvents(ctx context.Context, q Query, limit int, cursor string) (Page, error)
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
	if len(q.RiskLevels) > 0 {
		found := false
		for _, l := range q.RiskLevels {
			if e.RiskLevel == l {
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

// TenantIDs returns the distinct tenants that currently hold raw events,
// satisfying RawEventStore for the retention purger.
func (s *InMemoryAnalyticsStore) TenantIDs(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]struct{})
	var out []string
	for _, e := range s.events {
		if _, ok := seen[e.TenantID]; ok {
			continue
		}
		seen[e.TenantID] = struct{}{}
		out = append(out, e.TenantID)
	}
	return out, nil
}

// PurgeRawEventsOlderThan deletes the tenant's raw events strictly older than
// cutoffBucket and returns the number removed. It only ever touches the named
// tenant's events, preserving cross-tenant isolation.
func (s *InMemoryAnalyticsStore) PurgeRawEventsOlderThan(_ context.Context, tenantID string, cutoffBucket int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.events[:0]
	purged := 0
	for _, e := range s.events {
		if e.TenantID == tenantID && e.TimeBucket < cutoffBucket {
			purged++
			continue
		}
		kept = append(kept, e)
	}
	// Release references to purged events from the tail of the backing array.
	for i := len(kept); i < len(s.events); i++ {
		s.events[i] = StoredEvent{}
	}
	s.events = kept
	return purged, nil
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

const defaultEventPageSize = 50
const maxEventPageSize = 500

// ListEvents returns a recent-first page of matching events. Ordering is
// (TimeBucket desc, ID desc) which gives a strict total order, so the cursor
// (the last item's (TimeBucket, ID)) yields stable, gap-free keyset pagination.
func (s *InMemoryAnalyticsStore) ListEvents(_ context.Context, q Query, limit int, cursor string) (Page, error) {
	if limit <= 0 {
		limit = defaultEventPageSize
	}
	if limit > maxEventPageSize {
		limit = maxEventPageSize
	}
	curTB, curID, hasCur, err := decodeCursor(cursor)
	if err != nil {
		return Page{}, err
	}

	s.mu.RLock()
	var out []StoredEvent
	for _, e := range s.events {
		if q.matches(e) {
			out = append(out, e)
		}
	}
	s.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool { return eventLess(out[j], out[i]) })

	start := 0
	if hasCur {
		for start < len(out) {
			e := out[start]
			if e.TimeBucket < curTB || (e.TimeBucket == curTB && e.ID < curID) {
				break
			}
			start++
		}
	}
	out = out[start:]

	var next string
	if len(out) > limit {
		last := out[limit-1]
		next = encodeCursor(last.TimeBucket, last.ID)
		out = out[:limit]
	}
	return Page{Events: out, NextCursor: next}, nil
}

// eventLess defines the keyset order: later TimeBucket first, ID as tiebreaker.
func eventLess(a, b StoredEvent) bool {
	if a.TimeBucket != b.TimeBucket {
		return a.TimeBucket < b.TimeBucket
	}
	return a.ID < b.ID
}

func encodeCursor(tb int64, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(tb, 10) + ":" + id))
}

func decodeCursor(cursor string) (tb int64, id string, ok bool, err error) {
	if cursor == "" {
		return 0, "", false, nil
	}
	raw, derr := base64.RawURLEncoding.DecodeString(cursor)
	if derr != nil {
		return 0, "", false, derr
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return 0, "", false, errBadCursor
	}
	tb, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, "", false, err
	}
	return tb, parts[1], true, nil
}

// EventSink receives each validated event as it is drained, for fan-out to
// secondary consumers (e.g. webhook delivery). Emit must be non-blocking so it
// never stalls the write path.
type EventSink interface {
	Emit(e StoredEvent)
}

// defaultWriteTimeout bounds a single store flush attempt. Flushes run on a
// detached context (not the consume context) so an in-flight batch still
// persists during graceful shutdown instead of being cancelled and lost.
const defaultWriteTimeout = 30 * time.Second

// Retry/backoff bounds for a failing flush. A failed flush is retried (never
// silently dropped) so a transient store outage does not lose a batch; while it
// retries, the Writer stops draining, which backpressures the broker (a Kafka
// broker simply leaves the offsets uncommitted so they redeliver). The durable
// position only advances once a flush succeeds and is Ack'd.
const (
	defaultInitialBackoff = 100 * time.Millisecond
	defaultMaxBackoff     = 5 * time.Second
	// defaultShutdownGrace bounds total retry time during drain so a store that
	// is down at shutdown cannot hang termination — un-acked events stay
	// uncommitted in the broker and redeliver on the next start.
	defaultShutdownGrace = 30 * time.Second
)

// Writer drains the broker and flushes events to the analytics store in batches.
type Writer struct {
	broker         Broker
	store          AnalyticsStore
	batchSize      int
	interval       time.Duration
	writeTimeout   time.Duration
	initialBackoff time.Duration
	maxBackoff     time.Duration
	shutdownGrace  time.Duration
	sink           EventSink
	onWriteError   func(error)
}

// NewWriter builds a writer with batching parameters.
func NewWriter(broker Broker, store AnalyticsStore, batchSize int, interval time.Duration) *Writer {
	if batchSize <= 0 {
		batchSize = 256
	}
	if interval <= 0 {
		interval = time.Second
	}
	return &Writer{
		broker:         broker,
		store:          store,
		batchSize:      batchSize,
		interval:       interval,
		writeTimeout:   defaultWriteTimeout,
		initialBackoff: defaultInitialBackoff,
		maxBackoff:     defaultMaxBackoff,
		shutdownGrace:  defaultShutdownGrace,
	}
}

// SetEventSink registers a non-blocking sink notified of every drained event.
func (w *Writer) SetEventSink(s EventSink) { w.sink = s }

// SetWriteErrorHandler registers a callback invoked when a store flush fails. It
// lets the caller surface durability problems (e.g. ClickHouse unavailable)
// without coupling the writer to a logger. Optional.
func (w *Writer) SetWriteErrorHandler(fn func(error)) { w.onWriteError = fn }

// Run consumes until the context is cancelled or the broker channel closes,
// flushing on batch-size or tick. On shutdown it drains whatever is already
// buffered before returning, so a graceful stop persists in-flight telemetry
// rather than dropping it.
func (w *Writer) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	batch := make([]StoredEvent, 0, w.batchSize)
	// stopCtx bounds how long a failing flush may retry. During normal operation
	// it is the consume context (retry until shutdown, backpressuring the
	// broker); during drain it is a bounded grace context so a down store cannot
	// hang termination. Mutated only by this goroutine.
	stopCtx := ctx
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if w.flushWithRetry(stopCtx, batch) {
			// Persisted: advance the broker's durable position for exactly this
			// many events (no-op for brokers without a durable position).
			if acker, ok := w.broker.(PersistAcker); ok {
				acker.Ack(len(batch))
			}
		}
		// Whether persisted or abandoned at shutdown, start a fresh buffer.
		// Abandoned events were never Ack'd, so a durable broker redelivers
		// them. Allocate rather than reuse the backing array: the AnalyticsStore
		// interface does not promise to copy its input.
		batch = make([]StoredEvent, 0, w.batchSize)
	}
	add := func(e StoredEvent) {
		if w.sink != nil {
			w.sink.Emit(e)
		}
		batch = append(batch, e)
		if len(batch) >= w.batchSize {
			flush()
		}
	}
	ch := w.broker.Consume()
	shutdown := func() {
		drainCtx, cancel := context.WithTimeout(context.Background(), w.shutdownGrace)
		defer cancel()
		stopCtx = drainCtx
		w.drain(ch, add)
		flush()
	}
	for {
		select {
		case <-ctx.Done():
			shutdown()
			return
		case <-ticker.C:
			flush()
		case e, ok := <-ch:
			if !ok {
				shutdown()
				return
			}
			add(e)
		}
	}
}

// flushWithRetry persists batch, retrying on error with capped exponential
// backoff until it succeeds or stopCtx is done. It returns true if the batch was
// persisted and false if it gave up (stopCtx done) — in which case the caller
// must NOT Ack, so a durable broker redelivers the events. The in-memory store
// never errors, so the default path persists on the first attempt.
func (w *Writer) flushWithRetry(stopCtx context.Context, batch []StoredEvent) bool {
	backoff := w.initialBackoff
	for {
		// Detached, bounded per-attempt context: a flush must complete even while
		// the process is shutting down (the consume ctx may already be cancelled).
		writeCtx, cancel := context.WithTimeout(context.Background(), w.writeTimeout)
		err := w.store.Write(writeCtx, batch)
		cancel()
		if err == nil {
			return true
		}
		if w.onWriteError != nil {
			w.onWriteError(err)
		}
		select {
		case <-stopCtx.Done():
			// Out of grace (or shutting down): leave the events un-Ack'd so they
			// are redelivered rather than dropped, and stop retrying.
			return false
		case <-time.After(backoff):
		}
		if backoff < w.maxBackoff {
			if backoff *= 2; backoff > w.maxBackoff {
				backoff = w.maxBackoff
			}
		}
	}
}

// drain pulls every event currently buffered in the broker channel without
// blocking, so a shutdown flushes the in-flight backlog. It stops at the first
// empty read (or a closed channel), leaving the final flush to the caller.
func (w *Writer) drain(ch <-chan StoredEvent, add func(StoredEvent)) {
	for {
		select {
		case e, ok := <-ch:
			if !ok {
				return
			}
			add(e)
		default:
			return
		}
	}
}
