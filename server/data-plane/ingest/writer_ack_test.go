package ingest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// ackBroker is an in-process broker that also implements PersistAcker, so a test
// can observe exactly when (and how many) events the Writer reports persisted.
type ackBroker struct {
	ch        chan StoredEvent
	mu        sync.Mutex
	acked     int
	closeOnce sync.Once
}

func newAckBroker(buf int) *ackBroker { return &ackBroker{ch: make(chan StoredEvent, buf)} }

func (b *ackBroker) Publish(ctx context.Context, e StoredEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case b.ch <- e:
		return nil
	}
}
func (b *ackBroker) Consume() <-chan StoredEvent { return b.ch }
func (b *ackBroker) Close()                      { b.closeOnce.Do(func() { close(b.ch) }) }
func (b *ackBroker) Ack(n int)                   { b.mu.Lock(); b.acked += n; b.mu.Unlock() }
func (b *ackBroker) ackedCount() int             { b.mu.Lock(); defer b.mu.Unlock(); return b.acked }

// gatedStore fails every Write until release is closed, then succeeds. It models
// a ClickHouse outage that later recovers.
type gatedStore struct {
	mu      sync.Mutex
	written int
	release chan struct{}
}

func (s *gatedStore) Write(_ context.Context, events []StoredEvent) error {
	select {
	case <-s.release:
		s.mu.Lock()
		s.written += len(events)
		s.mu.Unlock()
		return nil
	default:
		return errors.New("clickhouse down")
	}
}
func (s *gatedStore) writes() int                                         { s.mu.Lock(); defer s.mu.Unlock(); return s.written }
func (s *gatedStore) Query(context.Context, Query) ([]StoredEvent, error) { return nil, nil }
func (s *gatedStore) Count(context.Context, Query) (int, error)           { return 0, nil }
func (s *gatedStore) ListEvents(context.Context, Query, int, string) (Page, error) {
	return Page{}, nil
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for: %s", msg)
		case <-time.After(time.Millisecond):
		}
	}
}

// The durable position must advance only after the store actually persists a
// batch: while the store is down the Writer retries and must NOT Ack; once the
// store recovers it persists and Acks exactly the batch size.
func TestWriterAcksOnlyAfterPersist(t *testing.T) {
	broker := newAckBroker(16)
	store := &gatedStore{release: make(chan struct{})}
	w := NewWriter(broker, store, 1, time.Hour)
	w.initialBackoff = time.Millisecond
	w.maxBackoff = 2 * time.Millisecond

	var errs int
	var mu sync.Mutex
	w.SetWriteErrorHandler(func(error) { mu.Lock(); errs++; mu.Unlock() })
	errCount := func() int { mu.Lock(); defer mu.Unlock(); return errs }

	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { w.Run(ctx); close(done) }()

	if err := broker.Publish(context.Background(), StoredEvent{ID: "e1", TenantID: "t"}); err != nil {
		t.Fatal(err)
	}

	// At least one failed flush must have happened (store is gated shut).
	waitFor(t, func() bool { return errCount() >= 1 }, "a write error to be reported")
	if got := broker.ackedCount(); got != 0 {
		t.Fatalf("broker acked %d before any successful persist (must be 0)", got)
	}
	if got := store.writes(); got != 0 {
		t.Fatalf("store recorded %d writes while gated shut (must be 0)", got)
	}

	// Recover the store: the retried flush now succeeds and the Writer Acks it.
	close(store.release)
	waitFor(t, func() bool { return store.writes() == 1 }, "the batch to be persisted")
	waitFor(t, func() bool { return broker.ackedCount() == 1 }, "the persisted batch to be acked")

	cancel()
	<-done
}

// A store that is down at shutdown must not hang termination: the drain flush
// retries only within the bounded grace window, then gives up WITHOUT acking so
// the durable broker redelivers the events on the next start.
func TestWriterShutdownBoundedAndDoesNotAckWhenStoreDown(t *testing.T) {
	broker := newAckBroker(16)
	store := &gatedStore{release: make(chan struct{})} // never released: always fails
	w := NewWriter(broker, store, 1, time.Hour)
	w.initialBackoff = time.Millisecond
	w.maxBackoff = 2 * time.Millisecond
	w.shutdownGrace = 50 * time.Millisecond

	var errs int
	var mu sync.Mutex
	w.SetWriteErrorHandler(func(error) { mu.Lock(); errs++; mu.Unlock() })
	errCount := func() int { mu.Lock(); defer mu.Unlock(); return errs }

	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { w.Run(ctx); close(done) }()

	if err := broker.Publish(context.Background(), StoredEvent{ID: "e1", TenantID: "t"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return errCount() >= 1 }, "a write error to be reported")

	cancel() // begin shutdown; the drain flush retries within shutdownGrace then gives up
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not exit within grace (hung retrying a down store)")
	}
	if got := broker.ackedCount(); got != 0 {
		t.Fatalf("broker acked %d despite the store never persisting (must be 0 so events redeliver)", got)
	}
}
