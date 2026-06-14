package ingest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// blockingStore lets a test gate the first Write so the writer is forced to
// drain a backlog at shutdown, then records everything it persists.
type recordingStore struct {
	mu        sync.Mutex
	written   []StoredEvent
	failNext  bool
	failErr   error
	writeGate chan struct{} // if non-nil, Write blocks until it is closed
}

func (s *recordingStore) Write(ctx context.Context, events []StoredEvent) error {
	if s.writeGate != nil {
		select {
		case <-s.writeGate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext {
		s.failNext = false
		return s.failErr
	}
	s.written = append(s.written, events...)
	return nil
}

func (s *recordingStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.written)
}

func (s *recordingStore) Query(context.Context, Query) ([]StoredEvent, error) { return nil, nil }
func (s *recordingStore) Count(context.Context, Query) (int, error)           { return 0, nil }
func (s *recordingStore) ListEvents(context.Context, Query, int, string) (Page, error) {
	return Page{}, nil
}

// On graceful shutdown (broker closed) the writer must drain and persist every
// event already published — none may be lost.
func TestWriterDrainsBacklogOnBrokerClose(t *testing.T) {
	broker := NewChannelBroker(1024)
	store := &recordingStore{}
	w := NewWriter(broker, store, 256, time.Hour) // long tick so only drain flushes
	done := make(chan struct{})
	go func() { w.Run(context.Background()); close(done) }()

	const n = 500
	for i := 0; i < n; i++ {
		if err := broker.Publish(context.Background(), StoredEvent{ID: "e", TenantID: "t"}); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}
	// Closing the broker closes the hand-off channel; the writer drains the
	// remaining backlog and exits.
	broker.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not exit after broker close")
	}
	if got := store.count(); got != n {
		t.Fatalf("persisted %d events, want %d (backlog lost on shutdown)", got, n)
	}
}

// A store flush that fails must invoke the registered error handler so
// durability problems are observable rather than silent.
func TestWriterReportsWriteErrors(t *testing.T) {
	broker := NewChannelBroker(16)
	store := &recordingStore{failNext: true, failErr: errors.New("clickhouse down")}
	w := NewWriter(broker, store, 1, time.Hour)

	var gotErr error
	var mu sync.Mutex
	handlerCalled := make(chan struct{}, 1)
	w.SetWriteErrorHandler(func(err error) {
		mu.Lock()
		gotErr = err
		mu.Unlock()
		select {
		case handlerCalled <- struct{}{}:
		default:
		}
	})

	done := make(chan struct{})
	go func() { w.Run(context.Background()); close(done) }()
	if err := broker.Publish(context.Background(), StoredEvent{ID: "e", TenantID: "t"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handlerCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("write error handler was not invoked")
	}
	broker.Close()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if gotErr == nil {
		t.Fatal("expected a write error to be reported")
	}
}

// The flush must run on a detached context so an already-cancelled consume
// context still persists the in-flight batch instead of dropping it.
func TestWriterFlushUsesDetachedContext(t *testing.T) {
	broker := NewChannelBroker(16)
	store := &recordingStore{}
	w := NewWriter(broker, store, 256, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	if err := broker.Publish(context.Background(), StoredEvent{ID: "e", TenantID: "t"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	// Cancel the consume context: the writer must still drain + flush the one
	// buffered event using its detached write context.
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not exit after context cancel")
	}
	if got := store.count(); got != 1 {
		t.Fatalf("persisted %d events, want 1 (detached flush dropped the batch)", got)
	}
}
