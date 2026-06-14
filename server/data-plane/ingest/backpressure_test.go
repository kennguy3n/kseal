package ingest

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Load/soak smoke: under sustained over-publish the broker must shed (return
// ErrBrokerFull) rather than block the request path, and a draining writer must
// still persist a steady stream without loss. This proves the bounded-queue
// backpressure contract deterministically, without a container.
func TestBrokerShedsUnderSustainedLoad(t *testing.T) {
	// Tiny buffer + no consumer: every publish past the buffer must shed
	// immediately instead of blocking.
	broker := NewChannelBroker(16)
	t.Cleanup(broker.Close)

	const attempts = 100_000
	var accepted, shed int
	deadline := time.Now().Add(5 * time.Second)
	for i := 0; i < attempts; i++ {
		err := broker.Publish(context.Background(), StoredEvent{ID: "x", TenantID: "t"})
		switch err {
		case nil:
			accepted++
		case ErrBrokerFull:
			shed++
		default:
			t.Fatalf("unexpected publish error: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("publish loop stalled — broker blocked instead of shedding (i=%d)", i)
		}
	}
	if accepted > 16 {
		t.Fatalf("accepted %d with a 16-slot buffer and no consumer; broker did not bound", accepted)
	}
	if shed == 0 {
		t.Fatal("expected load shedding under sustained over-publish, got none")
	}
}

// Under a continuously draining writer, sustained publishing (with retry on
// shed) must persist every event: backpressure throttles producers without
// dropping accepted work.
func TestWriterKeepsUpUnderLoadWithoutLoss(t *testing.T) {
	broker := NewChannelBroker(256)
	store := &recordingStore{}
	w := NewWriter(broker, store, 128, 5*time.Millisecond)

	done := make(chan struct{})
	go func() { w.Run(context.Background()); close(done) }()

	const total = 20_000
	var wg sync.WaitGroup
	wg.Add(4)
	for p := 0; p < 4; p++ {
		go func(shard int) {
			defer wg.Done()
			for i := shard; i < total; i += 4 {
				// Retry on shed so accepted work is never silently lost; this
				// is the producer-side contract under backpressure.
				for {
					err := broker.Publish(context.Background(), StoredEvent{ID: "x", TenantID: "t"})
					if err == nil {
						break
					}
					if err == ErrBrokerFull {
						time.Sleep(time.Millisecond)
						continue
					}
					t.Errorf("publish: %v", err)
					return
				}
			}
		}(p)
	}
	wg.Wait()
	broker.Close()
	<-done

	if got := store.count(); got != total {
		t.Fatalf("persisted %d events, want %d (loss under load)", got, total)
	}
}
