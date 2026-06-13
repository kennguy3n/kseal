package siem

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		status int
		err    error
		want   deliveryResult
	}{
		{200, nil, resultSuccess},
		{204, nil, resultSuccess},
		{400, nil, resultPermanent},
		{401, nil, resultPermanent},
		{404, nil, resultPermanent},
		{408, nil, resultRetryable},
		{429, nil, resultRetryable},
		{500, nil, resultRetryable},
		{503, nil, resultRetryable},
		{0, errors.New("dial"), resultRetryable},
	}
	for _, c := range cases {
		if got := classify(c.status, c.err); got != c.want {
			t.Fatalf("classify(%d,%v) = %v, want %v", c.status, c.err, got, c.want)
		}
	}
}

func TestBackoffBounds(t *testing.T) {
	ex := NewExporter(nil, ExporterConfig{BaseBackoff: 100 * time.Millisecond, MaxBackoff: time.Second}, nil)
	p := newTenantPipe(ex, "t")
	for attempt := 1; attempt <= 6; attempt++ {
		ideal := ex.cfg.BaseBackoff << (attempt - 1)
		if ideal <= 0 || ideal > ex.cfg.MaxBackoff {
			ideal = ex.cfg.MaxBackoff
		}
		for i := 0; i < 200; i++ {
			got := p.backoff(attempt)
			if got < 0 || got > ideal {
				t.Fatalf("attempt %d backoff %v out of [0,%v]", attempt, got, ideal)
			}
		}
	}
}

func TestBreakerTripsAndResets(t *testing.T) {
	b := &breaker{}
	now := time.Unix(1000, 0)
	reset := 10 * time.Second
	// Two failures below the trip threshold keep it closed.
	b.recordFailure(now, 3, reset)
	b.recordFailure(now, 3, reset)
	if !b.allow(now) {
		t.Fatal("breaker should still be closed before trip threshold")
	}
	// Third failure trips it.
	b.recordFailure(now, 3, reset)
	if b.allow(now) {
		t.Fatal("breaker should be open after tripping")
	}
	// Still open within the reset window.
	if b.allow(now.Add(reset - time.Second)) {
		t.Fatal("breaker should remain open within reset window")
	}
	// Closed again after the reset window.
	if !b.allow(now.Add(reset + time.Second)) {
		t.Fatal("breaker should close after reset window")
	}
	// A success clears failures.
	b.recordFailure(now, 3, reset)
	b.recordSuccess()
	b.recordFailure(now, 3, reset)
	b.recordFailure(now, 3, reset)
	if !b.allow(now) {
		t.Fatal("success should have reset the failure count")
	}
}

func TestIdempotencyKeyDeterministic(t *testing.T) {
	body := []byte(`{"event":{"risk_bits":3}}`)
	a := idempotencyKey("conn-1", body)
	b := idempotencyKey("conn-1", body)
	if a != b {
		t.Fatal("idempotency key must be stable for identical batch")
	}
	if idempotencyKey("conn-2", body) == a {
		t.Fatal("idempotency key must differ across connectors")
	}
	if idempotencyKey("conn-1", []byte(`{"event":{"risk_bits":4}}`)) == a {
		t.Fatal("idempotency key must differ across bodies")
	}
}

func TestMaybeGzipRoundTrip(t *testing.T) {
	big := make([]byte, 0, 2048)
	for i := 0; i < 2048; i++ {
		big = append(big, 'a')
	}
	body, enc, err := maybeGzip(renderedRequest{body: big, gzippable: true}, 512)
	if err != nil {
		t.Fatal(err)
	}
	if enc != "gzip" {
		t.Fatalf("expected gzip encoding, got %q", enc)
	}
	if len(body) >= len(big) {
		t.Fatal("gzip did not shrink a compressible body")
	}
	// Small bodies are not compressed.
	_, enc2, _ := maybeGzip(renderedRequest{body: []byte("hi"), gzippable: true}, 512)
	if enc2 != "" {
		t.Fatalf("small body should not be gzipped, got %q", enc2)
	}
	// Non-gzippable sinks are never compressed.
	_, enc3, _ := maybeGzip(renderedRequest{body: big, gzippable: false}, 512)
	if enc3 != "" {
		t.Fatalf("non-gzippable sink should not be compressed, got %q", enc3)
	}
}

func TestSubmitDropsWhenQueueFull(t *testing.T) {
	// A tiny queue and no draining (we never start delivery against a real sink)
	// proves backpressure sheds rather than blocks. The pipe goroutine drains
	// into batches, so to observe drops we fill faster than the batch loop; use
	// a store that returns no connectors so deliveries are cheap no-ops.
	ex := NewExporter(NewMemConnectorStore(testEncryptorNil{}), ExporterConfig{QueueSize: 1, FlushInterval: time.Hour}, nil)
	defer ex.Stop()
	// Pause the pipe by not letting it flush (huge interval); flood the queue.
	for i := 0; i < 1000; i++ {
		ex.Submit(Event{TenantID: "t", RiskBits: uint64(i)})
	}
	// No assertion on exact drops (timing-dependent), just that Submit never
	// blocks: reaching here without deadlock is the property under test.
}

func TestStopReturnsPromptlyUnderConcurrentSubmit(t *testing.T) {
	// IdleTimeout is deliberately huge: if Stop ever fails to signal a pipe that
	// Submit registers concurrently, Stop would block until this fires. The test
	// asserts Stop returns quickly regardless, proving the shutdown handshake.
	ex := NewExporter(
		NewMemConnectorStore(testEncryptorNil{}),
		ExporterConfig{QueueSize: 8, FlushInterval: time.Hour, IdleTimeout: time.Hour},
		nil,
	)

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				ex.Submit(Event{TenantID: "tenant-" + string(rune('a'+g%8)), RiskBits: uint64(i)})
			}
		}(g)
	}

	done := make(chan struct{})
	go func() {
		ex.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return promptly under concurrent Submit (pipe leaked past shutdown)")
	}
	wg.Wait()
}

// testEncryptorNil is a passthrough sealer used where encryption is irrelevant.
type testEncryptorNil struct{}

func (testEncryptorNil) Seal(p []byte) ([]byte, error) { return p, nil }
func (testEncryptorNil) Open(s []byte) ([]byte, error) { return s, nil }
