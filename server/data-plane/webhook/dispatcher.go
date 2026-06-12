package webhook

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/shared/crypto"
	"github.com/kennguy3n/kseal/server/shared/telemetry"
)

// DispatcherConfig tunes the dispatcher.
type DispatcherConfig struct {
	Workers      int
	QueueSize    int
	MaxAttempts  int
	BaseBackoff  time.Duration
	BreakerTrip  int           // consecutive failures before opening a breaker
	BreakerReset time.Duration // how long a breaker stays open
	Timeout      time.Duration // per-attempt HTTP timeout
}

func (c *DispatcherConfig) withDefaults() {
	if c.Workers <= 0 {
		c.Workers = 4
	}
	if c.QueueSize <= 0 {
		c.QueueSize = 1024
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 3
	}
	if c.BaseBackoff <= 0 {
		c.BaseBackoff = 100 * time.Millisecond
	}
	if c.BreakerTrip <= 0 {
		c.BreakerTrip = 5
	}
	if c.BreakerReset <= 0 {
		c.BreakerReset = 30 * time.Second
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
}

// Event is a domain event to fan out to subscribers.
type Event struct {
	TenantID  string
	AppID     string
	Type      ksealv1.EventType
	Payload   string
	Timestamp int64
}

type job struct {
	target  registry.WebhookSecret
	event   Event
	attempt int
}

// Dispatcher fans out events to registered webhooks with signing, retries, and
// per-endpoint circuit breaking via a bounded worker pool.
type Dispatcher struct {
	store    registry.Store
	client   *http.Client
	cfg      DispatcherConfig
	metrics  *telemetry.Metrics
	queue    chan job
	breakers sync.Map // webhook id -> *breaker
	wg       sync.WaitGroup
	stopOnce sync.Once
}

// NewDispatcher builds and starts a dispatcher.
func NewDispatcher(store registry.Store, cfg DispatcherConfig, metrics *telemetry.Metrics) *Dispatcher {
	cfg.withDefaults()
	d := &Dispatcher{
		store:   store,
		client:  &http.Client{Timeout: cfg.Timeout},
		cfg:     cfg,
		metrics: metrics,
		queue:   make(chan job, cfg.QueueSize),
	}
	for i := 0; i < cfg.Workers; i++ {
		d.wg.Add(1)
		go d.worker()
	}
	return d
}

// Dispatch enqueues an event for delivery to every matching active webhook. It
// is non-blocking; if the queue is saturated the event is dropped and counted.
func (d *Dispatcher) Dispatch(ctx context.Context, e Event) error {
	targets, err := d.store.ListWebhooksForEvent(ctx, e.TenantID, e.Type)
	if err != nil {
		return err
	}
	for _, t := range targets {
		d.enqueue(job{target: t, event: e, attempt: 1})
	}
	return nil
}

func (d *Dispatcher) enqueue(j job) {
	select {
	case d.queue <- j:
	default:
		if d.metrics != nil {
			d.metrics.WebhookDispatch.WithLabelValues("dropped").Inc()
		}
	}
}

func (d *Dispatcher) worker() {
	defer d.wg.Done()
	for j := range d.queue {
		d.deliver(j)
	}
}

func (d *Dispatcher) deliver(j job) {
	b := d.breakerFor(j.target.Webhook.Id)
	if !b.allow(time.Now()) {
		d.record("circuit_open")
		return
	}

	body := []byte(j.event.Payload)
	sig := crypto.HMACSHA256(j.target.Secret, body)
	req, err := http.NewRequest(http.MethodPost, j.target.Webhook.Url, bytes.NewReader(body))
	if err != nil {
		d.record("error")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Kseal-Signature", hex.EncodeToString(sig))
	req.Header.Set("X-Kseal-Key-Id", j.target.Webhook.SigningKeyId)
	req.Header.Set("X-Kseal-Event", j.event.Type.String())
	req.Header.Set("X-Kseal-Delivery-Attempt", fmt.Sprintf("%d", j.attempt))

	resp, err := d.client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		b.recordSuccess()
		d.record("success")
		return
	}

	b.recordFailure(time.Now(), d.cfg.BreakerTrip, d.cfg.BreakerReset)
	d.record("failure")
	if j.attempt >= d.cfg.MaxAttempts {
		d.record("exhausted")
		return
	}
	// Exponential backoff before re-enqueueing the next attempt.
	backoff := d.cfg.BaseBackoff * time.Duration(1<<(j.attempt-1))
	time.AfterFunc(backoff, func() {
		next := j
		next.attempt++
		d.enqueue(next)
	})
}

func (d *Dispatcher) record(outcome string) {
	if d.metrics != nil {
		d.metrics.WebhookDispatch.WithLabelValues(outcome).Inc()
	}
}

func (d *Dispatcher) breakerFor(id string) *breaker {
	b, _ := d.breakers.LoadOrStore(id, &breaker{})
	return b.(*breaker)
}

// Stop drains and waits for in-flight deliveries.
func (d *Dispatcher) Stop() {
	d.stopOnce.Do(func() {
		close(d.queue)
		d.wg.Wait()
	})
}

// breaker is a minimal per-endpoint circuit breaker.
type breaker struct {
	mu        sync.Mutex
	failures  int
	openUntil time.Time
}

func (b *breaker) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return now.After(b.openUntil)
}

func (b *breaker) recordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.openUntil = time.Time{}
}

func (b *breaker) recordFailure(now time.Time, trip int, reset time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures++
	if b.failures >= trip {
		b.openUntil = now.Add(reset)
		b.failures = 0
	}
}
