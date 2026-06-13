package siem

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// ExporterConfig tunes the async exporter. Zero values fall back to defaults.
type ExporterConfig struct {
	// QueueSize bounds each per-tenant queue. When full, new events are shed
	// (load-shedding) and counted, never blocking the ingest path.
	QueueSize int
	// BatchSize / FlushInterval govern batching: a batch flushes when it reaches
	// BatchSize events or FlushInterval elapses, whichever comes first.
	BatchSize     int
	FlushInterval time.Duration
	// MaxAttempts is the total number of delivery attempts (initial + retries).
	MaxAttempts int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	// BreakerTrip consecutive failures opens a per-connector breaker for
	// BreakerReset.
	BreakerTrip  int
	BreakerReset time.Duration
	// Timeout is the per-attempt HTTP timeout.
	Timeout time.Duration
	// ConnectorCacheTTL caches a tenant's connector set between batches to avoid
	// a store hit per batch.
	ConnectorCacheTTL time.Duration
	// IdleTimeout reaps a tenant pipe after this long with no events, bounding
	// goroutine/memory use across many tenants.
	IdleTimeout time.Duration
	// GzipMinBytes is the body size at/above which gzip is applied (when the
	// sink supports it). Small bodies skip compression.
	GzipMinBytes int
}

func (c *ExporterConfig) withDefaults() {
	if c.QueueSize <= 0 {
		c.QueueSize = 512
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 100
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = time.Second
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 5
	}
	if c.BaseBackoff <= 0 {
		c.BaseBackoff = 200 * time.Millisecond
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 5 * time.Second
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
	if c.ConnectorCacheTTL <= 0 {
		c.ConnectorCacheTTL = 10 * time.Second
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 2 * time.Minute
	}
	if c.GzipMinBytes <= 0 {
		c.GzipMinBytes = 512
	}
}

// Exporter fans privacy-minimized events out to each tenant's active SIEM
// connectors. It is async, batched, backpressured per tenant, at-least-once
// with idempotency keys, and per-connector circuit-broken.
type Exporter struct {
	store   ConnectorStore
	client  *http.Client
	cfg     ExporterConfig
	metrics *Metrics
	now     func() time.Time

	mu      sync.RWMutex
	pipes   map[string]*tenantPipe
	wg      sync.WaitGroup
	stopped chan struct{}
	stop    sync.Once
}

// NewExporter builds an exporter. store/metrics may be nil-tolerant in tests,
// but production passes the Postgres store and a registered Metrics.
func NewExporter(store ConnectorStore, cfg ExporterConfig, metrics *Metrics) *Exporter {
	cfg.withDefaults()
	return &Exporter{
		store:   store,
		client:  &http.Client{Timeout: cfg.Timeout},
		cfg:     cfg,
		metrics: metrics,
		now:     time.Now,
		pipes:   map[string]*tenantPipe{},
		stopped: make(chan struct{}),
	}
}

// Submit routes an event to its tenant's queue. It is non-blocking: a saturated
// queue sheds the event and counts it. Safe for concurrent callers.
func (ex *Exporter) Submit(ev Event) {
	if ev.TenantID == "" {
		return
	}
	select {
	case <-ex.stopped:
		return
	default:
	}
	te := timedEvent{ev: ev, at: ex.now()}
	for {
		p := ex.getOrCreate(ev.TenantID)
		if p == nil {
			return // exporter stopped between the guard above and pipe creation
		}
		switch p.enqueue(te) {
		case enqOK:
			ex.metrics.addQueueDepth(1)
			return
		case enqFull:
			ex.metrics.recordOutcome("all", outcomeDropped)
			return
		case enqClosed:
			// Pipe was reaped between lookup and send; drop it and retry.
			ex.removePipe(ev.TenantID, p)
			continue
		}
	}
}

func (ex *Exporter) getOrCreate(tenant string) *tenantPipe {
	ex.mu.RLock()
	p := ex.pipes[tenant]
	ex.mu.RUnlock()
	if p != nil {
		return p
	}
	ex.mu.Lock()
	defer ex.mu.Unlock()
	if p := ex.pipes[tenant]; p != nil {
		return p
	}
	// Re-check under the write lock that Stop holds while snapshotting pipes, so
	// we never register (and wg.Add) a pipe that Stop won't signal — which would
	// otherwise wedge Stop until the idle reaper fires.
	select {
	case <-ex.stopped:
		return nil
	default:
	}
	p = newTenantPipe(ex, tenant)
	ex.pipes[tenant] = p
	ex.wg.Add(1)
	go p.run()
	return p
}

// removePipe deletes p from the map only if it is still the registered pipe for
// tenant, so a freshly recreated pipe is never accidentally removed.
func (ex *Exporter) removePipe(tenant string, p *tenantPipe) {
	ex.mu.Lock()
	defer ex.mu.Unlock()
	if ex.pipes[tenant] == p {
		delete(ex.pipes, tenant)
	}
}

// Stop signals all pipes to flush and exit, then waits. Subsequent Submits are
// dropped. Idempotent.
func (ex *Exporter) Stop() {
	ex.stop.Do(func() {
		// Close the stop signal and snapshot pipes atomically under the same lock
		// getOrCreate uses, so no pipe can be registered after this snapshot.
		ex.mu.Lock()
		close(ex.stopped)
		pipes := make([]*tenantPipe, 0, len(ex.pipes))
		for _, p := range ex.pipes {
			pipes = append(pipes, p)
		}
		ex.mu.Unlock()
		for _, p := range pipes {
			p.signalStop()
		}
		ex.wg.Wait()
	})
}

type timedEvent struct {
	ev Event
	at time.Time
}

type enqResult int

const (
	enqOK enqResult = iota
	enqFull
	enqClosed
)

// tenantPipe owns one tenant's bounded queue and the goroutine that batches and
// delivers its events.
type tenantPipe struct {
	ex     *Exporter
	tenant string
	ch     chan timedEvent
	quit   chan struct{}

	mu     sync.Mutex
	closed bool

	// connector cache
	cached   []ConnectorWithSecret
	cachedAt time.Time

	breakers sync.Map // connector id -> *breaker
}

func newTenantPipe(ex *Exporter, tenant string) *tenantPipe {
	return &tenantPipe{
		ex:     ex,
		tenant: tenant,
		ch:     make(chan timedEvent, ex.cfg.QueueSize),
		quit:   make(chan struct{}),
	}
}

func (p *tenantPipe) enqueue(te timedEvent) enqResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return enqClosed
	}
	select {
	case p.ch <- te:
		return enqOK
	default:
		return enqFull
	}
}

func (p *tenantPipe) signalStop() { close(p.quit) }

func (p *tenantPipe) run() {
	defer p.ex.wg.Done()
	ticker := time.NewTicker(p.ex.cfg.FlushInterval)
	defer ticker.Stop()
	idle := time.NewTimer(p.ex.cfg.IdleTimeout)
	defer idle.Stop()

	batch := make([]timedEvent, 0, p.ex.cfg.BatchSize)
	resetIdle := func() {
		idle.Reset(p.ex.cfg.IdleTimeout)
	}
	flush := func() {
		if len(batch) == 0 {
			return
		}
		p.deliver(batch)
		batch = batch[:0]
	}

	for {
		select {
		case <-p.quit:
			p.drainInto(&batch)
			flush()
			return
		case <-ticker.C:
			flush()
		case <-idle.C:
			// Reap only when truly idle: no buffered events and nothing batched.
			if len(batch) == 0 && p.tryClose() {
				return
			}
			resetIdle()
		case te := <-p.ch:
			p.ex.metrics.addQueueDepth(-1)
			batch = append(batch, te)
			resetIdle()
			if len(batch) >= p.ex.cfg.BatchSize {
				flush()
			}
		}
	}
}

// tryClose marks the pipe closed if its queue is empty, removing it from the
// exporter. Returns true when the goroutine should exit.
func (p *tenantPipe) tryClose() bool {
	p.mu.Lock()
	if len(p.ch) > 0 {
		p.mu.Unlock()
		return false
	}
	p.closed = true
	p.mu.Unlock()
	p.ex.removePipe(p.tenant, p)
	return true
}

// drainInto pulls any buffered events into batch (used on shutdown).
func (p *tenantPipe) drainInto(batch *[]timedEvent) {
	for {
		select {
		case te := <-p.ch:
			p.ex.metrics.addQueueDepth(-1)
			*batch = append(*batch, te)
		default:
			return
		}
	}
}

// connectors returns the tenant's active connectors, using a short-lived cache.
func (p *tenantPipe) connectors(ctx context.Context) []ConnectorWithSecret {
	if time.Since(p.cachedAt) < p.ex.cfg.ConnectorCacheTTL && p.cached != nil {
		return p.cached
	}
	got, err := p.ex.store.ListActiveWithSecrets(ctx, p.tenant)
	if err != nil {
		// On a store error keep serving the last good set rather than dropping
		// deliveries; a transient DB blip must not lose events.
		return p.cached
	}
	p.cached = got
	p.cachedAt = time.Now()
	return got
}

func (p *tenantPipe) deliver(batch []timedEvent) {
	ctx := context.Background()
	conns := p.connectors(ctx)
	if len(conns) == 0 {
		return
	}
	// Earliest enqueue time drives the lag metric (worst-case staleness).
	earliest := batch[0].at
	events := make([]Event, len(batch))
	for i, te := range batch {
		events[i] = te.ev
		if te.at.Before(earliest) {
			earliest = te.at
		}
	}
	for _, cws := range conns {
		p.deliverToConnector(ctx, cws, events, earliest)
	}
}

func (p *tenantPipe) deliverToConnector(ctx context.Context, cws ConnectorWithSecret, events []Event, earliest time.Time) {
	c := cws.Connector
	kind := kindLabel(c.Kind)
	allow := allowSet(c.FieldAllowList)
	records := make([]map[string]any, 0, len(events))
	for _, ev := range events {
		records = append(records, ev.minimized(allow))
	}
	rr, err := renderBatch(c, cws.Secret, records, "")
	if err != nil {
		p.ex.metrics.recordOutcome(kind, outcomeRenderError)
		return
	}
	rr.headers["X-Kseal-Idempotency-Key"] = idempotencyKey(c.Id, rr.body)
	if c.Kind == ksealv1.SiemKind_SIEM_KIND_SPLUNK_HEC {
		rr.headers["X-Splunk-Request-Channel"] = rr.headers["X-Kseal-Idempotency-Key"]
	}
	p.ex.metrics.observeBatch(len(records))

	br := p.breakerFor(c.Id)
	if !br.allow(p.ex.now()) {
		p.ex.metrics.recordOutcome(kind, outcomeCircuitOpen)
		return
	}

	body, enc, err := maybeGzip(rr, p.ex.cfg.GzipMinBytes)
	if err != nil {
		p.ex.metrics.recordOutcome(kind, outcomeRenderError)
		return
	}

	for attempt := 1; attempt <= p.ex.cfg.MaxAttempts; attempt++ {
		status, sendErr := p.send(ctx, rr, body, enc)
		switch classify(status, sendErr) {
		case resultSuccess:
			br.recordSuccess()
			p.ex.metrics.recordOutcome(kind, outcomeSuccess)
			p.ex.metrics.observeLag(p.ex.now().Sub(earliest).Seconds())
			return
		case resultPermanent:
			br.recordFailure(p.ex.now(), p.ex.cfg.BreakerTrip, p.ex.cfg.BreakerReset)
			p.ex.metrics.recordDeadLetter(kind)
			return
		case resultRetryable:
			br.recordFailure(p.ex.now(), p.ex.cfg.BreakerTrip, p.ex.cfg.BreakerReset)
			if attempt == p.ex.cfg.MaxAttempts {
				p.ex.metrics.recordDeadLetter(kind)
				return
			}
			p.ex.metrics.recordOutcome(kind, outcomeRetry)
			if !sleepCtx(ctx, p.quit, p.backoff(attempt)) {
				// Interrupted by shutdown mid-backoff. With no durable queue we
				// cannot redeliver, so this batch is dead-lettered (counted) rather
				// than silently lost.
				p.ex.metrics.recordDeadLetter(kind)
				return
			}
		}
	}
}

// send performs one attempt and returns the HTTP status (0 on transport error).
func (p *tenantPipe) send(ctx context.Context, rr renderedRequest, body []byte, encoding string) (int, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, p.ex.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, rr.url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	for k, v := range rr.headers {
		req.Header.Set(k, v)
	}
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	resp, err := p.ex.client.Do(req)
	if err != nil {
		return 0, err
	}
	// Drain and close so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func (p *tenantPipe) backoff(attempt int) time.Duration {
	// Exponential base*2^(attempt-1), capped, with full jitter in [0, d].
	d := p.ex.cfg.BaseBackoff << (attempt - 1)
	if d <= 0 || d > p.ex.cfg.MaxBackoff {
		d = p.ex.cfg.MaxBackoff
	}
	return time.Duration(rand.Int64N(int64(d) + 1))
}

func (p *tenantPipe) breakerFor(id string) *breaker {
	b, _ := p.breakers.LoadOrStore(id, &breaker{})
	return b.(*breaker)
}

// maybeGzip compresses the body when the sink supports it and the body is large
// enough to benefit. Returns the (possibly compressed) body and the
// Content-Encoding to set ("" when uncompressed).
func maybeGzip(rr renderedRequest, minBytes int) ([]byte, string, error) {
	if !rr.gzippable || len(rr.body) < minBytes {
		return rr.body, "", nil
	}
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(rr.body); err != nil {
		return nil, "", err
	}
	if err := gw.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), "gzip", nil
}

type deliveryResult int

const (
	resultSuccess deliveryResult = iota
	resultRetryable
	resultPermanent
)

// classify maps an HTTP status / transport error to a delivery result.
// Transport errors and 408/429/5xx are retryable; other 4xx are permanent.
func classify(status int, err error) deliveryResult {
	if err != nil {
		return resultRetryable
	}
	switch {
	case status >= 200 && status < 300:
		return resultSuccess
	case status == http.StatusRequestTimeout || status == http.StatusTooManyRequests:
		return resultRetryable
	case status >= 500:
		return resultRetryable
	default:
		return resultPermanent
	}
}

// sleepCtx waits for d or until ctx/quit fires. Returns false if interrupted.
func sleepCtx(ctx context.Context, quit <-chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	case <-quit:
		return false
	}
}

// idempotencyKey is a deterministic key over the connector id and the exact
// body so retries of the same batch reuse it (enabling sink-side dedupe).
func idempotencyKey(connectorID string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(connectorID))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)[:16])
}

func kindLabel(k ksealv1.SiemKind) string {
	switch k {
	case ksealv1.SiemKind_SIEM_KIND_SPLUNK_HEC:
		return "splunk_hec"
	case ksealv1.SiemKind_SIEM_KIND_SENTINEL:
		return "sentinel"
	case ksealv1.SiemKind_SIEM_KIND_ELASTIC:
		return "elastic"
	default:
		return "unspecified"
	}
}

// breaker is a per-connector circuit breaker.
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
