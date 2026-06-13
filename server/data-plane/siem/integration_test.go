package siem

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// recordedReq captures one delivery the mock sink received.
type recordedReq struct {
	headers http.Header
	body    []byte
}

// mockSink is an httptest-backed stand-in for an external SIEM. It records every
// request and returns a status chosen by statusFor(attemptIndex).
type mockSink struct {
	mu        sync.Mutex
	reqs      []recordedReq
	statusFor func(n int) int
	got       chan struct{}
}

func newMockSink(statusFor func(n int) int) *mockSink {
	return &mockSink{statusFor: statusFor, got: make(chan struct{}, 64)}
}

func (m *mockSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if r.Header.Get("Content-Encoding") == "gzip" {
		if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
			if dec, err := io.ReadAll(zr); err == nil {
				body = dec
			}
		}
	}
	m.mu.Lock()
	m.reqs = append(m.reqs, recordedReq{headers: r.Header.Clone(), body: body})
	n := len(m.reqs)
	m.mu.Unlock()

	status := http.StatusOK
	if m.statusFor != nil {
		status = m.statusFor(n)
	}
	w.WriteHeader(status)
	select {
	case m.got <- struct{}{}:
	default:
	}
}

func (m *mockSink) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.reqs)
}

func (m *mockSink) requests() []recordedReq {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]recordedReq(nil), m.reqs...)
}

// waitForCount blocks until the sink has received n requests or the deadline.
func (m *mockSink) waitForCount(t *testing.T, n int, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for m.count() < n {
		select {
		case <-m.got:
		case <-deadline:
			t.Fatalf("timed out waiting for %d requests, got %d", n, m.count())
		}
	}
}

func fastConfig() ExporterConfig {
	return ExporterConfig{
		QueueSize:         128,
		BatchSize:         100,
		FlushInterval:     10 * time.Millisecond,
		MaxAttempts:       3,
		BaseBackoff:       time.Millisecond,
		MaxBackoff:        5 * time.Millisecond,
		BreakerTrip:       100, // high so the breaker doesn't interfere here
		BreakerReset:      time.Second,
		Timeout:           2 * time.Second,
		ConnectorCacheTTL: time.Millisecond,
		IdleTimeout:       time.Minute,
	}
}

func registerSplunk(t *testing.T, st *MemConnectorStore, tenant, url string, allow []string) {
	t.Helper()
	_, err := st.CreateConnector(context.Background(), CreateConnectorInput{
		TenantID:         tenant,
		Kind:             ksealv1.SiemKind_SIEM_KIND_SPLUNK_HEC,
		Endpoint:         url,
		Secret:           []byte("hec-token"),
		FieldAllowList:   allow,
		SplunkIndex:      "kseal",
		SplunkSourcetype: "kseal:trust",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationSuccessRespectsAllowListAndPrivacy(t *testing.T) {
	sink := newMockSink(func(int) int { return http.StatusOK })
	srv := httptest.NewServer(sink)
	defer srv.Close()

	st := NewMemConnectorStore(testEncryptor(t))
	// Deliberately EXCLUDE install_key_hash from the allow-list.
	registerSplunk(t, st, "t-1", srv.URL, []string{FieldEventType, FieldRiskBits, FieldRiskLevel})

	m, err := NewMetrics()
	if err != nil {
		t.Fatal(err)
	}
	ex := NewExporter(st, fastConfig(), m)
	defer ex.Stop()

	ev := sampleEvent()
	ev.TenantID = "t-1"
	ex.Submit(ev)

	sink.waitForCount(t, 1, 3*time.Second)

	req := sink.requests()[0]
	if got := req.headers.Get("Authorization"); got != "Splunk hec-token" {
		t.Fatalf("auth header = %q", got)
	}
	if req.headers.Get("X-Kseal-Idempotency-Key") == "" {
		t.Fatal("missing idempotency key header")
	}
	// The delivered event must contain ONLY allow-listed fields, never PII.
	var env map[string]any
	if err := json.Unmarshal(firstLine(req.body), &env); err != nil {
		t.Fatalf("body not json: %v", err)
	}
	event := env["event"].(map[string]any)
	if _, leaked := event[FieldInstallKeyHash]; leaked {
		t.Fatal("install_key_hash egressed despite exclusion from allow-list")
	}
	if _, ok := event[FieldRiskBits]; !ok {
		t.Fatal("allow-listed risk_bits missing")
	}
	assertNoPIIKeys(t, req.body)

	waitForFloat(t, func() float64 {
		return testutil.ToFloat64(m.ExportTotal.WithLabelValues("splunk_hec", outcomeSuccess))
	}, 1)
}

func TestIntegrationRetryThenSucceedReusesIdempotencyKey(t *testing.T) {
	// Fail the first two attempts (503), succeed on the third.
	sink := newMockSink(func(n int) int {
		if n < 3 {
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	})
	srv := httptest.NewServer(sink)
	defer srv.Close()

	st := NewMemConnectorStore(testEncryptor(t))
	registerSplunk(t, st, "t-1", srv.URL, nil)

	m, _ := NewMetrics()
	ex := NewExporter(st, fastConfig(), m)
	defer ex.Stop()

	ev := sampleEvent()
	ev.TenantID = "t-1"
	ex.Submit(ev)

	sink.waitForCount(t, 3, 3*time.Second)
	reqs := sink.requests()
	if len(reqs) != 3 {
		t.Fatalf("expected exactly 3 attempts, got %d", len(reqs))
	}
	key := reqs[0].headers.Get("X-Kseal-Idempotency-Key")
	for i, r := range reqs {
		if got := r.headers.Get("X-Kseal-Idempotency-Key"); got != key {
			t.Fatalf("attempt %d idempotency key %q != %q (retries must reuse the key)", i, got, key)
		}
	}
	waitForFloat(t, func() float64 {
		return testutil.ToFloat64(m.ExportTotal.WithLabelValues("splunk_hec", outcomeSuccess))
	}, 1)
}

func TestIntegrationPermanentFailureDeadLetters(t *testing.T) {
	sink := newMockSink(func(int) int { return http.StatusBadRequest })
	srv := httptest.NewServer(sink)
	defer srv.Close()

	st := NewMemConnectorStore(testEncryptor(t))
	registerSplunk(t, st, "t-1", srv.URL, nil)

	m, _ := NewMetrics()
	ex := NewExporter(st, fastConfig(), m)
	defer ex.Stop()

	ev := sampleEvent()
	ev.TenantID = "t-1"
	ex.Submit(ev)

	sink.waitForCount(t, 1, 3*time.Second)
	waitForFloat(t, func() float64 {
		return testutil.ToFloat64(m.DeadLetter.WithLabelValues("splunk_hec"))
	}, 1)
	// A 4xx is permanent: exactly one attempt, no retries.
	time.Sleep(50 * time.Millisecond)
	if c := sink.count(); c != 1 {
		t.Fatalf("permanent failure must not retry; got %d attempts", c)
	}
}

func TestIntegrationExhaustedRetriesDeadLetters(t *testing.T) {
	sink := newMockSink(func(int) int { return http.StatusServiceUnavailable })
	srv := httptest.NewServer(sink)
	defer srv.Close()

	st := NewMemConnectorStore(testEncryptor(t))
	registerSplunk(t, st, "t-1", srv.URL, nil)

	m, _ := NewMetrics()
	cfg := fastConfig()
	ex := NewExporter(st, cfg, m)
	defer ex.Stop()

	ev := sampleEvent()
	ev.TenantID = "t-1"
	ex.Submit(ev)

	sink.waitForCount(t, cfg.MaxAttempts, 3*time.Second)
	waitForFloat(t, func() float64 {
		return testutil.ToFloat64(m.DeadLetter.WithLabelValues("splunk_hec"))
	}, 1)
}

func waitForFloat(t *testing.T, get func() float64, want float64) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if get() == want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("metric did not reach %v (last=%v)", want, get())
		case <-time.After(5 * time.Millisecond):
		}
	}
}
