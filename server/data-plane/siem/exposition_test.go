package siem

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// TestCombinedMetricsHandlerNoMidStreamEOF proves that combining two disjoint
// registries yields a single exposition where the SECOND registry's metrics
// survive even when the scraper asks for OpenMetrics. A naive concatenation of
// OpenMetrics handlers would place a "# EOF" after the first registry and the
// second registry's metrics would be dropped by spec-compliant parsers.
func TestCombinedMetricsHandlerNoMidStreamEOF(t *testing.T) {
	regA := prometheus.NewRegistry()
	cA := prometheus.NewCounter(prometheus.CounterOpts{Name: "platform_metric_total", Help: "a"})
	cA.Inc()
	regA.MustRegister(cA)

	regB := prometheus.NewRegistry()
	cB := prometheus.NewCounter(prometheus.CounterOpts{Name: "kseal_siem_metric_total", Help: "b"})
	cB.Inc()
	regB.MustRegister(cB)

	h := CombinedMetricsHandler(
		promhttp.HandlerFor(regA, promhttp.HandlerOpts{}),
		promhttp.HandlerFor(regB, promhttp.HandlerOpts{}),
	)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	// Aggressively request OpenMetrics, the exact condition that breaks naive
	// concatenation.
	req.Header.Set("Accept", "application/openmetrics-text; version=1.0.0,text/plain;version=0.0.4;q=0.9")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "platform_metric_total") {
		t.Fatalf("first registry metric missing:\n%s", body)
	}
	if !strings.Contains(body, "kseal_siem_metric_total") {
		t.Fatalf("second registry metric dropped (mid-stream EOF truncation?):\n%s", body)
	}
	// Classic text exposition has no "# EOF" terminator; its presence would mean
	// a sub-handler negotiated OpenMetrics and could truncate the stream.
	if strings.Contains(body, "# EOF") {
		t.Fatalf("unexpected OpenMetrics EOF marker in combined output:\n%s", body)
	}
}
