package telemetry

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the Prometheus instruments exported by the server. They are
// registered on a private registry so tests can construct multiple instances.
type Metrics struct {
	registry *prometheus.Registry

	RPCRequests     *prometheus.CounterVec
	RPCLatency      *prometheus.HistogramVec
	RateLimited     *prometheus.CounterVec
	IngestEvents    *prometheus.CounterVec
	WebhookDispatch *prometheus.CounterVec
	BlockRate       *prometheus.GaugeVec
}

// NewMetrics constructs and registers the metric instruments.
func NewMetrics() (*Metrics, error) {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		registry: reg,
		RPCRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kseal_rpc_requests_total",
			Help: "Total Connect RPC requests by procedure and outcome.",
		}, []string{"procedure", "code"}),
		RPCLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "kseal_rpc_duration_seconds",
			Help:    "RPC handler latency in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"procedure"}),
		RateLimited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kseal_rate_limited_total",
			Help: "Requests rejected by the per-tenant rate limiter.",
		}, []string{"tenant"}),
		IngestEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kseal_ingest_events_total",
			Help: "Telemetry events processed by outcome.",
		}, []string{"outcome"}),
		WebhookDispatch: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kseal_webhook_dispatch_total",
			Help: "Webhook delivery attempts by outcome.",
		}, []string{"outcome"}),
		BlockRate: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kseal_block_rate",
			Help: "Observed block rate per tenant/app (0..1).",
		}, []string{"tenant", "app"}),
	}

	for _, c := range []prometheus.Collector{
		m.RPCRequests, m.RPCLatency, m.RateLimited, m.IngestEvents, m.WebhookDispatch, m.BlockRate,
	} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// Handler returns the Prometheus /metrics handler bound to this registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
