package siem

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Delivery outcomes recorded on the export counter.
const (
	outcomeSuccess     = "success"
	outcomeRetry       = "retry"
	outcomeDeadLetter  = "dead_letter"
	outcomeDropped     = "dropped"
	outcomeCircuitOpen = "circuit_open"
	outcomeRenderError = "render_error"
)

// Metrics holds the Prometheus instruments for the SIEM exporter. They live on
// a dedicated registry so the subsystem owns its metric lifecycle without
// reaching into the shared telemetry registry; main.go exposes this registry
// alongside the platform metrics on the existing /metrics endpoint.
//
// Labels are deliberately low-cardinality (sink kind + outcome only) so the
// instruments stay bounded across ~5000 tenants — no tenant_id label is ever
// attached.
type Metrics struct {
	registry *prometheus.Registry

	ExportTotal    *prometheus.CounterVec // {kind, outcome}
	DeadLetter     *prometheus.CounterVec // {kind}
	ExportLag      prometheus.Histogram   // seconds from enqueue to successful export
	ExportLagGauge prometheus.Gauge       // most recent export lag (seconds)
	QueueDepth     prometheus.Gauge       // aggregate events buffered across tenant queues
	BatchEvents    prometheus.Histogram   // events per delivered batch
}

// NewMetrics constructs and registers the SIEM instruments on a private registry.
func NewMetrics() (*Metrics, error) {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		registry: reg,
		ExportTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kseal_siem_export_total",
			Help: "SIEM export deliveries by sink kind and outcome.",
		}, []string{"kind", "outcome"}),
		DeadLetter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kseal_siem_dead_letter_total",
			Help: "SIEM batches dropped to the dead-letter after exhausting retries or on permanent failure.",
		}, []string{"kind"}),
		ExportLag: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "kseal_siem_export_lag_seconds",
			Help:    "Latency from event enqueue to successful SIEM export, in seconds.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300},
		}),
		ExportLagGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kseal_siem_export_lag_latest_seconds",
			Help: "Most recently observed SIEM export lag, in seconds.",
		}),
		QueueDepth: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kseal_siem_queue_depth",
			Help: "Aggregate telemetry events currently buffered across per-tenant SIEM queues.",
		}),
		BatchEvents: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "kseal_siem_batch_events",
			Help:    "Number of events per delivered SIEM batch.",
			Buckets: []float64{1, 2, 5, 10, 25, 50, 100, 250, 500},
		}),
	}
	for _, c := range []prometheus.Collector{
		m.ExportTotal, m.DeadLetter, m.ExportLag, m.ExportLagGauge, m.QueueDepth, m.BatchEvents,
	} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// Gatherer exposes the registry so callers can merge it into a combined
// exposition (see main.go's /metrics wiring).
func (m *Metrics) Gatherer() prometheus.Gatherer { return m.registry }

// Handler returns a standalone Prometheus handler for this registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *Metrics) recordOutcome(kind, outcome string) {
	if m == nil {
		return
	}
	m.ExportTotal.WithLabelValues(kind, outcome).Inc()
}

func (m *Metrics) recordDeadLetter(kind string) {
	if m == nil {
		return
	}
	m.DeadLetter.WithLabelValues(kind).Inc()
	m.ExportTotal.WithLabelValues(kind, outcomeDeadLetter).Inc()
}

func (m *Metrics) observeLag(seconds float64) {
	if m == nil {
		return
	}
	if seconds < 0 {
		seconds = 0
	}
	m.ExportLag.Observe(seconds)
	m.ExportLagGauge.Set(seconds)
}

func (m *Metrics) addQueueDepth(delta float64) {
	if m == nil {
		return
	}
	m.QueueDepth.Add(delta)
}

func (m *Metrics) observeBatch(n int) {
	if m == nil {
		return
	}
	m.BatchEvents.Observe(float64(n))
}
