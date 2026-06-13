// Package telemetry wires OpenTelemetry tracing, Prometheus metrics, and the
// liveness/readiness HTTP probes used by the server and docker/k8s healthchecks.
package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// Options configures the tracing pipeline. The zero value disables span export
// (current behavior) and samples every span.
type Options struct {
	// OTLPEndpoint is the OTLP/gRPC collector address (host:port). Empty means
	// no exporter is attached and spans are not shipped anywhere.
	OTLPEndpoint string
	// OTLPSampleRatio is the head-sampling probability in [0,1]. Values <= 0 or
	// >= 1 sample everything. Only meaningful when an exporter is attached.
	OTLPSampleRatio float64
	// OTLPInsecure disables transport security to the collector (typical for an
	// in-cluster collector behind a service mesh). Defaults to true.
	OTLPInsecure bool
}

// Telemetry holds the configured providers and exposes a Shutdown hook.
type Telemetry struct {
	Tracer   trace.Tracer
	Metrics  *Metrics
	provider *sdktrace.TracerProvider
}

// Setup configures a global tracer provider and the Prometheus metrics. When
// opts.OTLPEndpoint is set, a batched OTLP/gRPC span exporter is attached and
// the configured sampling ratio applied; otherwise spans are sampled but not
// exported (no collector dependency for local/dev).
func Setup(serviceName, env string, opts Options) (*Telemetry, error) {
	// Use a schemaless resource for our attributes so merging with the SDK's
	// default resource (which carries its own, newer schema URL) does not fail
	// with a schema-conflict error.
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName(serviceName),
		semconv.DeploymentEnvironment(env),
	))
	if err != nil {
		return nil, fmt.Errorf("build resource: %w", err)
	}

	tpOpts := []sdktrace.TracerProviderOption{
		sdktrace.WithSampler(newSampler(opts.OTLPEndpoint, opts.OTLPSampleRatio)),
		sdktrace.WithResource(res),
	}
	if opts.OTLPEndpoint != "" {
		exporter, err := newOTLPExporter(context.Background(), opts.OTLPEndpoint, opts.OTLPInsecure)
		if err != nil {
			return nil, fmt.Errorf("otlp exporter: %w", err)
		}
		tpOpts = append(tpOpts, sdktrace.WithBatcher(exporter))
	}

	tp := sdktrace.NewTracerProvider(tpOpts...)
	otel.SetTracerProvider(tp)

	metrics, err := NewMetrics()
	if err != nil {
		return nil, err
	}
	return &Telemetry{
		Tracer:   tp.Tracer(serviceName),
		Metrics:  metrics,
		provider: tp,
	}, nil
}

// Shutdown flushes and stops the tracer provider.
func (t *Telemetry) Shutdown(ctx context.Context) error {
	if t.provider == nil {
		return nil
	}
	return t.provider.Shutdown(ctx)
}

// Check is a named readiness probe.
type Check struct {
	Name string
	Func func(ctx context.Context) error
}

// HealthHandler returns an http.Handler serving liveness or readiness. Liveness
// (/healthz) always returns 200 once the process is up; readiness (/readyz) runs
// the provided checks and reports 503 if any fail.
func HealthHandler(checks ...Check) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(checks) == 0 {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		for _, c := range checks {
			if err := c.Func(ctx); err != nil {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = fmt.Fprintf(w, "%s: %v\n", c.Name, err)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
}
