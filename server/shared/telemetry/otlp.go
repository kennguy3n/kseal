package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// newSampler builds the head sampler. With no exporter configured the previous
// always-sample behavior is kept (spans are cheap and only feed in-process
// instrumentation). With an exporter and a ratio in (0,1) it samples
// probabilistically, parent-respecting so a sampled trace stays sampled across
// services.
func newSampler(otlpEndpoint string, ratio float64) sdktrace.Sampler {
	if otlpEndpoint == "" || ratio <= 0 || ratio >= 1 {
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	}
	return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
}

// newOTLPExporter constructs an OTLP/gRPC span exporter. The exporter connects
// lazily, so construction does not require a live collector; failures surface
// on export and are retried by the SDK's batch processor.
func newOTLPExporter(ctx context.Context, endpoint string, insecure bool) (*otlptrace.Exporter, error) {
	opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(endpoint)}
	if insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	return otlptracegrpc.New(ctx, opts...)
}

// newOTLPMetricExporter constructs an OTLP/gRPC metric exporter. Like the span
// exporter it connects lazily, so construction needs no live collector; the
// periodic reader retries pushes on its own cadence.
func newOTLPMetricExporter(ctx context.Context, endpoint string, insecure bool) (sdkmetric.Exporter, error) {
	opts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpoint(endpoint)}
	if insecure {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}
	return otlpmetricgrpc.New(ctx, opts...)
}
