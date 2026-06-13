package telemetry

import (
	"context"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func TestNewSamplerDefaultsAlwaysOn(t *testing.T) {
	// No endpoint -> always-sample regardless of ratio (current behavior).
	s := newSampler("", 0.1)
	if got := s.Description(); got == "" {
		t.Fatal("expected a sampler description")
	}
	if !alwaysSamples(t, s) {
		t.Fatal("expected always-sample when no exporter configured")
	}
}

func TestNewSamplerRatioBounds(t *testing.T) {
	// ratio >= 1 or <= 0 collapses to always-sample.
	if !alwaysSamples(t, newSampler("collector:4317", 1.0)) {
		t.Fatal("ratio 1.0 should always sample")
	}
	if !alwaysSamples(t, newSampler("collector:4317", 0)) {
		t.Fatal("ratio 0 should fall back to always sample")
	}
}

func TestNewSamplerProbabilistic(t *testing.T) {
	s := newSampler("collector:4317", 0.25)
	// TraceIDRatioBased samplers describe their ratio; assert we got one.
	if desc := s.Description(); desc == "" {
		t.Fatal("expected probabilistic sampler description")
	}
	// A probabilistic sampler must not sample every trace id.
	if alwaysSamples(t, s) {
		t.Fatal("probabilistic sampler should not sample every trace")
	}
}

func TestNewOTLPExporterConstructsWithoutCollector(t *testing.T) {
	// Construction connects lazily; it must succeed without a live collector.
	exp, err := newOTLPExporter(context.Background(), "localhost:4317", true)
	if err != nil {
		t.Fatalf("construct exporter: %v", err)
	}
	if exp == nil {
		t.Fatal("nil exporter")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = exp.Shutdown(ctx)
}

func TestSetupWithoutEndpointHasNoExporter(t *testing.T) {
	tel, err := Setup("test-svc", "dev", Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tel.Shutdown(context.Background()) }()
	if tel.Tracer == nil {
		t.Fatal("nil tracer")
	}
}

// alwaysSamples reports whether s records-and-samples a spread of trace ids.
func alwaysSamples(t *testing.T, s sdktrace.Sampler) bool {
	t.Helper()
	for i := byte(0); i < 32; i++ {
		var tid trace.TraceID
		// TraceIDRatioBased keys off the high bytes of tid[8:16]; spread them
		// across the full range so a sub-1.0 ratio rejects some ids.
		tid[8] = i << 3
		tid[9] = i
		res := s.ShouldSample(sdktrace.SamplingParameters{TraceID: tid})
		if res.Decision != sdktrace.RecordAndSample {
			return false
		}
	}
	return true
}
