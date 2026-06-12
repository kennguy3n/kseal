package telemetry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandlerLiveness(t *testing.T) {
	rr := httptest.NewRecorder()
	HealthHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("liveness = %d", rr.Code)
	}
}

func TestHealthHandlerReadinessFails(t *testing.T) {
	h := HealthHandler(Check{Name: "db", Func: func(ctx context.Context) error { return errors.New("down") }})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness should fail: %d", rr.Code)
	}
}

func TestHealthHandlerReadinessPasses(t *testing.T) {
	h := HealthHandler(Check{Name: "db", Func: func(ctx context.Context) error { return nil }})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("readiness = %d", rr.Code)
	}
}

func TestMetricsHandler(t *testing.T) {
	m, err := NewMetrics()
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	m.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("metrics = %d", rr.Code)
	}
}
