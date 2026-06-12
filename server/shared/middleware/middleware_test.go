package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

func TestRateLimiterTokenBucket(t *testing.T) {
	l := NewRedisRateLimiter(newRedis(t), 1, 3, "rl")
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		ok, err := l.Allow(ctx, "tenant1")
		if err != nil || !ok {
			t.Fatalf("request %d should be allowed: ok=%v err=%v", i, ok, err)
		}
	}
	ok, err := l.Allow(ctx, "tenant1")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("burst exhausted, should be limited")
	}
	// Independent bucket per key.
	if ok, _ := l.Allow(ctx, "tenant2"); !ok {
		t.Fatal("separate tenant should have its own budget")
	}
}

func TestCORSPreflight(t *testing.T) {
	h := CORS([]string{"https://app.example.com"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Fatalf("missing CORS origin header: %v", rr.Header())
	}
}

func TestRequestIDInjected(t *testing.T) {
	var seen string
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = w.Header().Get("X-Request-Id")
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if seen == "" {
		t.Fatal("expected request id header to be set")
	}
}
