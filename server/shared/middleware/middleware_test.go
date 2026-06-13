package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/kennguy3n/kseal/server/shared/telemetry"
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

// TestObservabilityErrorPathNoPanic pins the regression where a handler that
// returns (nil, err) made the observability interceptor panic. On the error
// path connect boxes a typed-nil *Response into the non-nil AnyResponse
// interface, so the old `if resp != nil { resp.Header()... }` dereferenced a
// nil pointer; the recovery interceptor then masked the handler's real code
// (e.g. NotFound) as Internal. The interceptor must instead pass the original
// error through untouched and not panic.
func TestObservabilityErrorPathNoPanic(t *testing.T) {
	tel, err := telemetry.Setup("test", "test")
	if err != nil {
		t.Fatal(err)
	}
	ic := &Interceptors{Logger: zerolog.Nop(), Tracer: *tel}

	// next mimics connect's unary handler on the error path: a typed-nil
	// *Response boxed into AnyResponse, alongside a NotFound error.
	var typedNil *connect.Response[emptypb.Empty]
	next := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		return typedNil, connect.NewError(connect.CodeNotFound, errors.New("registry: not found"))
	}
	wrapped := ic.observability()(next)

	// Before the fix this panicked (failing the test); after it returns the
	// original NotFound code.
	_, gotErr := wrapped(context.Background(), connect.NewRequest(&emptypb.Empty{}))
	if connect.CodeOf(gotErr) != connect.CodeNotFound {
		t.Fatalf("expected NotFound to pass through, got %v (%v)", connect.CodeOf(gotErr), gotErr)
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
