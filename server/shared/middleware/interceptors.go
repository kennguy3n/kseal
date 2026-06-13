package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog"

	"github.com/kennguy3n/kseal/server/shared/auth"
	"github.com/kennguy3n/kseal/server/shared/telemetry"
)

// APIKeyValidator validates a presented API key and returns the resolved
// principal. The control-plane registry store implements it.
type APIKeyValidator interface {
	ValidateAPIKey(ctx context.Context, plaintext string) (*auth.Principal, error)
}

// Interceptors assembles the standard Connect interceptor chain.
type Interceptors struct {
	Logger    zerolog.Logger
	Metrics   *telemetry.Metrics
	Tracer    telemetry.Telemetry
	Limiter   *RedisRateLimiter
	Validator APIKeyValidator
	// RequireAuth is the set of fully-qualified procedures that demand a valid
	// API key (control-plane surfaces). Device-plane procedures authenticate via
	// request body + signed proofs and are absent here.
	RequireAuth map[string]bool
}

// Chain returns the ordered interceptor options for connect handlers.
func (i *Interceptors) Chain() connect.Option {
	return connect.WithInterceptors(
		i.recovery(),
		i.observability(),
		i.authn(),
		i.rateLimit(),
	)
}

func genRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// recovery converts panics into internal errors so a single bad request never
// takes down the process — essential for a high-volume data plane.
func (i *Interceptors) recovery() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (resp connect.AnyResponse, err error) {
			defer func() {
				if p := recover(); p != nil {
					i.Logger.Error().
						Str("procedure", req.Spec().Procedure).
						Interface("panic", p).
						Msg("recovered panic in handler")
					err = connect.NewError(connect.CodeInternal, errors.New("internal error"))
				}
			}()
			return next(ctx, req)
		}
	}
}

// observability assigns a request id, starts a span, records metrics, and logs
// the outcome of every call.
func (i *Interceptors) observability() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			reqID := req.Header().Get("X-Request-Id")
			if reqID == "" {
				reqID = genRequestID()
			}
			ctx = auth.WithRequestID(ctx, reqID)
			procedure := req.Spec().Procedure

			ctx, span := i.Tracer.Tracer.Start(ctx, procedure)
			start := time.Now()
			resp, err := next(ctx, req)
			elapsed := time.Since(start)
			span.End()

			code := "ok"
			if err != nil {
				code = connect.CodeOf(err).String()
			}
			if i.Metrics != nil {
				i.Metrics.RPCRequests.WithLabelValues(procedure, code).Inc()
				i.Metrics.RPCLatency.WithLabelValues(procedure).Observe(elapsed.Seconds())
			}
			ev := i.Logger.Info()
			if err != nil {
				ev = i.Logger.Warn().Err(err)
			}
			tenant, _ := auth.TenantFrom(ctx)
			ev.Str("procedure", procedure).
				Str("request_id", reqID).
				Str("tenant", tenant).
				Str("code", code).
				Dur("duration", elapsed).
				Msg("rpc")
			// On the error path connect boxes a typed-nil *Response into the
			// non-nil AnyResponse interface, so a bare `resp != nil` check
			// passes yet resp.Header() dereferences a nil pointer and panics
			// (recovered as CodeInternal, masking the handler's real code, e.g.
			// NotFound). Guard the underlying pointer before touching it.
			if resp != nil && !reflect.ValueOf(resp).IsNil() {
				resp.Header().Set("X-Request-Id", reqID)
			}
			return resp, err
		}
	}
}

// authn validates an API key when present and injects the tenant context. For
// device-plane procedures the tenant is taken from the request body; for
// control-plane procedures a valid key is mandatory.
func (i *Interceptors) authn() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			procedure := req.Spec().Procedure
			key := bearerToken(req.Header().Get("Authorization"))
			if key == "" {
				key = req.Header().Get("X-API-Key")
			}

			if key != "" && i.Validator != nil {
				principal, err := i.Validator.ValidateAPIKey(ctx, key)
				if err != nil {
					return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid api key"))
				}
				ctx = auth.WithPrincipal(ctx, principal)
			} else if i.RequireAuth[procedure] {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("api key required"))
			}

			// Device-plane: derive tenant from the request body when not already
			// established by an API key.
			if _, err := auth.TenantFrom(ctx); err != nil {
				if tb, ok := req.Any().(interface{ GetTenantId() string }); ok && tb.GetTenantId() != "" {
					ctx = auth.WithTenant(ctx, tb.GetTenantId())
				}
			}
			return next(ctx, req)
		}
	}
}

// rateLimit enforces a per-tenant token bucket. It fails open on limiter errors.
func (i *Interceptors) rateLimit() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if i.Limiter == nil {
				return next(ctx, req)
			}
			tenant, err := auth.TenantFrom(ctx)
			if err != nil || tenant == "" {
				tenant = "anon"
			}
			allowed, lerr := i.Limiter.Allow(ctx, tenant)
			if lerr != nil {
				i.Logger.Warn().Err(lerr).Str("tenant", tenant).Msg("rate limiter degraded; failing open")
			} else if !allowed {
				if i.Metrics != nil {
					i.Metrics.RateLimited.WithLabelValues(tenant).Inc()
				}
				return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("rate limit exceeded"))
			}
			return next(ctx, req)
		}
	}
}

func bearerToken(header string) string {
	if header == "" {
		return ""
	}
	const prefix = "Bearer "
	if strings.HasPrefix(header, prefix) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return ""
}
