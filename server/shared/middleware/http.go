package middleware

import (
	"net/http"
	"strings"
)

// CORS wraps h with permissive-but-scoped CORS handling for the dashboard. Only
// the configured origins are echoed back; credentials are not allowed since the
// API authenticates via bearer keys, not cookies.
func CORS(allowedOrigins []string, h http.Handler) http.Handler {
	allowed := map[string]bool{}
	wildcard := false
	for _, o := range allowedOrigins {
		if o == "*" {
			wildcard = true
		}
		allowed[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && (wildcard || allowed[origin]) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", strings.Join([]string{
				"Content-Type", "Authorization", "X-API-Key", "X-Request-Id",
				"Connect-Protocol-Version", "Connect-Timeout-Ms",
			}, ", "))
			w.Header().Set("Access-Control-Max-Age", "86400")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// SecurityHeaders adds browser security headers to every response. When
// enableHSTS is true a Strict-Transport-Security header is included, directing
// browsers to only use HTTPS for the connection. Enable HSTS only when the
// server is actually serving TLS (or behind a TLS-terminating proxy that sets
// X-Forwarded-Proto).
func SecurityHeaders(enableHSTS bool, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if enableHSTS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		h.ServeHTTP(w, r)
	})
}

// MaxBodySize wraps h with a request body size limit. Requests whose
// Content-Length exceeds maxBytes are rejected with 413. For streaming bodies
// the reader is capped so a client cannot exhaust server memory by sending an
// oversized chunked body.
func MaxBodySize(maxBytes int64, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		h.ServeHTTP(w, r)
	})
}

// RequestID ensures every HTTP response carries an X-Request-Id, generating one
// when the client did not supply it. Connect handlers reuse the same id.
func RequestID(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			id = genRequestID()
			r.Header.Set("X-Request-Id", id)
		}
		w.Header().Set("X-Request-Id", id)
		h.ServeHTTP(w, r)
	})
}
