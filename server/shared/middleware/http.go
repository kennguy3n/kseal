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
