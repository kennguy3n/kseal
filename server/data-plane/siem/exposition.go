package siem

import (
	"bytes"
	"net/http"
)

// classicTextAccept selects the classic Prometheus text exposition format
// (version 0.0.4). Unlike OpenMetrics it has no terminating "# EOF" marker, so
// several disjoint registries can be concatenated into one valid response.
const classicTextAccept = "text/plain; version=0.0.4; charset=utf-8"

// CombinedMetricsHandler serves several Prometheus exposition handlers on a
// single endpoint by concatenating their output.
//
// It deliberately forces classic-text negotiation on every sub-handler. If a
// scraper negotiated OpenMetrics, each promhttp handler would terminate its
// body with a mandatory "# EOF" line; concatenating them would leave an "# EOF"
// in the middle of the response and OpenMetrics parsers stop reading there,
// silently dropping every metric after the first registry. Classic text has no
// such terminator, so the concatenation is a single valid exposition provided
// the registries expose disjoint metric families (they do: the platform and
// SIEM registries share no metric names and neither registers the default
// go/process collectors).
func CombinedMetricsHandler(handlers ...http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := r.Clone(r.Context())
		req.Header.Set("Accept", classicTextAccept)
		first := true
		for _, h := range handlers {
			rec := &bufferingResponseWriter{header: http.Header{}}
			h.ServeHTTP(rec, req)
			if first {
				if ct := rec.header.Get("Content-Type"); ct != "" {
					w.Header().Set("Content-Type", ct)
				}
				first = false
			}
			_, _ = w.Write(rec.buf.Bytes())
		}
	})
}

// bufferingResponseWriter captures a handler's body and headers in memory so a
// composite handler can post-process or concatenate sub-handler output.
type bufferingResponseWriter struct {
	header http.Header
	buf    bytes.Buffer
}

func (w *bufferingResponseWriter) Header() http.Header         { return w.header }
func (w *bufferingResponseWriter) Write(b []byte) (int, error) { return w.buf.Write(b) }
func (w *bufferingResponseWriter) WriteHeader(int)             {}
