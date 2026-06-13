package siem

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// renderedRequest is a sink-agnostic description of one HTTP delivery: where to
// POST, which headers to set (including auth), and the uncompressed body. The
// exporter owns transport concerns (gzip, retries, timeouts) so formatters stay
// pure and trivially testable.
type renderedRequest struct {
	url     string
	headers map[string]string
	body    []byte
	// gzippable indicates the sink accepts Content-Encoding: gzip for this body.
	gzippable bool
}

func iso8601(sec int64) string { return time.Unix(sec, 0).UTC().Format(time.RFC3339) }

// renderBatch builds the HTTP delivery for a connector and a batch of already
// minimized, allow-listed records. secret is the decrypted auth material.
func renderBatch(c *ksealv1.SiemConnector, secret []byte, records []map[string]any, idemKey string) (renderedRequest, error) {
	switch c.Format {
	case ksealv1.SiemPayloadFormat_SIEM_PAYLOAD_FORMAT_SPLUNK_HEC:
		return renderSplunk(c, secret, records, idemKey)
	case ksealv1.SiemPayloadFormat_SIEM_PAYLOAD_FORMAT_SENTINEL:
		return renderSentinel(c, secret, records, idemKey)
	case ksealv1.SiemPayloadFormat_SIEM_PAYLOAD_FORMAT_ECS:
		return renderElastic(c, secret, records, idemKey)
	default:
		return renderedRequest{}, fmt.Errorf("siem: unsupported payload format %s", c.Format)
	}
}

// renderSplunk produces Splunk HEC newline-delimited event envelopes. Each
// envelope wraps the minimized fields under "event"; index/sourcetype/time are
// HEC routing metadata, not telemetry. Auth is the HEC token.
func renderSplunk(c *ksealv1.SiemConnector, secret []byte, records []map[string]any, idemKey string) (renderedRequest, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	for _, r := range records {
		env := map[string]any{"event": r}
		if c.SplunkSourcetype != "" {
			env["sourcetype"] = c.SplunkSourcetype
		}
		if c.SplunkIndex != "" {
			env["index"] = c.SplunkIndex
		}
		if sec, ok := coarseTimeOf(r); ok {
			env["time"] = sec
		}
		if err := enc.Encode(env); err != nil { // Encode appends a newline.
			return renderedRequest{}, err
		}
	}
	return renderedRequest{
		url: joinPath(c.Endpoint, "/services/collector/event"),
		headers: map[string]string{
			"Authorization":            "Splunk " + string(secret),
			"Content-Type":             "application/json",
			"X-Kseal-Idempotency-Key":  idemKey,
			"X-Splunk-Request-Channel": idemKey,
		},
		body:      []byte(buf.String()),
		gzippable: true,
	}, nil
}

// renderSentinel produces a JSON array of flat rows for the Microsoft Sentinel
// Logs Ingestion API (DCR-based). TimeGenerated is the required ingest-time
// column, derived from the coarse bucket. Auth is a bearer token.
func renderSentinel(c *ksealv1.SiemConnector, secret []byte, records []map[string]any, idemKey string) (renderedRequest, error) {
	if c.SentinelDcrImmutableId == "" || c.SentinelStreamName == "" {
		return renderedRequest{}, fmt.Errorf("siem: sentinel connector requires dcr immutable id and stream name")
	}
	rows := make([]map[string]any, 0, len(records))
	for _, r := range records {
		row := make(map[string]any, len(r)+1)
		for k, v := range r {
			row[k] = v
		}
		if sec, ok := coarseTimeOf(r); ok {
			row["TimeGenerated"] = iso8601(sec)
		}
		rows = append(rows, row)
	}
	body, err := json.Marshal(rows)
	if err != nil {
		return renderedRequest{}, err
	}
	// Path-escape the DCR id and stream name: they are tenant-supplied and land
	// in the URL path, so escaping prevents a stray character from altering the
	// request target.
	dcrURL := fmt.Sprintf("%s/dataCollectionRules/%s/streams/%s?api-version=2023-01-01",
		strings.TrimRight(c.Endpoint, "/"),
		url.PathEscape(c.SentinelDcrImmutableId),
		url.PathEscape(c.SentinelStreamName))
	return renderedRequest{
		url: dcrURL,
		headers: map[string]string{
			"Authorization":           "Bearer " + string(secret),
			"Content-Type":            "application/json",
			"X-Kseal-Idempotency-Key": idemKey,
		},
		body:      body,
		gzippable: true,
	}, nil
}

// renderElastic produces an Elastic _bulk NDJSON request of ECS documents. The
// minimized fields live under ECS `labels` (the sanctioned location for
// arbitrary key/values); @timestamp + event.* are standard ECS envelope. Auth
// is an Elastic API key.
func renderElastic(c *ksealv1.SiemConnector, secret []byte, records []map[string]any, idemKey string) (renderedRequest, error) {
	if c.ElasticIndex == "" {
		return renderedRequest{}, fmt.Errorf("siem: elastic connector requires a target index")
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	action := map[string]any{"create": map[string]any{"_index": c.ElasticIndex}}
	for _, r := range records {
		doc := map[string]any{
			"event":  map[string]any{"kind": "alert", "dataset": "kseal.trust", "module": "kseal"},
			"labels": r,
		}
		if sec, ok := coarseTimeOf(r); ok {
			doc["@timestamp"] = iso8601(sec)
		}
		if err := enc.Encode(action); err != nil {
			return renderedRequest{}, err
		}
		if err := enc.Encode(doc); err != nil {
			return renderedRequest{}, err
		}
	}
	return renderedRequest{
		url: joinPath(c.Endpoint, "/_bulk"),
		headers: map[string]string{
			"Authorization":           "ApiKey " + string(secret),
			"Content-Type":            "application/x-ndjson",
			"X-Kseal-Idempotency-Key": idemKey,
		},
		body:      []byte(buf.String()),
		gzippable: true,
	}, nil
}

// coarseTimeOf extracts a single record's coarse bucket (unix seconds).
func coarseTimeOf(r map[string]any) (int64, bool) {
	if v, ok := r[FieldCoarseTimeBucket]; ok {
		if sec, ok := v.(int64); ok {
			return sec, true
		}
	}
	return 0, false
}

// joinPath appends suffix to base unless base already ends with it (so a fully
// qualified endpoint is used as-is and a bare host gets the standard path).
func joinPath(base, suffix string) string {
	b := strings.TrimRight(base, "/")
	if strings.HasSuffix(b, suffix) {
		return b
	}
	return b + suffix
}
