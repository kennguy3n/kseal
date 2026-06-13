package tests

import (
	"bytes"
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	"github.com/kennguy3n/kseal/server/data-plane/ingest"
	"github.com/kennguy3n/kseal/server/data-plane/query"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
)

// pipeline wires the real ingest write-path (validator + quota + broker +
// async writer + analytics store) to the real QueryService read-path, exactly
// as server/cmd/kseal-server/main.go does.
type pipeline struct {
	ingest    *ingest.Service
	analytics *ingest.InMemoryAnalyticsStore
	query     *query.Service
}

// newPipeline builds the ingest→query pipeline over the shared registry store.
// quotaPerMinute bounds the per-tenant event budget. An optional sink receives
// each drained event (used by the webhook fan-out test).
func newPipeline(t *testing.T, store registry.Store, quotaPerMinute int, sink ingest.EventSink) *pipeline {
	t.Helper()
	analytics := ingest.NewInMemoryAnalyticsStore()
	broker := ingest.NewChannelBroker(0)
	// batchSize=1 + a short tick flush events promptly so reads observe writes
	// without a long delay; tests still poll to avoid races.
	writer := ingest.NewWriter(broker, analytics, 1, 10*time.Millisecond)
	if sink != nil {
		writer.SetEventSink(sink)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go writer.Run(ctx)
	t.Cleanup(cancel)

	quota := ingest.NewQuota(newRedis(t), quotaPerMinute)
	validator := ingest.NewCachedAppValidator(store, 30*time.Second)
	svc, err := ingest.NewService(validator, quota, broker)
	if err != nil {
		t.Fatalf("new ingest service: %v", err)
	}
	return &pipeline{ingest: svc, analytics: analytics, query: query.NewService(store, analytics)}
}

// submit zstd-compresses and submits a telemetry batch.
func (p *pipeline) submit(t *testing.T, tenantID, appID string, batch *ksealv1.TelemetryBatch) *ksealv1.SubmitTelemetryResponse {
	t.Helper()
	raw, err := proto.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	resp, err := p.ingest.SubmitTelemetry(context.Background(), connect.NewRequest(&ksealv1.SubmitTelemetryRequest{
		TenantId:        tenantID,
		AppId:           appID,
		CompressedBatch: zstdCompress(t, raw),
		Compression:     ksealv1.Compression_COMPRESSION_ZSTD,
	}))
	if err != nil {
		t.Fatalf("submit telemetry: %v", err)
	}
	return resp.Msg
}

// waitForEvents polls ListEvents (as the tenant) until at least want events are
// readable or the deadline elapses, returning the final count.
func (p *pipeline) waitForEvents(t *testing.T, tenantID string, want int) int {
	t.Helper()
	ctx := auth.WithTenant(context.Background(), tenantID)
	deadline := time.Now().Add(5 * time.Second)
	for {
		n := countEvents(t, ctx, p.query, tenantID)
		if n >= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// countEvents counts tenant-scoped events via the public QueryService read path,
// walking pagination to completion.
func countEvents(t *testing.T, ctx context.Context, q *query.Service, tenantID string) int {
	t.Helper()
	total := 0
	token := ""
	for {
		resp, err := q.ListEvents(ctx, connect.NewRequest(&ksealv1.ListEventsRequest{
			TenantId: tenantID, PageSize: 100, PageToken: token,
		}))
		if err != nil {
			t.Fatalf("list events: %v", err)
		}
		total += len(resp.Msg.Events)
		token = resp.Msg.NextPageToken
		if token == "" {
			return total
		}
	}
}

// zstdCompress compresses data with zstd, matching the SDK's batch encoding.
func zstdCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	if _, err := enc.Write(data); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return buf.Bytes()
}
