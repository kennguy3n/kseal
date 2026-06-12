package ingest

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/alicebob/miniredis/v2"
	"github.com/klauspost/compress/zstd"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
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

func zstdCompress(t *testing.T, b []byte) []byte {
	t.Helper()
	w, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	return w.EncodeAll(b, nil)
}

func sampleBatch(n int) []byte {
	events := make([]*ksealv1.TelemetryEvent, n)
	for i := range events {
		events[i] = &ksealv1.TelemetryEvent{EventType: ksealv1.EventType_EVENT_TYPE_ROOT_RISK, RiskBits: 1, CoarseTimeBucket: 100}
	}
	b, _ := proto.Marshal(&ksealv1.TelemetryBatch{Events: events, Platform: ksealv1.Platform_PLATFORM_ANDROID})
	return b
}

func setupIngest(t *testing.T, perMinute int) (*Service, *registry.MemStore, *ksealv1.Tenant, *ksealv1.App, Broker) {
	t.Helper()
	store := registry.NewMemStore()
	ctx := context.Background()
	tn, _ := store.CreateTenant(ctx, registry.CreateTenantInput{Name: "T", Slug: "t-ing"})
	app, _ := store.CreateApp(ctx, registry.CreateAppInput{TenantID: tn.Id, Name: "A", PackageID: "com.ing", Platform: ksealv1.Platform_PLATFORM_ANDROID})
	quota := NewQuota(newRedis(t), perMinute)
	broker := NewChannelBroker(1024)
	svc, err := NewService(NewCachedAppValidator(store, time.Second), quota, broker)
	if err != nil {
		t.Fatal(err)
	}
	return svc, store, tn, app, broker
}

// countingStore embeds the registry.Store interface (nil underlying) and only
// implements GetApp so we can count DB lookups; the validator calls nothing else.
type countingStore struct {
	registry.Store
	calls int
	err   error
}

func (c *countingStore) GetApp(_ context.Context, _, _ string) (*ksealv1.App, error) {
	c.calls++
	return nil, c.err
}

func TestCachedAppValidatorNegativeCache(t *testing.T) {
	cs := &countingStore{err: registry.ErrNotFound}
	v := NewCachedAppValidator(cs, time.Minute)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		ok, err := v.Valid(ctx, "t1", "missing")
		if err != nil || ok {
			t.Fatalf("expected (false,nil), got (%v,%v)", ok, err)
		}
	}
	// The negative result must be cached so repeated unknown-app traffic does
	// not amplify into one DB hit per request.
	if cs.calls != 1 {
		t.Fatalf("expected 1 DB lookup, got %d", cs.calls)
	}
}

func TestSubmitTelemetryAcceptsCompressedBatch(t *testing.T) {
	svc, _, tn, app, _ := setupIngest(t, 1000)
	raw := sampleBatch(3)
	resp, err := svc.SubmitTelemetry(context.Background(), connect.NewRequest(&ksealv1.SubmitTelemetryRequest{
		TenantId: tn.Id, AppId: app.Id, Compression: ksealv1.Compression_COMPRESSION_ZSTD, CompressedBatch: zstdCompress(t, raw),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Accepted != 3 || resp.Msg.Rejected != 0 {
		t.Fatalf("accepted=%d rejected=%d", resp.Msg.Accepted, resp.Msg.Rejected)
	}
}

func TestSubmitTelemetryUncompressed(t *testing.T) {
	svc, _, tn, app, _ := setupIngest(t, 1000)
	resp, err := svc.SubmitTelemetry(context.Background(), connect.NewRequest(&ksealv1.SubmitTelemetryRequest{
		TenantId: tn.Id, AppId: app.Id, Compression: ksealv1.Compression_COMPRESSION_NONE, CompressedBatch: sampleBatch(2),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Accepted != 2 {
		t.Fatalf("accepted=%d", resp.Msg.Accepted)
	}
}

func TestSubmitTelemetryUnknownApp(t *testing.T) {
	svc, _, tn, _, _ := setupIngest(t, 1000)
	resp, err := svc.SubmitTelemetry(context.Background(), connect.NewRequest(&ksealv1.SubmitTelemetryRequest{
		TenantId: tn.Id, AppId: "00000000-0000-0000-0000-000000000000", CompressedBatch: sampleBatch(1),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Accepted != 0 || resp.Msg.RejectionReason == "" {
		t.Fatalf("expected rejection: %+v", resp.Msg)
	}
}

func TestSubmitTelemetryMalformed(t *testing.T) {
	svc, _, tn, app, _ := setupIngest(t, 1000)
	resp, err := svc.SubmitTelemetry(context.Background(), connect.NewRequest(&ksealv1.SubmitTelemetryRequest{
		TenantId: tn.Id, AppId: app.Id, Compression: ksealv1.Compression_COMPRESSION_NONE, CompressedBatch: []byte("not-a-proto"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.RejectionReason == "" {
		t.Fatal("expected malformed rejection")
	}
}

func TestSubmitTelemetryQuotaExceeded(t *testing.T) {
	svc, _, tn, app, _ := setupIngest(t, 2)
	resp, err := svc.SubmitTelemetry(context.Background(), connect.NewRequest(&ksealv1.SubmitTelemetryRequest{
		TenantId: tn.Id, AppId: app.Id, Compression: ksealv1.Compression_COMPRESSION_NONE, CompressedBatch: sampleBatch(5),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Msg.QuotaExceeded {
		t.Fatalf("expected quota exceeded: %+v", resp.Msg)
	}
}

func TestQuotaTokenBucket(t *testing.T) {
	q := NewQuota(newRedis(t), 5)
	ctx := context.Background()
	ok, _, _ := q.Allow(ctx, "t1", 3)
	if !ok {
		t.Fatal("first 3 should fit")
	}
	ok, _, _ = q.Allow(ctx, "t1", 3)
	if ok {
		t.Fatal("exceeding budget should be rejected")
	}
	// Separate tenant has its own budget.
	if ok, _, _ := q.Allow(ctx, "t2", 5); !ok {
		t.Fatal("other tenant budget independent")
	}
}

func TestWriterDrainsBrokerToStore(t *testing.T) {
	broker := NewChannelBroker(16)
	store := NewInMemoryAnalyticsStore()
	w := NewWriter(broker, store, 2, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	for i := 0; i < 4; i++ {
		if err := broker.Publish(ctx, StoredEvent{TenantID: "t1", AppID: "a1", EventType: ksealv1.EventType_EVENT_TYPE_ROOT_RISK, TimeBucket: int64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if n, _ := store.Count(ctx, Query{TenantID: "t1"}); n == 4 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("writer did not flush all events")
}

func TestBrokerFull(t *testing.T) {
	broker := NewChannelBroker(1)
	ctx := context.Background()
	if err := broker.Publish(ctx, StoredEvent{}); err != nil {
		t.Fatal(err)
	}
	if err := broker.Publish(ctx, StoredEvent{}); err != ErrBrokerFull {
		t.Fatalf("expected ErrBrokerFull, got %v", err)
	}
}
