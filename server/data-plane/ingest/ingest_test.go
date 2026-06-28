package ingest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/alicebob/miniredis/v2"
	"github.com/klauspost/compress/zstd"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
	"github.com/kennguy3n/kseal/server/shared/risk"
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
	defer func() { _ = w.Close() }()
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

func TestCachedAppValidatorBoundsCache(t *testing.T) {
	cs := &countingStore{err: registry.ErrNotFound}
	v := NewCachedAppValidator(cs, time.Minute)
	v.maxEntries = 100
	ctx := context.Background()
	// Spray many distinct unknown (tenant, app) pairs as an attacker would.
	for i := 0; i < 5000; i++ {
		if _, err := v.Valid(ctx, "t", fmt.Sprintf("app-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	v.mu.Lock()
	n := len(v.cache)
	v.mu.Unlock()
	if n > v.maxEntries {
		t.Fatalf("cache grew unbounded: %d entries (cap %d)", n, v.maxEntries)
	}
}

func TestSubmitTelemetryAcceptsCompressedBatch(t *testing.T) {
	svc, _, tn, app, _ := setupIngest(t, 1000)
	raw := sampleBatch(3)
	resp, err := svc.SubmitTelemetry(auth.WithTenant(context.Background(), tn.Id), connect.NewRequest(&ksealv1.SubmitTelemetryRequest{
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
	resp, err := svc.SubmitTelemetry(auth.WithTenant(context.Background(), tn.Id), connect.NewRequest(&ksealv1.SubmitTelemetryRequest{
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
	resp, err := svc.SubmitTelemetry(auth.WithTenant(context.Background(), tn.Id), connect.NewRequest(&ksealv1.SubmitTelemetryRequest{
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
	resp, err := svc.SubmitTelemetry(auth.WithTenant(context.Background(), tn.Id), connect.NewRequest(&ksealv1.SubmitTelemetryRequest{
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
	resp, err := svc.SubmitTelemetry(auth.WithTenant(context.Background(), tn.Id), connect.NewRequest(&ksealv1.SubmitTelemetryRequest{
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

func TestNormalizeTimeBucketSec(t *testing.T) {
	const now = int64(1_700_000_000) // fixed "server clock" in unix seconds
	cases := []struct {
		name string
		in   int64
		want int64
	}{
		{"zero falls back to now", 0, now},
		{"negative falls back to now", -5, now},
		{"seconds in past kept", 1_699_000_000, 1_699_000_000},
		{"millis normalized to seconds", 1_700_000_000_000, now},
		{"future within skew kept", now + 3600, now + 3600},
		{"future seconds beyond skew clamped", now + 200_000, now},
		{"huge millis future clamped", 5_000_000_000_000, now},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := normalizeTimeBucketSec(c.in, now); got != c.want {
				t.Fatalf("normalizeTimeBucketSec(%d, %d) = %d, want %d", c.in, now, got, c.want)
			}
		})
	}
}

// TestSubmitTelemetryTranslatesWireBitsAndTagsLayout proves ingest translates
// the device/wire bitset into the server layout before storing AND tags the
// row risk.LayoutServer, so the stored bits are self-describing. A wire
// DEBUGGER (bit 4) must become server DEBUGGER, not server APP_TAMPER (bit 4).
func TestSubmitTelemetryTranslatesWireBitsAndTagsLayout(t *testing.T) {
	svc, _, tn, app, broker := setupIngest(t, 1000)
	const wireDebugger = uint64(1) << 4
	batch, _ := proto.Marshal(&ksealv1.TelemetryBatch{
		Platform: ksealv1.Platform_PLATFORM_ANDROID,
		Events: []*ksealv1.TelemetryEvent{
			{EventType: ksealv1.EventType_EVENT_TYPE_DEBUGGER, RiskBits: wireDebugger, CoarseTimeBucket: 100},
		},
	})
	resp, err := svc.SubmitTelemetry(auth.WithTenant(context.Background(), tn.Id), connect.NewRequest(&ksealv1.SubmitTelemetryRequest{
		TenantId: tn.Id, AppId: app.Id, Compression: ksealv1.Compression_COMPRESSION_NONE, CompressedBatch: batch,
	}))
	if err != nil || resp.Msg.Accepted != 1 {
		t.Fatalf("submit: err=%v accepted=%d", err, resp.Msg.Accepted)
	}
	select {
	case e := <-broker.Consume():
		if e.RiskBits != risk.BitDebugger {
			t.Fatalf("stored RiskBits = %#x, want server BitDebugger %#x", e.RiskBits, risk.BitDebugger)
		}
		if e.RiskBits&risk.BitAppTamper != 0 {
			t.Fatal("wire DEBUGGER must not store as server APP_TAMPER")
		}
		if e.RiskBitsLayout != risk.LayoutServer {
			t.Fatalf("RiskBitsLayout = %d, want LayoutServer %d", e.RiskBitsLayout, risk.LayoutServer)
		}
	case <-time.After(time.Second):
		t.Fatal("no event published to broker")
	}
}

// TestSubmitTelemetryNormalizesMillisBucket proves the wire-contract millis bucket
// is stored as canonical unix seconds, so the query-boundary millis<->seconds
// conversion can never be fed an ambiguous unit.
func TestSubmitTelemetryNormalizesMillisBucket(t *testing.T) {
	svc, _, tn, app, broker := setupIngest(t, 1000)
	millisBucket := time.Now().Add(-time.Hour).UnixMilli()
	batch, _ := proto.Marshal(&ksealv1.TelemetryBatch{
		Platform: ksealv1.Platform_PLATFORM_ANDROID,
		Events: []*ksealv1.TelemetryEvent{
			{EventType: ksealv1.EventType_EVENT_TYPE_ROOT_RISK, RiskBits: 1, CoarseTimeBucket: millisBucket},
		},
	})
	resp, err := svc.SubmitTelemetry(auth.WithTenant(context.Background(), tn.Id), connect.NewRequest(&ksealv1.SubmitTelemetryRequest{
		TenantId: tn.Id, AppId: app.Id, Compression: ksealv1.Compression_COMPRESSION_NONE, CompressedBatch: batch,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.Accepted != 1 {
		t.Fatalf("accepted=%d rejected=%d", resp.Msg.Accepted, resp.Msg.Rejected)
	}
	select {
	case e := <-broker.Consume():
		if e.TimeBucket != millisBucket/1000 {
			t.Fatalf("TimeBucket=%d, want canonical seconds %d", e.TimeBucket, millisBucket/1000)
		}
	case <-time.After(time.Second):
		t.Fatal("no event published to broker")
	}
}

func TestSubmitTelemetryRejectsUnauthenticatedTenantBodyOnlyRequest(t *testing.T) {
	svc, _, tn, app, _ := setupIngest(t, 1000)
	_, err := svc.SubmitTelemetry(context.Background(), connect.NewRequest(&ksealv1.SubmitTelemetryRequest{
		TenantId: tn.Id, AppId: app.Id, Compression: ksealv1.Compression_COMPRESSION_NONE, CompressedBatch: sampleBatch(1),
	}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected unauthenticated, got %v", err)
	}
}
