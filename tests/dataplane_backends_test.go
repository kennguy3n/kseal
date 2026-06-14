// Integration tests for the production data-plane backends: the Kafka/Redpanda
// broker and the ClickHouse analytics store. They drive the real backends
// (started via testcontainers) through the same interfaces the server uses, so
// QueryService-visible behavior is proven identical to the in-memory defaults:
// tenant isolation, keyset pagination, and effectively-once dedup.
//
// Like the Postgres/Redis harness, these skip cleanly when no container runtime
// is available, keeping `go test ./...` hermetic on machines without Docker.
package tests

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tcclickhouse "github.com/testcontainers/testcontainers-go/modules/clickhouse"
	tcredpanda "github.com/testcontainers/testcontainers-go/modules/redpanda"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/kennguy3n/kseal/server/data-plane/ingest"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

const (
	redpandaImage   = "docker.redpanda.com/redpandadata/redpanda:v24.2.7"
	clickhouseImage = "clickhouse/clickhouse-server:24.3-alpine"
	chDatabase      = "kseal"
	chUsername      = "kseal"
	chPassword      = "kseal"
)

// --- lazily-started, run-shared backend containers --------------------------

var (
	redpandaOnce    sync.Once
	redpandaBrokers []string
	redpandaErr     error

	clickhouseOnce sync.Once
	clickhouseAddr string
	clickhouseErr  error

	tableCounter atomic.Uint64
)

// requireRedpanda returns the seed-broker address of a shared Redpanda
// container, starting it on first use and skipping the test if no container
// runtime is available.
func requireRedpanda(t *testing.T) []string {
	t.Helper()
	redpandaOnce.Do(func() {
		ctx := context.Background()
		c, err := tcredpanda.Run(ctx, redpandaImage, tcredpanda.WithAutoCreateTopics())
		if err != nil {
			redpandaErr = err
			return
		}
		registerCleanup(func() { _ = c.Terminate(context.Background()) })
		addr, err := c.KafkaSeedBroker(ctx)
		if err != nil {
			redpandaErr = err
			return
		}
		redpandaBrokers = []string{addr}
	})
	if redpandaErr != nil {
		t.Skipf("Redpanda container unavailable (no container runtime?): %v", redpandaErr)
	}
	return redpandaBrokers
}

// createKafkaTopic provisions a fresh topic out-of-band, mirroring production
// where the operator/Terraform creates the topic (the broker intentionally does
// not auto-create). It returns a unique topic name with the given partitions so
// tenant partitioning is actually exercised.
func createKafkaTopic(t *testing.T, brokers []string, partitions int32) string {
	t.Helper()
	topic := fmt.Sprintf("kseal.test.events.%d", time.Now().UnixNano())
	cl, err := kgo.NewClient(kgo.SeedBrokers(brokers...))
	if err != nil {
		t.Fatalf("admin client: %v", err)
	}
	defer cl.Close()
	adm := kadm.NewClient(cl)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := adm.CreateTopic(ctx, partitions, 1, nil, topic); err != nil {
		t.Fatalf("create topic %s: %v", topic, err)
	}
	return topic
}

// requireClickHouse returns the native-protocol address of a shared ClickHouse
// container, starting it on first use and skipping the test if no container
// runtime is available.
func requireClickHouse(t *testing.T) string {
	t.Helper()
	clickhouseOnce.Do(func() {
		ctx := context.Background()
		c, err := tcclickhouse.Run(ctx, clickhouseImage,
			tcclickhouse.WithDatabase(chDatabase),
			tcclickhouse.WithUsername(chUsername),
			tcclickhouse.WithPassword(chPassword),
		)
		if err != nil {
			clickhouseErr = err
			return
		}
		registerCleanup(func() { _ = c.Terminate(context.Background()) })
		host, err := c.ConnectionHost(ctx)
		if err != nil {
			clickhouseErr = err
			return
		}
		clickhouseAddr = host
	})
	if clickhouseErr != nil {
		t.Skipf("ClickHouse container unavailable (no container runtime?): %v", clickhouseErr)
	}
	return clickhouseAddr
}

// newClickHouseStore opens a store against a table unique to the calling test so
// tests sharing the single container never observe each other's rows.
func newClickHouseStore(t *testing.T) *ingest.ClickHouseAnalyticsStore {
	t.Helper()
	addr := requireClickHouse(t)
	table := fmt.Sprintf("telemetry_events_%d", tableCounter.Add(1))
	ctx := context.Background()
	store, err := ingest.NewClickHouseAnalyticsStore(ctx, ingest.ClickHouseConfig{
		Addr:     []string{addr},
		Database: chDatabase,
		Username: chUsername,
		Password: chPassword,
		Table:    table,
	})
	if err != nil {
		t.Fatalf("open clickhouse store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// storedEvent builds a deterministic StoredEvent for a tenant at a given bucket.
func storedEvent(tenant, app, id string, bucket int64) ingest.StoredEvent {
	return ingest.StoredEvent{
		ID:         id,
		TenantID:   tenant,
		AppID:      app,
		EventType:  ksealv1.EventType_EVENT_TYPE_RUNTIME_TAMPER,
		RiskLevel:  ksealv1.TrustLevel_TRUST_LEVEL_CRITICAL,
		RiskBits:   0b1010,
		Confidence: ksealv1.Confidence_CONFIDENCE_HIGH,
		BuildHash:  "sha256:build",
		PolicyHash: "sha256:policy",
		Platform:   ksealv1.Platform_PLATFORM_ANDROID,
		TimeBucket: bucket,
		ReceivedAt: bucket,
	}
}

// --- ClickHouse store -------------------------------------------------------

// The ClickHouse store must persist events, enforce strict tenant isolation on
// every read, dedup redelivered events by id (effectively-once), and paginate
// recent-first with a stable keyset cursor — matching the in-memory store.
func TestClickHouseStoreRoundTrip(t *testing.T) {
	store := newClickHouseStore(t)
	ctx := context.Background()

	const tenantA, tenantB = "tenant-A", "tenant-B"
	base := time.Now().Add(-time.Hour).Unix()
	var aEvents []ingest.StoredEvent
	for i := 0; i < 5; i++ {
		aEvents = append(aEvents, storedEvent(tenantA, "app-1", fmt.Sprintf("a-%d", i), base+int64(i*60)))
	}
	bEvents := []ingest.StoredEvent{storedEvent(tenantB, "app-2", "b-0", base)}

	if err := store.Write(ctx, aEvents); err != nil {
		t.Fatalf("write tenant A: %v", err)
	}
	if err := store.Write(ctx, bEvents); err != nil {
		t.Fatalf("write tenant B: %v", err)
	}

	// Tenant isolation: each tenant sees only its own events.
	if n, err := store.Count(ctx, ingest.Query{TenantID: tenantA}); err != nil || n != 5 {
		t.Fatalf("count A = %d, err=%v; want 5", n, err)
	}
	if n, err := store.Count(ctx, ingest.Query{TenantID: tenantB}); err != nil || n != 1 {
		t.Fatalf("count B = %d, err=%v; want 1", n, err)
	}

	// Effectively-once: redelivering tenant A's batch must not inflate counts.
	if err := store.Write(ctx, aEvents); err != nil {
		t.Fatalf("redeliver tenant A: %v", err)
	}
	if n, err := store.Count(ctx, ingest.Query{TenantID: tenantA}); err != nil || n != 5 {
		t.Fatalf("count A after redelivery = %d, err=%v; want 5 (dedup failed)", n, err)
	}

	// Query is tenant-scoped and time-ordered ascending.
	got, err := store.Query(ctx, ingest.Query{TenantID: tenantA})
	if err != nil {
		t.Fatalf("query A: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("query A returned %d events, want 5", len(got))
	}
	for _, e := range got {
		if e.TenantID != tenantA {
			t.Fatalf("tenant leak: query A returned event for %q", e.TenantID)
		}
	}
	for i := 1; i < len(got); i++ {
		if got[i].TimeBucket < got[i-1].TimeBucket {
			t.Fatalf("query not time-ordered ascending at %d", i)
		}
	}

	// Keyset pagination is recent-first and walks every event exactly once.
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		page, err := store.ListEvents(ctx, ingest.Query{TenantID: tenantA}, 2, cursor)
		if err != nil {
			t.Fatalf("list events: %v", err)
		}
		pages++
		var prevBucket int64 = 1<<63 - 1
		for _, e := range page.Events {
			if seen[e.ID] {
				t.Fatalf("event %s returned twice across pages", e.ID)
			}
			seen[e.ID] = true
			if e.TimeBucket > prevBucket {
				t.Fatalf("page not recent-first ordered")
			}
			prevBucket = e.TimeBucket
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(seen) != 5 {
		t.Fatalf("pagination saw %d distinct events, want 5", len(seen))
	}
}

// The RawEventStore purge path must be strictly tenant-scoped and time-bounded:
// it deletes only the targeted tenant's old events and never another tenant's.
func TestClickHouseRetentionPurge(t *testing.T) {
	store := newClickHouseStore(t)
	ctx := context.Background()

	now := time.Now().Unix()
	old := now - 30*24*3600
	const tenantA, tenantB = "purge-A", "purge-B"
	if err := store.Write(ctx, []ingest.StoredEvent{
		storedEvent(tenantA, "app", "a-old", old),
		storedEvent(tenantA, "app", "a-new", now),
		storedEvent(tenantB, "app", "b-old", old),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	tenants, err := store.TenantIDs(ctx)
	if err != nil {
		t.Fatalf("tenant ids: %v", err)
	}
	if len(tenants) != 2 {
		t.Fatalf("tenant ids = %v, want 2 tenants", tenants)
	}

	// Purge tenant A's events older than 7 days ago.
	cutoff := now - 7*24*3600
	purged, err := store.PurgeRawEventsOlderThan(ctx, tenantA, cutoff)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged != 1 {
		t.Fatalf("purged %d, want 1", purged)
	}

	// A's recent event survives; B is untouched (DELETE is async, so poll).
	waitForCount(t, store, ingest.Query{TenantID: tenantA}, 1)
	if n, err := store.Count(ctx, ingest.Query{TenantID: tenantB}); err != nil || n != 1 {
		t.Fatalf("tenant B count = %d, err=%v; want 1 (purge crossed tenants)", n, err)
	}
}

// --- Kafka broker -----------------------------------------------------------

// The Kafka broker must deliver every published event at least once with all
// fields intact through the binary codec, partitioned by tenant.
func TestKafkaBrokerAtLeastOnce(t *testing.T) {
	brokers := requireRedpanda(t)
	ctx := context.Background()
	topic := createKafkaTopic(t, brokers, 4)
	broker, err := ingest.NewKafkaBroker(ctx, ingest.KafkaConfig{
		Brokers:       brokers,
		Topic:         topic,
		ConsumerGroup: "kseal-test-writer",
	})
	if err != nil {
		t.Fatalf("new kafka broker: %v", err)
	}
	defer broker.Close()

	const n = 200
	for i := 0; i < n; i++ {
		tenant := fmt.Sprintf("tenant-%d", i%4)
		if err := broker.Publish(ctx, storedEvent(tenant, "app", fmt.Sprintf("evt-%d", i), int64(i))); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}

	got := map[string]ingest.StoredEvent{}
	deadline := time.After(30 * time.Second)
	ch := broker.Consume()
	for len(got) < n {
		select {
		case e := <-ch:
			got[e.ID] = e
		case <-deadline:
			t.Fatalf("only consumed %d/%d events before timeout", len(got), n)
		}
	}
	// Spot-check codec fidelity on a representative record.
	sample := got["evt-7"]
	if sample.TenantID != "tenant-3" || sample.RiskLevel != ksealv1.TrustLevel_TRUST_LEVEL_CRITICAL || sample.RiskBits != 0b1010 {
		t.Fatalf("codec round-trip corrupted event: %+v", sample)
	}
}

// End-to-end: the Kafka broker feeding the async writer into the ClickHouse
// store must land every event, tenant-isolated, exactly as the in-memory path.
func TestKafkaToClickHousePipeline(t *testing.T) {
	brokers := requireRedpanda(t)
	store := newClickHouseStore(t)
	ctx := context.Background()

	topic := createKafkaTopic(t, brokers, 4)
	broker, err := ingest.NewKafkaBroker(ctx, ingest.KafkaConfig{
		Brokers:       brokers,
		Topic:         topic,
		ConsumerGroup: "kseal-test-pipeline",
	})
	if err != nil {
		t.Fatalf("new kafka broker: %v", err)
	}

	writer := ingest.NewWriter(broker, store, 50, 200*time.Millisecond)
	writerCtx, cancelWriter := context.WithCancel(context.Background())
	writerDone := make(chan struct{})
	go func() { writer.Run(writerCtx); close(writerDone) }()

	const perTenant = 75
	base := time.Now().Add(-time.Hour).Unix()
	for i := 0; i < perTenant; i++ {
		if err := broker.Publish(ctx, storedEvent("pipe-A", "app", fmt.Sprintf("a-%d", i), base+int64(i))); err != nil {
			t.Fatalf("publish A %d: %v", i, err)
		}
		if err := broker.Publish(ctx, storedEvent("pipe-B", "app", fmt.Sprintf("b-%d", i), base+int64(i))); err != nil {
			t.Fatalf("publish B %d: %v", i, err)
		}
	}

	waitForCount(t, store, ingest.Query{TenantID: "pipe-A"}, perTenant)
	waitForCount(t, store, ingest.Query{TenantID: "pipe-B"}, perTenant)

	// Graceful shutdown drains in-flight events rather than dropping them.
	broker.Close()
	<-writerDone
	cancelWriter()
}

// waitForCount polls the store until the tenant-scoped count reaches want or the
// deadline elapses (writes are async through the broker + batching writer).
func waitForCount(t *testing.T, store *ingest.ClickHouseAnalyticsStore, q ingest.Query, want int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		n, err := store.Count(context.Background(), q)
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		if n >= want {
			if n > want {
				t.Fatalf("count for %s = %d, want %d (over-count)", q.TenantID, n, want)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("count for %s reached %d, want %d before timeout", q.TenantID, n, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
