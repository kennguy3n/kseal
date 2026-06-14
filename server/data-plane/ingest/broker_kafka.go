package ingest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// KafkaConfig configures the Kafka/Redpanda-backed broker. The zero value is
// invalid (no brokers); NewKafkaBroker fills sensible defaults for the rest so
// only Brokers + Topic are strictly required.
type KafkaConfig struct {
	// Brokers is the seed broker list (host:port). Required.
	Brokers []string
	// Topic is the telemetry topic. Required. It is created out-of-band (by the
	// operator / Terraform); the broker does not auto-create it in production.
	Topic string
	// ConsumerGroup is the consumer group id for the writer-side consumer.
	ConsumerGroup string

	// ProducerBufferRecords bounds in-flight (un-acked) produced records. When
	// reached, Publish sheds (ErrBrokerFull) instead of blocking the request
	// path — the same load-shed contract as the in-memory broker.
	ProducerBufferRecords int
	// ConsumeChannelBuffer bounds the decoded-event hand-off channel. A full
	// channel naturally backpressures the consumer (it stops polling), which
	// backpressures the fetch from Kafka.
	ConsumeChannelBuffer int
	// ProducerRetries is the number of internal produce retries before the
	// record's promise fails (and the event is counted as dropped).
	ProducerRetries int
	// CommitInterval is how often marked offsets are committed (at-least-once).
	CommitInterval time.Duration
	// DialTimeout bounds the initial broker connection.
	DialTimeout time.Duration

	// TLS enables transport security to the brokers. CAFile optionally pins the
	// broker CA (PEM); empty uses the system roots.
	TLS    bool
	CAFile string
	// InsecureSkipVerify disables certificate verification (test/dev only).
	InsecureSkipVerify bool

	// SASLMechanism is one of "", "plain", "scram-sha-256", "scram-sha-512".
	SASLMechanism string
	SASLUsername  string
	SASLPassword  string

	// Logger receives async produce errors. Optional; nil disables logging
	// (the dropped-record counter still increments).
	Logger *zerolog.Logger
}

func (c *KafkaConfig) withDefaults() {
	if c.Topic == "" {
		c.Topic = "kseal.telemetry.events"
	}
	if c.ConsumerGroup == "" {
		c.ConsumerGroup = "kseal-analytics-writer"
	}
	if c.ProducerBufferRecords <= 0 {
		c.ProducerBufferRecords = 50_000
	}
	if c.ConsumeChannelBuffer <= 0 {
		c.ConsumeChannelBuffer = 8192
	}
	if c.ProducerRetries <= 0 {
		c.ProducerRetries = 10
	}
	if c.CommitInterval <= 0 {
		c.CommitInterval = 2 * time.Second
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 10 * time.Second
	}
}

func (c *KafkaConfig) validate() error {
	if len(c.Brokers) == 0 {
		return errors.New("kafka: at least one broker is required")
	}
	switch strings.ToLower(c.SASLMechanism) {
	case "", "plain", "scram-sha-256", "scram-sha-512":
	default:
		return fmt.Errorf("kafka: unsupported SASL mechanism %q", c.SASLMechanism)
	}
	if c.SASLMechanism != "" && (c.SASLUsername == "" || c.SASLPassword == "") {
		return errors.New("kafka: SASL mechanism set but username/password missing")
	}
	return nil
}

// KafkaBroker is a Kafka/Redpanda-backed Broker. Publishing is async,
// partitioned by tenant id (so a tenant's events stay ordered and isolated to
// its partitions), idempotent, and acked by all in-sync replicas — durable and
// at-least-once. The consumer side runs a consumer group, decodes records onto
// a bounded channel the Writer drains, and commits offsets only after each
// record is handed off, so a crash redelivers rather than loses events. The
// ClickHouse store dedupes by event id, making the end-to-end path
// effectively-once.
type KafkaBroker struct {
	client *kgo.Client
	cfg    KafkaConfig
	topic  string

	out       chan StoredEvent
	cancel    context.CancelFunc
	consumeWG sync.WaitGroup
	closeOnce sync.Once

	inflight atomic.Int64

	// metrics
	published    metric.Int64Counter
	publishErr   metric.Int64Counter
	shed         metric.Int64Counter
	consumed     metric.Int64Counter
	decodeErrors metric.Int64Counter
}

// NewKafkaBroker connects to the brokers, starts the consumer-group reader, and
// returns a ready broker. Construction fails closed: an unreachable cluster or
// bad credentials returns an error so a server that explicitly selected Kafka
// never silently falls back to losing telemetry.
func NewKafkaBroker(ctx context.Context, cfg KafkaConfig) (*KafkaBroker, error) {
	cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	opts, err := cfg.clientOptions()
	if err != nil {
		return nil, err
	}
	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("kafka: new client: %w", err)
	}

	// Fail closed on construction: verify the cluster is actually reachable so a
	// misconfigured KSEAL_KAFKA_BROKERS surfaces immediately, not on first
	// produce.
	pingCtx, cancelPing := context.WithTimeout(ctx, cfg.DialTimeout)
	defer cancelPing()
	if err := client.Ping(pingCtx); err != nil {
		client.Close()
		return nil, fmt.Errorf("kafka: ping brokers: %w", err)
	}

	meter := otel.Meter(instrumentationScope)
	b := &KafkaBroker{
		client: client,
		cfg:    cfg,
		topic:  cfg.Topic,
		out:    make(chan StoredEvent, cfg.ConsumeChannelBuffer),
	}
	b.published, _ = meter.Int64Counter("kseal.broker.published", metric.WithDescription("Telemetry records acked by the broker."))
	b.publishErr, _ = meter.Int64Counter("kseal.broker.publish_errors", metric.WithDescription("Records that failed to be produced after retries."))
	b.shed, _ = meter.Int64Counter("kseal.broker.shed", metric.WithDescription("Records shed because the producer buffer was full."))
	b.consumed, _ = meter.Int64Counter("kseal.broker.consumed", metric.WithDescription("Records decoded and handed to the writer."))
	b.decodeErrors, _ = meter.Int64Counter("kseal.broker.decode_errors", metric.WithDescription("Broker records that failed to decode."))

	consumeCtx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	b.consumeWG.Add(1)
	go b.consume(consumeCtx)
	return b, nil
}

func (c *KafkaConfig) clientOptions() ([]kgo.Opt, error) {
	opts := []kgo.Opt{
		kgo.SeedBrokers(c.Brokers...),
		kgo.DefaultProduceTopic(c.Topic),
		// Durability: every record is acked by all in-sync replicas and the
		// producer is idempotent, so retries never reorder or duplicate within
		// a partition.
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ProducerBatchCompression(kgo.ZstdCompression(), kgo.SnappyCompression()),
		kgo.RecordRetries(c.ProducerRetries),
		// A generous hard cap; Publish enforces the real soft cap via inflight
		// accounting so it can shed without ever blocking the request path.
		kgo.MaxBufferedRecords(c.ProducerBufferRecords * 2),
		kgo.ProduceRequestTimeout(c.DialTimeout),
		// Consumer group: read the telemetry topic, commit marked offsets only
		// (at-least-once tied to hand-off, not to poll).
		kgo.ConsumerGroup(c.ConsumerGroup),
		kgo.ConsumeTopics(c.Topic),
		kgo.AutoCommitMarks(),
		kgo.AutoCommitInterval(c.CommitInterval),
		kgo.FetchMaxWait(time.Second),
	}

	if c.TLS {
		tlsCfg, err := c.tlsConfig()
		if err != nil {
			return nil, err
		}
		opts = append(opts, kgo.DialTLSConfig(tlsCfg))
	}

	switch strings.ToLower(c.SASLMechanism) {
	case "plain":
		opts = append(opts, kgo.SASL(plain.Auth{User: c.SASLUsername, Pass: c.SASLPassword}.AsMechanism()))
	case "scram-sha-256":
		opts = append(opts, kgo.SASL(scram.Auth{User: c.SASLUsername, Pass: c.SASLPassword}.AsSha256Mechanism()))
	case "scram-sha-512":
		opts = append(opts, kgo.SASL(scram.Auth{User: c.SASLUsername, Pass: c.SASLPassword}.AsSha512Mechanism()))
	}
	return opts, nil
}

func (c *KafkaConfig) tlsConfig() (*tls.Config, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.InsecureSkipVerify} //nolint:gosec // opt-in for dev only
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("kafka: read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("kafka: CA file contained no valid certificates")
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

// Publish produces one event keyed by tenant id. It is non-blocking: when the
// in-flight buffer is saturated it sheds (ErrBrokerFull) rather than stalling
// the ingest request, matching the in-memory broker's contract.
func (b *KafkaBroker) Publish(ctx context.Context, e StoredEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.inflight.Load() >= int64(b.cfg.ProducerBufferRecords) {
		b.shed.Add(ctx, 1)
		return ErrBrokerFull
	}
	rec := &kgo.Record{
		Topic: b.topic,
		// Partition by tenant: a tenant's events land on a stable partition set,
		// keeping per-tenant ordering and isolating one tenant's volume spikes
		// from another's ordering.
		Key:   []byte(e.TenantID),
		Value: encodeStoredEvent(e),
	}
	b.inflight.Add(1)
	b.client.Produce(ctx, rec, func(_ *kgo.Record, err error) {
		b.inflight.Add(-1)
		if err != nil {
			b.publishErr.Add(context.Background(), 1)
			if b.cfg.Logger != nil {
				b.cfg.Logger.Error().Err(err).Str("tenant", e.TenantID).Msg("kafka produce failed after retries")
			}
			return
		}
		b.published.Add(context.Background(), 1)
	})
	return nil
}

// Consume exposes the decoded-event channel the Writer drains.
func (b *KafkaBroker) Consume() <-chan StoredEvent { return b.out }

// consume runs the consumer-group read loop: poll, decode, hand off (with
// backpressure), and mark the record committed only after a successful hand-off
// so an interrupted process redelivers rather than loses events.
func (b *KafkaBroker) consume(ctx context.Context) {
	defer b.consumeWG.Done()
	for {
		fetches := b.client.PollFetches(ctx)
		if fetches.IsClientClosed() || ctx.Err() != nil {
			return
		}
		fetches.EachError(func(topic string, partition int32, err error) {
			if b.cfg.Logger != nil {
				b.cfg.Logger.Warn().Err(err).Str("topic", topic).Int32("partition", partition).Msg("kafka fetch error")
			}
		})
		iter := fetches.RecordIter()
		for !iter.Done() {
			rec := iter.Next()
			e, err := decodeStoredEvent(rec.Value)
			if err != nil {
				// Poison record: count, mark committed so it is not redelivered
				// forever, and move on. It cannot be retried into validity.
				b.decodeErrors.Add(ctx, 1)
				b.client.MarkCommitRecords(rec)
				continue
			}
			select {
			case b.out <- e:
				b.consumed.Add(ctx, 1, metric.WithAttributes(attribute.String("tenant", e.TenantID)))
				b.client.MarkCommitRecords(rec)
			case <-ctx.Done():
				return
			}
		}
	}
}

// Close stops the consumer, flushes outstanding produces and commits marked
// offsets (best-effort), then closes the hand-off channel so the Writer drains
// and exits. Idempotent.
func (b *KafkaBroker) Close() {
	b.closeOnce.Do(func() {
		// Stop the consume loop first so nothing new is written to out.
		if b.cancel != nil {
			b.cancel()
		}
		b.consumeWG.Wait()

		// Flush any buffered produces so in-flight telemetry is durably acked
		// before we tear down.
		flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = b.client.Flush(flushCtx)
		cancel()

		// Close commits marked offsets and leaves the group cleanly.
		b.client.Close()
		close(b.out)
	})
}
