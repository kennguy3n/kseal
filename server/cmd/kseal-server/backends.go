package main

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/kennguy3n/kseal/server/data-plane/ingest"
	cfgpkg "github.com/kennguy3n/kseal/server/shared/config"
)

// buildBroker selects the telemetry broker from config. Default (memory) keeps
// the in-process channel broker; "kafka" builds the durable Kafka/Redpanda
// broker. A selected-but-unreachable backend fails closed so the server refuses
// to start rather than silently dropping telemetry.
func buildBroker(ctx context.Context, cfg *cfgpkg.Config, logger zerolog.Logger) (ingest.Broker, error) {
	if !cfg.DataPlane.UsesKafka() {
		return ingest.NewChannelBroker(0), nil
	}
	d := cfg.DataPlane
	klog := logger.With().Str("component", "kafka-broker").Logger()
	broker, err := ingest.NewKafkaBroker(ctx, ingest.KafkaConfig{
		Brokers:            d.KafkaBrokers,
		Topic:              d.KafkaTopic,
		ConsumerGroup:      d.KafkaConsumerGroup,
		TLS:                d.KafkaTLS,
		CAFile:             d.KafkaCAFile,
		InsecureSkipVerify: d.KafkaInsecureSkipVerify,
		SASLMechanism:      d.KafkaSASLMechanism,
		SASLUsername:       d.KafkaSASLUsername,
		SASLPassword:       d.KafkaSASLPassword,
		Logger:             &klog,
	})
	if err != nil {
		return nil, fmt.Errorf("kafka broker: %w", err)
	}
	return broker, nil
}

// buildAnalytics selects the analytics store from config. Default (memory) keeps
// the in-process store; "clickhouse" builds the ClickHouse-backed store. The
// returned store satisfies both AnalyticsStore (queries) and RawEventStore
// (retention purge). cleanup closes any backend resources and is always
// non-nil. A selected-but-unreachable backend fails closed.
func buildAnalytics(ctx context.Context, cfg *cfgpkg.Config) (ingest.AnalyticsStore, ingest.RawEventStore, func(), error) {
	if !cfg.DataPlane.UsesClickHouse() {
		store := ingest.NewInMemoryAnalyticsStore()
		return store, store, func() {}, nil
	}
	d := cfg.DataPlane
	store, err := ingest.NewClickHouseAnalyticsStore(ctx, ingest.ClickHouseConfig{
		Addr:               d.ClickHouseAddr,
		Database:           d.ClickHouseDatabase,
		Username:           d.ClickHouseUsername,
		Password:           d.ClickHousePassword,
		Table:              d.ClickHouseTable,
		Cluster:            d.ClickHouseCluster,
		RetentionTTLDays:   d.ClickHouseRetentionTTLDays,
		TLS:                d.ClickHouseTLS,
		CAFile:             d.ClickHouseCAFile,
		InsecureSkipVerify: d.ClickHouseInsecureSkipVerify,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("clickhouse analytics: %w", err)
	}
	return store, store, func() { _ = store.Close() }, nil
}
