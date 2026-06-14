package ingest

import (
	"context"
	"fmt"
)

// ensureSchema creates the events table if it does not already exist. The
// configured database is assumed to exist (created by deploy/ops); the table is
// idempotently created so a fresh cluster or a rolling deploy converges without
// a separate migration step.
//
// Engine choice:
//   - ReplacingMergeTree(received_at) deduplicates rows sharing the ORDER BY key
//     (tenant_id, time_bucket, id), keeping the row with the greatest
//     received_at. Combined with the at-least-once broker this makes redelivered
//     events idempotent — a retried event collapses into the original.
//   - PARTITION BY toYYYYMM(time_bucket) keeps partitions month-sized so the
//     per-tenant retention purge and the TTL drop whole, cheap partitions.
//   - ORDER BY leads with tenant_id so every tenant-scoped read prunes straight
//     to that tenant's granules — strong physical isolation and fast reads.
//
// When cfg.Cluster is set the statement runs ON CLUSTER with a
// ReplicatedReplacingMergeTree so a sharded/replicated cluster converges on all
// nodes; otherwise a single-node engine is used.
func (s *ClickHouseAnalyticsStore) ensureSchema(ctx context.Context) error {
	var onCluster, engine string
	if s.cfg.Cluster != "" {
		onCluster = fmt.Sprintf(" ON CLUSTER %s", s.cfg.Cluster)
		engine = fmt.Sprintf("ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/%s', '{replica}', received_at)", s.table)
	} else {
		engine = "ReplacingMergeTree(received_at)"
	}

	var ttl string
	if s.cfg.RetentionTTLDays > 0 {
		// Coarse backstop only; the Purger enforces precise per-tenant windows.
		ttl = fmt.Sprintf("\nTTL time_bucket + INTERVAL %d DAY", s.cfg.RetentionTTLDays)
	}

	ddl := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s%s (
	tenant_id        String,
	app_id           String,
	id               String,
	event_type       Int32,
	risk_level       Int32,
	risk_bits        UInt64,
	confidence       Int32,
	build_hash       String,
	policy_hash      String,
	install_key_hash String,
	country          LowCardinality(String),
	platform         Int32,
	time_bucket      DateTime,
	received_at      DateTime
)
ENGINE = %s
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (tenant_id, time_bucket, id)%s
SETTINGS index_granularity = 8192`, s.table, onCluster, engine, ttl)

	if err := s.conn.Exec(ctx, ddl); err != nil {
		return fmt.Errorf("clickhouse: ensure schema: %w", err)
	}
	return nil
}
