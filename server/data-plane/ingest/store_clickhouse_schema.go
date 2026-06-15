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
	risk_bits_layout UInt8 DEFAULT 0,
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

	// Add risk_bits_layout to clusters created before the column existed.
	// Existing rows materialize the DEFAULT 0 (risk.LayoutUnknown), which
	// readers treat as the server layout — matching their pre-column behavior,
	// so the migration is a pure no-op for already-correct rows.
	//
	// We gate the ALTER on a cheap, node-local system.columns lookup instead of
	// issuing it unconditionally. ALTER ... ADD COLUMN IF NOT EXISTS is
	// idempotent, but on an ON CLUSTER deployment it enqueues a distributed DDL
	// task on every node on every server boot; with many pods restarting that is
	// needless chatter in the distributed-DDL queue. The existence probe is a
	// plain SELECT (no DDL), so once the column is present the common path issues
	// no DDL at all.
	exists, err := s.columnExists(ctx, "risk_bits_layout")
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	alter := fmt.Sprintf("ALTER TABLE %s%s ADD COLUMN IF NOT EXISTS risk_bits_layout UInt8 DEFAULT 0 AFTER risk_bits", s.table, onCluster)
	if err := s.conn.Exec(ctx, alter); err != nil {
		return fmt.Errorf("clickhouse: add risk_bits_layout column: %w", err)
	}
	return nil
}

// columnExists reports whether the events table already has the named column,
// using a node-local system.columns lookup (no distributed DDL). table is a
// validated safe identifier living in the connection's current database, so it
// is matched as a bound parameter against currentDatabase().
func (s *ClickHouseAnalyticsStore) columnExists(ctx context.Context, column string) (bool, error) {
	var n uint64
	const q = "SELECT count() FROM system.columns WHERE database = currentDatabase() AND table = ? AND name = ?"
	if err := s.conn.QueryRow(ctx, q, s.table, column).Scan(&n); err != nil {
		return false, fmt.Errorf("clickhouse: check column %q: %w", column, err)
	}
	return n > 0, nil
}
