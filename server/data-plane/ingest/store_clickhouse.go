package ingest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/risk"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// ClickHouseConfig configures the ClickHouse-backed analytics store. Only Addr
// is strictly required; the rest default to a local dev cluster.
type ClickHouseConfig struct {
	// Addr is the list of ClickHouse native-protocol endpoints (host:port).
	Addr []string
	// Database / Username / Password authenticate to the cluster.
	Database string
	Username string
	Password string

	// Table is the events table name. Defaults to "telemetry_events".
	Table string
	// RetentionTTLDays is the table-level TTL backstop in days. Per-tenant
	// retention is enforced precisely by the Purger; this is a coarse safety net
	// so a tenant whose purge is disabled cannot grow unbounded. 0 disables the
	// table TTL (rely solely on the Purger).
	RetentionTTLDays int
	// Cluster, when set, makes DDL run ON CLUSTER and the engine Replicated for
	// a sharded/replicated deployment. Empty keeps single-node DDL.
	Cluster string

	// DialTimeout bounds the initial connection.
	DialTimeout time.Duration
	// MaxOpenConns / MaxIdleConns size the native connection pool.
	MaxOpenConns int
	MaxIdleConns int

	// TLS enables transport security. CAFile optionally pins the CA (PEM).
	TLS                bool
	CAFile             string
	InsecureSkipVerify bool
}

func (c *ClickHouseConfig) withDefaults() {
	if c.Table == "" {
		c.Table = "telemetry_events"
	}
	if c.Database == "" {
		c.Database = "kseal"
	}
	if c.Username == "" {
		// Match the ClickHouse protocol default explicitly so the documented
		// contract holds even when the server runs without the env var set.
		c.Username = "default"
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 10 * time.Second
	}
	if c.MaxOpenConns <= 0 {
		c.MaxOpenConns = 10
	}
	if c.MaxIdleConns <= 0 {
		c.MaxIdleConns = 5
	}
}

func (c *ClickHouseConfig) validate() error {
	if len(c.Addr) == 0 {
		return errors.New("clickhouse: at least one address is required")
	}
	// The table name is interpolated into DDL/DML (ClickHouse does not
	// parameterize identifiers), so it must be a safe identifier.
	if !isSafeIdentifier(c.Table) {
		return fmt.Errorf("clickhouse: unsafe table name %q", c.Table)
	}
	if c.Cluster != "" && !isSafeIdentifier(c.Cluster) {
		return fmt.Errorf("clickhouse: unsafe cluster name %q", c.Cluster)
	}
	if c.RetentionTTLDays < 0 {
		return errors.New("clickhouse: retention TTL days must be >= 0")
	}
	return nil
}

// ClickHouseAnalyticsStore implements AnalyticsStore and RawEventStore against a
// ClickHouse cluster. The schema is tenant-isolated (tenant_id is the leading
// ORDER BY/primary-key column so every tenant-scoped read prunes to that
// tenant), time-partitioned (monthly), and deduplicated by event id via a
// ReplacingMergeTree so the at-least-once broker path is effectively-once. All
// reads filter on tenant_id, preserving cross-tenant isolation identical to the
// in-memory store.
type ClickHouseAnalyticsStore struct {
	conn  driver.Conn
	cfg   ClickHouseConfig
	table string

	tracer        trace.Tracer
	writes        metric.Int64Counter
	writeErrors   metric.Int64Counter
	rowsWritten   metric.Int64Counter
	writeLatency  metric.Float64Histogram
	purgedRecords metric.Int64Counter
}

// NewClickHouseAnalyticsStore opens the cluster, fails closed if it is
// unreachable, and ensures the schema exists. A server that explicitly selected
// ClickHouse never silently runs without durable analytics.
func NewClickHouseAnalyticsStore(ctx context.Context, cfg ClickHouseConfig) (*ClickHouseAnalyticsStore, error) {
	cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	opts := &clickhouse.Options{
		Addr:         cfg.Addr,
		Auth:         clickhouse.Auth{Database: cfg.Database, Username: cfg.Username, Password: cfg.Password},
		DialTimeout:  cfg.DialTimeout,
		MaxOpenConns: cfg.MaxOpenConns,
		MaxIdleConns: cfg.MaxIdleConns,
		Compression:  &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
	}
	if cfg.TLS {
		tlsCfg, err := cfg.tlsConfig()
		if err != nil {
			return nil, err
		}
		opts.TLS = tlsCfg
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: open: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	defer cancel()
	if err := conn.Ping(pingCtx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("clickhouse: ping: %w", err)
	}

	s := &ClickHouseAnalyticsStore{conn: conn, cfg: cfg, table: cfg.Table}
	if err := s.ensureSchema(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}

	meter := otel.Meter(instrumentationScope)
	s.tracer = otel.Tracer(instrumentationScope)
	s.writes, _ = meter.Int64Counter("kseal.analytics.writes", metric.WithDescription("ClickHouse write batches."))
	s.writeErrors, _ = meter.Int64Counter("kseal.analytics.write_errors", metric.WithDescription("ClickHouse write batches that failed."))
	s.rowsWritten, _ = meter.Int64Counter("kseal.analytics.rows_written", metric.WithDescription("ClickHouse rows persisted."))
	s.writeLatency, _ = meter.Float64Histogram("kseal.analytics.write_latency_seconds", metric.WithDescription("ClickHouse batch write latency."))
	s.purgedRecords, _ = meter.Int64Counter("kseal.analytics.purged_rows", metric.WithDescription("Raw events removed by retention purge."))
	return s, nil
}

func (c *ClickHouseConfig) tlsConfig() (*tls.Config, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.InsecureSkipVerify} //nolint:gosec // opt-in for dev only
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("clickhouse: read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("clickhouse: CA file contained no valid certificates")
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

// Close releases the connection pool.
func (s *ClickHouseAnalyticsStore) Close() error { return s.conn.Close() }

// Write inserts a batch of events. The whole batch is sent in one columnar
// INSERT (ClickHouse's efficient path); on any error the entire batch fails so
// the Writer retries it and the broker's durable position is not advanced
// (offsets are committed only after a successful write), making the path
// at-least-once. The ReplacingMergeTree dedupes the eventual retry/redelivery by
// id, so the end-to-end result is effectively-once.
func (s *ClickHouseAnalyticsStore) Write(ctx context.Context, events []StoredEvent) error {
	if len(events) == 0 {
		return nil
	}
	ctx, span := s.tracer.Start(ctx, "clickhouse.Write", trace.WithAttributes(attribute.Int("rows", len(events))))
	defer span.End()
	start := time.Now()

	batch, err := s.conn.PrepareBatch(ctx, "INSERT INTO "+s.table+" ("+selectColumns+")")
	if err != nil {
		s.writeErrors.Add(ctx, 1)
		span.RecordError(err)
		return fmt.Errorf("clickhouse: prepare batch: %w", err)
	}
	for _, e := range events {
		if err := batch.Append(
			e.TenantID,
			e.AppID,
			e.ID,
			int32(e.EventType),
			int32(e.RiskLevel),
			e.RiskBits,
			uint8(e.RiskBitsLayout),
			int32(e.Confidence),
			e.BuildHash,
			e.PolicyHash,
			e.InstallKeyHash,
			e.Country,
			int32(e.Platform),
			time.Unix(e.TimeBucket, 0).UTC(),
			time.Unix(e.ReceivedAt, 0).UTC(),
		); err != nil {
			_ = batch.Abort()
			s.writeErrors.Add(ctx, 1)
			span.RecordError(err)
			return fmt.Errorf("clickhouse: append row: %w", err)
		}
	}
	if err := batch.Send(); err != nil {
		s.writeErrors.Add(ctx, 1)
		span.RecordError(err)
		return fmt.Errorf("clickhouse: send batch: %w", err)
	}
	s.writes.Add(ctx, 1)
	s.rowsWritten.Add(ctx, int64(len(events)))
	s.writeLatency.Record(ctx, time.Since(start).Seconds())
	return nil
}

// selectColumns is the canonical projection, ordered to match scanRow.
const selectColumns = "tenant_id, app_id, id, event_type, risk_level, risk_bits, risk_bits_layout, confidence, build_hash, policy_hash, install_key_hash, country, platform, time_bucket, received_at"

// Query returns matching events ordered by time bucket ascending, mirroring the
// in-memory store. FINAL collapses any ReplacingMergeTree duplicates so a
// redelivered event is never double-counted.
func (s *ClickHouseAnalyticsStore) Query(ctx context.Context, q Query) ([]StoredEvent, error) {
	ctx, span := s.tracer.Start(ctx, "clickhouse.Query")
	defer span.End()
	where, args := q.clickhouseWhere()
	sql := fmt.Sprintf("SELECT %s FROM %s FINAL %s ORDER BY time_bucket ASC, id ASC", selectColumns, s.table, where)
	rows, err := s.conn.Query(ctx, sql, args...)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("clickhouse: query: %w", err)
	}
	defer rows.Close()
	return scanRows(rows)
}

// Count returns the number of distinct matching events.
func (s *ClickHouseAnalyticsStore) Count(ctx context.Context, q Query) (int, error) {
	ctx, span := s.tracer.Start(ctx, "clickhouse.Count")
	defer span.End()
	where, args := q.clickhouseWhere()
	// count(DISTINCT id) is exact regardless of pending merges, so the count is
	// correct even before the ReplacingMergeTree collapses redelivered rows.
	sql := fmt.Sprintf("SELECT count(DISTINCT id) FROM %s %s", s.table, where)
	var n uint64
	if err := s.conn.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		span.RecordError(err)
		return 0, fmt.Errorf("clickhouse: count: %w", err)
	}
	return int(n), nil
}

// ListEvents returns a recent-first (time_bucket desc, id desc) keyset page,
// identical in shape and ordering to the in-memory store so QueryService
// behaves the same against either backend.
func (s *ClickHouseAnalyticsStore) ListEvents(ctx context.Context, q Query, limit int, cursor string) (Page, error) {
	ctx, span := s.tracer.Start(ctx, "clickhouse.ListEvents")
	defer span.End()
	if limit <= 0 {
		limit = defaultEventPageSize
	}
	if limit > maxEventPageSize {
		limit = maxEventPageSize
	}
	curTB, curID, hasCur, err := decodeCursor(cursor)
	if err != nil {
		return Page{}, err
	}
	where, args := q.clickhouseWhere()
	if hasCur {
		// Keyset predicate for descending (time_bucket, id) order. Both
		// time_bucket bind params must be time.Time — the column is a ClickHouse
		// DateTime and the native driver rejects a raw int64 for it.
		curTime := time.Unix(curTB, 0).UTC()
		args = append(args, curTime, curTime, curID)
		clause := "(time_bucket < ? OR (time_bucket = ? AND id < ?))"
		if where == "" {
			where = "WHERE " + clause
		} else {
			where += " AND " + clause
		}
	}
	// Fetch limit+1 to determine whether a further page exists.
	sql := fmt.Sprintf("SELECT %s FROM %s FINAL %s ORDER BY time_bucket DESC, id DESC LIMIT %d", selectColumns, s.table, where, limit+1)
	rows, err := s.conn.Query(ctx, sql, args...)
	if err != nil {
		span.RecordError(err)
		return Page{}, fmt.Errorf("clickhouse: list events: %w", err)
	}
	defer rows.Close()
	out, err := scanRows(rows)
	if err != nil {
		return Page{}, err
	}
	var next string
	if len(out) > limit {
		last := out[limit-1]
		next = encodeCursor(last.TimeBucket, last.ID)
		out = out[:limit]
	}
	return Page{Events: out, NextCursor: next}, nil
}

// TenantIDs returns the distinct tenants currently holding raw events.
func (s *ClickHouseAnalyticsStore) TenantIDs(ctx context.Context) ([]string, error) {
	rows, err := s.conn.Query(ctx, fmt.Sprintf("SELECT DISTINCT tenant_id FROM %s", s.table))
	if err != nil {
		return nil, fmt.Errorf("clickhouse: tenant ids: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// PurgeRawEventsOlderThan deletes a single tenant's raw events older than
// cutoffBucket. It is strictly tenant-scoped (the WHERE pins tenant_id), so it
// can never touch another tenant's data. A lightweight DELETE is used so the
// rows disappear from queries promptly; the count is computed first because
// ClickHouse DELETE does not report affected rows synchronously.
func (s *ClickHouseAnalyticsStore) PurgeRawEventsOlderThan(ctx context.Context, tenantID string, cutoffBucket int64) (int, error) {
	if tenantID == "" {
		return 0, errors.New("clickhouse: empty tenant id for purge")
	}
	cutoff := time.Unix(cutoffBucket, 0).UTC()
	var toDelete uint64
	if err := s.conn.QueryRow(ctx,
		fmt.Sprintf("SELECT count(DISTINCT id) FROM %s WHERE tenant_id = ? AND time_bucket < ?", s.table),
		tenantID, cutoff,
	).Scan(&toDelete); err != nil {
		return 0, fmt.Errorf("clickhouse: count purge: %w", err)
	}
	if toDelete == 0 {
		return 0, nil
	}
	if err := s.conn.Exec(ctx,
		fmt.Sprintf("DELETE FROM %s WHERE tenant_id = ? AND time_bucket < ?", s.table),
		tenantID, cutoff,
	); err != nil {
		return 0, fmt.Errorf("clickhouse: purge delete: %w", err)
	}
	s.purgedRecords.Add(ctx, int64(toDelete))
	return int(toDelete), nil
}

// clickhouseWhere builds the parameterized WHERE clause and arguments for a
// Query. tenant_id is always the first predicate so every read is physically
// tenant-scoped. All values are passed as bound parameters (never interpolated)
// so the query is injection-safe.
func (q Query) clickhouseWhere() (string, []any) {
	var preds []string
	var args []any
	if q.TenantID != "" {
		preds = append(preds, "tenant_id = ?")
		args = append(args, q.TenantID)
	}
	if q.AppID != "" {
		preds = append(preds, "app_id = ?")
		args = append(args, q.AppID)
	}
	if q.PolicyHash != "" {
		preds = append(preds, "policy_hash = ?")
		args = append(args, q.PolicyHash)
	}
	if q.From != 0 {
		preds = append(preds, "time_bucket >= ?")
		args = append(args, time.Unix(q.From, 0).UTC())
	}
	if q.To != 0 {
		preds = append(preds, "time_bucket <= ?")
		args = append(args, time.Unix(q.To, 0).UTC())
	}
	if len(q.EventTypes) > 0 {
		ph := make([]string, len(q.EventTypes))
		for i, t := range q.EventTypes {
			ph[i] = "?"
			args = append(args, int32(t))
		}
		preds = append(preds, "event_type IN ("+strings.Join(ph, ",")+")")
	}
	if len(q.RiskLevels) > 0 {
		ph := make([]string, len(q.RiskLevels))
		for i, l := range q.RiskLevels {
			ph[i] = "?"
			args = append(args, int32(l))
		}
		preds = append(preds, "risk_level IN ("+strings.Join(ph, ",")+")")
	}
	if len(preds) == 0 {
		return "", nil
	}
	return "WHERE " + strings.Join(preds, " AND "), args
}

func scanRows(rows driver.Rows) ([]StoredEvent, error) {
	var out []StoredEvent
	for rows.Next() {
		e, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func scanRow(rows driver.Rows) (StoredEvent, error) {
	var (
		e          StoredEvent
		eventType  int32
		riskLevel  int32
		layout     uint8
		confidence int32
		platform   int32
		timeBucket time.Time
		receivedAt time.Time
	)
	if err := rows.Scan(
		&e.TenantID,
		&e.AppID,
		&e.ID,
		&eventType,
		&riskLevel,
		&e.RiskBits,
		&layout,
		&confidence,
		&e.BuildHash,
		&e.PolicyHash,
		&e.InstallKeyHash,
		&e.Country,
		&platform,
		&timeBucket,
		&receivedAt,
	); err != nil {
		return StoredEvent{}, fmt.Errorf("clickhouse: scan: %w", err)
	}
	e.EventType = ksealv1.EventType(eventType)
	e.RiskLevel = ksealv1.TrustLevel(riskLevel)
	e.RiskBitsLayout = risk.Layout(layout)
	e.Confidence = ksealv1.Confidence(confidence)
	e.Platform = ksealv1.Platform(platform)
	e.TimeBucket = timeBucket.Unix()
	e.ReceivedAt = receivedAt.Unix()
	return e, nil
}

// isSafeIdentifier permits only [A-Za-z0-9_] identifiers, used to gate the few
// places a name is interpolated into ClickHouse DDL/DML (identifiers cannot be
// bound parameters).
func isSafeIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}
