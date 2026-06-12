// Package db provides the Postgres connection pool, an embedded SQL migration
// runner, tenant-scoped transaction helpers that drive Postgres row-level
// security, and small query utilities shared by the control and data planes.
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps a pgx connection pool with tenant-aware helpers.
type DB struct {
	Pool *pgxpool.Pool
}

// New connects to Postgres using dsn and verifies connectivity.
func New(ctx context.Context, dsn string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	cfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &DB{Pool: pool}, nil
}

// Close releases pooled connections.
func (d *DB) Close() {
	if d.Pool != nil {
		d.Pool.Close()
	}
}

// Ping checks liveness of the database.
func (d *DB) Ping(ctx context.Context) error {
	return d.Pool.Ping(ctx)
}

// WithTx runs fn inside a transaction, committing on success and rolling back on
// error or panic. Used for privileged/admin operations not bound to a tenant.
func (d *DB) WithTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	if err := runTx(ctx, tx, fn); err != nil {
		return err
	}
	return nil
}

// WithTenantTx runs fn inside a transaction after setting the per-transaction
// "app.tenant_id" GUC, which the row-level-security policies key off. This makes
// every query inside fn physically tenant-isolated by Postgres in addition to
// the application-layer guard.
func (d *DB) WithTenantTx(ctx context.Context, tenantID string, fn func(tx pgx.Tx) error) error {
	if tenantID == "" {
		return errors.New("db: empty tenant id for tenant tx")
	}
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	// set_config(..., true) scopes the setting to the current transaction.
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("set tenant guc: %w", err)
	}
	return runTx(ctx, tx, fn)
}

// WithAdminTx runs fn inside a transaction with the "app.bypass_rls" GUC set,
// which the row-level-security policies honor to permit pre-tenant lookups
// (API-key validation, proof validation by token id, cross-tenant dispatch).
// Use sparingly and only where a tenant cannot yet be established.
func (d *DB) WithAdminTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.bypass_rls', 'on', true)"); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("set bypass guc: %w", err)
	}
	return runTx(ctx, tx, fn)
}

func runTx(ctx context.Context, tx pgx.Tx, fn func(tx pgx.Tx) error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		}
	}()
	if err = fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// ErrNotFound is returned by scoped helpers when no row matches.
var ErrNotFound = errors.New("db: not found")
