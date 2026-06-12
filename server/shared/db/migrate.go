package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Migration is a single embedded SQL migration file.
type Migration struct {
	Name string
	SQL  string
}

// LoadMigrations reads and sorts every *.sql file from fsys. Files are applied in
// lexical order, so callers must zero-pad numeric prefixes (001_, 002_, ...).
func LoadMigrations(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("read migrations dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	migs := make([]Migration, 0, len(names))
	for _, n := range names {
		b, err := fs.ReadFile(fsys, n)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", n, err)
		}
		migs = append(migs, Migration{Name: n, SQL: string(b)})
	}
	return migs, nil
}

// Migrate applies every migration in fsys that has not yet been recorded. It is
// idempotent: already-applied migrations are skipped, and each new migration is
// applied atomically together with the bookkeeping insert. A checksum guards
// against accidental edits to an already-applied file.
func (d *DB) Migrate(ctx context.Context, fsys fs.FS) error {
	migs, err := LoadMigrations(fsys)
	if err != nil {
		return err
	}
	if _, err := d.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name        TEXT PRIMARY KEY,
			checksum    TEXT NOT NULL,
			applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, err := d.appliedMigrations(ctx)
	if err != nil {
		return err
	}

	for _, m := range migs {
		sum := checksum(m.SQL)
		if prev, ok := applied[m.Name]; ok {
			if prev != sum {
				return fmt.Errorf("migration %s checksum mismatch: already applied with %s, now %s", m.Name, prev, sum)
			}
			continue
		}
		if err := d.applyOne(ctx, m, sum); err != nil {
			return fmt.Errorf("apply %s: %w", m.Name, err)
		}
	}
	return nil
}

func (d *DB) applyOne(ctx context.Context, m Migration, sum string) error {
	return d.WithTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			"INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)", m.Name, sum)
		return err
	})
}

func (d *DB) appliedMigrations(ctx context.Context) (map[string]string, error) {
	rows, err := d.Pool.Query(ctx, "SELECT name, checksum FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("query applied: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, sum string
		if err := rows.Scan(&name, &sum); err != nil {
			return nil, err
		}
		out[name] = sum
	}
	return out, rows.Err()
}

func checksum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
