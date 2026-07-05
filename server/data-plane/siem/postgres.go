package siem

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/db"
)

// Local aliases keep the Postgres scan code readable.
type ksealv1Connector = ksealv1.SiemConnector

func ksealKind(v int32) ksealv1.SiemKind            { return ksealv1.SiemKind(v) }
func ksealFormat(v int32) ksealv1.SiemPayloadFormat { return ksealv1.SiemPayloadFormat(v) }

// PostgresConnectorStore is the production ConnectorStore. It persists connector
// config in Postgres with the same row-level-security model as the rest of the
// platform (the "app.tenant_id" GUC), and seals auth secrets at rest with the
// shared AES-GCM-under-KEK envelope.
//
// The connector table is provisioned idempotently by EnsureSchema rather than
// through the control-plane migration runner: this keeps the SIEM workstream
// self-contained within its owned package and avoids a cross-cutting edit to
// the shared migrations directory. EnsureSchema is safe to call on every boot.
type PostgresConnectorStore struct {
	db  *db.DB
	enc Sealer
}

// NewPostgresConnectorStore builds a Postgres-backed store.
func NewPostgresConnectorStore(database *db.DB, enc Sealer) *PostgresConnectorStore {
	return &PostgresConnectorStore{db: database, enc: enc}
}

// EnsureSchema creates the siem_connectors table, its indexes, and its RLS
// policy if absent. Idempotent.
func (s *PostgresConnectorStore) EnsureSchema(ctx context.Context) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS siem_connectors (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                 UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind                      INT NOT NULL,
    endpoint                  TEXT NOT NULL,
    auth_secret_ref           TEXT NOT NULL,
    secret_enc                BYTEA NOT NULL,
    format                    INT NOT NULL,
    field_allow_list          TEXT[] NOT NULL DEFAULT '{}',
    is_active                 BOOLEAN NOT NULL DEFAULT true,
    sentinel_dcr_immutable_id TEXT NOT NULL DEFAULT '',
    sentinel_stream_name      TEXT NOT NULL DEFAULT '',
    elastic_index             TEXT NOT NULL DEFAULT '',
    splunk_index              TEXT NOT NULL DEFAULT '',
    splunk_sourcetype         TEXT NOT NULL DEFAULT '',
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_siem_connectors_tenant ON siem_connectors (tenant_id);
CREATE INDEX IF NOT EXISTS idx_siem_connectors_active ON siem_connectors (tenant_id, is_active);
ALTER TABLE siem_connectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE siem_connectors FORCE ROW LEVEL SECURITY;
`
	// RLS policy creation is not IF NOT EXISTS in this PG version; guard it.
	const policy = `
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'siem_connectors'
          AND policyname = 'siem_connectors_tenant_isolation'
    ) THEN
        CREATE POLICY siem_connectors_tenant_isolation ON siem_connectors
            USING (current_setting('app.bypass_rls', true) = 'on'
                   OR tenant_id::text = current_setting('app.tenant_id', true))
            WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
                   OR tenant_id::text = current_setting('app.tenant_id', true));
    END IF;
END$$;
`
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, ddl); err != nil {
			return fmt.Errorf("siem ensure ddl: %w", err)
		}
		if _, err := tx.Exec(ctx, policy); err != nil {
			return fmt.Errorf("siem ensure policy: %w", err)
		}
		return nil
	})
}

const connectorColumns = `id, tenant_id, kind, endpoint, auth_secret_ref, format,
	field_allow_list, is_active, sentinel_dcr_immutable_id, sentinel_stream_name,
	elastic_index, splunk_index, splunk_sourcetype,
	EXTRACT(EPOCH FROM created_at)::bigint`

// CreateConnector seals the secret and inserts a new connector under RLS.
func (s *PostgresConnectorStore) CreateConnector(ctx context.Context, in CreateConnectorInput) (*ksealv1Connector, error) {
	return s.create(ctx, in)
}

// ListConnectors returns the tenant's connectors (no secrets).
func (s *PostgresConnectorStore) ListConnectors(ctx context.Context, tenantID string) ([]*ksealv1Connector, error) {
	var out []*ksealv1Connector
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+connectorColumns+`
			FROM siem_connectors WHERE tenant_id = $1 ORDER BY created_at DESC, id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanConnector(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteConnector removes a connector by id.
func (s *PostgresConnectorStore) DeleteConnector(ctx context.Context, tenantID, id string) (bool, error) {
	var deleted bool
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM siem_connectors WHERE tenant_id = $1 AND id = $2`, tenantID, id)
		if err != nil {
			return err
		}
		deleted = ct.RowsAffected() > 0
		return nil
	})
	if err != nil {
		return false, err
	}
	return deleted, nil
}

// ListActiveWithSecrets returns active connectors with decrypted secrets.
func (s *PostgresConnectorStore) ListActiveWithSecrets(ctx context.Context, tenantID string) ([]ConnectorWithSecret, error) {
	var out []ConnectorWithSecret
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+connectorColumns+`, secret_enc
			FROM siem_connectors WHERE tenant_id = $1 AND is_active ORDER BY created_at`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, sealed, err := scanConnectorWithSecret(rows)
			if err != nil {
				return err
			}
			secret, err := s.enc.Open(sealed)
			if err != nil {
				return fmt.Errorf("decrypt siem secret: %w", err)
			}
			out = append(out, ConnectorWithSecret{Connector: c, Secret: secret})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresConnectorStore) create(ctx context.Context, in CreateConnectorInput) (*ksealv1Connector, error) {
	if in.Format == 0 {
		in.Format = defaultFormatFor(in.Kind)
	}
	if err := validateInput(in); err != nil {
		return nil, err
	}
	allow, err := NormalizeAllowList(in.FieldAllowList)
	if err != nil {
		return nil, err
	}
	sealed, err := s.enc.Seal(in.Secret)
	if err != nil {
		return nil, err
	}
	var c *ksealv1Connector
	err = s.db.WithTenantTx(ctx, in.TenantID, func(tx pgx.Tx) error {
		// Generate the id first so the auth_secret_ref can be derived from it.
		var id string
		if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&id); err != nil {
			return err
		}
		row := tx.QueryRow(ctx, `
			INSERT INTO siem_connectors
			    (id, tenant_id, kind, endpoint, auth_secret_ref, secret_enc, format,
			     field_allow_list, sentinel_dcr_immutable_id, sentinel_stream_name,
			     elastic_index, splunk_index, splunk_sourcetype)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			RETURNING `+connectorColumns,
			id, in.TenantID, int32(in.Kind), in.Endpoint, secretRef(id), sealed, int32(in.Format),
			allow, in.SentinelDcrImmutableID, in.SentinelStreamName,
			in.ElasticIndex, in.SplunkIndex, in.SplunkSourcetype)
		c, err = scanConnector(row)
		return err
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// scannable is satisfied by both pgx.Row and pgx.Rows.
type scannable interface {
	Scan(dest ...any) error
}

func scanConnector(row scannable) (*ksealv1Connector, error) {
	c := &ksealv1Connector{}
	var kind, format int32
	if err := row.Scan(
		&c.Id, &c.TenantId, &kind, &c.Endpoint, &c.AuthSecretRef, &format,
		&c.FieldAllowList, &c.IsActive, &c.SentinelDcrImmutableId, &c.SentinelStreamName,
		&c.ElasticIndex, &c.SplunkIndex, &c.SplunkSourcetype, &c.CreatedAt,
	); err != nil {
		return nil, err
	}
	c.Kind = ksealKind(kind)
	c.Format = ksealFormat(format)
	return c, nil
}

func scanConnectorWithSecret(row scannable) (*ksealv1Connector, []byte, error) {
	c := &ksealv1Connector{}
	var kind, format int32
	var sealed []byte
	if err := row.Scan(
		&c.Id, &c.TenantId, &kind, &c.Endpoint, &c.AuthSecretRef, &format,
		&c.FieldAllowList, &c.IsActive, &c.SentinelDcrImmutableId, &c.SentinelStreamName,
		&c.ElasticIndex, &c.SplunkIndex, &c.SplunkSourcetype, &c.CreatedAt, &sealed,
	); err != nil {
		return nil, nil, err
	}
	c.Kind = ksealKind(kind)
	c.Format = ksealFormat(format)
	return c, sealed, nil
}
