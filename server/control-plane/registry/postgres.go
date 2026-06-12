package registry

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
	"github.com/kennguy3n/kseal/server/shared/crypto"
	"github.com/kennguy3n/kseal/server/shared/db"
)

// PostgresStore is the production Store backed by Postgres with row-level
// security. Signing-key private material and webhook secrets are sealed with the
// configured envelope encryptor before they touch the database.
type PostgresStore struct {
	db  *db.DB
	enc *crypto.Encryptor
}

// NewPostgresStore builds a Postgres-backed store.
func NewPostgresStore(database *db.DB, enc *crypto.Encryptor) *PostgresStore {
	return &PostgresStore{db: database, enc: enc}
}

// Close is a no-op; the pool lifecycle is owned by the caller.
func (s *PostgresStore) Close() {}

func nowUnix() int64 { return time.Now().Unix() }

func encodeOffset(n int) string {
	if n <= 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(n)))
}

func decodeOffset(token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, ErrInvalidInput
	}
	n, err := strconv.Atoi(string(b))
	if err != nil || n < 0 {
		return 0, ErrInvalidInput
	}
	return n, nil
}

func clampPageSize(n int) int {
	switch {
	case n <= 0:
		return 50
	case n > 500:
		return 500
	default:
		return n
	}
}

// ---- Tenants ----

func (s *PostgresStore) CreateTenant(ctx context.Context, in CreateTenantInput) (*ksealv1.Tenant, error) {
	if in.Name == "" || in.Slug == "" {
		return nil, fmt.Errorf("%w: name and slug required", ErrInvalidInput)
	}
	tier := in.Tier
	if tier == "" {
		tier = "starter"
	}
	var t ksealv1.Tenant
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		return scanTenant(tx.QueryRow(ctx, `
			INSERT INTO tenants (name, slug, tier)
			VALUES ($1, $2, $3)
			RETURNING id, name, slug, tier, status,
			          EXTRACT(EPOCH FROM created_at)::bigint,
			          EXTRACT(EPOCH FROM updated_at)::bigint`,
			in.Name, in.Slug, tier), &t)
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return &t, nil
}

func (s *PostgresStore) GetTenant(ctx context.Context, id string) (*ksealv1.Tenant, error) {
	var t ksealv1.Tenant
	err := scanTenant(s.db.Pool.QueryRow(ctx, `
		SELECT id, name, slug, tier, status,
		       EXTRACT(EPOCH FROM created_at)::bigint,
		       EXTRACT(EPOCH FROM updated_at)::bigint
		FROM tenants WHERE id = $1`, id), &t)
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return &t, nil
}

func (s *PostgresStore) ListTenants(ctx context.Context, page Page) ([]*ksealv1.Tenant, string, error) {
	size := clampPageSize(page.Size)
	offset, err := decodeOffset(page.Token)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, slug, tier, status,
		       EXTRACT(EPOCH FROM created_at)::bigint,
		       EXTRACT(EPOCH FROM updated_at)::bigint
		FROM tenants
		ORDER BY created_at, id
		LIMIT $1 OFFSET $2`, size+1, offset)
	if err != nil {
		return nil, "", wrapPgErr(err)
	}
	defer rows.Close()
	var out []*ksealv1.Tenant
	for rows.Next() {
		var t ksealv1.Tenant
		if err := scanTenant(rows, &t); err != nil {
			return nil, "", err
		}
		out = append(out, &t)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return paginate(out, size, offset)
}

func (s *PostgresStore) UpdateTenant(ctx context.Context, in UpdateTenantInput) (*ksealv1.Tenant, error) {
	if in.ID == "" {
		return nil, fmt.Errorf("%w: id required", ErrInvalidInput)
	}
	var t ksealv1.Tenant
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		return scanTenant(tx.QueryRow(ctx, `
			UPDATE tenants SET
				name = COALESCE(NULLIF($2, ''), name),
				tier = COALESCE(NULLIF($3, ''), tier),
				status = COALESCE(NULLIF($4, ''), status),
				updated_at = now()
			WHERE id = $1
			RETURNING id, name, slug, tier, status,
			          EXTRACT(EPOCH FROM created_at)::bigint,
			          EXTRACT(EPOCH FROM updated_at)::bigint`,
			in.ID, in.Name, in.Tier, in.Status), &t)
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return &t, nil
}

// ---- Apps ----

func (s *PostgresStore) CreateApp(ctx context.Context, in CreateAppInput) (*ksealv1.App, error) {
	if in.TenantID == "" || in.Name == "" || in.PackageID == "" {
		return nil, fmt.Errorf("%w: tenant_id, name, package_id required", ErrInvalidInput)
	}
	identities := in.SigningIdentities
	if identities == nil {
		identities = []string{}
	}
	var a ksealv1.App
	err := s.db.WithTenantTx(ctx, in.TenantID, func(tx pgx.Tx) error {
		return scanApp(tx.QueryRow(ctx, `
			INSERT INTO apps (tenant_id, name, platform, package_id, signing_identities)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id, tenant_id, name, platform, package_id, signing_identities, status,
			          EXTRACT(EPOCH FROM created_at)::bigint,
			          EXTRACT(EPOCH FROM updated_at)::bigint`,
			in.TenantID, in.Name, int32(in.Platform), in.PackageID, identities), &a)
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return &a, nil
}

func (s *PostgresStore) GetApp(ctx context.Context, tenantID, id string) (*ksealv1.App, error) {
	var a ksealv1.App
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return scanApp(tx.QueryRow(ctx, `
			SELECT id, tenant_id, name, platform, package_id, signing_identities, status,
			       EXTRACT(EPOCH FROM created_at)::bigint,
			       EXTRACT(EPOCH FROM updated_at)::bigint
			FROM apps WHERE id = $1 AND tenant_id = $2`, id, tenantID), &a)
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return &a, nil
}

func (s *PostgresStore) ListApps(ctx context.Context, tenantID string, page Page) ([]*ksealv1.App, string, error) {
	size := clampPageSize(page.Size)
	offset, err := decodeOffset(page.Token)
	if err != nil {
		return nil, "", err
	}
	var out []*ksealv1.App
	err = s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, name, platform, package_id, signing_identities, status,
			       EXTRACT(EPOCH FROM created_at)::bigint,
			       EXTRACT(EPOCH FROM updated_at)::bigint
			FROM apps WHERE tenant_id = $1
			ORDER BY created_at, id
			LIMIT $2 OFFSET $3`, tenantID, size+1, offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a ksealv1.App
			if err := scanApp(rows, &a); err != nil {
				return err
			}
			out = append(out, &a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, "", wrapPgErr(err)
	}
	return paginate(out, size, offset)
}

// ---- Builds ----

func (s *PostgresStore) CreateBuild(ctx context.Context, in CreateBuildInput) (*ksealv1.Build, error) {
	if in.TenantID == "" || in.AppID == "" || in.BuildHash == "" {
		return nil, fmt.Errorf("%w: tenant_id, app_id, build_hash required", ErrInvalidInput)
	}
	manifest := in.Manifest
	if strings.TrimSpace(manifest) == "" {
		manifest = "{}"
	}
	var b ksealv1.Build
	err := s.db.WithTenantTx(ctx, in.TenantID, func(tx pgx.Tx) error {
		return scanBuild(tx.QueryRow(ctx, `
			INSERT INTO builds (tenant_id, app_id, build_hash, version_name, version_code, protection_profile_id, manifest)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING id, tenant_id, app_id, build_hash, version_name, version_code, protection_profile_id, manifest,
			          EXTRACT(EPOCH FROM created_at)::bigint`,
			in.TenantID, in.AppID, in.BuildHash, in.VersionName, in.VersionCode, in.ProtectionProfileID, manifest), &b)
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return &b, nil
}

func (s *PostgresStore) GetBuild(ctx context.Context, tenantID, id string) (*ksealv1.Build, error) {
	var b ksealv1.Build
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return scanBuild(tx.QueryRow(ctx, `
			SELECT id, tenant_id, app_id, build_hash, version_name, version_code, protection_profile_id, manifest,
			       EXTRACT(EPOCH FROM created_at)::bigint
			FROM builds WHERE id = $1 AND tenant_id = $2`, id, tenantID), &b)
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return &b, nil
}

func (s *PostgresStore) ListBuilds(ctx context.Context, tenantID, appID string, page Page) ([]*ksealv1.Build, string, error) {
	size := clampPageSize(page.Size)
	offset, err := decodeOffset(page.Token)
	if err != nil {
		return nil, "", err
	}
	var out []*ksealv1.Build
	err = s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, app_id, build_hash, version_name, version_code, protection_profile_id, manifest,
			       EXTRACT(EPOCH FROM created_at)::bigint
			FROM builds WHERE tenant_id = $1 AND ($2 = '' OR app_id = $2)
			ORDER BY created_at, id
			LIMIT $3 OFFSET $4`, tenantID, appID, size+1, offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b ksealv1.Build
			if err := scanBuild(rows, &b); err != nil {
				return err
			}
			out = append(out, &b)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, "", wrapPgErr(err)
	}
	return paginate(out, size, offset)
}

// ---- Policies ----

func (s *PostgresStore) CreatePolicy(ctx context.Context, in CreatePolicyInput) (*ksealv1.Policy, error) {
	if in.TenantID == "" || in.Name == "" {
		return nil, fmt.Errorf("%w: tenant_id and name required", ErrInvalidInput)
	}
	rules := defaultJSON(in.Rules, "[]")
	thresholds := defaultJSON(in.RiskThresholds, "{}")
	modules := in.ModulesEnabled
	if modules == nil {
		modules = []string{}
	}
	hash := HashPolicy(in.AppID, in.EnforcementMode, rules, thresholds, modules)
	var p ksealv1.Policy
	err := s.db.WithTenantTx(ctx, in.TenantID, func(tx pgx.Tx) error {
		var version int32
		if err := tx.QueryRow(ctx, `
			SELECT COALESCE(MAX(version), 0) + 1 FROM policies
			WHERE tenant_id = $1 AND app_id = $2`, in.TenantID, in.AppID).Scan(&version); err != nil {
			return err
		}
		return scanPolicy(tx.QueryRow(ctx, `
			INSERT INTO policies (tenant_id, app_id, name, version, enforcement_mode, rules, risk_thresholds, modules_enabled, policy_hash, is_active)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false)
			RETURNING id, tenant_id, app_id, name, version, enforcement_mode, rules, risk_thresholds, modules_enabled, is_active,
			          EXTRACT(EPOCH FROM created_at)::bigint,
			          EXTRACT(EPOCH FROM updated_at)::bigint`,
			in.TenantID, in.AppID, in.Name, version, int32(in.EnforcementMode), rules, thresholds, modules, hash), &p)
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return &p, nil
}

func (s *PostgresStore) GetActivePolicy(ctx context.Context, tenantID, appID string) (*ksealv1.Policy, error) {
	var p ksealv1.Policy
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		// Prefer an app-specific active policy, falling back to the tenant-wide one.
		return scanPolicy(tx.QueryRow(ctx, `
			SELECT id, tenant_id, app_id, name, version, enforcement_mode, rules, risk_thresholds, modules_enabled, is_active,
			       EXTRACT(EPOCH FROM created_at)::bigint,
			       EXTRACT(EPOCH FROM updated_at)::bigint
			FROM policies
			WHERE tenant_id = $1 AND is_active AND (app_id = $2 OR app_id = '')
			ORDER BY (app_id = $2) DESC
			LIMIT 1`, tenantID, appID), &p)
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return &p, nil
}

func (s *PostgresStore) ListPolicies(ctx context.Context, tenantID, appID string) ([]*ksealv1.Policy, error) {
	var out []*ksealv1.Policy
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, app_id, name, version, enforcement_mode, rules, risk_thresholds, modules_enabled, is_active,
			       EXTRACT(EPOCH FROM created_at)::bigint,
			       EXTRACT(EPOCH FROM updated_at)::bigint
			FROM policies WHERE tenant_id = $1 AND ($2 = '' OR app_id = $2)
			ORDER BY app_id, version DESC`, tenantID, appID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p ksealv1.Policy
			if err := scanPolicy(rows, &p); err != nil {
				return err
			}
			out = append(out, &p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return out, nil
}

func (s *PostgresStore) ActivatePolicy(ctx context.Context, tenantID, id string) (*ksealv1.Policy, error) {
	var p ksealv1.Policy
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var appID string
		if err := tx.QueryRow(ctx,
			`SELECT app_id FROM policies WHERE id = $1 AND tenant_id = $2`, id, tenantID).Scan(&appID); err != nil {
			return err
		}
		// Deactivate the current active policy for this scope, then activate the target.
		if _, err := tx.Exec(ctx,
			`UPDATE policies SET is_active = false, updated_at = now()
			 WHERE tenant_id = $1 AND app_id = $2 AND is_active`, tenantID, appID); err != nil {
			return err
		}
		return scanPolicy(tx.QueryRow(ctx, `
			UPDATE policies SET is_active = true, updated_at = now()
			WHERE id = $1 AND tenant_id = $2
			RETURNING id, tenant_id, app_id, name, version, enforcement_mode, rules, risk_thresholds, modules_enabled, is_active,
			          EXTRACT(EPOCH FROM created_at)::bigint,
			          EXTRACT(EPOCH FROM updated_at)::bigint`, id, tenantID), &p)
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return &p, nil
}

// ---- Protection profiles ----

func (s *PostgresStore) CreateProtectionProfile(ctx context.Context, in CreateProtectionProfileInput) (*ksealv1.ProtectionProfile, error) {
	if in.TenantID == "" || in.Name == "" {
		return nil, fmt.Errorf("%w: tenant_id and name required", ErrInvalidInput)
	}
	modules := in.ModulesEnabled
	if modules == nil {
		modules = []string{}
	}
	mode := in.DefaultMode
	if mode == ksealv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED {
		mode = ksealv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE
	}
	var pp ksealv1.ProtectionProfile
	err := s.db.WithTenantTx(ctx, in.TenantID, func(tx pgx.Tx) error {
		return scanProfile(tx.QueryRow(ctx, `
			INSERT INTO protection_profiles (tenant_id, name, modules_enabled, default_mode)
			VALUES ($1, $2, $3, $4)
			RETURNING id, tenant_id, name, modules_enabled, default_mode,
			          EXTRACT(EPOCH FROM created_at)::bigint`,
			in.TenantID, in.Name, modules, int32(mode)), &pp)
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return &pp, nil
}

func (s *PostgresStore) ListProtectionProfiles(ctx context.Context, tenantID string) ([]*ksealv1.ProtectionProfile, error) {
	var out []*ksealv1.ProtectionProfile
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, name, modules_enabled, default_mode,
			       EXTRACT(EPOCH FROM created_at)::bigint
			FROM protection_profiles WHERE tenant_id = $1 ORDER BY created_at`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var pp ksealv1.ProtectionProfile
			if err := scanProfile(rows, &pp); err != nil {
				return err
			}
			out = append(out, &pp)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return out, nil
}

// ---- API keys ----

func (s *PostgresStore) CreateAPIKey(ctx context.Context, tenantID, name string, scopes []string) (string, *APIKeyRecord, error) {
	if tenantID == "" {
		return "", nil, fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	gen, err := auth.GenerateAPIKey()
	if err != nil {
		return "", nil, err
	}
	if scopes == nil {
		scopes = []string{}
	}
	rec := &APIKeyRecord{}
	err = s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO api_keys (tenant_id, key_id, name, secret_hash, scopes)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id, tenant_id, key_id, name, scopes, status,
			          EXTRACT(EPOCH FROM created_at)::bigint`,
			tenantID, gen.KeyID, name, gen.Hash, scopes).Scan(
			&rec.ID, &rec.TenantID, &rec.KeyID, &rec.Name, &rec.Scopes, &rec.Status, &rec.CreatedAt)
	})
	if err != nil {
		return "", nil, wrapPgErr(err)
	}
	return gen.Plaintext, rec, nil
}

func (s *PostgresStore) ValidateAPIKey(ctx context.Context, plaintext string) (*auth.Principal, error) {
	keyID, secret, err := auth.ParseAPIKey(plaintext)
	if err != nil {
		return nil, err
	}
	var (
		tenantID, hash, status string
		scopes                 []string
	)
	err = s.db.WithAdminTx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			SELECT tenant_id, secret_hash, status, scopes FROM api_keys WHERE key_id = $1`, keyID).
			Scan(&tenantID, &hash, &status, &scopes); err != nil {
			return err
		}
		if status != "active" {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	ok, err := auth.VerifySecret(secret, hash)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFound
	}
	// Best-effort bookkeeping, only after the secret is verified so failed auth
	// attempts with a valid key_id don't pollute last_used_at. Runs in its own
	// admin tx so the RLS-bypass GUC is set (api_keys forces RLS).
	_ = s.db.WithAdminTx(ctx, func(tx pgx.Tx) error {
		_, _ = tx.Exec(ctx, `UPDATE api_keys SET last_used_at = now() WHERE key_id = $1`, keyID)
		return nil
	})
	return &auth.Principal{TenantID: tenantID, APIKeyID: keyID, Scopes: scopes}, nil
}

func (s *PostgresStore) RevokeAPIKey(ctx context.Context, tenantID, keyID string) error {
	return s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE api_keys SET status = 'revoked', revoked_at = now()
			WHERE tenant_id = $1 AND key_id = $2 AND status = 'active'`, tenantID, keyID)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// ---- Signing keys ----

func (s *PostgresStore) CreateSigningKey(ctx context.Context, tenantID string) (*SigningKey, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	kp, err := crypto.GenerateEd25519()
	if err != nil {
		return nil, err
	}
	sealed, err := s.enc.Seal(kp.Private)
	if err != nil {
		return nil, err
	}
	sk := &SigningKey{TenantID: tenantID, Algorithm: "ed25519", Public: kp.Public, Private: kp.Private, IsActive: true}
	err = s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		// Deactivate any current active key first; the partial unique index
		// uq_signing_keys_active permits only one active key per tenant.
		if _, err := tx.Exec(ctx,
			`UPDATE signing_keys SET is_active = false WHERE tenant_id = $1 AND is_active`, tenantID); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `
			INSERT INTO signing_keys (tenant_id, algorithm, public_key, private_key_enc, is_active)
			VALUES ($1, 'ed25519', $2, $3, true)
			RETURNING id, EXTRACT(EPOCH FROM created_at)::bigint`,
			tenantID, []byte(kp.Public), sealed).Scan(&sk.ID, &sk.CreatedAt)
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return sk, nil
}

func (s *PostgresStore) GetActiveSigningKey(ctx context.Context, tenantID string) (*SigningKey, error) {
	sk, err := s.loadSigningKey(ctx, tenantID,
		`SELECT id, tenant_id, algorithm, public_key, private_key_enc, is_active,
		        EXTRACT(EPOCH FROM created_at)::bigint
		 FROM signing_keys WHERE tenant_id = $1 AND is_active LIMIT 1`, tenantID)
	if err != nil {
		return nil, err
	}
	return sk, nil
}

func (s *PostgresStore) GetSigningKey(ctx context.Context, tenantID, id string) (*SigningKey, error) {
	return s.loadSigningKey(ctx, tenantID,
		`SELECT id, tenant_id, algorithm, public_key, private_key_enc, is_active,
		        EXTRACT(EPOCH FROM created_at)::bigint
		 FROM signing_keys WHERE tenant_id = $1 AND id = $2`, tenantID, id)
}

func (s *PostgresStore) loadSigningKey(ctx context.Context, tenantID, query string, args ...interface{}) (*SigningKey, error) {
	sk := &SigningKey{}
	var pub, privEnc []byte
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, args...).Scan(
			&sk.ID, &sk.TenantID, &sk.Algorithm, &pub, &privEnc, &sk.IsActive, &sk.CreatedAt)
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	priv, err := s.enc.Open(privEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt signing key: %w", err)
	}
	sk.Public = ed25519.PublicKey(pub)
	sk.Private = ed25519.PrivateKey(priv)
	return sk, nil
}

func (s *PostgresStore) RotateSigningKey(ctx context.Context, tenantID string) (*SigningKey, error) {
	kp, err := crypto.GenerateEd25519()
	if err != nil {
		return nil, err
	}
	sealed, err := s.enc.Seal(kp.Private)
	if err != nil {
		return nil, err
	}
	sk := &SigningKey{TenantID: tenantID, Algorithm: "ed25519", Public: kp.Public, Private: kp.Private, IsActive: true}
	err = s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE signing_keys SET is_active = false, rotated_at = now()
			WHERE tenant_id = $1 AND is_active`, tenantID); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `
			INSERT INTO signing_keys (tenant_id, algorithm, public_key, private_key_enc, is_active)
			VALUES ($1, 'ed25519', $2, $3, true)
			RETURNING id, EXTRACT(EPOCH FROM created_at)::bigint`,
			tenantID, []byte(kp.Public), sealed).Scan(&sk.ID, &sk.CreatedAt)
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return sk, nil
}

// ---- Webhooks ----

func (s *PostgresStore) CreateWebhook(ctx context.Context, tenantID, url string, eventTypes []ksealv1.EventType) (*ksealv1.Webhook, error) {
	if tenantID == "" || url == "" {
		return nil, fmt.Errorf("%w: tenant_id and url required", ErrInvalidInput)
	}
	secret, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	sealed, err := s.enc.Seal(secret)
	if err != nil {
		return nil, err
	}
	signingKeyID, err := crypto.RandomBytes(8)
	if err != nil {
		return nil, err
	}
	keyID := fmt.Sprintf("whk_%x", signingKeyID)
	types := eventTypesToInts(eventTypes)
	wh := &ksealv1.Webhook{}
	var ev []int32
	err = s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO webhooks (tenant_id, url, event_types, signing_key_id, secret_enc)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id, tenant_id, url, event_types, signing_key_id, is_active,
			          EXTRACT(EPOCH FROM created_at)::bigint`,
			tenantID, url, types, keyID, sealed).Scan(
			&wh.Id, &wh.TenantId, &wh.Url, &ev, &wh.SigningKeyId, &wh.IsActive, &wh.CreatedAt)
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	wh.EventTypes = intsToEventTypes(ev)
	return wh, nil
}

func (s *PostgresStore) ListWebhooks(ctx context.Context, tenantID string) ([]*ksealv1.Webhook, error) {
	var out []*ksealv1.Webhook
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, url, event_types, signing_key_id, is_active,
			       EXTRACT(EPOCH FROM created_at)::bigint
			FROM webhooks WHERE tenant_id = $1 ORDER BY created_at`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			wh := &ksealv1.Webhook{}
			var ev []int32
			if err := rows.Scan(&wh.Id, &wh.TenantId, &wh.Url, &ev, &wh.SigningKeyId, &wh.IsActive, &wh.CreatedAt); err != nil {
				return err
			}
			wh.EventTypes = intsToEventTypes(ev)
			out = append(out, wh)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return out, nil
}

func (s *PostgresStore) DeleteWebhook(ctx context.Context, tenantID, id string) (bool, error) {
	var deleted bool
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM webhooks WHERE tenant_id = $1 AND id = $2`, tenantID, id)
		if err != nil {
			return err
		}
		deleted = ct.RowsAffected() > 0
		return nil
	})
	if err != nil {
		return false, wrapPgErr(err)
	}
	return deleted, nil
}

func (s *PostgresStore) ListWebhooksForEvent(ctx context.Context, tenantID string, eventType ksealv1.EventType) ([]WebhookSecret, error) {
	var out []WebhookSecret
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, url, event_types, signing_key_id, is_active,
			       EXTRACT(EPOCH FROM created_at)::bigint, secret_enc
			FROM webhooks
			WHERE tenant_id = $1 AND is_active AND ($2 = ANY(event_types) OR cardinality(event_types) = 0)`,
			tenantID, int32(eventType))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			wh := &ksealv1.Webhook{}
			var ev []int32
			var sealed []byte
			if err := rows.Scan(&wh.Id, &wh.TenantId, &wh.Url, &ev, &wh.SigningKeyId, &wh.IsActive, &wh.CreatedAt, &sealed); err != nil {
				return err
			}
			secret, err := s.enc.Open(sealed)
			if err != nil {
				return fmt.Errorf("decrypt webhook secret: %w", err)
			}
			wh.EventTypes = intsToEventTypes(ev)
			out = append(out, WebhookSecret{Webhook: wh, Secret: secret})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return out, nil
}

// ---- Trust sessions ----

func (s *PostgresStore) CreateTrustSession(ctx context.Context, sess *TrustSession) error {
	if sess.TenantID == "" || sess.TokenID == "" {
		return fmt.Errorf("%w: tenant_id and token_id required", ErrInvalidInput)
	}
	scope := sess.CapabilityScope
	if scope == nil {
		scope = []string{}
	}
	return wrapPgErr(s.db.WithTenantTx(ctx, sess.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO trust_sessions
			    (token_id, tenant_id, app_id, build_hash, instance_id, policy_hash, risk_level, capability_scope, session_secret, last_sequence, status, issued_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, 'active', to_timestamp($10), to_timestamp($11))`,
			sess.TokenID, sess.TenantID, sess.AppID, sess.BuildHash, sess.InstanceID, sess.PolicyHash,
			sess.RiskLevel, scope, sess.SessionSecret, sess.IssuedAt, sess.ExpiresAt)
		return err
	}))
}

func (s *PostgresStore) GetTrustSession(ctx context.Context, tokenID string) (*TrustSession, error) {
	sess := &TrustSession{}
	err := s.db.WithAdminTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT token_id, tenant_id, app_id, build_hash, instance_id, policy_hash, risk_level,
			       capability_scope, session_secret, last_sequence, status,
			       EXTRACT(EPOCH FROM issued_at)::bigint, EXTRACT(EPOCH FROM expires_at)::bigint
			FROM trust_sessions WHERE token_id = $1`, tokenID).Scan(
			&sess.TokenID, &sess.TenantID, &sess.AppID, &sess.BuildHash, &sess.InstanceID, &sess.PolicyHash,
			&sess.RiskLevel, &sess.CapabilityScope, &sess.SessionSecret, &sess.LastSequence, &sess.Status,
			&sess.IssuedAt, &sess.ExpiresAt)
	})
	if err != nil {
		return nil, wrapPgErr(err)
	}
	return sess, nil
}

// ConsumeSequence atomically enforces a strictly-increasing per-token sequence,
// returning ErrReplay if seq does not advance. This is the anti-replay guard for
// request proofs.
func (s *PostgresStore) ConsumeSequence(ctx context.Context, tokenID string, seq int64) error {
	return wrapPgErr(s.db.WithAdminTx(ctx, func(tx pgx.Tx) error {
		// Distinguish a missing/inactive session (ErrNotFound) from a genuine
		// replay (ErrReplay) so the contract matches MemStore.
		var lastSeq int64
		if err := tx.QueryRow(ctx,
			`SELECT last_sequence FROM trust_sessions WHERE token_id = $1 AND status = 'active'`,
			tokenID).Scan(&lastSeq); err != nil {
			return err // pgx.ErrNoRows -> ErrNotFound via wrapPgErr
		}
		if seq <= lastSeq {
			return ErrReplay
		}
		if _, err := tx.Exec(ctx,
			`UPDATE trust_sessions SET last_sequence = $2 WHERE token_id = $1`, tokenID, seq); err != nil {
			return err
		}
		return nil
	}))
}

func (s *PostgresStore) RevokeTrustSession(ctx context.Context, tenantID, tokenID string) error {
	return wrapPgErr(s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE trust_sessions SET status = 'revoked'
			WHERE tenant_id = $1 AND token_id = $2`, tenantID, tokenID)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	}))
}

func defaultJSON(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func wrapPgErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	msg := err.Error()
	if strings.Contains(msg, "duplicate key") || strings.Contains(msg, "unique constraint") {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return err
}
