package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/db"
)

// PostgresStore is the production compliance Store backed by Postgres with
// row-level security. Per-tenant audit appends are serialized with a
// transaction-scoped advisory lock so sequence numbers and the hash chain stay
// strictly ordered under concurrency.
type PostgresStore struct {
	db   *db.DB
	keys KeySource
}

// NewPostgresStore builds a Postgres-backed compliance store. keys supplies the
// per-tenant signing key used to sign kill switches.
func NewPostgresStore(database *db.DB, keys KeySource) *PostgresStore {
	return &PostgresStore{db: database, keys: keys}
}

// appendAuditTx appends one event to the tenant chain inside an existing
// tenant-scoped transaction. It takes a per-tenant advisory lock so concurrent
// appends serialize and the seq/hash chain has no gaps or forks.
func appendAuditTx(ctx context.Context, tx pgx.Tx, tenantID string, e Entry) (*ksealv1.AuditEvent, error) {
	if err := validateEntry(e); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, tenantID); err != nil {
		return nil, err
	}
	var prevSeq int64
	prevHash := ""
	err := tx.QueryRow(ctx,
		`SELECT seq, hash FROM audit_events WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1`, tenantID).
		Scan(&prevSeq, &prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	seq := prevSeq + 1
	created := nowMillis()
	hash := hashAuditEvent(tenantID, seq, e, created, prevHash)
	mdJSON, err := json.Marshal(metaOrEmpty(e.Metadata))
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_events
		    (tenant_id, seq, action, resource_type, resource_id, actor_key_id, metadata, prev_hash, hash, created_at_ms)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		tenantID, seq, e.Action, e.ResourceType, e.ResourceID, e.ActorKeyID, mdJSON, prevHash, hash, created); err != nil {
		return nil, err
	}
	return &ksealv1.AuditEvent{
		TenantId:     tenantID,
		Seq:          seq,
		Action:       e.Action,
		ResourceType: e.ResourceType,
		ResourceId:   e.ResourceID,
		ActorKeyId:   e.ActorKeyID,
		Metadata:     cloneMeta(e.Metadata),
		PrevHash:     prevHash,
		Hash:         hash,
		CreatedAt:    created,
	}, nil
}

func (s *PostgresStore) AppendAudit(ctx context.Context, tenantID string, e Entry) (*ksealv1.AuditEvent, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	var ev *ksealv1.AuditEvent
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var e2 error
		ev, e2 = appendAuditTx(ctx, tx, tenantID, e)
		return e2
	})
	if err != nil {
		return nil, err
	}
	return ev, nil
}

func (s *PostgresStore) ListAudit(ctx context.Context, tenantID string, f AuditFilter, pageSize int, pageToken string) ([]*ksealv1.AuditEvent, string, error) {
	if tenantID == "" {
		return nil, "", fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	size := clampPageSize(pageSize)
	cursor := int64(-1)
	if pageToken != "" {
		v, err := strconv.ParseInt(pageToken, 10, 64)
		if err != nil {
			return nil, "", ErrInvalidInput
		}
		cursor = v
	}
	var out []*ksealv1.AuditEvent
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tenant_id, seq, action, resource_type, resource_id, actor_key_id, metadata, prev_hash, hash, created_at_ms
			FROM audit_events
			WHERE tenant_id = $1
			  AND ($2 < 0 OR seq < $2)
			  AND ($3 = '' OR action = $3)
			  AND ($4 = '' OR resource_type = $4)
			  AND ($5 = 0 OR created_at_ms >= $5)
			  AND ($6 = 0 OR created_at_ms <= $6)
			ORDER BY seq DESC
			LIMIT $7`,
			tenantID, cursor, f.Action, f.ResourceType, f.FromMillis, f.ToMillis, size+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			ev, err := scanAudit(rows)
			if err != nil {
				return err
			}
			out = append(out, ev)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > size {
		out = out[:size]
		next = strconv.FormatInt(out[len(out)-1].Seq, 10)
	}
	return out, next, nil
}

func (s *PostgresStore) VerifyAudit(ctx context.Context, tenantID string) (VerifyResult, error) {
	if tenantID == "" {
		return VerifyResult{}, fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	var events []*ksealv1.AuditEvent
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tenant_id, seq, action, resource_type, resource_id, actor_key_id, metadata, prev_hash, hash, created_at_ms
			FROM audit_events WHERE tenant_id = $1 ORDER BY seq ASC`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			ev, err := scanAudit(rows)
			if err != nil {
				return err
			}
			events = append(events, ev)
		}
		return rows.Err()
	})
	if err != nil {
		return VerifyResult{}, err
	}
	return recompute(tenantID, events), nil
}

func (s *PostgresStore) PutDataProcessing(ctx context.Context, in DataProcessingInput) (*ksealv1.DataProcessingRecord, error) {
	if in.TenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	categories := in.DataCategories
	if categories == nil {
		categories = []string{}
	}
	updated := nowMillis()
	err := s.db.WithTenantTx(ctx, in.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO data_processing_records
			    (tenant_id, app_id, data_categories, purpose, retention_days, legal_basis, third_party_sharing, updated_at_ms)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (tenant_id, app_id) DO UPDATE SET
			    data_categories = EXCLUDED.data_categories,
			    purpose = EXCLUDED.purpose,
			    retention_days = EXCLUDED.retention_days,
			    legal_basis = EXCLUDED.legal_basis,
			    third_party_sharing = EXCLUDED.third_party_sharing,
			    updated_at_ms = EXCLUDED.updated_at_ms,
			    updated_at = now()`,
			in.TenantID, in.AppID, categories, in.Purpose, in.RetentionDays, in.LegalBasis, in.ThirdPartySharing, updated)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &ksealv1.DataProcessingRecord{
		TenantId:          in.TenantID,
		AppId:             in.AppID,
		DataCategories:    append([]string(nil), categories...),
		Purpose:           in.Purpose,
		RetentionDays:     in.RetentionDays,
		LegalBasis:        in.LegalBasis,
		ThirdPartySharing: in.ThirdPartySharing,
		UpdatedAt:         updated,
	}, nil
}

func (s *PostgresStore) ListDataProcessing(ctx context.Context, tenantID string) ([]*ksealv1.DataProcessingRecord, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	var out []*ksealv1.DataProcessingRecord
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tenant_id, app_id, data_categories, purpose, retention_days, legal_basis, third_party_sharing, updated_at_ms
			FROM data_processing_records WHERE tenant_id = $1 ORDER BY app_id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r ksealv1.DataProcessingRecord
			if err := rows.Scan(&r.TenantId, &r.AppId, &r.DataCategories, &r.Purpose,
				&r.RetentionDays, &r.LegalBasis, &r.ThirdPartySharing, &r.UpdatedAt); err != nil {
				return err
			}
			out = append(out, &r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) IssueKillSwitch(ctx context.Context, in KillSwitchInput) (*ksealv1.SignedKillSwitch, error) {
	if in.TenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	if in.Command == ksealv1.KillSwitchCommand_KILL_SWITCH_COMMAND_UNSPECIFIED {
		return nil, fmt.Errorf("%w: command required", ErrInvalidInput)
	}
	sk, err := signingKey(ctx, s.keys, in.TenantID)
	if err != nil {
		return nil, err
	}
	var ks *ksealv1.SignedKillSwitch
	err = s.db.WithTenantTx(ctx, in.TenantID, func(tx pgx.Tx) error {
		// Serialize per-scope version increments so concurrent issues for the same
		// (tenant, app, build) cannot read the same MAX(version) and produce a
		// duplicate, violating the anti-rollback monotonic invariant. Mirrors the
		// advisory lock guarding the audit seq in appendAuditTx; the scope lock is
		// taken first so the lock order (scope -> tenant) is consistent.
		if _, err := tx.Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtext($1 || '\x00' || $2 || '\x00' || $3))`,
			in.TenantID, in.AppID, in.BuildHash); err != nil {
			return err
		}
		var version int64
		if err := tx.QueryRow(ctx,
			`SELECT COALESCE(MAX(version), 0) + 1 FROM kill_switches
			 WHERE tenant_id = $1 AND app_id = $2 AND build_hash = $3`,
			in.TenantID, in.AppID, in.BuildHash).Scan(&version); err != nil {
			return err
		}
		ks = &ksealv1.SignedKillSwitch{
			TenantId:  in.TenantID,
			AppId:     in.AppID,
			BuildHash: in.BuildHash,
			Command:   in.Command,
			Version:   version,
			IssuedAt:  nowMillis(),
			Reason:    in.Reason,
			KeyId:     sk.ID,
		}
		signKillSwitch(sk.Private, ks)
		if _, err := tx.Exec(ctx, `
			INSERT INTO kill_switches
			    (tenant_id, app_id, build_hash, command, version, issued_at_ms, reason, signature, key_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (tenant_id, app_id, build_hash) DO UPDATE SET
			    command = EXCLUDED.command,
			    version = EXCLUDED.version,
			    issued_at_ms = EXCLUDED.issued_at_ms,
			    reason = EXCLUDED.reason,
			    signature = EXCLUDED.signature,
			    key_id = EXCLUDED.key_id,
			    updated_at = now()`,
			ks.TenantId, ks.AppId, ks.BuildHash, int32(ks.Command), ks.Version, ks.IssuedAt, ks.Reason, ks.Signature, ks.KeyId); err != nil {
			return err
		}
		_, err := appendAuditTx(ctx, tx, in.TenantID, killSwitchEntry(in, version))
		return err
	})
	if err != nil {
		return nil, err
	}
	return ks, nil
}

func (s *PostgresStore) ListKillSwitches(ctx context.Context, tenantID string) ([]*ksealv1.SignedKillSwitch, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	var out []*ksealv1.SignedKillSwitch
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tenant_id, app_id, build_hash, command, version, issued_at_ms, reason, signature, key_id
			FROM kill_switches WHERE tenant_id = $1 ORDER BY app_id, build_hash`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			ks, err := scanKillSwitch(rows)
			if err != nil {
				return err
			}
			out = append(out, ks)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) SetCanary(ctx context.Context, in CanaryInput) (*ksealv1.CanaryStatus, error) {
	if in.TenantID == "" || in.AppID == "" {
		return nil, fmt.Errorf("%w: tenant_id and app_id required", ErrInvalidInput)
	}
	if in.CandidatePolicyID == "" {
		return nil, fmt.Errorf("%w: candidate_policy_id required", ErrInvalidInput)
	}
	if in.Percent > 100 {
		return nil, fmt.Errorf("%w: percent must be 0..100", ErrInvalidInput)
	}
	threshold := in.RollbackThreshold
	if threshold <= 0 {
		threshold = DefaultRollbackThreshold
	}
	var cs *ksealv1.CanaryStatus
	err := s.db.WithTenantTx(ctx, in.TenantID, func(tx pgx.Tx) error {
		updated := nowMillis()
		lastEvent := fmt.Sprintf("rollout set to %d%%", in.Percent)
		// A caller-supplied stable (the current active policy) always wins so
		// re-canarying after a rollback targets the new active policy; only fall
		// back to the previously recorded last-known-good when the caller could
		// not resolve one (empty).
		if _, err := tx.Exec(ctx, `
			INSERT INTO canary_rollouts
			    (tenant_id, app_id, candidate_policy_id, stable_policy_id, percent, state, rollback_threshold, last_event, updated_at_ms)
			VALUES ($1,$2,$3,$4,$5,1,$6,$7,$8)
			ON CONFLICT (tenant_id, app_id) DO UPDATE SET
			    candidate_policy_id = EXCLUDED.candidate_policy_id,
			    stable_policy_id = CASE WHEN EXCLUDED.stable_policy_id <> '' THEN EXCLUDED.stable_policy_id ELSE canary_rollouts.stable_policy_id END,
			    percent = EXCLUDED.percent,
			    state = 1,
			    rollback_threshold = EXCLUDED.rollback_threshold,
			    last_event = EXCLUDED.last_event,
			    updated_at_ms = EXCLUDED.updated_at_ms,
			    updated_at = now()`,
			in.TenantID, in.AppID, in.CandidatePolicyID, in.StablePolicyID, int32(in.Percent), threshold, lastEvent, updated); err != nil {
			return err
		}
		if _, err := appendAuditTx(ctx, tx, in.TenantID, canaryEntry("canary.set", in.AppID, in.ActorKeyID, map[string]string{
			"candidate": in.CandidatePolicyID,
			"percent":   strconv.FormatUint(uint64(in.Percent), 10),
		})); err != nil {
			return err
		}
		var e2 error
		cs, e2 = getCanaryTx(ctx, tx, in.TenantID, in.AppID)
		return e2
	})
	if err != nil {
		return nil, err
	}
	return cs, nil
}

func (s *PostgresStore) GetCanary(ctx context.Context, tenantID, appID string) (*ksealv1.CanaryStatus, error) {
	if tenantID == "" || appID == "" {
		return nil, fmt.Errorf("%w: tenant_id and app_id required", ErrInvalidInput)
	}
	var cs *ksealv1.CanaryStatus
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var e2 error
		cs, e2 = getCanaryTx(ctx, tx, tenantID, appID)
		return e2
	})
	if err != nil {
		return nil, err
	}
	return cs, nil
}

func (s *PostgresStore) ListActiveCanaries(ctx context.Context) ([]*ksealv1.CanaryStatus, error) {
	// Cross-tenant background sweep for the auto-rollback controller; runs in
	// the privileged context since it spans every tenant by design.
	var out []*ksealv1.CanaryStatus
	err := s.db.WithAdminTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tenant_id, app_id, candidate_policy_id, stable_policy_id, percent, state, block_rate, sample_count, rollback_threshold, last_event, updated_at_ms
			FROM canary_rollouts WHERE state = 1`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			cs, err := scanCanary(rows)
			if err != nil {
				return err
			}
			out = append(out, cs)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) PromoteCanary(ctx context.Context, tenantID, appID, actorKeyID string) (*ksealv1.CanaryStatus, error) {
	if tenantID == "" || appID == "" {
		return nil, fmt.Errorf("%w: tenant_id and app_id required", ErrInvalidInput)
	}
	var cs *ksealv1.CanaryStatus
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE canary_rollouts SET
			    state = 2, percent = 100, stable_policy_id = candidate_policy_id,
			    last_event = 'promoted to stable', updated_at_ms = $3, updated_at = now()
			WHERE tenant_id = $1 AND app_id = $2`, tenantID, appID, nowMillis())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		cs2, err := getCanaryTx(ctx, tx, tenantID, appID)
		if err != nil {
			return err
		}
		if _, err := appendAuditTx(ctx, tx, tenantID, canaryEntry("canary.promote", appID, actorKeyID, map[string]string{
			"candidate": cs2.CandidatePolicyId,
		})); err != nil {
			return err
		}
		cs = cs2
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cs, nil
}

func (s *PostgresStore) RollbackCanary(ctx context.Context, tenantID, appID, reason, actorKeyID string, obs CanaryObservation) (*ksealv1.CanaryStatus, error) {
	if tenantID == "" || appID == "" {
		return nil, fmt.Errorf("%w: tenant_id and app_id required", ErrInvalidInput)
	}
	var cs *ksealv1.CanaryStatus
	err := s.db.WithTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE canary_rollouts SET
			    state = 3, percent = 0, block_rate = $3, sample_count = $4,
			    last_event = $5, updated_at_ms = $6, updated_at = now()
			WHERE tenant_id = $1 AND app_id = $2`,
			tenantID, appID, obs.BlockRate, obs.SampleCount, rollbackEvent(reason), nowMillis())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		cs2, err := getCanaryTx(ctx, tx, tenantID, appID)
		if err != nil {
			return err
		}
		if _, err := appendAuditTx(ctx, tx, tenantID, canaryEntry("canary.rollback", appID, actorKeyID, map[string]string{
			"reason":     reason,
			"block_rate": strconv.FormatFloat(obs.BlockRate, 'f', 4, 64),
			"stable":     cs2.StablePolicyId,
		})); err != nil {
			return err
		}
		cs = cs2
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cs, nil
}

// ---- scanning helpers ----

func getCanaryTx(ctx context.Context, tx pgx.Tx, tenantID, appID string) (*ksealv1.CanaryStatus, error) {
	row := tx.QueryRow(ctx, `
		SELECT tenant_id, app_id, candidate_policy_id, stable_policy_id, percent, state, block_rate, sample_count, rollback_threshold, last_event, updated_at_ms
		FROM canary_rollouts WHERE tenant_id = $1 AND app_id = $2`, tenantID, appID)
	cs, err := scanCanary(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return cs, err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanAudit(r scanner) (*ksealv1.AuditEvent, error) {
	var ev ksealv1.AuditEvent
	var mdJSON []byte
	if err := r.Scan(&ev.TenantId, &ev.Seq, &ev.Action, &ev.ResourceType, &ev.ResourceId,
		&ev.ActorKeyId, &mdJSON, &ev.PrevHash, &ev.Hash, &ev.CreatedAt); err != nil {
		return nil, err
	}
	if len(mdJSON) > 0 {
		md := map[string]string{}
		if err := json.Unmarshal(mdJSON, &md); err != nil {
			return nil, err
		}
		if len(md) > 0 {
			ev.Metadata = md
		}
	}
	return &ev, nil
}

func scanKillSwitch(r scanner) (*ksealv1.SignedKillSwitch, error) {
	var ks ksealv1.SignedKillSwitch
	var command int32
	if err := r.Scan(&ks.TenantId, &ks.AppId, &ks.BuildHash, &command, &ks.Version,
		&ks.IssuedAt, &ks.Reason, &ks.Signature, &ks.KeyId); err != nil {
		return nil, err
	}
	ks.Command = ksealv1.KillSwitchCommand(command)
	return &ks, nil
}

func scanCanary(r scanner) (*ksealv1.CanaryStatus, error) {
	var cs ksealv1.CanaryStatus
	var state int32
	var percent int32
	if err := r.Scan(&cs.TenantId, &cs.AppId, &cs.CandidatePolicyId, &cs.StablePolicyId,
		&percent, &state, &cs.BlockRate, &cs.SampleCount, &cs.RollbackThreshold, &cs.LastEvent, &cs.UpdatedAt); err != nil {
		return nil, err
	}
	cs.Percent = uint32(percent)
	cs.State = ksealv1.CanaryState(state)
	return &cs, nil
}

func metaOrEmpty(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
