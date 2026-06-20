package compliance

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/kennguy3n/kseal/server/control-plane/registry"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// DefaultRollbackThreshold is the candidate block-rate above which a canary is
// auto-rolled-back when no explicit threshold is configured. It mirrors the
// guardrails detector default so the observe path and the rollback path agree.
const DefaultRollbackThreshold = 0.05

// MemStore is the in-memory compliance Store for unit tests. It mirrors the
// Postgres store's semantics — per-tenant audit chaining, scoped kill-switch
// versioning, data-processing upserts, and canary transitions — without a
// database.
type MemStore struct {
	keys KeySource

	mu       sync.Mutex
	audit    map[string][]*ksealv1.AuditEvent         // tenant -> events (ordered)
	dataProc map[string]*ksealv1.DataProcessingRecord // tenant|app -> record
	killSw   map[string]*ksealv1.SignedKillSwitch     // tenant|app|build -> switch
	canaries map[string]*ksealv1.CanaryStatus         // tenant|app -> status
}

// NewMemStore builds an empty in-memory compliance store. keys supplies the
// per-tenant signing key used to sign kill switches.
func NewMemStore(keys KeySource) *MemStore {
	return &MemStore{
		keys:     keys,
		audit:    map[string][]*ksealv1.AuditEvent{},
		dataProc: map[string]*ksealv1.DataProcessingRecord{},
		killSw:   map[string]*ksealv1.SignedKillSwitch{},
		canaries: map[string]*ksealv1.CanaryStatus{},
	}
}

func scopeKey(parts ...string) string {
	return parts[0] + "\x00" + parts[1] + "\x00" + parts[2]
}

func nowMillis() int64 { return time.Now().UnixMilli() }

// appendLocked appends an event to the tenant chain. The caller holds s.mu.
func (s *MemStore) appendLocked(tenantID string, e Entry) (*ksealv1.AuditEvent, error) {
	if err := validateEntry(e); err != nil {
		return nil, err
	}
	chain := s.audit[tenantID]
	prevHash := ""
	if n := len(chain); n > 0 {
		prevHash = chain[n-1].Hash
	}
	seq := int64(len(chain) + 1)
	created := nowMillis()
	ev := &ksealv1.AuditEvent{
		TenantId:     tenantID,
		Seq:          seq,
		Action:       e.Action,
		ResourceType: e.ResourceType,
		ResourceId:   e.ResourceID,
		ActorKeyId:   e.ActorKeyID,
		Metadata:     cloneMeta(e.Metadata),
		PrevHash:     prevHash,
		Hash:         hashAuditEvent(tenantID, seq, e, created, prevHash),
		CreatedAt:    created,
	}
	s.audit[tenantID] = append(chain, ev)
	return ev, nil
}

func (s *MemStore) AppendAudit(_ context.Context, tenantID string, e Entry) (*ksealv1.AuditEvent, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ev, err := s.appendLocked(tenantID, e)
	if err != nil {
		return nil, err
	}
	return cloneAudit(ev), nil
}

func (s *MemStore) ListAudit(_ context.Context, tenantID string, f AuditFilter, pageSize int, pageToken string) ([]*ksealv1.AuditEvent, string, error) {
	if tenantID == "" {
		return nil, "", fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	size := clampPageSize(pageSize)
	// Keyset cursor is the seq to read strictly below (newest-first paging).
	cursor := int64(-1)
	if pageToken != "" {
		v, err := strconv.ParseInt(pageToken, 10, 64)
		if err != nil {
			return nil, "", ErrInvalidInput
		}
		cursor = v
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.audit[tenantID]
	out := make([]*ksealv1.AuditEvent, 0, size)
	next := ""
	for i := len(chain) - 1; i >= 0; i-- {
		ev := chain[i]
		if cursor >= 0 && ev.Seq >= cursor {
			continue
		}
		if !matchAuditFilter(ev, f) {
			continue
		}
		if len(out) == size {
			// A further matching event exists beyond this full page, so emit a
			// cursor. When the chain is exhausted at exactly `size` items this
			// branch never runs and next stays empty — no trailing empty page.
			next = strconv.FormatInt(out[len(out)-1].Seq, 10)
			break
		}
		out = append(out, cloneAudit(ev))
	}
	return out, next, nil
}

func (s *MemStore) VerifyAudit(_ context.Context, tenantID string) (VerifyResult, error) {
	if tenantID == "" {
		return VerifyResult{}, fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return recompute(tenantID, s.audit[tenantID]), nil
}

func (s *MemStore) PutDataProcessing(_ context.Context, in DataProcessingInput) (*ksealv1.DataProcessingRecord, error) {
	normalized, err := normalizeDataProcessingInput(in)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := &ksealv1.DataProcessingRecord{
		TenantId:          normalized.TenantID,
		AppId:             normalized.AppID,
		DataCategories:    append([]string(nil), normalized.DataCategories...),
		Purpose:           normalized.Purpose,
		RetentionDays:     normalized.RetentionDays,
		LegalBasis:        normalized.LegalBasis,
		ThirdPartySharing: normalized.ThirdPartySharing,
		UpdatedAt:         nowMillis(),
	}
	s.dataProc[scopeKey(normalized.TenantID, normalized.AppID, "")] = rec
	return cloneDataProc(rec), nil
}

func (s *MemStore) ListDataProcessing(_ context.Context, tenantID string) ([]*ksealv1.DataProcessingRecord, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*ksealv1.DataProcessingRecord
	for _, r := range s.dataProc {
		if r.TenantId == tenantID {
			out = append(out, cloneDataProc(r))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AppId < out[j].AppId })
	return out, nil
}

func (s *MemStore) IssueKillSwitch(ctx context.Context, in KillSwitchInput) (*ksealv1.SignedKillSwitch, error) {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scopeKey(in.TenantID, in.AppID, in.BuildHash)
	version := int64(1)
	if prev, ok := s.killSw[key]; ok {
		version = prev.Version + 1
	}
	ks := &ksealv1.SignedKillSwitch{
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
	s.killSw[key] = ks
	if _, err := s.appendLocked(in.TenantID, killSwitchEntry(in, version)); err != nil {
		return nil, err
	}
	return cloneKillSwitch(ks), nil
}

func (s *MemStore) ListKillSwitches(_ context.Context, tenantID string) ([]*ksealv1.SignedKillSwitch, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*ksealv1.SignedKillSwitch
	for _, ks := range s.killSw {
		if ks.TenantId == tenantID {
			out = append(out, cloneKillSwitch(ks))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AppId != out[j].AppId {
			return out[i].AppId < out[j].AppId
		}
		return out[i].BuildHash < out[j].BuildHash
	})
	return out, nil
}

func (s *MemStore) SetCanary(_ context.Context, in CanaryInput) (*ksealv1.CanaryStatus, error) {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scopeKey(in.TenantID, in.AppID, "")
	cs := &ksealv1.CanaryStatus{
		TenantId:          in.TenantID,
		AppId:             in.AppID,
		CandidatePolicyId: in.CandidatePolicyID,
		StablePolicyId:    in.StablePolicyID,
		Percent:           in.Percent,
		State:             ksealv1.CanaryState_CANARY_STATE_ACTIVE,
		RollbackThreshold: threshold,
		LastEvent:         fmt.Sprintf("rollout set to %d%%", in.Percent),
		UpdatedAt:         nowMillis(),
	}
	if cs.StablePolicyId == "" {
		// Only fall back to the previously recorded stable when the caller could
		// not resolve a current active policy; a caller-supplied stable always
		// wins so re-canarying after a rollback targets the new active policy,
		// not a stale one.
		if prev, ok := s.canaries[key]; ok && prev.StablePolicyId != "" {
			cs.StablePolicyId = prev.StablePolicyId
		}
	}
	s.canaries[key] = cs
	if _, err := s.appendLocked(in.TenantID, canaryEntry("canary.set", in.AppID, in.ActorKeyID, map[string]string{
		"candidate": in.CandidatePolicyID,
		"percent":   strconv.FormatUint(uint64(in.Percent), 10),
	})); err != nil {
		return nil, err
	}
	return cloneCanary(cs), nil
}

func (s *MemStore) GetCanary(_ context.Context, tenantID, appID string) (*ksealv1.CanaryStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, ok := s.canaries[scopeKey(tenantID, appID, "")]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneCanary(cs), nil
}

func (s *MemStore) ListActiveCanaries(_ context.Context) ([]*ksealv1.CanaryStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*ksealv1.CanaryStatus
	for _, cs := range s.canaries {
		if cs.State == ksealv1.CanaryState_CANARY_STATE_ACTIVE {
			out = append(out, cloneCanary(cs))
		}
	}
	return out, nil
}

func (s *MemStore) PromoteCanary(_ context.Context, tenantID, appID, actorKeyID string) (*ksealv1.CanaryStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, ok := s.canaries[scopeKey(tenantID, appID, "")]
	if !ok {
		return nil, ErrNotFound
	}
	cs.State = ksealv1.CanaryState_CANARY_STATE_PROMOTED
	cs.Percent = 100
	cs.StablePolicyId = cs.CandidatePolicyId
	cs.LastEvent = "promoted to stable"
	cs.UpdatedAt = nowMillis()
	if _, err := s.appendLocked(tenantID, canaryEntry("canary.promote", appID, actorKeyID, map[string]string{
		"candidate": cs.CandidatePolicyId,
	})); err != nil {
		return nil, err
	}
	return cloneCanary(cs), nil
}

func (s *MemStore) RollbackCanary(_ context.Context, tenantID, appID, reason, actorKeyID string, obs CanaryObservation) (*ksealv1.CanaryStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, ok := s.canaries[scopeKey(tenantID, appID, "")]
	if !ok {
		return nil, ErrNotFound
	}
	cs.State = ksealv1.CanaryState_CANARY_STATE_ROLLED_BACK
	cs.Percent = 0
	cs.BlockRate = obs.BlockRate
	cs.SampleCount = obs.SampleCount
	cs.LastEvent = rollbackEvent(reason)
	cs.UpdatedAt = nowMillis()
	if _, err := s.appendLocked(tenantID, canaryEntry("canary.rollback", appID, actorKeyID, map[string]string{
		"reason":     reason,
		"block_rate": strconv.FormatFloat(obs.BlockRate, 'f', 4, 64),
		"stable":     cs.StablePolicyId,
	})); err != nil {
		return nil, err
	}
	return cloneCanary(cs), nil
}

// signingKey fetches the tenant's active signing key, creating one on first use
// (mirrors the config signer). Returned key includes the private material used
// to sign the kill switch.
func signingKey(ctx context.Context, keys KeySource, tenantID string) (*registry.SigningKey, error) {
	if keys == nil {
		return nil, errors.New("compliance: no key source configured")
	}
	sk, err := keys.GetActiveSigningKey(ctx, tenantID)
	if errors.Is(err, registry.ErrNotFound) {
		sk, err = keys.CreateSigningKey(ctx, tenantID)
	}
	if err != nil {
		return nil, err
	}
	return sk, nil
}
