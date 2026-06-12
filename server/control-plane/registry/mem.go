package registry

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/auth"
	"github.com/kennguy3n/kseal/server/shared/crypto"
)

// MemStore is an in-memory Store used by unit tests. It mirrors the Postgres
// store's semantics — tenant isolation, unique constraints, policy versioning
// and activation, API-key hashing, signing-key generation, and atomic sequence
// consumption — without a database.
type MemStore struct {
	mu sync.Mutex

	tenants      map[string]*ksealv1.Tenant
	apps         map[string]*ksealv1.App
	builds       map[string]*ksealv1.Build
	policies     map[string]*ksealv1.Policy
	policyHashes map[string]string
	profiles     map[string]*ksealv1.ProtectionProfile
	apiKeys      map[string]*memAPIKey // keyed by key_id
	signing      map[string]*SigningKey
	webhooks     map[string]*memWebhook
	sessions     map[string]*TrustSession
}

type memAPIKey struct {
	rec        *APIKeyRecord
	secretHash string
}

type memWebhook struct {
	wh     *ksealv1.Webhook
	secret []byte
}

// NewMemStore builds an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		tenants:      map[string]*ksealv1.Tenant{},
		apps:         map[string]*ksealv1.App{},
		builds:       map[string]*ksealv1.Build{},
		policies:     map[string]*ksealv1.Policy{},
		policyHashes: map[string]string{},
		profiles:     map[string]*ksealv1.ProtectionProfile{},
		apiKeys:      map[string]*memAPIKey{},
		signing:      map[string]*SigningKey{},
		webhooks:     map[string]*memWebhook{},
		sessions:     map[string]*TrustSession{},
	}
}

// Close is a no-op.
func (m *MemStore) Close() {}

func newID() string { return uuid.NewString() }

// ---- Tenants ----

func (m *MemStore) CreateTenant(_ context.Context, in CreateTenantInput) (*ksealv1.Tenant, error) {
	if in.Name == "" || in.Slug == "" {
		return nil, fmt.Errorf("%w: name and slug required", ErrInvalidInput)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tenants {
		if t.Slug == in.Slug {
			return nil, fmt.Errorf("%w: slug exists", ErrConflict)
		}
	}
	tier := in.Tier
	if tier == "" {
		tier = "starter"
	}
	now := nowUnix()
	t := &ksealv1.Tenant{Id: newID(), Name: in.Name, Slug: in.Slug, Tier: tier, Status: "active", CreatedAt: now, UpdatedAt: now}
	m.tenants[t.Id] = t
	return cloneTenant(t), nil
}

func (m *MemStore) GetTenant(_ context.Context, id string) (*ksealv1.Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tenants[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneTenant(t), nil
}

func (m *MemStore) ListTenants(_ context.Context, page Page) ([]*ksealv1.Tenant, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []*ksealv1.Tenant
	for _, t := range m.tenants {
		all = append(all, cloneTenant(t))
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].CreatedAt != all[j].CreatedAt {
			return all[i].CreatedAt < all[j].CreatedAt
		}
		return all[i].Id < all[j].Id
	})
	return pageSlice(all, page)
}

func (m *MemStore) UpdateTenant(_ context.Context, in UpdateTenantInput) (*ksealv1.Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tenants[in.ID]
	if !ok {
		return nil, ErrNotFound
	}
	if in.Name != "" {
		t.Name = in.Name
	}
	if in.Tier != "" {
		t.Tier = in.Tier
	}
	if in.Status != "" {
		t.Status = in.Status
	}
	t.UpdatedAt = nowUnix()
	return cloneTenant(t), nil
}

// ---- Apps ----

func (m *MemStore) CreateApp(_ context.Context, in CreateAppInput) (*ksealv1.App, error) {
	if in.TenantID == "" || in.Name == "" || in.PackageID == "" {
		return nil, fmt.Errorf("%w: tenant_id, name, package_id required", ErrInvalidInput)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.apps {
		if a.TenantId == in.TenantID && a.Platform == in.Platform && a.PackageId == in.PackageID {
			return nil, fmt.Errorf("%w: app exists", ErrConflict)
		}
	}
	now := nowUnix()
	identities := append([]string(nil), in.SigningIdentities...)
	if identities == nil {
		identities = []string{}
	}
	a := &ksealv1.App{
		Id: newID(), TenantId: in.TenantID, Name: in.Name, Platform: in.Platform,
		PackageId: in.PackageID, SigningIdentities: identities, Status: "active",
		CreatedAt: now, UpdatedAt: now,
	}
	m.apps[a.Id] = a
	return cloneApp(a), nil
}

func (m *MemStore) GetApp(_ context.Context, tenantID, id string) (*ksealv1.App, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.apps[id]
	if !ok || a.TenantId != tenantID {
		return nil, ErrNotFound
	}
	return cloneApp(a), nil
}

func (m *MemStore) ListApps(_ context.Context, tenantID string, page Page) ([]*ksealv1.App, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []*ksealv1.App
	for _, a := range m.apps {
		if a.TenantId == tenantID {
			all = append(all, cloneApp(a))
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].CreatedAt != all[j].CreatedAt {
			return all[i].CreatedAt < all[j].CreatedAt
		}
		return all[i].Id < all[j].Id
	})
	return pageSlice(all, page)
}

// ---- Builds ----

func (m *MemStore) CreateBuild(_ context.Context, in CreateBuildInput) (*ksealv1.Build, error) {
	if in.TenantID == "" || in.AppID == "" || in.BuildHash == "" {
		return nil, fmt.Errorf("%w: tenant_id, app_id, build_hash required", ErrInvalidInput)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.builds {
		if b.TenantId == in.TenantID && b.BuildHash == in.BuildHash {
			return nil, fmt.Errorf("%w: build exists", ErrConflict)
		}
	}
	manifest := in.Manifest
	if strings.TrimSpace(manifest) == "" {
		manifest = "{}"
	}
	b := &ksealv1.Build{
		Id: newID(), TenantId: in.TenantID, AppId: in.AppID, BuildHash: in.BuildHash,
		VersionName: in.VersionName, VersionCode: in.VersionCode,
		ProtectionProfileId: in.ProtectionProfileID, Manifest: manifest, CreatedAt: nowUnix(),
	}
	m.builds[b.Id] = b
	return cloneBuild(b), nil
}

func (m *MemStore) GetBuild(_ context.Context, tenantID, id string) (*ksealv1.Build, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.builds[id]
	if !ok || b.TenantId != tenantID {
		return nil, ErrNotFound
	}
	return cloneBuild(b), nil
}

func (m *MemStore) ListBuilds(_ context.Context, tenantID, appID string, page Page) ([]*ksealv1.Build, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []*ksealv1.Build
	for _, b := range m.builds {
		if b.TenantId == tenantID && (appID == "" || b.AppId == appID) {
			all = append(all, cloneBuild(b))
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].CreatedAt != all[j].CreatedAt {
			return all[i].CreatedAt < all[j].CreatedAt
		}
		return all[i].Id < all[j].Id
	})
	return pageSlice(all, page)
}

// ---- Policies ----

func (m *MemStore) CreatePolicy(_ context.Context, in CreatePolicyInput) (*ksealv1.Policy, error) {
	if in.TenantID == "" || in.Name == "" {
		return nil, fmt.Errorf("%w: tenant_id and name required", ErrInvalidInput)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rules := defaultJSON(in.Rules, "[]")
	thresholds := defaultJSON(in.RiskThresholds, "{}")
	modules := append([]string(nil), in.ModulesEnabled...)
	if modules == nil {
		modules = []string{}
	}
	var version int32 = 1
	for _, p := range m.policies {
		if p.TenantId == in.TenantID && p.AppId == in.AppID && p.Version >= version {
			version = p.Version + 1
		}
	}
	now := nowUnix()
	p := &ksealv1.Policy{
		Id: newID(), TenantId: in.TenantID, AppId: in.AppID, Name: in.Name, Version: version,
		EnforcementMode: in.EnforcementMode, Rules: rules, RiskThresholds: thresholds,
		ModulesEnabled: modules, IsActive: false, CreatedAt: now, UpdatedAt: now,
	}
	m.policies[p.Id] = p
	m.policyHashes[p.Id] = HashPolicy(in.AppID, in.EnforcementMode, rules, thresholds, modules)
	return clonePolicy(p), nil
}

func (m *MemStore) GetActivePolicy(_ context.Context, tenantID, appID string) (*ksealv1.Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var appScoped, tenantWide *ksealv1.Policy
	for _, p := range m.policies {
		if p.TenantId != tenantID || !p.IsActive {
			continue
		}
		if p.AppId == appID {
			appScoped = p
		} else if p.AppId == "" {
			tenantWide = p
		}
	}
	if appScoped != nil {
		return clonePolicy(appScoped), nil
	}
	if tenantWide != nil {
		return clonePolicy(tenantWide), nil
	}
	return nil, ErrNotFound
}

func (m *MemStore) ListPolicies(_ context.Context, tenantID, appID string) ([]*ksealv1.Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*ksealv1.Policy
	for _, p := range m.policies {
		if p.TenantId == tenantID && (appID == "" || p.AppId == appID) {
			out = append(out, clonePolicy(p))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AppId != out[j].AppId {
			return out[i].AppId < out[j].AppId
		}
		return out[i].Version > out[j].Version
	})
	return out, nil
}

func (m *MemStore) ActivatePolicy(_ context.Context, tenantID, id string) (*ksealv1.Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	target, ok := m.policies[id]
	if !ok || target.TenantId != tenantID {
		return nil, ErrNotFound
	}
	for _, p := range m.policies {
		if p.TenantId == tenantID && p.AppId == target.AppId && p.IsActive {
			p.IsActive = false
			p.UpdatedAt = nowUnix()
		}
	}
	target.IsActive = true
	target.UpdatedAt = nowUnix()
	return clonePolicy(target), nil
}

// PolicyHashByID exposes the stored content hash for a policy (used by config
// assembly in tests and tooling).
func (m *MemStore) PolicyHashByID(id string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.policyHashes[id]
}

// ---- Protection profiles ----

func (m *MemStore) CreateProtectionProfile(_ context.Context, in CreateProtectionProfileInput) (*ksealv1.ProtectionProfile, error) {
	if in.TenantID == "" || in.Name == "" {
		return nil, fmt.Errorf("%w: tenant_id and name required", ErrInvalidInput)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, pp := range m.profiles {
		if pp.TenantId == in.TenantID && pp.Name == in.Name {
			return nil, fmt.Errorf("%w: profile exists", ErrConflict)
		}
	}
	mode := in.DefaultMode
	if mode == ksealv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED {
		mode = ksealv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE
	}
	modules := append([]string(nil), in.ModulesEnabled...)
	if modules == nil {
		modules = []string{}
	}
	pp := &ksealv1.ProtectionProfile{Id: newID(), TenantId: in.TenantID, Name: in.Name, ModulesEnabled: modules, DefaultMode: mode, CreatedAt: nowUnix()}
	m.profiles[pp.Id] = pp
	return cloneProfile(pp), nil
}

func (m *MemStore) ListProtectionProfiles(_ context.Context, tenantID string) ([]*ksealv1.ProtectionProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*ksealv1.ProtectionProfile
	for _, pp := range m.profiles {
		if pp.TenantId == tenantID {
			out = append(out, cloneProfile(pp))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

// ---- API keys ----

func (m *MemStore) CreateAPIKey(_ context.Context, tenantID, name string, scopes []string) (string, *APIKeyRecord, error) {
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
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := &APIKeyRecord{ID: newID(), TenantID: tenantID, KeyID: gen.KeyID, Name: name, Scopes: append([]string(nil), scopes...), Status: "active", CreatedAt: nowUnix()}
	m.apiKeys[gen.KeyID] = &memAPIKey{rec: rec, secretHash: gen.Hash}
	return gen.Plaintext, rec, nil
}

func (m *MemStore) ValidateAPIKey(_ context.Context, plaintext string) (*auth.Principal, error) {
	keyID, secret, err := auth.ParseAPIKey(plaintext)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	k, ok := m.apiKeys[keyID]
	m.mu.Unlock()
	if !ok || k.rec.Status != "active" {
		return nil, ErrNotFound
	}
	valid, err := auth.VerifySecret(secret, k.secretHash)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, ErrNotFound
	}
	return &auth.Principal{TenantID: k.rec.TenantID, APIKeyID: keyID, Scopes: append([]string(nil), k.rec.Scopes...)}, nil
}

func (m *MemStore) RevokeAPIKey(_ context.Context, tenantID, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.apiKeys[keyID]
	if !ok || k.rec.TenantID != tenantID || k.rec.Status != "active" {
		return ErrNotFound
	}
	k.rec.Status = "revoked"
	return nil
}

// ---- Signing keys ----

func (m *MemStore) CreateSigningKey(_ context.Context, tenantID string) (*SigningKey, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	kp, err := crypto.GenerateEd25519()
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.signing {
		if k.TenantID == tenantID {
			k.IsActive = false
		}
	}
	sk := &SigningKey{ID: newID(), TenantID: tenantID, Algorithm: "ed25519", Public: kp.Public, Private: kp.Private, IsActive: true, CreatedAt: nowUnix()}
	m.signing[sk.ID] = sk
	return cloneSigningKey(sk), nil
}

func (m *MemStore) GetActiveSigningKey(_ context.Context, tenantID string) (*SigningKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.signing {
		if k.TenantID == tenantID && k.IsActive {
			return cloneSigningKey(k), nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemStore) GetSigningKey(_ context.Context, tenantID, id string) (*SigningKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.signing[id]
	if !ok || k.TenantID != tenantID {
		return nil, ErrNotFound
	}
	return cloneSigningKey(k), nil
}

func (m *MemStore) RotateSigningKey(ctx context.Context, tenantID string) (*SigningKey, error) {
	return m.CreateSigningKey(ctx, tenantID)
}

// ---- Webhooks ----

func (m *MemStore) CreateWebhook(_ context.Context, tenantID, url string, eventTypes []ksealv1.EventType) (*ksealv1.Webhook, error) {
	if tenantID == "" || url == "" {
		return nil, fmt.Errorf("%w: tenant_id and url required", ErrInvalidInput)
	}
	secret, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	idb, _ := crypto.RandomBytes(8)
	m.mu.Lock()
	defer m.mu.Unlock()
	wh := &ksealv1.Webhook{
		Id: newID(), TenantId: tenantID, Url: url,
		EventTypes:   append([]ksealv1.EventType(nil), eventTypes...),
		SigningKeyId: fmt.Sprintf("whk_%x", idb), IsActive: true, CreatedAt: nowUnix(),
	}
	m.webhooks[wh.Id] = &memWebhook{wh: wh, secret: secret}
	return cloneWebhook(wh), nil
}

func (m *MemStore) ListWebhooks(_ context.Context, tenantID string) ([]*ksealv1.Webhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*ksealv1.Webhook
	for _, w := range m.webhooks {
		if w.wh.TenantId == tenantID {
			out = append(out, cloneWebhook(w.wh))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

func (m *MemStore) DeleteWebhook(_ context.Context, tenantID, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.webhooks[id]
	if !ok || w.wh.TenantId != tenantID {
		return false, nil
	}
	delete(m.webhooks, id)
	return true, nil
}

func (m *MemStore) ListWebhooksForEvent(_ context.Context, tenantID string, eventType ksealv1.EventType) ([]WebhookSecret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []WebhookSecret
	for _, w := range m.webhooks {
		if w.wh.TenantId != tenantID || !w.wh.IsActive {
			continue
		}
		if len(w.wh.EventTypes) == 0 || containsEventType(w.wh.EventTypes, eventType) {
			out = append(out, WebhookSecret{Webhook: cloneWebhook(w.wh), Secret: append([]byte(nil), w.secret...)})
		}
	}
	return out, nil
}

// ---- Trust sessions ----

func (m *MemStore) CreateTrustSession(_ context.Context, sess *TrustSession) error {
	if sess.TenantID == "" || sess.TokenID == "" {
		return fmt.Errorf("%w: tenant_id and token_id required", ErrInvalidInput)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *sess
	cp.CapabilityScope = append([]string(nil), sess.CapabilityScope...)
	cp.SessionSecret = append([]byte(nil), sess.SessionSecret...)
	cp.Status = "active"
	m.sessions[sess.TokenID] = &cp
	return nil
}

func (m *MemStore) GetTrustSession(_ context.Context, tokenID string) (*TrustSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[tokenID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *s
	cp.CapabilityScope = append([]string(nil), s.CapabilityScope...)
	cp.SessionSecret = append([]byte(nil), s.SessionSecret...)
	return &cp, nil
}

func (m *MemStore) ConsumeSequence(_ context.Context, tokenID string, seq int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[tokenID]
	if !ok || s.Status != "active" {
		return ErrNotFound
	}
	if seq <= s.LastSequence {
		return ErrReplay
	}
	s.LastSequence = seq
	return nil
}

func (m *MemStore) RevokeTrustSession(_ context.Context, tenantID, tokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[tokenID]
	if !ok || s.TenantID != tenantID {
		return ErrNotFound
	}
	s.Status = "revoked"
	return nil
}

func (m *MemStore) RecordFailedAttestation(_ context.Context, sess *TrustSession) error {
	if sess.TenantID == "" {
		return fmt.Errorf("%w: tenant_id required", ErrInvalidInput)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *sess
	if cp.TokenID == "" {
		cp.TokenID = uuid.NewString()
	}
	cp.CapabilityScope = nil
	cp.SessionSecret = nil
	cp.Status = "failed"
	m.sessions[cp.TokenID] = &cp
	return nil
}

func (m *MemStore) GetTenantCounts(_ context.Context, tenantID string) (*TenantCounts, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := &TenantCounts{}
	for _, a := range m.apps {
		if a.TenantId == tenantID {
			c.Apps++
		}
	}
	for _, b := range m.builds {
		if b.TenantId == tenantID {
			c.Builds++
		}
	}
	for _, p := range m.policies {
		if p.TenantId == tenantID && p.IsActive {
			c.ActivePolicies++
		}
	}
	for _, w := range m.webhooks {
		if w.wh.TenantId == tenantID {
			c.Webhooks++
		}
	}
	return c, nil
}

func (m *MemStore) GetTrustSessionStats(_ context.Context, tenantID string, fromSec, toSec int64) (*TrustSessionStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stats := &TrustSessionStats{ByRiskLevel: map[int32]int64{}}
	for _, s := range m.sessions {
		if s.TenantID != tenantID {
			continue
		}
		if fromSec != 0 && s.IssuedAt < fromSec {
			continue
		}
		if toSec != 0 && s.IssuedAt > toSec {
			continue
		}
		stats.TotalSessions++
		if s.Status == "failed" {
			stats.AttestationsFailed++
			continue
		}
		stats.TokensIssued++
		stats.ByRiskLevel[s.RiskLevel]++
	}
	return stats, nil
}

func containsEventType(types []ksealv1.EventType, t ksealv1.EventType) bool {
	for _, v := range types {
		if v == t {
			return true
		}
	}
	return false
}

func pageSlice[T any](all []T, page Page) ([]T, string, error) {
	size := clampPageSize(page.Size)
	offset, err := decodeOffset(page.Token)
	if err != nil {
		return nil, "", err
	}
	if offset >= len(all) {
		return nil, "", nil
	}
	end := offset + size
	if end >= len(all) {
		return all[offset:], "", nil
	}
	return all[offset:end], encodeOffset(end), nil
}
