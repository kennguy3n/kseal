package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanTenant(r rowScanner, t *ksealv1.Tenant) error {
	return r.Scan(&t.Id, &t.Name, &t.Slug, &t.Tier, &t.Status, &t.CreatedAt, &t.UpdatedAt)
}

func scanApp(r rowScanner, a *ksealv1.App) error {
	var platform int32
	if err := r.Scan(&a.Id, &a.TenantId, &a.Name, &platform, &a.PackageId, &a.SigningIdentities, &a.Status, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return err
	}
	a.Platform = ksealv1.Platform(platform)
	return nil
}

func scanBuild(r rowScanner, b *ksealv1.Build) error {
	return r.Scan(&b.Id, &b.TenantId, &b.AppId, &b.BuildHash, &b.VersionName, &b.VersionCode, &b.ProtectionProfileId, &b.Manifest, &b.CreatedAt)
}

func scanPolicy(r rowScanner, p *ksealv1.Policy) error {
	var mode int32
	if err := r.Scan(&p.Id, &p.TenantId, &p.AppId, &p.Name, &p.Version, &mode, &p.Rules, &p.RiskThresholds, &p.ModulesEnabled, &p.IsActive, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return err
	}
	p.EnforcementMode = ksealv1.EnforcementMode(mode)
	return nil
}

func scanProfile(r rowScanner, pp *ksealv1.ProtectionProfile) error {
	var mode int32
	if err := r.Scan(&pp.Id, &pp.TenantId, &pp.Name, &pp.ModulesEnabled, &mode, &pp.CreatedAt); err != nil {
		return err
	}
	pp.DefaultMode = ksealv1.EnforcementMode(mode)
	return nil
}

func eventTypesToInts(types []ksealv1.EventType) []int32 {
	out := make([]int32, 0, len(types))
	for _, t := range types {
		out = append(out, int32(t))
	}
	return out
}

func intsToEventTypes(vals []int32) []ksealv1.EventType {
	out := make([]ksealv1.EventType, 0, len(vals))
	for _, v := range vals {
		out = append(out, ksealv1.EventType(v))
	}
	return out
}

// paginate trims an over-fetched page (size+1) and computes the next offset
// token. Returning the (size+1)th row signals more pages remain.
func paginate[T any](items []T, size, offset int) ([]T, string, error) {
	if len(items) > size {
		return items[:size], encodeOffset(offset + size), nil
	}
	return items, "", nil
}

// HashPolicy computes a stable content hash over the policy-defining fields. The
// same hash is embedded in the signed config so the device and server agree on
// exactly which policy is in force.
func HashPolicy(appID string, mode ksealv1.EnforcementMode, rules, thresholds string, modules []string) string {
	mods := append([]string(nil), modules...)
	sort.Strings(mods)
	h := sha256.New()
	h.Write([]byte(appID))
	h.Write([]byte{0})
	h.Write([]byte(mode.String()))
	h.Write([]byte{0})
	h.Write([]byte(rules))
	h.Write([]byte{0})
	h.Write([]byte(thresholds))
	h.Write([]byte{0})
	h.Write([]byte(strings.Join(mods, ",")))
	return hex.EncodeToString(h.Sum(nil))
}
