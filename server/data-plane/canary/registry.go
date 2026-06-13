package canary

import (
	"sync/atomic"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// Active is the immutable runtime view of one active rollout used for hot-path
// cohort selection. It is a value copy so callers never alias store state.
type Active struct {
	CandidatePolicyID string
	StablePolicyID    string
	Percent           uint32
}

// Registry is a lock-free-read, in-memory snapshot of every active canary,
// refreshed atomically by the controller each sweep. The config and trust hot
// paths consult it with zero database round-trips, so canary cohort selection
// never adds latency to request handling. An empty registry (the default, when
// no controller runs or the feature is off) classifies every instance as
// stable, preserving baseline behavior.
type Registry struct {
	snap atomic.Pointer[map[string]Active]
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	r := &Registry{}
	empty := map[string]Active{}
	r.snap.Store(&empty)
	return r
}

func regKey(tenantID, appID string) string { return tenantID + "\x00" + appID }

// Replace atomically swaps the active-canary snapshot. The controller builds the
// map from the authoritative store each sweep and publishes it here.
func (r *Registry) Replace(canaries []*ksealv1.CanaryStatus) {
	next := make(map[string]Active, len(canaries))
	for _, cs := range canaries {
		if cs.State != ksealv1.CanaryState_CANARY_STATE_ACTIVE {
			continue
		}
		next[regKey(cs.TenantId, cs.AppId)] = Active{
			CandidatePolicyID: cs.CandidatePolicyId,
			StablePolicyID:    cs.StablePolicyId,
			Percent:           cs.Percent,
		}
	}
	r.snap.Store(&next)
}

// Lookup returns the active rollout for a scope, if any.
func (r *Registry) Lookup(tenantID, appID string) (Active, bool) {
	m := *r.snap.Load()
	a, ok := m[regKey(tenantID, appID)]
	return a, ok
}

// Cohort classifies an instance for a scope into the policy id it should run and
// whether it is in the candidate cohort. When no rollout is active it returns
// ("", false) so the caller keeps its default (active) policy.
func (r *Registry) Cohort(tenantID, appID, instanceID string) (policyID string, candidate bool) {
	a, ok := r.Lookup(tenantID, appID)
	if !ok {
		return "", false
	}
	if InCanary(tenantID, appID, instanceID, a.Percent) {
		return a.CandidatePolicyID, true
	}
	return a.StablePolicyID, false
}
