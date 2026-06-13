package cli

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
)

// packFiles holds the curated vertical policy packs as embedded data. Packs are
// pure client-side defaults: applying one composes an ordinary CreatePolicy
// request (no dedicated server RPC), so the four bundled verticals can evolve
// by editing these JSON files alone.
//
//go:embed packs_data/*.json
var packFiles embed.FS

// PolicyPack is a curated, vertical-specific policy default. It is the on-disk
// (embedded) authoring shape: enforcement mode, the enabled module set, the
// per-TrustLevel score thresholds, and per-signal weights keyed by risk-bit
// index ("0".."63"). It composes into a Policy via the existing CreatePolicy
// RPC; scoring (weights+thresholds+mode) mirrors the server's risk package so a
// pack behaves identically to a hand-authored policy.
type PolicyPack struct {
	ID              string            `json:"id"`
	Vertical        string            `json:"vertical"`
	Name            string            `json:"name"`
	Description     string            `json:"description"`
	EnforcementMode string            `json:"enforcement_mode"`
	ModulesEnabled  []string          `json:"modules_enabled"`
	RiskThresholds  map[string]uint32 `json:"risk_thresholds"`
	// SignalWeights maps a risk-bit index (as a base-10 string in 0..63) to a
	// severity weight, matching the policy authoring document's signal_weights.
	SignalWeights map[string]uint32 `json:"signal_weights"`
}

// loadPacks decodes and validates every embedded pack, returning them sorted by
// id for stable output. A malformed or invalid embedded pack is a build-time
// defect, so it surfaces as an error rather than being silently skipped.
func loadPacks() ([]PolicyPack, error) {
	entries, err := packFiles.ReadDir("packs_data")
	if err != nil {
		return nil, fmt.Errorf("read embedded packs: %w", err)
	}
	packs := make([]PolicyPack, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, rerr := packFiles.ReadFile("packs_data/" + e.Name())
		if rerr != nil {
			return nil, fmt.Errorf("read pack %s: %w", e.Name(), rerr)
		}
		var p PolicyPack
		if jerr := json.Unmarshal(data, &p); jerr != nil {
			return nil, fmt.Errorf("parse pack %s: %w", e.Name(), jerr)
		}
		if problems := p.validate(); len(problems) > 0 {
			return nil, fmt.Errorf("pack %s is invalid: %s", e.Name(), strings.Join(problems, "; "))
		}
		packs = append(packs, p)
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].ID < packs[j].ID })
	return packs, nil
}

// findPack returns the pack with the given id (case-insensitive).
func findPack(id string) (PolicyPack, error) {
	packs, err := loadPacks()
	if err != nil {
		return PolicyPack{}, err
	}
	want := strings.ToLower(strings.TrimSpace(id))
	for _, p := range packs {
		if strings.ToLower(p.ID) == want {
			return p, nil
		}
	}
	ids := make([]string, 0, len(packs))
	for _, p := range packs {
		ids = append(ids, p.ID)
	}
	return PolicyPack{}, newUsageError("unknown policy pack %q (available: %s)", id, strings.Join(ids, ", "))
}

// validate checks a pack for the same structural invariants the policy authoring
// file enforces, so a composed policy is guaranteed to pass server validation.
func (p PolicyPack) validate() []string {
	var problems []string
	if p.ID == "" {
		problems = append(problems, "id is required")
	}
	if p.Name == "" {
		problems = append(problems, "name is required")
	}
	if _, ok := parseEnforcementMode(p.EnforcementMode); !ok {
		problems = append(problems, fmt.Sprintf("enforcement_mode %q is invalid (want observe|step_up|block)", p.EnforcementMode))
	}
	for name := range p.RiskThresholds {
		if !validLevelNames[name] {
			problems = append(problems, fmt.Sprintf("risk_thresholds key %q is not a valid TrustLevel name", name))
		}
	}
	for k := range p.SignalWeights {
		idx, perr := strconv.ParseUint(k, 10, 32)
		if perr != nil || idx > 63 {
			problems = append(problems, fmt.Sprintf("signal_weights key %q must be a bit index in 0..63", k))
		}
	}
	return problems
}

// toPolicyFile renders the pack as a policy authoring document for the given
// policy name and app scope, reusing the exact JSON shape the server stores and
// `policy author` submits. signal_weights live inside the rules object so the
// scoring tables round-trip through the existing parse path.
func (p PolicyPack) toPolicyFile(name, appID string) (*PolicyFile, error) {
	rules := map[string]any{}
	if len(p.SignalWeights) > 0 {
		rules["signal_weights"] = p.SignalWeights
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		return nil, fmt.Errorf("encode pack rules: %w", err)
	}
	var thresholdsJSON json.RawMessage
	if len(p.RiskThresholds) > 0 {
		b, terr := json.Marshal(p.RiskThresholds)
		if terr != nil {
			return nil, fmt.Errorf("encode pack thresholds: %w", terr)
		}
		thresholdsJSON = b
	}
	pf := &PolicyFile{
		Name:            name,
		AppID:           appID,
		EnforcementMode: p.EnforcementMode,
		Rules:           rulesJSON,
		RiskThresholds:  thresholdsJSON,
		ModulesEnabled:  append([]string(nil), p.ModulesEnabled...),
	}
	return pf, nil
}

// createRequest composes the CreatePolicyRequest for applying this pack to a
// tenant. It validates the composed authoring document so a bad pack can never
// reach the server.
func (p PolicyPack) createRequest(tenant, name, appID string) (*ksealv1.CreatePolicyRequest, error) {
	pf, err := p.toPolicyFile(name, appID)
	if err != nil {
		return nil, err
	}
	if problems := pf.Validate(); len(problems) > 0 {
		return nil, newUsageError("composed policy is invalid:\n  - %s", joinLines(problems))
	}
	mode, _ := parseEnforcementMode(pf.EnforcementMode)
	return &ksealv1.CreatePolicyRequest{
		TenantId:        tenant,
		AppId:           pf.AppID,
		Name:            pf.Name,
		EnforcementMode: mode,
		Rules:           pf.rulesString(),
		RiskThresholds:  pf.thresholdsString(),
		ModulesEnabled:  pf.ModulesEnabled,
	}, nil
}

// defaultPolicyName is the policy name used when applying a pack without an
// explicit --name. It encodes the source pack so applied policies are
// self-describing in the registry.
func (p PolicyPack) defaultPolicyName() string {
	return "pack-" + p.ID
}

// policyShape is the comparable projection of a policy used for pack diffs: the
// enforcement mode, score thresholds (keyed by canonical TrustLevel name),
// per-bit weights, and the enabled module set. Both a stored Policy and a pack
// reduce to this shape so the diff is a pure, deterministic function.
type policyShape struct {
	Mode       ksealv1.EnforcementMode
	Thresholds map[string]uint32
	Weights    map[uint32]uint32
	Modules    []string
}

// canonLevel normalizes a TrustLevel threshold key to its short canonical form
// (e.g. "TRUST_LEVEL_HIGH_RISK" -> "HIGH_RISK") so the two sides of a diff
// compare equal regardless of which alias the stored policy used.
func canonLevel(name string) string {
	return strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(name)), "TRUST_LEVEL_")
}

func canonThresholds(in map[string]uint32) map[string]uint32 {
	out := make(map[string]uint32, len(in))
	for k, v := range in {
		out[canonLevel(k)] = v
	}
	return out
}

// shape builds the comparable projection of this pack.
func (p PolicyPack) shape() (policyShape, error) {
	mode, ok := parseEnforcementMode(p.EnforcementMode)
	if !ok {
		return policyShape{}, fmt.Errorf("invalid enforcement_mode %q", p.EnforcementMode)
	}
	weights := make(map[uint32]uint32, len(p.SignalWeights))
	for k, v := range p.SignalWeights {
		if idx, perr := strconv.ParseUint(k, 10, 32); perr == nil && idx <= 63 {
			weights[uint32(idx)] = v
		}
	}
	return policyShape{
		Mode:       mode,
		Thresholds: canonThresholds(p.RiskThresholds),
		Weights:    weights,
		Modules:    append([]string(nil), p.ModulesEnabled...),
	}, nil
}

// shapeFromPolicy projects a stored Policy into the comparable shape. A nil
// policy (no active policy) yields an empty observe-mode baseline so the diff
// against a pack reads as "everything is new".
func shapeFromPolicy(p *ksealv1.Policy) (policyShape, error) {
	if p == nil {
		return policyShape{
			Mode:       ksealv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE,
			Thresholds: map[string]uint32{},
			Weights:    map[uint32]uint32{},
			Modules:    nil,
		}, nil
	}
	spec, err := specFromPolicy(p)
	if err != nil {
		return policyShape{}, err
	}
	return policyShape{
		Mode:       spec.Mode,
		Thresholds: canonThresholds(spec.Thresholds),
		Weights:    spec.Weights,
		Modules:    append([]string(nil), p.GetModulesEnabled()...),
	}, nil
}

// FieldChange is a single before/after change in a pack diff.
type FieldChange struct {
	Field string `json:"field"`
	From  string `json:"from"`
	To    string `json:"to"`
}

// PackDiff is the structural difference between a tenant's current policy and a
// pack-composed policy: the ordered set of field changes plus a convenience
// flag for "no changes" (used by idempotent bulk apply to skip a tenant).
type PackDiff struct {
	PackID  string        `json:"pack_id"`
	Changes []FieldChange `json:"changes"`
}

// HasChanges reports whether applying the pack would change the current policy.
func (d PackDiff) HasChanges() bool { return len(d.Changes) > 0 }

// diffPolicy computes the ordered field changes from current to candidate. It is
// pure and total over the two shapes; ordering is deterministic (mode, then
// thresholds by level severity, then weights by bit index, then modules) so
// output is stable for golden tests and human review.
func diffPolicy(packID string, current, candidate policyShape) PackDiff {
	diff := PackDiff{PackID: packID}

	if current.Mode != candidate.Mode {
		diff.Changes = append(diff.Changes, FieldChange{
			Field: "enforcement_mode",
			From:  enforcementModeName(current.Mode),
			To:    enforcementModeName(candidate.Mode),
		})
	}

	// Thresholds, ordered by descending severity for readability.
	for _, lvl := range []string{"CRITICAL", "HIGH_RISK", "MEDIUM_RISK", "LOW_RISK", "TRUSTED"} {
		cur, curOK := current.Thresholds[lvl]
		cand, candOK := candidate.Thresholds[lvl]
		if curOK == candOK && cur == cand {
			continue
		}
		diff.Changes = append(diff.Changes, FieldChange{
			Field: "risk_thresholds." + lvl,
			From:  optUintString(cur, curOK),
			To:    optUintString(cand, candOK),
		})
	}

	// Weights, ordered by bit index.
	bitKeys := unionUint32Keys(current.Weights, candidate.Weights)
	for _, bit := range bitKeys {
		cur, curOK := current.Weights[bit]
		cand, candOK := candidate.Weights[bit]
		if curOK == candOK && cur == cand {
			continue
		}
		diff.Changes = append(diff.Changes, FieldChange{
			Field: "signal_weights." + strconv.FormatUint(uint64(bit), 10),
			From:  optUintString(cur, curOK),
			To:    optUintString(cand, candOK),
		})
	}

	// Modules added/removed, each as its own change for clarity.
	added, removed := diffStringSets(current.Modules, candidate.Modules)
	for _, m := range removed {
		diff.Changes = append(diff.Changes, FieldChange{Field: "modules_enabled.-", From: m, To: ""})
	}
	for _, m := range added {
		diff.Changes = append(diff.Changes, FieldChange{Field: "modules_enabled.+", From: "", To: m})
	}
	return diff
}

func enforcementModeName(m ksealv1.EnforcementMode) string {
	switch m {
	case ksealv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE:
		return "observe"
	case ksealv1.EnforcementMode_ENFORCEMENT_MODE_STEP_UP:
		return "step_up"
	case ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK:
		return "block"
	default:
		return "unspecified"
	}
}

func optUintString(v uint32, present bool) string {
	if !present {
		return "—"
	}
	return strconv.FormatUint(uint64(v), 10)
}

// unionUint32Keys returns the sorted union of the keys of two maps.
func unionUint32Keys(a, b map[uint32]uint32) []uint32 {
	seen := map[uint32]struct{}{}
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	keys := make([]uint32, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

// diffStringSets returns the elements added in next and removed from prev, each
// sorted, treating the inputs as sets (duplicates collapse).
func diffStringSets(prev, next []string) (added, removed []string) {
	prevSet := map[string]struct{}{}
	for _, s := range prev {
		prevSet[s] = struct{}{}
	}
	nextSet := map[string]struct{}{}
	for _, s := range next {
		nextSet[s] = struct{}{}
	}
	for s := range nextSet {
		if _, ok := prevSet[s]; !ok {
			added = append(added, s)
		}
	}
	for s := range prevSet {
		if _, ok := nextSet[s]; !ok {
			removed = append(removed, s)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}
