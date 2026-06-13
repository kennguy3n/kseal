package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/risk"
)

// PolicyFile is the authoring document for `policy author`, `policy validate`,
// and the candidate side of `policy simulate`. It maps 1:1 to a
// CreatePolicyRequest. `rules` and `risk_thresholds` are kept as raw JSON so the
// file mirrors exactly what the server stores and the dashboard renders, and so
// the authoring schema can evolve without a CLI change.
type PolicyFile struct {
	Name string `json:"name"`
	// AppID is optional; empty means a tenant-wide default policy.
	AppID string `json:"app_id,omitempty"`
	// EnforcementMode is observe | step_up | block.
	EnforcementMode string `json:"enforcement_mode"`
	// Rules is the policy rules document (object form with optional
	// signal_weights, or a bare array of rules).
	Rules json.RawMessage `json:"rules,omitempty"`
	// RiskThresholds maps a TrustLevel name (e.g. "HIGH_RISK") to its minimum
	// fused score.
	RiskThresholds json.RawMessage `json:"risk_thresholds,omitempty"`
	ModulesEnabled []string        `json:"modules_enabled,omitempty"`
}

// policyDoc mirrors the server's authoring JSON in server/data-plane/config.
// Both the object form ({"rules":[...],"signal_weights":{...}}) and the bare
// array form ([{rule}, ...]) are accepted.
type policyDoc struct {
	Rules         []ruleDoc         `json:"rules"`
	SignalWeights map[string]uint32 `json:"signal_weights"`
}

type ruleDoc struct {
	ID          string `json:"id"`
	RiskMask    uint64 `json:"risk_mask"`
	MinScore    uint32 `json:"min_score"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

// parseEnforcementMode converts an authoring string to the proto enum.
func parseEnforcementMode(s string) (ksealv1.EnforcementMode, bool) {
	switch s {
	case "observe", "OBSERVE", "ENFORCEMENT_MODE_OBSERVE":
		return ksealv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE, true
	case "step_up", "STEP_UP", "ENFORCEMENT_MODE_STEP_UP":
		return ksealv1.EnforcementMode_ENFORCEMENT_MODE_STEP_UP, true
	case "block", "BLOCK", "ENFORCEMENT_MODE_BLOCK":
		return ksealv1.EnforcementMode_ENFORCEMENT_MODE_BLOCK, true
	default:
		return ksealv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED, false
	}
}

// validLevelNames is the set of TrustLevel names accepted in risk_thresholds.
var validLevelNames = map[string]bool{
	"TRUSTED": true, "TRUST_LEVEL_TRUSTED": true,
	"LOW_RISK": true, "TRUST_LEVEL_LOW_RISK": true,
	"MEDIUM_RISK": true, "TRUST_LEVEL_MEDIUM_RISK": true,
	"HIGH_RISK": true, "TRUST_LEVEL_HIGH_RISK": true,
	"CRITICAL": true, "TRUST_LEVEL_CRITICAL": true,
}

// parsePolicyDoc accepts both the object and array forms, matching the server.
func parsePolicyDoc(rules []byte) (policyDoc, error) {
	var doc policyDoc
	if len(rules) == 0 {
		return doc, nil
	}
	// Object form: {"rules":[...],"signal_weights":{...}}. A JSON array or
	// scalar cannot unmarshal into the struct, so a nil error here reliably
	// means the input was a JSON object (or null) — including an empty "{}",
	// which is a valid rule-less document (e.g. a policy authored by the
	// dashboard or another client). It must not be rejected as malformed.
	if err := json.Unmarshal(rules, &doc); err == nil {
		return doc, nil
	}
	// Bare-array form: [{rule}, ...].
	var arr []ruleDoc
	if err := json.Unmarshal(rules, &arr); err != nil {
		return doc, fmt.Errorf("rules must be a rules object or an array of rules: %w", err)
	}
	doc.Rules = arr
	return doc, nil
}

// Validate checks the policy file for structural and semantic correctness,
// returning all problems found (not just the first) so an author can fix them
// in one pass.
func (pf *PolicyFile) Validate() []string {
	var problems []string
	if pf.Name == "" {
		problems = append(problems, "name is required")
	}
	if _, ok := parseEnforcementMode(pf.EnforcementMode); !ok {
		problems = append(problems, fmt.Sprintf("enforcement_mode %q is invalid (want observe|step_up|block)", pf.EnforcementMode))
	}
	doc, err := parsePolicyDoc(pf.Rules)
	if err != nil {
		problems = append(problems, err.Error())
	} else {
		for i, r := range doc.Rules {
			if r.Action != "" {
				if _, ok := parseEnforcementMode(r.Action); !ok {
					problems = append(problems, fmt.Sprintf("rules[%d] (id=%q) action %q is invalid", i, r.ID, r.Action))
				}
			}
		}
		for k := range doc.SignalWeights {
			idx, perr := strconv.ParseUint(k, 10, 32)
			if perr != nil || idx > 63 {
				problems = append(problems, fmt.Sprintf("signal_weights key %q must be a bit index in 0..63", k))
			}
		}
	}
	if th, perr := pf.thresholds(); perr != nil {
		problems = append(problems, perr.Error())
	} else {
		for name := range th {
			if !validLevelNames[name] {
				problems = append(problems, fmt.Sprintf("risk_thresholds key %q is not a valid TrustLevel name", name))
			}
		}
	}
	return problems
}

// thresholds parses the risk_thresholds JSON into a name->min-score map.
func (pf *PolicyFile) thresholds() (map[string]uint32, error) {
	th := map[string]uint32{}
	if len(pf.RiskThresholds) == 0 {
		return th, nil
	}
	if err := json.Unmarshal(pf.RiskThresholds, &th); err != nil {
		return nil, fmt.Errorf("risk_thresholds must be a map of level name to score: %w", err)
	}
	return th, nil
}

// rulesString returns the canonical JSON string stored in Policy.rules.
func (pf *PolicyFile) rulesString() string {
	if len(pf.Rules) == 0 {
		return ""
	}
	return string(pf.Rules)
}

// thresholdsString returns the canonical JSON string stored in
// Policy.risk_thresholds.
func (pf *PolicyFile) thresholdsString() string {
	if len(pf.RiskThresholds) == 0 {
		return ""
	}
	return string(pf.RiskThresholds)
}

// scoringTables parses the weights and thresholds used for risk scoring,
// independent of enforcement mode. Both `spec` (authoring) and `specFromPolicy`
// (stored) share this so the two paths can never diverge.
func (pf *PolicyFile) scoringTables() (weights map[uint32]uint32, thresholds map[string]uint32, err error) {
	doc, err := parsePolicyDoc(pf.Rules)
	if err != nil {
		return nil, nil, err
	}
	weights = map[uint32]uint32{}
	for k, v := range doc.SignalWeights {
		if idx, perr := strconv.ParseUint(k, 10, 32); perr == nil && idx <= 63 {
			weights[uint32(idx)] = v
		}
	}
	thresholds, err = pf.thresholds()
	if err != nil {
		return nil, nil, err
	}
	return weights, thresholds, nil
}

// spec builds the scoring spec (weights/thresholds/mode) for the simulator,
// using the exact mapping the server's config service applies.
func (pf *PolicyFile) spec() (PolicySpec, error) {
	mode, ok := parseEnforcementMode(pf.EnforcementMode)
	if !ok {
		return PolicySpec{}, fmt.Errorf("invalid enforcement_mode %q", pf.EnforcementMode)
	}
	weights, th, err := pf.scoringTables()
	if err != nil {
		return PolicySpec{}, err
	}
	return PolicySpec{Thresholds: th, Weights: weights, Mode: mode}, nil
}

// PolicySpec is the minimal scoring configuration needed to evaluate decisions.
// It mirrors simulator.PolicySpec; the diff is computed here (client-side) over
// events fetched from QueryService, reusing the server's authoritative risk
// scoring helpers so decisions match production exactly.
type PolicySpec struct {
	Thresholds map[string]uint32
	Weights    map[uint32]uint32
	Mode       ksealv1.EnforcementMode
}

// specFromPolicy builds a PolicySpec from a stored Policy (the active one). It
// takes the enforcement mode directly from the proto rather than re-parsing a
// string, so a stored UNSPECIFIED mode is preserved (and scored exactly as the
// server would) instead of being rejected.
func specFromPolicy(p *ksealv1.Policy) (PolicySpec, error) {
	if p == nil {
		// No active policy: a permissive OBSERVE baseline (ALLOW for every
		// level), consistent with the simulate fallback. The zero-value mode
		// (UNSPECIFIED) would instead DENY/STEP_UP and is not permissive.
		return PolicySpec{
			Thresholds: map[string]uint32{},
			Weights:    map[uint32]uint32{},
			Mode:       ksealv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE,
		}, nil
	}
	pf := &PolicyFile{
		Rules:          json.RawMessage(p.GetRules()),
		RiskThresholds: json.RawMessage(p.GetRiskThresholds()),
	}
	weights, th, err := pf.scoringTables()
	if err != nil {
		return PolicySpec{}, err
	}
	return PolicySpec{Thresholds: th, Weights: weights, Mode: p.GetEnforcementMode()}, nil
}

// decide reproduces the server decision pipeline for a packed risk bitset.
func (s PolicySpec) decide(bits uint64) ksealv1.RequestProofResult_Decision {
	score := risk.Score(bits, s.Weights)
	level := risk.Level(score, s.Thresholds)
	return risk.Decision(level, s.Mode)
}

// DiffReport summarizes how decisions shift between current and candidate
// policies over a set of historical events.
type DiffReport struct {
	Total           int            `json:"total"`
	CurrentCounts   map[string]int `json:"current_counts"`
	CandidateCounts map[string]int `json:"candidate_counts"`
	Changed         int            `json:"changed"`
	NewlyBlocked    int            `json:"newly_blocked"`
	NewlyAllowed    int            `json:"newly_allowed"`
}

// simulate diffs decisions for the given risk bitsets under current vs.
// candidate policies.
func simulate(bitsets []uint64, current, candidate PolicySpec) DiffReport {
	rep := DiffReport{
		CurrentCounts:   map[string]int{},
		CandidateCounts: map[string]int{},
	}
	for _, bits := range bitsets {
		cur := current.decide(bits)
		cand := candidate.decide(bits)
		rep.Total++
		rep.CurrentCounts[decisionName(cur)]++
		rep.CandidateCounts[decisionName(cand)]++
		if cur != cand {
			rep.Changed++
			if isBlock(cand) && !isBlock(cur) {
				rep.NewlyBlocked++
			}
			if !isBlock(cand) && isBlock(cur) {
				rep.NewlyAllowed++
			}
		}
	}
	return rep
}

func isBlock(d ksealv1.RequestProofResult_Decision) bool {
	return d == ksealv1.RequestProofResult_DECISION_DENY
}

func decisionName(d ksealv1.RequestProofResult_Decision) string {
	switch d {
	case ksealv1.RequestProofResult_DECISION_ALLOW:
		return "ALLOW"
	case ksealv1.RequestProofResult_DECISION_STEP_UP:
		return "STEP_UP"
	case ksealv1.RequestProofResult_DECISION_DENY:
		return "DENY"
	default:
		return "UNSPECIFIED"
	}
}

// sortedCountRows renders a decision-count map as deterministic table rows.
func sortedCountRows(counts map[string]int) [][]string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := make([][]string, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, []string{k, strconv.Itoa(counts[k])})
	}
	return rows
}
