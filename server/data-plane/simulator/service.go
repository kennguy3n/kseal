// Package simulator replays recorded telemetry against a candidate policy and
// reports how decisions would change versus the current policy. It powers safe
// policy rollout ("what would this policy have done last week?").
package simulator

import (
	"context"

	"github.com/kennguy3n/kseal/server/data-plane/ingest"
	ksealv1 "github.com/kennguy3n/kseal/server/gen/kseal/v1"
	"github.com/kennguy3n/kseal/server/shared/risk"
)

// PolicySpec is the minimal scoring configuration needed to evaluate decisions.
type PolicySpec struct {
	Thresholds map[string]uint32
	Weights    map[uint32]uint32
	Mode       ksealv1.EnforcementMode
}

// DiffReport summarizes decision changes between current and candidate policies.
type DiffReport struct {
	Total           int
	CurrentCounts   map[ksealv1.RequestProofResult_Decision]int
	CandidateCounts map[ksealv1.RequestProofResult_Decision]int
	// Changed counts events whose decision differs under the candidate.
	Changed int
	// NewlyBlocked / NewlyAllowed quantify the most operationally important shifts.
	NewlyBlocked int
	NewlyAllowed int
}

// Simulator replays events from an analytics store.
type Simulator struct {
	store ingest.AnalyticsStore
}

// New builds a simulator over the analytics store.
func New(store ingest.AnalyticsStore) *Simulator { return &Simulator{store: store} }

// Simulate replays the tenant/app events in [from,to] and diffs decisions.
func (s *Simulator) Simulate(ctx context.Context, tenantID, appID string, from, to int64, current, candidate PolicySpec) (*DiffReport, error) {
	events, err := s.store.Query(ctx, ingest.Query{TenantID: tenantID, AppID: appID, From: from, To: to})
	if err != nil {
		return nil, err
	}
	report := &DiffReport{
		CurrentCounts:   map[ksealv1.RequestProofResult_Decision]int{},
		CandidateCounts: map[ksealv1.RequestProofResult_Decision]int{},
	}
	for _, e := range events {
		// Score in the server layout regardless of how the row was stored: a
		// row tagged LayoutWire (or a future layout) is translated here so
		// historical events are never scored under the wrong namespace.
		bits := risk.NormalizeStored(e.RiskBits, e.RiskBitsLayout)
		cur := decide(bits, current)
		cand := decide(bits, candidate)
		report.Total++
		report.CurrentCounts[cur]++
		report.CandidateCounts[cand]++
		if cur != cand {
			report.Changed++
			if isBlock(cand) && !isBlock(cur) {
				report.NewlyBlocked++
			}
			if !isBlock(cand) && isBlock(cur) {
				report.NewlyAllowed++
			}
		}
	}
	return report, nil
}

func decide(bits uint64, spec PolicySpec) ksealv1.RequestProofResult_Decision {
	score := risk.Score(bits, spec.Weights)
	level := risk.Level(score, spec.Thresholds)
	return risk.Decision(level, spec.Mode)
}

func isBlock(d ksealv1.RequestProofResult_Decision) bool {
	return d == ksealv1.RequestProofResult_DECISION_DENY
}
