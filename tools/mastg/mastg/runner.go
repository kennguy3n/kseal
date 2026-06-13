package mastg

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Status is the run status of a verification procedure for a release.
type Status string

const (
	// StatusPass: verified by an explicit device-test assertion.
	StatusPass Status = "pass"
	// StatusFail: an explicit assertion reported the check failed.
	StatusFail Status = "fail"
	// StatusObserved: supporting evidence exists (e.g. build-proof from
	// masvs-report) but a full MASTG device verification has not been asserted.
	StatusObserved Status = "observed"
	// StatusPending: a device procedure with no evidence yet (must be run).
	StatusPending Status = "pending"
	// StatusInformational: verified outside MASTG device scope (server/tenant);
	// surfaced for completeness, never gates the release.
	StatusInformational Status = "informational"
	// StatusNotApplicable: explicitly marked not applicable for this release.
	StatusNotApplicable Status = "not-applicable"
)

// Evidence is the per-release input to the runner: explicit device-test
// assertions plus an optional overlay derived from a masvs-report JSON.
type Evidence struct {
	Release   string             `json:"release"`
	Platform  string             `json:"platform"`
	BuildHash string             `json:"build_hash"`
	Results   []AssertedResult   `json:"results"`
	overlay   map[string]overlay // keyed by category|objective
}

// AssertedResult is one explicit verification outcome. Match is a substring
// matched (case-insensitively) against a procedure's objective, kseal control,
// id, or any MASTG test token; it applies to every procedure it matches so a
// whole test area can be asserted at once.
type AssertedResult struct {
	Match  string `json:"match"`
	Status Status `json:"status"`
	Note   string `json:"note"`
}

type overlay struct {
	status Status
	note   string
}

// Result is the evaluated status of one procedure.
type Result struct {
	Procedure Procedure `json:"procedure"`
	Status    Status    `json:"status"`
	Note      string    `json:"note,omitempty"`
}

// Report is the full per-release MASTG verification report.
type Report struct {
	Release   string         `json:"release,omitempty"`
	Platform  string         `json:"platform,omitempty"`
	BuildHash string         `json:"build_hash,omitempty"`
	Summary   map[Status]int `json:"summary"`
	Results   []Result       `json:"results"`
	Gating    GatingSummary  `json:"gating"`
}

// GatingSummary reports whether the release is blocked. Only explicit failures
// gate; pending/observed are advisory so the report is fail-safe and never
// blocks a release on absent evidence by itself.
type GatingSummary struct {
	Failed      int      `json:"failed"`
	FailedIDs   []string `json:"failed_ids"`
	Blocked     bool     `json:"blocked"`
	RequirePass bool     `json:"require_pass"`
	Pending     int      `json:"pending"`
	PendingIDs  []string `json:"pending_ids,omitempty"`
}

// RunOptions tunes evaluation.
type RunOptions struct {
	// RequirePass makes pending device procedures gate the release too (strict
	// mode for a final release sign-off). Default false: only failures gate.
	RequirePass bool
}

// Run evaluates every procedure against the evidence and returns the report.
func (c *Catalog) Run(ev *Evidence, opts RunOptions) *Report {
	procs := c.Procedures()
	results := make([]Result, 0, len(procs))
	summary := map[Status]int{}

	for _, p := range procs {
		st, note := evaluate(p, ev)
		results = append(results, Result{Procedure: p, Status: st, Note: note})
		summary[st]++
	}

	rep := &Report{
		Summary: summary,
		Results: results,
		Gating:  GatingSummary{RequirePass: opts.RequirePass},
	}
	if ev != nil {
		rep.Release, rep.Platform, rep.BuildHash = ev.Release, ev.Platform, ev.BuildHash
	}
	for _, r := range results {
		switch r.Status {
		case StatusFail:
			rep.Gating.Failed++
			rep.Gating.FailedIDs = append(rep.Gating.FailedIDs, r.Procedure.ID)
		case StatusPending:
			rep.Gating.Pending++
			rep.Gating.PendingIDs = append(rep.Gating.PendingIDs, r.Procedure.ID)
		}
	}
	rep.Gating.Blocked = rep.Gating.Failed > 0 || (opts.RequirePass && rep.Gating.Pending > 0)
	return rep
}

// evaluate resolves one procedure's status. Precedence: an explicit asserted
// result wins; otherwise a masvs-report overlay yields "observed"; otherwise
// the plane's fail-safe default applies (device→pending, server/tenant→info).
func evaluate(p Procedure, ev *Evidence) (Status, string) {
	if ev != nil {
		if st, note, ok := matchAssertion(p, ev.Results); ok {
			return st, note
		}
		if ov, ok := ev.overlay[overlayKey(p.Category, p.Objective)]; ok {
			return ov.status, ov.note
		}
	}
	switch p.Plane {
	case PlaneDevice:
		return StatusPending, "no evidence supplied; run this MASTG procedure against the release build"
	case PlaneServer:
		return StatusInformational, "verified by server-side test; outside MASTG device scope"
	default:
		return StatusInformational, fmt.Sprintf("verified by %q; outside MASTG device scope", p.Method)
	}
}

func matchAssertion(p Procedure, results []AssertedResult) (Status, string, bool) {
	var (
		matched bool
		status  Status
		note    string
	)
	for _, r := range results {
		if r.Match == "" || !r.Status.valid() {
			continue
		}
		if procedureMatches(p, r.Match) {
			// Later matching results override earlier ones (deterministic by
			// input order), letting a specific row refine a bulk assertion.
			matched, status, note = true, r.Status, r.Note
		}
	}
	return status, note, matched
}

func procedureMatches(p Procedure, match string) bool {
	m := strings.ToLower(strings.TrimSpace(match))
	if m == "" {
		return false
	}
	if strings.Contains(strings.ToLower(p.Objective), m) ||
		strings.Contains(strings.ToLower(p.Control), m) ||
		strings.Contains(strings.ToLower(p.ID), m) {
		return true
	}
	for _, t := range p.MASTGTests {
		if strings.Contains(strings.ToLower(t), m) {
			return true
		}
	}
	return false
}

func (s Status) valid() bool {
	switch s {
	case StatusPass, StatusFail, StatusObserved, StatusPending, StatusInformational, StatusNotApplicable:
		return true
	}
	return false
}

func overlayKey(category, objective string) string {
	return strings.ToLower(category) + "|" + strings.ToLower(strings.TrimSpace(objective))
}

// LoadEvidence parses an Evidence JSON document and validates its statuses.
func LoadEvidence(data []byte) (*Evidence, error) {
	var ev Evidence
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		return nil, fmt.Errorf("parse evidence: %w", err)
	}
	for i, r := range ev.Results {
		if r.Match == "" {
			return nil, fmt.Errorf("evidence result %d: empty match", i)
		}
		if !r.Status.valid() {
			return nil, fmt.Errorf("evidence result %d: invalid status %q", i, r.Status)
		}
	}
	return &ev, nil
}

// minimal projection of the tools/masvs-report JSON output we consume.
type masvsReportDoc struct {
	Categories []struct {
		Name     string `json:"name"`
		Controls []struct {
			Objective string `json:"objective"`
			Evidence  struct {
				Status string `json:"status"`
			} `json:"evidence"`
		} `json:"controls"`
	} `json:"categories"`
}

// MergeMASVSReport overlays a masvs-report JSON onto the evidence: controls the
// build-proof report marks "evidenced"/"partial" become "observed" supporting
// evidence for the matching MASTG procedure (unless an explicit assertion
// overrides). Matching is exact on (category, objective) since both tools parse
// the same mapping doc.
func (e *Evidence) MergeMASVSReport(data []byte) error {
	var doc masvsReportDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse masvs-report: %w", err)
	}
	if e.overlay == nil {
		e.overlay = map[string]overlay{}
	}
	for _, cat := range doc.Categories {
		for _, ctrl := range cat.Controls {
			st := strings.ToLower(strings.TrimSpace(ctrl.Evidence.Status))
			if st != "evidenced" && st != "partial" {
				continue
			}
			note := fmt.Sprintf("masvs-report build evidence: %s", st)
			e.overlay[overlayKey(cat.Name, ctrl.Objective)] = overlay{status: StatusObserved, note: note}
		}
	}
	return nil
}

// SortedSummary returns summary counts in a stable status order for rendering.
func (r *Report) SortedSummary() []struct {
	Status Status
	Count  int
} {
	order := []Status{StatusPass, StatusObserved, StatusPending, StatusFail, StatusInformational, StatusNotApplicable}
	out := make([]struct {
		Status Status
		Count  int
	}, 0, len(order))
	for _, s := range order {
		out = append(out, struct {
			Status Status
			Count  int
		}{s, r.Summary[s]})
	}
	return out
}
