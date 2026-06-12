// Package guardrails watches live enforcement decisions and raises alerts when a
// tenant/app/policy blocks more traffic than expected — the safety net against a
// bad policy or a false-positive-prone detection module taking down real users.
package guardrails

import (
	"sort"
	"sync"
)

// DefaultBlockRateThreshold is the fraction of blocked requests above which a
// policy is flagged for rollback.
const DefaultBlockRateThreshold = 0.05

type scopeKey struct {
	tenant string
	app    string
	policy string
}

type counts struct {
	total   int
	blocked int
	modules map[string]*moduleCounts
}

type moduleCounts struct {
	flagged       int
	falsePositive int
}

// Detector aggregates decision outcomes and per-module false-positive signals.
type Detector struct {
	threshold float64
	mu        sync.Mutex
	scopes    map[scopeKey]*counts
}

// NewDetector builds a detector. A threshold <= 0 uses the default.
func NewDetector(threshold float64) *Detector {
	if threshold <= 0 {
		threshold = DefaultBlockRateThreshold
	}
	return &Detector{threshold: threshold, scopes: map[scopeKey]*counts{}}
}

func (d *Detector) scope(k scopeKey) *counts {
	c, ok := d.scopes[k]
	if !ok {
		c = &counts{modules: map[string]*moduleCounts{}}
		d.scopes[k] = c
	}
	return c
}

// RecordDecision records one enforcement outcome for a scope.
func (d *Detector) RecordDecision(tenant, app, policy string, blocked bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := d.scope(scopeKey{tenant, app, policy})
	c.total++
	if blocked {
		c.blocked++
	}
}

// RecordModule records that a detection module flagged a request, and whether it
// was later judged a false positive (e.g. via user appeal or override).
func (d *Detector) RecordModule(tenant, app, policy, module string, falsePositive bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := d.scope(scopeKey{tenant, app, policy})
	mc, ok := c.modules[module]
	if !ok {
		mc = &moduleCounts{}
		c.modules[module] = mc
	}
	mc.flagged++
	if falsePositive {
		mc.falsePositive++
	}
}

// BlockRate returns the block rate for a scope (0 when no traffic).
func (d *Detector) BlockRate(tenant, app, policy string) float64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.scopes[scopeKey{tenant, app, policy}]
	if !ok || c.total == 0 {
		return 0
	}
	return float64(c.blocked) / float64(c.total)
}

// ModuleFalsePositiveRate returns a module's FP rate within a scope.
func (d *Detector) ModuleFalsePositiveRate(tenant, app, policy, module string) float64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.scopes[scopeKey{tenant, app, policy}]
	if !ok {
		return 0
	}
	mc, ok := c.modules[module]
	if !ok || mc.flagged == 0 {
		return 0
	}
	return float64(mc.falsePositive) / float64(mc.flagged)
}

// Alert describes a scope whose block rate exceeds the threshold.
type Alert struct {
	Tenant      string
	App         string
	Policy      string
	BlockRate   float64
	Total       int
	Blocked     int
	Recommend   string
	ModuleFPRat map[string]float64
}

// Evaluate returns alerts for every scope over the threshold, worst first. A
// minimum sample size avoids alerting on statistically meaningless traffic.
func (d *Detector) Evaluate(minSamples int) []Alert {
	if minSamples <= 0 {
		minSamples = 20
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var alerts []Alert
	for k, c := range d.scopes {
		if c.total < minSamples {
			continue
		}
		rate := float64(c.blocked) / float64(c.total)
		if rate <= d.threshold {
			continue
		}
		fp := map[string]float64{}
		for name, mc := range c.modules {
			if mc.flagged > 0 {
				fp[name] = float64(mc.falsePositive) / float64(mc.flagged)
			}
		}
		alerts = append(alerts, Alert{
			Tenant:      k.tenant,
			App:         k.app,
			Policy:      k.policy,
			BlockRate:   rate,
			Total:       c.total,
			Blocked:     c.blocked,
			Recommend:   "rollback to previous policy",
			ModuleFPRat: fp,
		})
	}
	sort.Slice(alerts, func(i, j int) bool { return alerts[i].BlockRate > alerts[j].BlockRate })
	return alerts
}
