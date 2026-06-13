// Package guardrails watches live enforcement decisions and raises alerts when a
// tenant/app/policy blocks more traffic than expected — the safety net against a
// bad policy or a false-positive-prone detection module taking down real users.
package guardrails

import (
	"sort"
	"sync"
	"time"
)

// DefaultBlockRateThreshold is the fraction of blocked requests above which a
// policy is flagged for rollback.
const DefaultBlockRateThreshold = 0.05

const (
	// defaultWindow is the trailing period block rates are measured over, so a
	// regression is reflected promptly instead of being diluted by all-time
	// history; bucketCount fixes per-scope memory and time granularity.
	defaultWindow = 10 * time.Minute
	bucketCount   = 10
)

type scopeKey struct {
	tenant string
	app    string
	policy string
}

type moduleCounts struct {
	flagged       int
	falsePositive int
}

// bucket holds the counts for one slice of the sliding window. epoch identifies
// which time slice it currently represents; a stale epoch means the bucket has
// rolled over and its counts are reset on next use.
type bucket struct {
	epoch   int64
	total   int
	blocked int
	modules map[string]*moduleCounts
}

// counts is a fixed-size ring of buckets implementing a sliding window. Memory
// per scope is bounded to bucketCount buckets regardless of traffic volume.
type counts struct {
	buckets [bucketCount]bucket
}

// Detector aggregates decision outcomes and per-module false-positive signals
// over a trailing time window.
type Detector struct {
	threshold  float64
	bucketSize time.Duration
	now        func() time.Time

	mu     sync.Mutex
	scopes map[scopeKey]*counts
}

// NewDetector builds a detector. A threshold <= 0 uses the default.
func NewDetector(threshold float64) *Detector {
	if threshold <= 0 {
		threshold = DefaultBlockRateThreshold
	}
	return &Detector{
		threshold:  threshold,
		bucketSize: defaultWindow / bucketCount,
		now:        time.Now,
		scopes:     map[scopeKey]*counts{},
	}
}

func (d *Detector) epoch() int64 {
	return d.now().UnixNano() / int64(d.bucketSize)
}

func (d *Detector) scope(k scopeKey) *counts {
	c, ok := d.scopes[k]
	if !ok {
		c = &counts{}
		d.scopes[k] = c
	}
	return c
}

// liveBucket returns the bucket for the current epoch, resetting it first if it
// has rolled over since it was last written.
func (c *counts) liveBucket(epoch int64) *bucket {
	b := &c.buckets[((epoch%bucketCount)+bucketCount)%bucketCount]
	if b.epoch != epoch {
		b.epoch = epoch
		b.total = 0
		b.blocked = 0
		b.modules = nil
	}
	return b
}

// aggregate sums the buckets within the trailing window ending at epoch.
func (c *counts) aggregate(epoch int64) (total, blocked int, fp map[string]float64) {
	minEpoch := epoch - (bucketCount - 1)
	flagged := map[string]int{}
	falsePos := map[string]int{}
	for i := range c.buckets {
		b := &c.buckets[i]
		if b.epoch < minEpoch || b.epoch > epoch {
			continue
		}
		total += b.total
		blocked += b.blocked
		for name, mc := range b.modules {
			flagged[name] += mc.flagged
			falsePos[name] += mc.falsePositive
		}
	}
	fp = map[string]float64{}
	for name, f := range flagged {
		if f > 0 {
			fp[name] = float64(falsePos[name]) / float64(f)
		}
	}
	return total, blocked, fp
}

// hasTraffic reports whether any bucket still falls within the window.
func (c *counts) hasTraffic(epoch int64) bool {
	minEpoch := epoch - (bucketCount - 1)
	for i := range c.buckets {
		if b := &c.buckets[i]; b.epoch >= minEpoch && b.epoch <= epoch && b.total > 0 {
			return true
		}
	}
	return false
}

// RecordDecision records one enforcement outcome for a scope.
func (d *Detector) RecordDecision(tenant, app, policy string, blocked bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	b := d.scope(scopeKey{tenant, app, policy}).liveBucket(d.epoch())
	b.total++
	if blocked {
		b.blocked++
	}
}

// RecordModule records that a detection module flagged a request, and whether it
// was later judged a false positive (e.g. via user appeal or override).
func (d *Detector) RecordModule(tenant, app, policy, module string, falsePositive bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	b := d.scope(scopeKey{tenant, app, policy}).liveBucket(d.epoch())
	if b.modules == nil {
		b.modules = map[string]*moduleCounts{}
	}
	mc, ok := b.modules[module]
	if !ok {
		mc = &moduleCounts{}
		b.modules[module] = mc
	}
	mc.flagged++
	if falsePositive {
		mc.falsePositive++
	}
}

// BlockRate returns the windowed block rate for a scope (0 when no traffic).
func (d *Detector) BlockRate(tenant, app, policy string) float64 {
	rate, _ := d.Sample(tenant, app, policy)
	return rate
}

// Sample returns the windowed block rate and the number of decisions observed
// for a scope (0, 0 when no traffic). It is the health signal the canary
// auto-rollback controller reads for the candidate cohort.
func (d *Detector) Sample(tenant, app, policy string) (blockRate float64, total int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.scopes[scopeKey{tenant, app, policy}]
	if !ok {
		return 0, 0
	}
	total, blocked, _ := c.aggregate(d.epoch())
	if total == 0 {
		return 0, 0
	}
	return float64(blocked) / float64(total), total
}

// ModuleFalsePositiveRate returns a module's windowed FP rate within a scope.
func (d *Detector) ModuleFalsePositiveRate(tenant, app, policy, module string) float64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.scopes[scopeKey{tenant, app, policy}]
	if !ok {
		return 0
	}
	_, _, fp := c.aggregate(d.epoch())
	return fp[module]
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

// Evaluate returns alerts for every scope over the threshold within the current
// window, worst first. A minimum sample size avoids alerting on statistically
// meaningless traffic. Scopes with no traffic left in the window are pruned so
// the scope map cannot grow without bound.
func (d *Detector) Evaluate(minSamples int) []Alert {
	if minSamples <= 0 {
		minSamples = 20
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	epoch := d.epoch()
	var alerts []Alert
	for k, c := range d.scopes {
		total, blocked, fp := c.aggregate(epoch)
		if !c.hasTraffic(epoch) {
			delete(d.scopes, k)
			continue
		}
		if total < minSamples {
			continue
		}
		rate := float64(blocked) / float64(total)
		if rate <= d.threshold {
			continue
		}
		alerts = append(alerts, Alert{
			Tenant:      k.tenant,
			App:         k.app,
			Policy:      k.policy,
			BlockRate:   rate,
			Total:       total,
			Blocked:     blocked,
			Recommend:   "rollback to previous policy",
			ModuleFPRat: fp,
		})
	}
	sort.Slice(alerts, func(i, j int) bool { return alerts[i].BlockRate > alerts[j].BlockRate })
	return alerts
}
