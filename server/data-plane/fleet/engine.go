// Package fleet implements population-level abuse detection for the trust
// decision. Per-instance attestation is blind to coordinated attacks where each
// individual proof is cryptographically valid — an emulator farm, a mass
// account-creation wave, or a leaked/repackaged build spreading across many
// devices. The Engine watches the *population* of attestations per cohort and,
// when the current window shows either (a) a statistically meaningful surge of
// an abuse signal above the cohort's learned baseline, or (b) a volume velocity
// spike far above the cohort's normal arrival rate, it reports a fleet anomaly
// so the trust path can fuse a server-derived risk bit into newly joining
// clients.
//
// A cohort is a (tenant, app, build, region) tuple, so the engine answers "this
// build / this region is under coordinated attack" rather than only "this app".
// region is best-effort (populated from an edge country header when present);
// an empty region simply means a build-level cohort.
//
// Design constraints (must hold at 5,000 tenants × millions of apps × tens of
// millions of MAU):
//
//   - O(1) work per observed attestation; O(buckets) per assessment.
//   - Fixed memory per cohort (a small ring of sliding-window buckets plus one
//     EWMA baseline per watched signal and one for volume).
//   - Bounded total memory: cohorts are kept in sharded LRU maps capped at
//     MaxScopes; idle cohorts are evicted, not leaked.
//   - No new identifiers and no per-user state: the engine counts already
//     collected, non-PII risk bits and arrival volume. It aggregates; it does
//     not profile.
//
// The engine is in-process and per-replica. With multiple server replicas each
// observes a slice of traffic; the relative baseline/surge model still detects a
// real surge on every replica that sees it, with no cross-replica coordination
// cost. A shared (e.g. Redis-backed) aggregator is a possible future extension;
// the per-replica model is intentional for the NoOps/low-cost target.
package fleet

import (
	"container/list"
	"hash/fnv"
	"sort"
	"sync"
	"time"
)

// Signal names a coordinated-abuse signal the engine watches at the population
// level. The associated bit mask is matched against the fused risk bitset
// (server risk bit layout) passed to Observe.
type Signal struct {
	Name string
	Mask uint64
}

// Config tunes the detector. The zero value is not valid; use DefaultConfig and
// override fields as needed. All knobs have safe NoOps defaults so an SME never
// has to tune anything.
type Config struct {
	// Window is the trailing period surge/velocity is measured over.
	Window time.Duration
	// Buckets is the number of slices the window is divided into (fixed memory
	// and time granularity per cohort).
	Buckets int
	// SurgeFactor: a seeded signal is anomalous only when its current rate is at
	// least this multiple of the learned baseline rate.
	SurgeFactor float64
	// AbsoluteFloor: a seeded signal must also reach this current rate to trip,
	// so a tiny baseline (e.g. 0.1%) tripling to 0.3% does not raise an anomaly.
	AbsoluteFloor float64
	// ColdStartFloor: before a signal baseline has been learned, a signal trips
	// only when its current rate reaches this (higher) absolute rate.
	ColdStartFloor float64
	// MinSamples: a cohort's window must contain at least this many attestations
	// before any per-signal assessment can trip, to avoid small-sample noise.
	MinSamples int
	// BaselineAlpha is the EWMA smoothing factor (0..1] applied as completed
	// buckets leave the window; higher adapts faster to a new normal.
	BaselineAlpha float64
	// VelocityFactor: a seeded cohort's window volume is a velocity anomaly when
	// it reaches this multiple of its projected (baseline) window volume.
	VelocityFactor float64
	// VelocityMinVolume: minimum window volume for a seeded velocity trip.
	VelocityMinVolume int
	// VelocityColdVolume: window volume at which a brand-new cohort (no learned
	// volume baseline yet) is treated as a velocity anomaly — i.e. a sudden flood
	// from a cohort that did not exist before.
	VelocityColdVolume int
	// MaxScopes caps the number of tracked cohorts; least-recently observed
	// cohorts are evicted beyond the cap.
	MaxScopes int
	// Signals is the watched signal set. Defaults to DefaultSignals.
	Signals []Signal
	// now is injectable for tests; nil means time.Now.
	now func() time.Time
}

const shardCount = 256

// Assessment is the result of evaluating one cohort's current window.
type Assessment struct {
	// Anomalous is true when at least one watched signal is surging OR the
	// cohort's arrival volume is a velocity anomaly.
	Anomalous bool
	// Signals lists the per-signal detail for every surging signal.
	Signals []SignalAssessment
	// VelocitySurge is true when arrival volume spiked above the cohort baseline.
	VelocitySurge bool
	// VelocityRatio is windowVolume/projectedBaselineVolume (0 on a cold-start
	// volume trip, where no baseline exists yet).
	VelocityRatio float64
	// Observed is the number of attestations in the current window.
	Observed int
}

// SignalAssessment carries why a signal tripped, for observability and SIEM.
type SignalAssessment struct {
	Name        string
	CurrentRate float64
	Baseline    float64
	// SurgeRatio is CurrentRate/Baseline (0 when the baseline is not yet seeded).
	SurgeRatio float64
}

// Engine is the concurrency-safe, bounded fleet-anomaly detector.
type Engine struct {
	cfg        Config
	bucketSize time.Duration
	now        func() time.Time
	shards     [shardCount]shard
}

type shard struct {
	mu    sync.Mutex
	byKey map[scopeKey]*list.Element // scopeKey -> *list.Element(*scope)
	lru   *list.List                 // front = most recently used
}

type scopeKey struct {
	tenant string
	app    string
	build  string
	region string
}

type scope struct {
	key         scopeKey
	ring        []bucket
	baseline    []ewma // one per watched signal, index-aligned with cfg.Signals
	volBaseline ewma   // EWMA of per-bucket attestation volume
}

type bucket struct {
	epoch  int64
	total  int
	counts []int // one per watched signal, index-aligned with cfg.Signals
}

type ewma struct {
	value  float64
	seeded bool
}

// DefaultSignals are the coordinated-abuse signals worth watching at the
// population level. Masks use the server risk bit layout (see
// server/shared/risk).
func DefaultSignals() []Signal {
	return []Signal{
		{Name: "root_jailbreak", Mask: 1 << 0},   // risk.BitRootJailbreak
		{Name: "emulator", Mask: 1 << 2},         // risk.BitEmulator
		{Name: "hooking", Mask: 1 << 3},          // risk.BitHooking
		{Name: "app_tamper", Mask: 1 << 4},       // risk.BitAppTamper
		{Name: "attestation_fail", Mask: 1 << 5}, // risk.BitAttestationFail
		{Name: "device_integrity", Mask: 1 << 8}, // risk.BitDeviceIntegrity
		{Name: "app_unrecognized", Mask: 1 << 9}, // risk.BitAppUnrecognized
	}
}

// DefaultConfig returns the NoOps defaults.
func DefaultConfig() Config {
	return Config{
		Window:             5 * time.Minute,
		Buckets:            10,
		SurgeFactor:        3.0,
		AbsoluteFloor:      0.15,
		ColdStartFloor:     0.30,
		MinSamples:         50,
		BaselineAlpha:      0.2,
		VelocityFactor:     4.0,
		VelocityMinVolume:  200,
		VelocityColdVolume: 500,
		MaxScopes:          200_000,
		Signals:            DefaultSignals(),
	}
}

// New builds an Engine from cfg, filling any unset field with its default.
func New(cfg Config) *Engine {
	d := DefaultConfig()
	if cfg.Window <= 0 {
		cfg.Window = d.Window
	}
	if cfg.Buckets <= 0 {
		cfg.Buckets = d.Buckets
	}
	if cfg.SurgeFactor <= 1 {
		cfg.SurgeFactor = d.SurgeFactor
	}
	if cfg.AbsoluteFloor <= 0 {
		cfg.AbsoluteFloor = d.AbsoluteFloor
	}
	if cfg.ColdStartFloor <= 0 {
		cfg.ColdStartFloor = d.ColdStartFloor
	}
	if cfg.MinSamples <= 0 {
		cfg.MinSamples = d.MinSamples
	}
	if cfg.BaselineAlpha <= 0 || cfg.BaselineAlpha > 1 {
		cfg.BaselineAlpha = d.BaselineAlpha
	}
	if cfg.VelocityFactor <= 1 {
		cfg.VelocityFactor = d.VelocityFactor
	}
	if cfg.VelocityMinVolume <= 0 {
		cfg.VelocityMinVolume = d.VelocityMinVolume
	}
	if cfg.VelocityColdVolume <= 0 {
		cfg.VelocityColdVolume = d.VelocityColdVolume
	}
	if cfg.MaxScopes <= 0 {
		cfg.MaxScopes = d.MaxScopes
	}
	if len(cfg.Signals) == 0 {
		cfg.Signals = d.Signals
	}
	nowFn := cfg.now
	if nowFn == nil {
		nowFn = time.Now
	}
	e := &Engine{
		cfg:        cfg,
		bucketSize: cfg.Window / time.Duration(cfg.Buckets),
		now:        nowFn,
	}
	for i := range e.shards {
		e.shards[i].byKey = make(map[scopeKey]*list.Element)
		e.shards[i].lru = list.New()
	}
	return e
}

func (e *Engine) maxScopesPerShard() int {
	per := e.cfg.MaxScopes / shardCount
	if per < 1 {
		per = 1
	}
	return per
}

func (e *Engine) epoch(t time.Time) int64 {
	return t.UnixNano() / int64(e.bucketSize)
}

func (e *Engine) shardFor(k scopeKey) *shard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(k.tenant))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(k.app))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(k.build))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(k.region))
	return &e.shards[h.Sum32()%shardCount]
}

// getOrCreateLocked returns the cohort for k within sh, creating it (and
// evicting the LRU cohort past the cap) if absent. sh.mu must be held.
func (e *Engine) getOrCreateLocked(sh *shard, k scopeKey) *scope {
	if el, ok := sh.byKey[k]; ok {
		sh.lru.MoveToFront(el)
		return el.Value.(*scope)
	}
	sc := &scope{
		key:      k,
		ring:     make([]bucket, e.cfg.Buckets),
		baseline: make([]ewma, len(e.cfg.Signals)),
	}
	for i := range sc.ring {
		sc.ring[i].counts = make([]int, len(e.cfg.Signals))
	}
	el := sh.lru.PushFront(sc)
	sh.byKey[k] = el
	for sh.lru.Len() > e.maxScopesPerShard() {
		back := sh.lru.Back()
		if back == nil {
			break
		}
		evicted := back.Value.(*scope)
		delete(sh.byKey, evicted.key)
		sh.lru.Remove(back)
	}
	return sc
}

// Observe records one attestation for the (tenant, app, build, region) cohort
// with its fused (server-layout) risk bits at time t. It is O(1) and safe for
// concurrent use.
func (e *Engine) Observe(tenant, app, build, region string, bits uint64, t time.Time) {
	k := scopeKey{tenant: tenant, app: app, build: build, region: region}
	ep := e.epoch(t)
	sh := e.shardFor(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sc := e.getOrCreateLocked(sh, k)
	idx := int(((ep % int64(e.cfg.Buckets)) + int64(e.cfg.Buckets)) % int64(e.cfg.Buckets))
	b := &sc.ring[idx]
	if b.epoch != ep {
		// The slot is being recycled. If it held a completed past bucket with
		// traffic, fold its finalized rates and volume into the baselines before
		// reset — that bucket has just aged out of the window and is "normal".
		if b.epoch != 0 && b.total > 0 {
			e.foldBaseline(sc, b)
		}
		b.epoch = ep
		b.total = 0
		for i := range b.counts {
			b.counts[i] = 0
		}
	}
	b.total++
	for i := range e.cfg.Signals {
		if bits&e.cfg.Signals[i].Mask != 0 {
			b.counts[i]++
		}
	}
}

func (e *Engine) foldBaseline(sc *scope, b *bucket) {
	for i := range e.cfg.Signals {
		rate := float64(b.counts[i]) / float64(b.total)
		foldEWMA(&sc.baseline[i], rate, e.cfg.BaselineAlpha)
	}
	foldEWMA(&sc.volBaseline, float64(b.total), e.cfg.BaselineAlpha)
}

func foldEWMA(bl *ewma, sample, alpha float64) {
	if !bl.seeded {
		bl.value = sample
		bl.seeded = true
		return
	}
	bl.value = alpha*sample + (1-alpha)*bl.value
}

// Assess evaluates the current window for the (tenant, app, build, region)
// cohort. It never creates a cohort: an unobserved cohort is reported clean.
func (e *Engine) Assess(tenant, app, build, region string) Assessment {
	k := scopeKey{tenant: tenant, app: app, build: build, region: region}
	ep := e.epoch(e.now())
	sh := e.shardFor(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	el, ok := sh.byKey[k]
	if !ok {
		return Assessment{}
	}
	sh.lru.MoveToFront(el)
	sc := el.Value.(*scope)
	return e.assessLocked(sc, ep)
}

func (e *Engine) assessLocked(sc *scope, ep int64) Assessment {
	minEpoch := ep - int64(e.cfg.Buckets-1)
	total := 0
	counts := make([]int, len(e.cfg.Signals))
	for i := range sc.ring {
		b := &sc.ring[i]
		if b.epoch < minEpoch || b.epoch > ep {
			continue
		}
		total += b.total
		for j := range counts {
			counts[j] += b.counts[j]
		}
	}
	out := Assessment{Observed: total}

	// Per-signal surge detection (needs a minimum sample size).
	if total >= e.cfg.MinSamples {
		for i := range e.cfg.Signals {
			cur := float64(counts[i]) / float64(total)
			bl := sc.baseline[i]
			anomalous := false
			ratio := 0.0
			if !bl.seeded {
				anomalous = cur >= e.cfg.ColdStartFloor
			} else {
				if bl.value > 0 {
					ratio = cur / bl.value
				}
				anomalous = cur >= e.cfg.AbsoluteFloor && cur >= bl.value*e.cfg.SurgeFactor
			}
			if anomalous {
				out.Anomalous = true
				out.Signals = append(out.Signals, SignalAssessment{
					Name:        e.cfg.Signals[i].Name,
					CurrentRate: cur,
					Baseline:    bl.value,
					SurgeRatio:  ratio,
				})
			}
		}
	}

	// Volume-velocity detection: a cohort whose arrival volume spikes far above
	// its own normal — catches a coordinated flood even when every signal looks
	// individually clean (e.g. a brand-new build suddenly seen everywhere).
	if sc.volBaseline.seeded {
		projected := sc.volBaseline.value * float64(e.cfg.Buckets)
		if projected > 0 {
			out.VelocityRatio = float64(total) / projected
		}
		if total >= e.cfg.VelocityMinVolume && float64(total) >= projected*e.cfg.VelocityFactor {
			out.Anomalous = true
			out.VelocitySurge = true
		}
	} else if total >= e.cfg.VelocityColdVolume {
		out.Anomalous = true
		out.VelocitySurge = true
	}
	return out
}

// ScopeAnomaly is one anomalous cohort in a snapshot.
type ScopeAnomaly struct {
	TenantID  string
	AppID     string
	BuildHash string
	Region    string
	Assessment
}

// Snapshot returns every currently-anomalous cohort. It is used by the metrics
// sampler and the dashboard read path; it does not mutate LRU order.
func (e *Engine) Snapshot() []ScopeAnomaly {
	ep := e.epoch(e.now())
	var out []ScopeAnomaly
	for s := range e.shards {
		sh := &e.shards[s]
		sh.mu.Lock()
		for el := sh.lru.Front(); el != nil; el = el.Next() {
			sc := el.Value.(*scope)
			a := e.assessLocked(sc, ep)
			if a.Anomalous {
				out = append(out, ScopeAnomaly{
					TenantID:   sc.key.tenant,
					AppID:      sc.key.app,
					BuildHash:  sc.key.build,
					Region:     sc.key.region,
					Assessment: a,
				})
			}
		}
		sh.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID != out[j].TenantID {
			return out[i].TenantID < out[j].TenantID
		}
		if out[i].AppID != out[j].AppID {
			return out[i].AppID < out[j].AppID
		}
		if out[i].BuildHash != out[j].BuildHash {
			return out[i].BuildHash < out[j].BuildHash
		}
		return out[i].Region < out[j].Region
	})
	return out
}

// TenantSnapshot returns the currently-anomalous cohorts for one tenant.
func (e *Engine) TenantSnapshot(tenant string) []ScopeAnomaly {
	all := e.Snapshot()
	out := make([]ScopeAnomaly, 0, len(all))
	for _, a := range all {
		if a.TenantID == tenant {
			out = append(out, a)
		}
	}
	return out
}
