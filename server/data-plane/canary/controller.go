package canary

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/kennguy3n/kseal/server/control-plane/compliance"
	"github.com/kennguy3n/kseal/server/data-plane/guardrails"
)

// HealthSource reports the observed guardrail health for a candidate cohort,
// keyed by the scope the detector records decisions under (tenant, app,
// policy). samples is the number of decisions in the trailing window.
type HealthSource interface {
	CanaryHealth(tenantID, appID, policyID string) (blockRate float64, samples int64)
}

// GuardrailHealth adapts the guardrails detector to HealthSource. The candidate
// policy id is the detector's policy dimension, so health reflects exactly the
// cohort served the candidate config.
type GuardrailHealth struct {
	Detector *guardrails.Detector
}

// CanaryHealth returns the windowed block rate and sample count for the
// candidate policy cohort.
func (g GuardrailHealth) CanaryHealth(tenantID, appID, policyID string) (float64, int64) {
	rate, total := g.Detector.Sample(tenantID, appID, policyID)
	return rate, int64(total)
}

// Controller periodically evaluates active canaries and auto-rolls-back any
// whose candidate cohort breaches its guardrail block-rate threshold, reverting
// to the last-known-good policy and recording an audit event (via the store).
type Controller struct {
	store      compliance.Store
	health     HealthSource
	reg        *Registry
	interval   time.Duration
	minSamples int64
	logger     *slog.Logger
}

// Config tunes the controller. Zero values fall back to safe defaults.
type Config struct {
	// Interval between rollback evaluation sweeps.
	Interval time.Duration
	// MinSamples is the minimum decisions observed before a rollback can fire,
	// so a rollout is never rolled back on statistically meaningless traffic.
	MinSamples int64
	Logger     *slog.Logger
}

// NewController builds an auto-rollback controller over the compliance store and
// a health source. reg is the in-memory snapshot the controller refreshes each
// sweep for the hot-path cohort selection; it may be nil (rollback still runs).
func NewController(store compliance.Store, health HealthSource, reg *Registry, cfg Config) *Controller {
	interval := cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	minSamples := cfg.MinSamples
	if minSamples <= 0 {
		minSamples = 20
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Controller{store: store, health: health, reg: reg, interval: interval, minSamples: minSamples, logger: logger}
}

// Run drives the evaluation loop until ctx is cancelled. It is safe to run in a
// background goroutine; one sweep runs immediately so a freshly started server
// reacts without waiting a full interval.
func (c *Controller) Run(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	c.evaluateOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.evaluateOnce(ctx)
		}
	}
}

// evaluateOnce performs one rollback sweep across all active canaries. Errors on
// individual rollouts are logged and skipped so one bad rollout cannot stall the
// controller.
func (c *Controller) evaluateOnce(ctx context.Context) {
	canaries, err := c.store.ListActiveCanaries(ctx)
	if err != nil {
		c.logger.WarnContext(ctx, "canary: list active failed", "err", err)
		return
	}
	if c.reg != nil {
		c.reg.Replace(canaries)
	}
	for _, cs := range canaries {
		rate, samples := c.health.CanaryHealth(cs.TenantId, cs.AppId, cs.CandidatePolicyId)
		if samples < c.minSamples || rate <= cs.RollbackThreshold {
			continue
		}
		reason := fmt.Sprintf("guardrail breach: block rate %.2f%% over %.2f%% threshold (n=%d)",
			rate*100, cs.RollbackThreshold*100, samples)
		if _, err := c.store.RollbackCanary(ctx, cs.TenantId, cs.AppId, reason, "system", compliance.CanaryObservation{
			BlockRate:   rate,
			SampleCount: samples,
		}); err != nil {
			c.logger.WarnContext(ctx, "canary: auto-rollback failed", "tenant", cs.TenantId, "app", cs.AppId, "err", err)
			continue
		}
		c.logger.InfoContext(ctx, "canary: auto-rolled-back", "tenant", cs.TenantId, "app", cs.AppId, "block_rate", rate)
	}
}
