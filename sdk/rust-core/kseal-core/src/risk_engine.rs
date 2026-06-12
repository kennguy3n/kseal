//! Local signal fusion (Phase 2).
//!
//! The engine fuses incoming [`RiskBitset`] signals against the active
//! [`Policy`]: it computes a weighted composite score, maps it to a
//! [`TrustLevel`], and derives the **local** response. Per ARCHITECTURE.md the
//! device never hard-blocks on its own — the local response is capped at
//! `step-up`; only the server may `block`. A sliding window of recent
//! observations powers lightweight anomaly detection (a newly emerged signal).

use crate::policy::Policy;
use crate::proto::{Confidence, EnforcementMode, TrustLevel};
use crate::risk::{RiskBitset, RiskScore};
use std::collections::VecDeque;

/// Default number of recent observations retained for anomaly detection.
pub const DEFAULT_WINDOW: usize = 32;

/// The fused result of a single evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FusedRisk {
    /// Weighted composite score over the (module-filtered) signals.
    pub score: u32,
    /// Composite trust classification from the policy thresholds.
    pub level: TrustLevel,
    /// Confidence derived from signal corroboration.
    pub confidence: Confidence,
    /// Local response — always `observe` or `step_up`, never `block`.
    pub local_response: EnforcementMode,
    /// Whether a signal appeared that was absent across the recent window.
    pub anomaly: bool,
}

/// Stateful local risk engine bound to an active policy.
#[derive(Debug, Clone)]
pub struct RiskEngine {
    policy: Policy,
    history: VecDeque<RiskBitset>,
    window: usize,
}

impl RiskEngine {
    /// Builds an engine over `policy` retaining up to `window` recent
    /// observations (a `window` of 0 is treated as 1).
    #[must_use]
    pub fn new(policy: Policy, window: usize) -> Self {
        Self {
            policy,
            history: VecDeque::new(),
            window: window.max(1),
        }
    }

    /// The active policy.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Replaces the active policy and clears history (signals are policy-relative).
    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
        self.history.clear();
    }

    /// Caps a policy enforcement mode to the strongest *local* response.
    ///
    /// `block` is downgraded to `step_up` because the device is not authorized
    /// to deny locally; everything else passes through.
    fn cap_local(mode: EnforcementMode) -> EnforcementMode {
        match mode {
            EnforcementMode::Block => EnforcementMode::StepUp,
            EnforcementMode::Unspecified => EnforcementMode::Observe,
            other => other,
        }
    }

    /// Returns the union of all signals currently in the window.
    fn window_union(&self) -> RiskBitset {
        self.history
            .iter()
            .fold(RiskBitset::empty(), |acc, b| acc | *b)
    }

    /// Fuses `signals` into a [`FusedRisk`] and records them in the window.
    ///
    /// Anomaly detection runs against the window *before* `signals` are
    /// appended, so a bit that was never seen in the recent window flags an
    /// anomaly on first appearance.
    pub fn fuse(&mut self, signals: RiskBitset) -> FusedRisk {
        let filtered = self.policy.filter_signals(signals);
        let prior_union = self.window_union();
        let emerged = RiskBitset::from_raw(filtered.as_u64() & !prior_union.as_u64());
        let anomaly = !filtered.is_clean() && !emerged.is_clean();

        let RiskScore { score, confidence, .. } =
            RiskScore::compute(filtered, &self.policy.config().signal_weights);
        let level = self.policy.trust_level_for_score(score);
        let local_response = Self::cap_local(self.policy.evaluate(signals).mode);

        self.record(filtered);

        FusedRisk {
            score,
            level,
            confidence,
            local_response,
            anomaly,
        }
    }

    /// Appends an observation, evicting the oldest once the window is full.
    fn record(&mut self, bits: RiskBitset) {
        if self.history.len() == self.window {
            self.history.pop_front();
        }
        self.history.push_back(bits);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{PolicyConfig, PolicyRule};
    use std::collections::HashMap;

    fn policy() -> Policy {
        let mut weights = HashMap::new();
        weights.insert(5, 60); // HOOKING
        weights.insert(4, 30); // DEBUGGER
        weights.insert(0, 25); // ROOT
        let mut thresholds = HashMap::new();
        thresholds.insert("LOW_RISK".to_string(), 10);
        thresholds.insert("MEDIUM_RISK".to_string(), 40);
        thresholds.insert("HIGH_RISK".to_string(), 70);
        thresholds.insert("CRITICAL".to_string(), 100);
        Policy::new(PolicyConfig {
            rules: vec![PolicyRule {
                id: "block-hooking".into(),
                risk_mask: RiskBitset::HOOKING.as_u64(),
                min_score: 0,
                action: EnforcementMode::Block as i32,
                description: String::new(),
            }],
            risk_thresholds: thresholds,
            default_mode: EnforcementMode::Observe as i32,
            modules_enabled: vec![],
            signal_weights: weights,
            policy_hash: "h".into(),
        })
    }

    #[test]
    fn clean_signals_are_trusted_and_observe() {
        let mut e = RiskEngine::new(policy(), DEFAULT_WINDOW);
        let r = e.fuse(RiskBitset::empty());
        assert_eq!(r.score, 0);
        assert_eq!(r.level, TrustLevel::Trusted);
        assert_eq!(r.local_response, EnforcementMode::Observe);
        assert!(!r.anomaly);
    }

    #[test]
    fn block_policy_is_capped_to_stepup_locally() {
        let mut e = RiskEngine::new(policy(), DEFAULT_WINDOW);
        let r = e.fuse(RiskBitset::HOOKING);
        // Policy says block, but the local response must cap at step-up.
        assert_eq!(r.local_response, EnforcementMode::StepUp);
        assert_eq!(r.level, TrustLevel::MediumRisk); // score 60
    }

    #[test]
    fn anomaly_fires_on_first_appearance_then_settles() {
        let mut e = RiskEngine::new(policy(), DEFAULT_WINDOW);
        // First observation of DEBUGGER → anomaly.
        let r1 = e.fuse(RiskBitset::DEBUGGER);
        assert!(r1.anomaly);
        // Same signal again → already in window, no longer anomalous.
        let r2 = e.fuse(RiskBitset::DEBUGGER);
        assert!(!r2.anomaly);
        // A brand-new signal → anomaly again.
        let r3 = e.fuse(RiskBitset::DEBUGGER | RiskBitset::ROOT);
        assert!(r3.anomaly);
    }

    #[test]
    fn window_evicts_old_observations() {
        // A 1-slot window only remembers the immediately preceding observation.
        let mut e = RiskEngine::new(policy(), 1);
        e.fuse(RiskBitset::ROOT); // window: [ROOT]
        e.fuse(RiskBitset::DEBUGGER); // evicts ROOT; window: [DEBUGGER]
        // ROOT has aged out, so it re-emerges as anomalous.
        let r = e.fuse(RiskBitset::ROOT);
        assert!(r.anomaly);
    }

    #[test]
    fn composite_level_scales_with_score() {
        let mut e = RiskEngine::new(policy(), DEFAULT_WINDOW);
        let r = e.fuse(RiskBitset::HOOKING | RiskBitset::DEBUGGER | RiskBitset::ROOT);
        // 60 + 30 + 25 = 115 → CRITICAL.
        assert_eq!(r.score, 115);
        assert_eq!(r.level, TrustLevel::Critical);
    }
}
