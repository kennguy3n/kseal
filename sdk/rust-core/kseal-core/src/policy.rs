//! Device-side policy evaluation.
//!
//! Wraps the signed [`proto::PolicyConfig`] and turns a [`RiskBitset`] into an
//! enforcement decision. Evaluation is deterministic and ordered: rules are
//! tried top-to-bottom and the first one that fires wins, mirroring how the
//! server evaluates the same policy.
//!
//! The local decision is advisory. The authoritative `observe → step-up →
//! block` decision is always made server-side; the [`crate::risk_engine`] caps
//! the *local* response so the device never hard-blocks on its own.

use crate::proto::{EnforcementMode, PolicyConfig, TrustLevel};
use crate::risk::RiskBitset;

/// Maps a logical module identifier (as used in `PolicyConfig.modules_enabled`)
/// to the risk bits it produces. Ordering is irrelevant; the union is used.
fn module_bits(module: &str) -> RiskBitset {
    match module {
        "root" => RiskBitset::ROOT,
        "jailbreak" => RiskBitset::JAILBREAK,
        "emulator" => RiskBitset::EMULATOR,
        "simulator" => RiskBitset::SIMULATOR,
        "debugger" => RiskBitset::DEBUGGER,
        "hooking" => RiskBitset::HOOKING,
        "tamper" => RiskBitset::TAMPER,
        "app_integrity" => RiskBitset::APP_INTEGRITY | RiskBitset::REPACKAGED,
        "network_mitm" => {
            RiskBitset::NETWORK_MITM
                | RiskBitset::PROXY
                | RiskBitset::USER_CA
                | RiskBitset::PINNING_FAILURE
        }
        "environment" => {
            RiskBitset::ENVIRONMENT
                | RiskBitset::EMULATOR
                | RiskBitset::SIMULATOR
                | RiskBitset::SECURE_HW_MISSING
        }
        "attestation" => RiskBitset::ATTESTATION_FAIL,
        _ => RiskBitset::empty(),
    }
}

/// Short `TrustLevel` names, ascending in severity, used as `risk_thresholds`
/// map keys (e.g. `"MEDIUM_RISK" -> 40`).
const THRESHOLD_LEVELS: [(&str, TrustLevel); 5] = [
    ("TRUSTED", TrustLevel::Trusted),
    ("LOW_RISK", TrustLevel::LowRisk),
    ("MEDIUM_RISK", TrustLevel::MediumRisk),
    ("HIGH_RISK", TrustLevel::HighRisk),
    ("CRITICAL", TrustLevel::Critical),
];

/// Outcome of evaluating a policy against a risk bitset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    /// The selected enforcement posture.
    pub mode: EnforcementMode,
    /// Identifier of the rule that fired, or `None` when the default applied.
    pub matched_rule_id: Option<String>,
    /// Weighted score of the (module-filtered) bits at decision time.
    pub score: u32,
}

/// An evaluable wrapper around a [`PolicyConfig`].
#[derive(Debug, Clone)]
pub struct Policy {
    config: PolicyConfig,
    enabled_mask: RiskBitset,
}

impl Policy {
    /// Wraps a [`PolicyConfig`], precomputing the enabled-module signal mask.
    ///
    /// An empty `modules_enabled` list means **all** modules are enabled
    /// (no filtering), which keeps a minimal policy fail-safe rather than
    /// silently dropping every signal. The "allow all" mask is `u64::MAX`
    /// (via [`RiskBitset::from_raw`]) rather than `RiskBitset::all()`: the
    /// latter only covers the *named* bits (0–15), which would silently drop
    /// forward-compatible signal bits added at higher positions later.
    #[must_use]
    pub fn new(config: PolicyConfig) -> Self {
        let enabled_mask = if config.modules_enabled.is_empty() {
            RiskBitset::from_raw(u64::MAX)
        } else {
            config
                .modules_enabled
                .iter()
                .fold(RiskBitset::empty(), |acc, m| acc | module_bits(m))
        };
        Self {
            config,
            enabled_mask,
        }
    }

    /// The wrapped configuration.
    #[must_use]
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// Whether `module` is enabled for this policy.
    #[must_use]
    pub fn is_module_enabled(&self, module: &str) -> bool {
        self.config.modules_enabled.is_empty()
            || self.config.modules_enabled.iter().any(|m| m == module)
    }

    /// Drops signal bits belonging to disabled modules.
    #[must_use]
    pub fn filter_signals(&self, bits: RiskBitset) -> RiskBitset {
        bits & self.enabled_mask
    }

    /// Weighted score of `bits` after module filtering.
    #[must_use]
    pub fn score(&self, bits: RiskBitset) -> u32 {
        self.filter_signals(bits)
            .weighted_score(&self.config.signal_weights)
    }

    /// Maps a weighted `score` to the highest [`TrustLevel`] whose configured
    /// threshold it meets. Unconfigured levels are skipped; a score below every
    /// threshold is [`TrustLevel::Trusted`].
    #[must_use]
    pub fn trust_level_for_score(&self, score: u32) -> TrustLevel {
        let mut level = TrustLevel::Trusted;
        for (name, lvl) in THRESHOLD_LEVELS {
            if let Some(&threshold) = self.config.risk_thresholds.get(name) {
                if score >= threshold {
                    level = lvl;
                }
            }
        }
        level
    }

    /// Evaluates the ordered rules against `bits` and returns the decision.
    ///
    /// A rule fires when it shares at least one set bit with `bits` *and* the
    /// weighted score of those shared bits meets its `min_score` (a `min_score`
    /// of `0` fires on any shared bit). The first firing rule wins; if none
    /// fire, the policy's `default_mode` applies.
    #[must_use]
    pub fn evaluate(&self, bits: RiskBitset) -> PolicyDecision {
        let filtered = self.filter_signals(bits);
        let total_score = filtered.weighted_score(&self.config.signal_weights);

        for rule in &self.config.rules {
            let masked = RiskBitset::from_raw(filtered.as_u64() & rule.risk_mask);
            if masked.is_clean() {
                continue;
            }
            let masked_score = masked.weighted_score(&self.config.signal_weights);
            if masked_score >= rule.min_score {
                return PolicyDecision {
                    mode: rule.action(),
                    matched_rule_id: Some(rule.id.clone()),
                    score: total_score,
                };
            }
        }

        PolicyDecision {
            mode: self.default_mode(),
            matched_rule_id: None,
            score: total_score,
        }
    }

    /// The configured default enforcement mode, normalizing the proto's
    /// `UNSPECIFIED` to the safe `OBSERVE` posture.
    #[must_use]
    pub fn default_mode(&self) -> EnforcementMode {
        match self.config.default_mode() {
            EnforcementMode::Unspecified => EnforcementMode::Observe,
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::PolicyRule;
    use std::collections::HashMap;

    fn rule(id: &str, mask: u64, min_score: u32, action: EnforcementMode) -> PolicyRule {
        PolicyRule {
            id: id.to_string(),
            risk_mask: mask,
            min_score,
            action: action as i32,
            description: String::new(),
        }
    }

    fn base_config() -> PolicyConfig {
        let mut weights = HashMap::new();
        weights.insert(4, 30); // DEBUGGER
        weights.insert(5, 60); // HOOKING
        weights.insert(0, 25); // ROOT
        let mut thresholds = HashMap::new();
        thresholds.insert("LOW_RISK".to_string(), 10);
        thresholds.insert("MEDIUM_RISK".to_string(), 40);
        thresholds.insert("HIGH_RISK".to_string(), 70);
        thresholds.insert("CRITICAL".to_string(), 100);
        PolicyConfig {
            rules: vec![
                rule(
                    "block-hooking",
                    RiskBitset::HOOKING.as_u64(),
                    0,
                    EnforcementMode::Block,
                ),
                rule(
                    "stepup-debugger",
                    RiskBitset::DEBUGGER.as_u64(),
                    20,
                    EnforcementMode::StepUp,
                ),
            ],
            risk_thresholds: thresholds,
            default_mode: EnforcementMode::Observe as i32,
            modules_enabled: vec![],
            signal_weights: weights,
            policy_hash: "h1".to_string(),
        }
    }

    #[test]
    fn first_matching_rule_wins() {
        let p = Policy::new(base_config());
        let d = p.evaluate(RiskBitset::HOOKING | RiskBitset::DEBUGGER);
        assert_eq!(d.mode, EnforcementMode::Block);
        assert_eq!(d.matched_rule_id.as_deref(), Some("block-hooking"));
    }

    #[test]
    fn min_score_gates_rule_firing() {
        let p = Policy::new(base_config());
        // DEBUGGER weight 30 >= min_score 20 → step up.
        let d = p.evaluate(RiskBitset::DEBUGGER);
        assert_eq!(d.mode, EnforcementMode::StepUp);
        assert_eq!(d.matched_rule_id.as_deref(), Some("stepup-debugger"));
    }

    #[test]
    fn no_rule_uses_default_mode() {
        let p = Policy::new(base_config());
        let d = p.evaluate(RiskBitset::PROXY);
        assert_eq!(d.mode, EnforcementMode::Observe);
        assert_eq!(d.matched_rule_id, None);
    }

    #[test]
    fn disabled_module_signals_are_filtered() {
        let mut cfg = base_config();
        cfg.modules_enabled = vec!["debugger".to_string()]; // hooking disabled
        let p = Policy::new(cfg);
        // HOOKING is filtered out, so its rule cannot fire; DEBUGGER still does.
        let d = p.evaluate(RiskBitset::HOOKING | RiskBitset::DEBUGGER);
        assert_eq!(d.mode, EnforcementMode::StepUp);
    }

    #[test]
    fn trust_level_thresholds() {
        let p = Policy::new(base_config());
        assert_eq!(p.trust_level_for_score(0), TrustLevel::Trusted);
        assert_eq!(p.trust_level_for_score(10), TrustLevel::LowRisk);
        assert_eq!(p.trust_level_for_score(55), TrustLevel::MediumRisk);
        assert_eq!(p.trust_level_for_score(70), TrustLevel::HighRisk);
        assert_eq!(p.trust_level_for_score(150), TrustLevel::Critical);
    }

    #[test]
    fn empty_modules_enables_all() {
        let p = Policy::new(base_config());
        assert!(p.is_module_enabled("anything"));
        assert_eq!(p.filter_signals(RiskBitset::all()), RiskBitset::all());
    }

    #[test]
    fn empty_modules_preserves_forward_compat_bits() {
        // With no modules listed ("all enabled"), the mask must not drop
        // forward-compatible signal bits above the named range (0–15).
        let p = Policy::new(base_config());
        let future = RiskBitset::from_raw(1u64 << 40) | RiskBitset::ROOT;
        assert_eq!(
            p.filter_signals(future),
            future,
            "unnamed high bits must survive when all modules are enabled"
        );
    }
}
