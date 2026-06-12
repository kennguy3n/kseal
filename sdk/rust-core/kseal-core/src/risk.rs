//! Packed risk signals, weighted scoring, and confidence derivation.
//!
//! [`RiskBitset`] is a `u64` newtype (via [`bitflags`]) carrying one bit per
//! risk signal. The bit layout is part of the cross-platform contract: the
//! Android and iOS SDKs set these exact bits when they pack native probe
//! results, and the server decodes the same layout from
//! [`crate::proto::RiskBitset`]. **Do not renumber existing bits** — only
//! append new signals at higher positions.
//!
//! ## Bit layout
//!
//! | Bit | Flag | Meaning |
//! |----:|------|---------|
//! | 0 | `ROOT` | Android root (su/Magisk) detected |
//! | 1 | `JAILBREAK` | iOS jailbreak detected |
//! | 2 | `EMULATOR` | Running under an Android emulator |
//! | 3 | `SIMULATOR` | Running under the iOS simulator |
//! | 4 | `DEBUGGER` | A debugger is attached |
//! | 5 | `HOOKING` | Hooking framework (Frida/Xposed/objection) present |
//! | 6 | `TAMPER` | Runtime in-memory tamper (code/section checksum) |
//! | 7 | `APP_INTEGRITY` | App-integrity mismatch (repackage/resign) |
//! | 8 | `NETWORK_MITM` | Network MITM / interception detected |
//! | 9 | `ENVIRONMENT` | Generic elevated-environment risk |
//! | 10 | `PROXY` | A system HTTP proxy is configured |
//! | 11 | `USER_CA` | A user-installed CA is trusted |
//! | 12 | `PINNING_FAILURE` | TLS certificate pinning failed |
//! | 13 | `ATTESTATION_FAIL` | Platform attestation failed/unavailable |
//! | 14 | `SECURE_HW_MISSING` | Hardware-backed keystore unavailable |
//! | 15 | `REPACKAGED` | Signing certificate mismatch |

use crate::proto::Confidence;
use std::collections::HashMap;

bitflags::bitflags! {
    /// Packed set of risk signals observed on-device.
    ///
    /// Backed by a `u64`; see the [module docs](self) for the authoritative
    /// bit layout shared with the platform SDKs and the server.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct RiskBitset: u64 {
        /// Android root (su/Magisk) detected.
        const ROOT = 1 << 0;
        /// iOS jailbreak detected.
        const JAILBREAK = 1 << 1;
        /// Running under an Android emulator.
        const EMULATOR = 1 << 2;
        /// Running under the iOS simulator.
        const SIMULATOR = 1 << 3;
        /// A debugger is attached.
        const DEBUGGER = 1 << 4;
        /// Hooking framework (Frida/Xposed/objection) present.
        const HOOKING = 1 << 5;
        /// Runtime in-memory tamper (code/section checksum mismatch).
        const TAMPER = 1 << 6;
        /// App-integrity mismatch (repackaging / resigning).
        const APP_INTEGRITY = 1 << 7;
        /// Network MITM / interception detected.
        const NETWORK_MITM = 1 << 8;
        /// Generic elevated-environment risk.
        const ENVIRONMENT = 1 << 9;
        /// A system HTTP proxy is configured.
        const PROXY = 1 << 10;
        /// A user-installed CA is trusted.
        const USER_CA = 1 << 11;
        /// TLS certificate pinning failed.
        const PINNING_FAILURE = 1 << 12;
        /// Platform attestation failed or was unavailable.
        const ATTESTATION_FAIL = 1 << 13;
        /// Hardware-backed keystore/enclave unavailable.
        const SECURE_HW_MISSING = 1 << 14;
        /// Signing certificate mismatch (repackaged binary).
        const REPACKAGED = 1 << 15;
    }
}

/// Highest meaningful bit index, used to bound scoring iteration.
pub const MAX_SIGNAL_BIT: u32 = 15;

/// Weight applied to a set signal bit that has no explicit policy weight.
pub const DEFAULT_SIGNAL_WEIGHT: u32 = 10;

impl RiskBitset {
    /// Builds a bitset from a raw `u64`, preserving every bit (including any
    /// not yet named here so forward-compatible signals survive a round trip).
    #[must_use]
    pub fn from_raw(bits: u64) -> Self {
        Self::from_bits_retain(bits)
    }

    /// Returns the raw `u64` representation for the wire / FFI boundary.
    #[must_use]
    pub fn as_u64(self) -> u64 {
        self.bits()
    }

    /// Number of signal bits set.
    #[must_use]
    pub fn count(self) -> u32 {
        self.bits().count_ones()
    }

    /// Whether no signals are set (a clean observation).
    #[must_use]
    pub fn is_clean(self) -> bool {
        self.bits() == 0
    }

    /// Weighted score = sum of per-bit weights for every set bit.
    ///
    /// `weights` maps a bit *index* (0-based) to its weight; bits without an
    /// entry contribute [`DEFAULT_SIGNAL_WEIGHT`]. Addition saturates so a
    /// hostile policy can never overflow the score.
    ///
    /// Iterates only the *set* bits (clearing the lowest set bit each step via
    /// `bits & (bits - 1)`) rather than scanning all 64 positions, so the cost
    /// scales with the number of active signals — typically a handful — on this
    /// per-evaluation hot path.
    #[must_use]
    pub fn weighted_score(self, weights: &HashMap<u32, u32>) -> u32 {
        let mut bits = self.bits();
        let mut score: u32 = 0;
        while bits != 0 {
            let idx = bits.trailing_zeros();
            let w = weights.get(&idx).copied().unwrap_or(DEFAULT_SIGNAL_WEIGHT);
            score = score.saturating_add(w);
            bits &= bits - 1; // clear the lowest set bit
        }
        score
    }

    /// Derives a coarse [`Confidence`] from how many signals corroborate.
    ///
    /// More independent signals make a false positive less likely:
    /// 0 → `HIGH` (unambiguously clean), 1 → `LOW` (single, possibly spurious),
    /// 2 → `MEDIUM`, 3+ → `HIGH`.
    #[must_use]
    pub fn confidence(self) -> Confidence {
        match self.count() {
            0 => Confidence::High,
            1 => Confidence::Low,
            2 => Confidence::Medium,
            _ => Confidence::High,
        }
    }
}

/// A computed risk assessment: the originating bits, their weighted score, and
/// a derived confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiskScore {
    /// The signals this score was computed from.
    pub bits: RiskBitset,
    /// Weighted score (sum of per-bit weights).
    pub score: u32,
    /// Coarse confidence in the assessment.
    pub confidence: Confidence,
}

impl RiskScore {
    /// Computes a [`RiskScore`] for `bits` using the supplied per-bit weights.
    #[must_use]
    pub fn compute(bits: RiskBitset, weights: &HashMap<u32, u32>) -> Self {
        Self {
            bits,
            score: bits.weighted_score(weights),
            confidence: bits.confidence(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn weights(pairs: &[(u32, u32)]) -> HashMap<u32, u32> {
        pairs.iter().copied().collect()
    }

    #[test]
    fn raw_round_trip_preserves_unknown_bits() {
        let raw = 0b1010_0000_0000_0000_0001u64 | (1u64 << 40);
        assert_eq!(RiskBitset::from_raw(raw).as_u64(), raw);
    }

    #[test]
    fn bit_positions_are_stable() {
        assert_eq!(RiskBitset::ROOT.bits(), 1);
        assert_eq!(RiskBitset::DEBUGGER.bits(), 1 << 4);
        assert_eq!(RiskBitset::REPACKAGED.bits(), 1 << 15);
    }

    #[test]
    fn weighted_score_uses_default_for_unweighted_bits() {
        let b = RiskBitset::ROOT | RiskBitset::HOOKING;
        // ROOT weighted 50, HOOKING falls back to default.
        let w = weights(&[(0, 50)]);
        assert_eq!(b.weighted_score(&w), 50 + DEFAULT_SIGNAL_WEIGHT);
    }

    #[test]
    fn empty_bitset_scores_zero() {
        assert_eq!(RiskBitset::empty().weighted_score(&HashMap::new()), 0);
        assert!(RiskBitset::empty().is_clean());
    }

    #[test]
    fn weighted_score_saturates() {
        let b = RiskBitset::ROOT | RiskBitset::DEBUGGER;
        let w = weights(&[(0, u32::MAX), (4, 5)]);
        assert_eq!(b.weighted_score(&w), u32::MAX);
    }

    #[test]
    fn confidence_scales_with_corroboration() {
        assert_eq!(RiskBitset::empty().confidence(), Confidence::High);
        assert_eq!(RiskBitset::ROOT.confidence(), Confidence::Low);
        assert_eq!(
            (RiskBitset::ROOT | RiskBitset::PROXY).confidence(),
            Confidence::Medium
        );
        assert_eq!(
            (RiskBitset::ROOT | RiskBitset::PROXY | RiskBitset::DEBUGGER).confidence(),
            Confidence::High
        );
    }

    #[test]
    fn risk_score_compute() {
        let b = RiskBitset::DEBUGGER | RiskBitset::PROXY;
        let s = RiskScore::compute(b, &weights(&[(4, 30), (10, 5)]));
        assert_eq!(s.score, 35);
        assert_eq!(s.confidence, Confidence::Medium);
        assert_eq!(s.bits, b);
    }
}
