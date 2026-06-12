//! Telemetry event construction, the on-device privacy guard, and batching.
//!
//! Events are deliberately tiny and carry **no raw PII**: identity is reduced to
//! a tenant-scoped install-key hash and time is coarsened to a bucket. The
//! [`PrivacyGuard`] is the last line of data minimization before anything
//! enters a batch — it denies disallowed event types, masks off risk bits that
//! the tenant's privacy policy forbids exporting, and strips coarse geography
//! when disallowed.

use crate::proto::{Compression, Confidence, EventType, Platform, TelemetryBatch, TelemetryEvent};
use crate::risk::RiskBitset;
use std::collections::HashSet;

/// Inputs needed to build a single [`TelemetryEvent`] from raw native signals.
#[derive(Debug, Clone)]
pub struct EventInput {
    /// Canonical category of the observation.
    pub event_type: EventType,
    /// Packed risk signals observed.
    pub risk_bits: RiskBitset,
    /// Coarse confidence in the observation.
    pub confidence: Confidence,
    /// Content hash of the running build.
    pub app_build_hash: String,
    /// Hash of the active policy that produced this observation.
    pub policy_hash: String,
    /// Tenant-scoped HMAC of the install key (never the raw install id).
    pub tenant_scoped_install_key_hash: String,
    /// Unix-millis truncated to a coarse bucket (e.g. the hour).
    pub coarse_time_bucket: i64,
    /// Optional coarse geography (country/region), subject to the privacy guard.
    pub country_or_region: Option<String>,
}

/// Builds a [`TelemetryEvent`] from raw signal inputs.
///
/// This performs no minimization itself — run the result through a
/// [`PrivacyGuard`] (or add it to an [`EventBatch`], which guards on insert).
#[must_use]
pub fn build_event(input: EventInput) -> TelemetryEvent {
    TelemetryEvent {
        event_type: input.event_type as i32,
        risk_bits: input.risk_bits.as_u64(),
        confidence: input.confidence as i32,
        app_build_hash: input.app_build_hash,
        policy_hash: input.policy_hash,
        tenant_scoped_install_key_hash: input.tenant_scoped_install_key_hash,
        coarse_time_bucket: input.coarse_time_bucket,
        country_or_region: input.country_or_region,
    }
}

/// On-device data-minimization filter applied before events enter a batch.
#[derive(Debug, Clone)]
pub struct PrivacyGuard {
    allowed_event_types: HashSet<i32>,
    allowed_risk_mask: u64,
    allow_country: bool,
}

impl PrivacyGuard {
    /// A guard that allows everything — only suitable for tests/tools, never a
    /// privacy-conscious production default.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            allowed_event_types: HashSet::new(),
            allowed_risk_mask: u64::MAX,
            allow_country: true,
        }
    }

    /// Builds a guard from an explicit allow-list.
    ///
    /// * `allowed_event_types` — event types permitted to leave the device. An
    ///   empty set means *all* types are allowed (so a misconfigured guard
    ///   never silently drops everything).
    /// * `allowed_risk_mask` — bits permitted on exported events; others are
    ///   masked off.
    /// * `allow_country` — whether coarse geography may be retained.
    #[must_use]
    pub fn new(
        allowed_event_types: impl IntoIterator<Item = EventType>,
        allowed_risk_mask: RiskBitset,
        allow_country: bool,
    ) -> Self {
        Self {
            allowed_event_types: allowed_event_types.into_iter().map(|e| e as i32).collect(),
            allowed_risk_mask: allowed_risk_mask.as_u64(),
            allow_country,
        }
    }

    /// Whether `event_type` is permitted to be exported.
    #[must_use]
    pub fn allows_type(&self, event_type: i32) -> bool {
        self.allowed_event_types.is_empty() || self.allowed_event_types.contains(&event_type)
    }

    /// Applies the guard to an event.
    ///
    /// Returns `None` if the event's type is denied; otherwise returns the
    /// event with disallowed risk bits masked off and geography stripped when
    /// disallowed.
    #[must_use]
    pub fn sanitize(&self, mut event: TelemetryEvent) -> Option<TelemetryEvent> {
        if !self.allows_type(event.event_type) {
            return None;
        }
        event.risk_bits &= self.allowed_risk_mask;
        if !self.allow_country {
            event.country_or_region = None;
        }
        Some(event)
    }
}

/// A size-bounded accumulator of privacy-guarded events that seals into a
/// [`TelemetryBatch`].
#[derive(Debug, Clone)]
pub struct EventBatch {
    events: Vec<TelemetryEvent>,
    guard: PrivacyGuard,
    max_events: usize,
    sdk_version: String,
    platform: Platform,
}

/// Reason an event was not added to a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// The batch already holds `max_events`.
    Full,
    /// The privacy guard denied the event's type.
    Denied,
}

impl EventBatch {
    /// Creates an empty batch with a capacity ceiling and privacy guard.
    #[must_use]
    pub fn new(
        guard: PrivacyGuard,
        max_events: usize,
        sdk_version: impl Into<String>,
        platform: Platform,
    ) -> Self {
        Self {
            events: Vec::new(),
            guard,
            max_events: max_events.max(1),
            sdk_version: sdk_version.into(),
            platform,
        }
    }

    /// Number of events currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the batch holds no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Whether the batch has reached its capacity ceiling.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.events.len() >= self.max_events
    }

    /// Guards and appends `event`.
    ///
    /// # Errors
    /// Returns [`RejectReason::Full`] when at capacity or
    /// [`RejectReason::Denied`] when the privacy guard drops the event.
    pub fn add(&mut self, event: TelemetryEvent) -> core::result::Result<(), RejectReason> {
        if self.is_full() {
            return Err(RejectReason::Full);
        }
        match self.guard.sanitize(event) {
            Some(e) => {
                self.events.push(e);
                Ok(())
            }
            None => Err(RejectReason::Denied),
        }
    }

    /// Consumes the batch into a [`TelemetryBatch`] message.
    ///
    /// `compression` records how the wire payload will be encoded; the returned
    /// message itself is uncompressed (compression happens in
    /// [`crate::transport`]).
    #[must_use]
    pub fn seal(self, compression: Compression) -> TelemetryBatch {
        TelemetryBatch {
            events: self.events,
            sdk_version: self.sdk_version,
            compression: compression as i32,
            compression_dictionary_id: String::new(),
            platform: self.platform as i32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input(event_type: EventType) -> EventInput {
        EventInput {
            event_type,
            risk_bits: RiskBitset::ROOT | RiskBitset::NETWORK_MITM,
            confidence: Confidence::Medium,
            app_build_hash: "build".into(),
            policy_hash: "policy".into(),
            tenant_scoped_install_key_hash: "hash".into(),
            coarse_time_bucket: 1_700_000_000,
            country_or_region: Some("US".into()),
        }
    }

    #[test]
    fn build_event_maps_fields() {
        let e = build_event(sample_input(EventType::RootRisk));
        assert_eq!(e.event_type, EventType::RootRisk as i32);
        assert_eq!(e.risk_bits, (RiskBitset::ROOT | RiskBitset::NETWORK_MITM).as_u64());
        assert_eq!(e.country_or_region.as_deref(), Some("US"));
    }

    #[test]
    fn guard_denies_disallowed_type() {
        let guard = PrivacyGuard::new([EventType::Debugger], RiskBitset::all(), true);
        let e = build_event(sample_input(EventType::RootRisk));
        assert!(guard.sanitize(e).is_none());
    }

    #[test]
    fn guard_masks_risk_bits_and_strips_country() {
        let guard = PrivacyGuard::new([EventType::RootRisk], RiskBitset::ROOT, false);
        let e = build_event(sample_input(EventType::RootRisk));
        let s = guard.sanitize(e).unwrap();
        // NETWORK_MITM is masked off; only ROOT survives.
        assert_eq!(s.risk_bits, RiskBitset::ROOT.as_u64());
        assert_eq!(s.country_or_region, None);
    }

    #[test]
    fn batch_enforces_capacity_and_guard() {
        let guard = PrivacyGuard::new([EventType::RootRisk], RiskBitset::all(), true);
        let mut batch = EventBatch::new(guard, 2, "1.0", Platform::Android);
        assert!(batch.add(build_event(sample_input(EventType::RootRisk))).is_ok());
        // Denied type.
        assert_eq!(
            batch.add(build_event(sample_input(EventType::Debugger))),
            Err(RejectReason::Denied)
        );
        assert!(batch.add(build_event(sample_input(EventType::RootRisk))).is_ok());
        // Now full.
        assert_eq!(
            batch.add(build_event(sample_input(EventType::RootRisk))),
            Err(RejectReason::Full)
        );
        assert_eq!(batch.len(), 2);
        let sealed = batch.seal(Compression::Zstd);
        assert_eq!(sealed.events.len(), 2);
        assert_eq!(sealed.compression, Compression::Zstd as i32);
        assert_eq!(sealed.platform, Platform::Android as i32);
    }
}
