//! kseal device trust core.
//!
//! This crate implements the device-side trust logic shared by the Android and
//! iOS SDKs: policy evaluation, risk scoring, privacy-minimized telemetry,
//! config signature verification, and per-request proof generation. It contains
//! no platform-specific probe code — that lives in the platform SDKs and feeds
//! signals into this core as a packed [`risk::RiskBitset`].
//!
//! The protobuf wire types are generated from `proto/` at build time (see
//! `build.rs`) and re-exported under [`proto`].
//!
//! # Layout
//!
//! - [`risk`] — packed signal bitset, weighted scoring, confidence.
//! - [`policy`] — ordered rule evaluation and trust-level thresholds.
//! - [`crypto`] — Ed25519 verification, HMAC request proofs, nonces.
//! - [`config`] — signed-config verification and TTL caching.
//! - [`events`] — event construction, privacy guard, batching.
//! - [`transport`] — protobuf + zstd serialization and retry policy.
//! - [`risk_engine`] — Phase 2 signal fusion with anomaly detection.
//!
//! [`KsealCore`] ties these together behind the surface the FFI layer exposes.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Protobuf-generated wire types (`kseal.v1`).
pub mod proto {
    #![allow(missing_docs)]
    include!(concat!(env!("OUT_DIR"), "/kseal.v1.rs"));
}

pub mod config;
pub mod crypto;
pub mod events;
pub mod policy;
pub mod risk;
pub mod risk_engine;
pub mod transport;

use crate::config::ConfigCache;
use crate::events::{EventBatch, EventInput, PrivacyGuard};
use crate::policy::Policy;
use crate::proto::{Compression, Platform, RequestProof, SignedConfig, TelemetryEvent};
use crate::risk::{RiskBitset, RiskScore};
use crate::risk_engine::{FusedRisk, RiskEngine};
use prost::Message;
use std::collections::HashMap;

/// Crate-wide error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A protobuf message failed to decode.
    #[error("decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    /// A protobuf message failed to encode.
    #[error("encode error: {0}")]
    Encode(#[from] prost::EncodeError),
    /// A cryptographic verification or operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// Configuration was missing, malformed, or expired.
    #[error("config error: {0}")]
    Config(String),
    /// Serialization or compression on the transport path failed.
    #[error("transport error: {0}")]
    Transport(String),
}

/// Convenience result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Crate version string, surfaced to telemetry as the SDK version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the current wall-clock time in whole Unix seconds.
///
/// Used to stamp/age the config cache. The platform may instead call the
/// `*_at` variants with its own clock for deterministic control.
#[must_use]
pub fn now_unix_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Immutable configuration for a [`KsealCore`] instance.
#[derive(Debug, Clone)]
pub struct CoreConfig {
    /// Ed25519 public key used to verify signed configs.
    pub config_public_key: Vec<u8>,
    /// Instance HMAC key for request proofs (hardware-bound in the platform SDK).
    pub proof_key: Vec<u8>,
    /// SDK version string stamped onto telemetry batches.
    pub sdk_version: String,
    /// Reporting platform.
    pub platform: Platform,
    /// Data-minimization guard applied to telemetry.
    pub privacy_guard: PrivacyGuard,
    /// Maximum events per telemetry batch.
    pub max_batch_events: usize,
    /// Sliding-window size for the risk engine's anomaly detection.
    pub risk_window: usize,
    /// zstd level for telemetry compression.
    pub zstd_level: i32,
    /// Optional shared zstd dictionary bytes.
    pub zstd_dictionary: Option<Vec<u8>>,
    /// Identifier of the shared dictionary (recorded on the batch for decode).
    pub zstd_dictionary_id: String,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            config_public_key: Vec::new(),
            proof_key: Vec::new(),
            sdk_version: VERSION.to_string(),
            platform: Platform::Unspecified,
            privacy_guard: PrivacyGuard::permissive(),
            max_batch_events: 64,
            risk_window: risk_engine::DEFAULT_WINDOW,
            zstd_level: transport::DEFAULT_ZSTD_LEVEL,
            zstd_dictionary: None,
            zstd_dictionary_id: String::new(),
        }
    }
}

/// The device-side trust core: holds the verified policy cache and the local
/// risk engine, and exposes the operations consumed by the platform SDKs (and,
/// via `kseal-ffi`, by C callers).
#[derive(Debug, Clone)]
pub struct KsealCore {
    config: CoreConfig,
    cache: ConfigCache,
    engine: Option<RiskEngine>,
}

impl KsealCore {
    /// Creates a core from immutable configuration. No policy is active until
    /// [`KsealCore::load_config`] succeeds.
    #[must_use]
    pub fn new(config: CoreConfig) -> Self {
        Self {
            config,
            cache: ConfigCache::new(),
            engine: None,
        }
    }

    /// Verifies and installs a signed config from its protobuf bytes, stamped
    /// at the current time. Builds the local risk engine on success.
    ///
    /// # Errors
    /// Propagates decode/verification/rollback failures.
    pub fn load_config(&mut self, signed_bytes: &[u8]) -> Result<()> {
        self.load_config_at(signed_bytes, now_unix_secs())
    }

    /// Like [`KsealCore::load_config`] but with a caller-supplied `now`
    /// (Unix seconds) for deterministic caching/testing.
    ///
    /// # Errors
    /// Propagates decode/verification/rollback failures.
    pub fn load_config_at(&mut self, signed_bytes: &[u8], now: i64) -> Result<()> {
        let signed = SignedConfig::decode(signed_bytes)?;
        let cached = self
            .cache
            .update(&signed, &self.config.config_public_key, now)?;
        let policy = cached.policy.clone();
        match self.engine.as_mut() {
            Some(engine) => engine.set_policy(policy),
            None => self.engine = Some(RiskEngine::new(policy, self.config.risk_window)),
        }
        Ok(())
    }

    /// Whether a verified policy is currently active.
    #[must_use]
    pub fn has_policy(&self) -> bool {
        self.engine.is_some()
    }

    /// The active policy, if a config has been loaded.
    #[must_use]
    pub fn policy(&self) -> Option<&Policy> {
        self.engine.as_ref().map(RiskEngine::policy)
    }

    /// Scores `signals` against the active policy's weights. Without a loaded
    /// policy, default per-signal weights apply (and no module filtering).
    #[must_use]
    pub fn evaluate_risk(&self, signals: RiskBitset) -> RiskScore {
        match self.engine.as_ref() {
            Some(engine) => {
                let p = engine.policy();
                RiskScore::compute(p.filter_signals(signals), &p.config().signal_weights)
            }
            None => RiskScore::compute(signals, &HashMap::new()),
        }
    }

    /// Fuses `signals` through the local risk engine (Phase 2). Returns `None`
    /// until a policy is loaded.
    pub fn fuse_risk(&mut self, signals: RiskBitset) -> Option<FusedRisk> {
        self.engine.as_mut().map(|e| e.fuse(signals))
    }

    /// Builds a [`TelemetryEvent`] from raw signals. Field-level minimization
    /// (risk-bit masking, type denial) is applied when the event is batched via
    /// [`KsealCore::batch_and_compress`].
    #[must_use]
    pub fn create_event(&self, input: EventInput) -> TelemetryEvent {
        events::build_event(input)
    }

    /// Privacy-guards `events` into a batch and returns the protobuf+zstd wire
    /// payload. Events whose type the guard denies are dropped.
    ///
    /// # Errors
    /// [`Error::Transport`] if compression fails.
    pub fn batch_and_compress(&self, events: Vec<TelemetryEvent>) -> Result<Vec<u8>> {
        let mut batch = EventBatch::new(
            self.config.privacy_guard.clone(),
            self.config.max_batch_events,
            self.config.sdk_version.clone(),
            self.config.platform,
        );
        for ev in events {
            // Drop denied/over-capacity events; partial batches are valid.
            let _ = batch.add(ev);
        }
        let mut sealed = batch.seal(Compression::Zstd);
        sealed
            .compression_dictionary_id
            .clone_from(&self.config.zstd_dictionary_id);
        transport::compress_batch(
            &sealed,
            self.config.zstd_level,
            self.config.zstd_dictionary.as_deref(),
        )
    }

    /// Generates a per-request proof binding `request_hash` to a trust token
    /// using the instance proof key.
    #[must_use]
    pub fn generate_request_proof(
        &self,
        token_id: &str,
        request_hash: &[u8],
        nonce: &[u8],
        seq: i64,
    ) -> RequestProof {
        crypto::generate_request_proof(&self.config.proof_key, token_id, request_hash, nonce, seq)
    }

    /// Verifies an Ed25519 signature over `config_bytes` with `public_key`.
    #[must_use]
    pub fn verify_config_signature(config_bytes: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        crypto::verify_ed25519(public_key, config_bytes, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Confidence, EnforcementMode, EventType, PolicyConfig};
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_policy(sk: &SigningKey) -> Vec<u8> {
        let mut weights = HashMap::new();
        weights.insert(0, 25); // ROOT
        let policy = PolicyConfig {
            default_mode: EnforcementMode::Observe as i32,
            signal_weights: weights,
            policy_hash: "ph".into(),
            ..Default::default()
        };
        let config_bytes = policy.encode_to_vec();
        let signature = sk.sign(&config_bytes).to_bytes().to_vec();
        SignedConfig {
            config_bytes,
            signature,
            key_id: "k1".into(),
            version: 1,
            ttl_seconds: 3600,
        }
        .encode_to_vec()
    }

    fn core_with(sk: &SigningKey) -> KsealCore {
        KsealCore::new(CoreConfig {
            config_public_key: sk.verifying_key().as_bytes().to_vec(),
            proof_key: b"instance-key".to_vec(),
            platform: Platform::Ios,
            ..Default::default()
        })
    }

    #[test]
    fn load_config_activates_policy() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let mut core = core_with(&sk);
        assert!(!core.has_policy());
        core.load_config_at(&signed_policy(&sk), 100).unwrap();
        assert!(core.has_policy());
        let score = core.evaluate_risk(RiskBitset::ROOT);
        assert_eq!(score.score, 25);
    }

    #[test]
    fn load_config_rejects_bad_key() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let wrong = SigningKey::from_bytes(&[2u8; 32]);
        let mut core = core_with(&wrong);
        assert!(core.load_config_at(&signed_policy(&sk), 0).is_err());
    }

    #[test]
    fn batch_and_compress_roundtrips() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let core = core_with(&sk);
        let ev = core.create_event(EventInput {
            event_type: EventType::RootRisk,
            risk_bits: RiskBitset::ROOT,
            confidence: Confidence::Low,
            app_build_hash: "b".into(),
            policy_hash: "p".into(),
            tenant_scoped_install_key_hash: "h".into(),
            coarse_time_bucket: 1_700_000_000,
            country_or_region: None,
        });
        let wire = core.batch_and_compress(vec![ev]).unwrap();
        let batch = transport::decompress_batch(&wire, None).unwrap();
        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.events[0].risk_bits, RiskBitset::ROOT.as_u64());
    }

    #[test]
    fn request_proof_uses_instance_key() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let core = core_with(&sk);
        let proof = core.generate_request_proof("tok", b"reqhash", b"nonce", 1);
        assert!(crypto::verify_request_proof(b"instance-key", &proof));
        assert_eq!(proof.monotonic_sequence, 1);
    }

    #[test]
    fn verify_config_signature_associated_fn() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let msg = b"bytes";
        let sig = sk.sign(msg).to_bytes().to_vec();
        assert!(KsealCore::verify_config_signature(
            msg,
            &sig,
            sk.verifying_key().as_bytes()
        ));
        assert!(!KsealCore::verify_config_signature(b"other", &sig, sk.verifying_key().as_bytes()));
    }
}
