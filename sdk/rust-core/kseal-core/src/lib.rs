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

// Declared before the modules that use `obfstr!`/`obfstr_string!` so the
// macros are in scope crate-wide.
#[macro_use]
mod obfuscate;

pub mod config;
pub mod crypto;
pub mod events;
pub mod policy;
pub mod risk;
pub mod risk_engine;
pub mod transport;

// Phase 5.3 DECISION SPIKE: selective code-virtualization prototype. Compiled
// only under the default-off `vm-spike` feature; additive and isolated, it is
// not wired into the trust/crypto path or the FFI surface. The standard build is
// byte-for-byte unchanged. See `vmspike` and `docs/virtualization-tier-decision.md`.
#[cfg(feature = "vm-spike")]
pub mod vmspike;

use crate::config::ConfigCache;
use crate::events::{EventBatch, EventInput, PrivacyGuard};
use crate::proto::request_proof_result::Decision;
use crate::proto::{
    Compression, KillSwitchCommand, Platform, RequestProof, SignedConfig, SignedKillSwitch,
    TelemetryEvent, TrustLevel,
};
use crate::risk::{RiskBitset, RiskScore};
use crate::risk_engine::{FusedRisk, RiskEngine};
use prost::Message;
use std::collections::HashMap;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

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
        // Saturate rather than wrap: a clock past i64::MAX seconds (~year 2262)
        // must never produce a negative timestamp, which would make every cached
        // config look prematurely expired.
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
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
///
/// # Thread-safety
///
/// `KsealCore` is internally synchronized and therefore `Sync`: every method
/// takes `&self`, including the mutating ones ([`load_config`](Self::load_config),
/// [`set_privacy_guard`](Self::set_privacy_guard),
/// [`fuse_risk`](Self::fuse_risk)). The mutable runtime state lives behind a
/// [`RwLock`] ([`CoreState`]) so a single shared instance — e.g. the one behind
/// the C ABI's opaque handle — can be read concurrently from many threads while
/// a config reload happens on another, with no external locking and no data
/// race. Reads take a shared lock; the three writers take the exclusive lock,
/// which also serializes concurrent reloads.
///
/// `RwLock` (rather than `ArcSwap`/lock-free snapshots) is deliberate: it adds
/// no dependency, correctly serializes the rare writers, and lets the stateful
/// anomaly-detection window in [`fuse_risk`](Self::fuse_risk) be updated
/// in place under the write lock. The per-request hot paths stay cheap — an
/// uncontended read lock on the mobile single-reader workload — and
/// [`generate_request_proof`](Self::generate_request_proof) reads only immutable
/// config, so it takes no lock at all.
#[derive(Debug)]
pub struct KsealCore {
    /// Immutable per-instance configuration (verification key, proof key, SDK
    /// version, platform, batch/zstd parameters). The privacy guard is mutable
    /// and lives in [`CoreState`] instead; the copy here is only the seed.
    config: CoreConfig,
    /// Mutable runtime state behind a lock so the core is `Sync` and the FFI
    /// handle can be shared across threads. See the type-level docs.
    state: RwLock<CoreState>,
}

/// Mutable runtime state of a [`KsealCore`], guarded by its `RwLock`.
#[derive(Debug)]
struct CoreState {
    /// TTL-bounded cache of the active verified config (rollback-protected).
    cache: ConfigCache,
    /// Local fusion engine; `None` until a config is loaded.
    engine: Option<RiskEngine>,
    /// Active data-minimization guard applied when batching telemetry.
    privacy_guard: PrivacyGuard,
    /// Whether a verified server kill switch is currently in effect. Defaults
    /// to `false` and only flips on a signature-verified command, so an absent,
    /// forged, or undecodable command can never disable the app (fail-safe).
    killed: bool,
    /// Highest kill-switch `version` accepted per scope
    /// `(tenant_id, app_id, build_hash)`, for client-side anti-rollback. A
    /// verified command whose version is below the last seen for its scope is
    /// rejected as a replay; see [`apply_kill_switch`](KsealCore::apply_kill_switch).
    /// In-memory for the process lifetime — the server folds `(command, version)`
    /// into the config `ETag`, so a superseded command is not re-served on a
    /// cold start.
    kill_switch_versions: HashMap<(String, String, String), i64>,
}

impl KsealCore {
    /// Creates a core from immutable configuration. No policy is active until
    /// [`KsealCore::load_config`] succeeds.
    #[must_use]
    pub fn new(config: CoreConfig) -> Self {
        let privacy_guard = config.privacy_guard.clone();
        Self {
            config,
            state: RwLock::new(CoreState {
                cache: ConfigCache::new(),
                engine: None,
                privacy_guard,
                killed: false,
                kill_switch_versions: HashMap::new(),
            }),
        }
    }

    /// Acquires the shared (read) lock over [`CoreState`], recovering from a
    /// poisoned lock.
    ///
    /// Poisoning would only occur if a thread panicked mid-critical-section;
    /// our sections are short and leave the state consistent, and the FFI
    /// boundary already converts panics into an error code, so recovering keeps
    /// a security-critical core usable rather than wedging every later call.
    fn read_state(&self) -> RwLockReadGuard<'_, CoreState> {
        self.state.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Acquires the exclusive (write) lock over [`CoreState`], recovering from
    /// a poisoned lock (see [`read_state`](Self::read_state)).
    fn write_state(&self) -> RwLockWriteGuard<'_, CoreState> {
        self.state.write().unwrap_or_else(|e| e.into_inner())
    }

    /// Installs the tenant's [`PrivacyGuard`], replacing the one set at
    /// construction.
    ///
    /// `kseal_core_new` (FFI) starts with [`PrivacyGuard::permissive`]; the
    /// platform SDK calls this once the tenant's privacy policy is known so the
    /// data-minimization rules actually apply to telemetry batched afterward.
    /// Takes `&self` (interior mutability) so it is sound to call on a shared
    /// instance concurrently with reads from other threads.
    pub fn set_privacy_guard(&self, guard: PrivacyGuard) {
        self.write_state().privacy_guard = guard;
    }

    /// Verifies and installs a signed config from its protobuf bytes, stamped
    /// at the current time. Builds the local risk engine on success.
    ///
    /// # Errors
    /// Propagates decode/verification/rollback failures.
    pub fn load_config(&self, signed_bytes: &[u8]) -> Result<()> {
        self.load_config_at(signed_bytes, now_unix_secs())
    }

    /// Like [`KsealCore::load_config`] but with a caller-supplied `now`
    /// (Unix seconds) for deterministic caching/testing.
    ///
    /// # Errors
    /// Propagates decode/verification/rollback failures.
    pub fn load_config_at(&self, signed_bytes: &[u8], now: i64) -> Result<()> {
        let signed = SignedConfig::decode(signed_bytes)?;
        let mut state = self.write_state();
        let policy = state
            .cache
            .update(&signed, &self.config.config_public_key, now)?
            .policy
            .clone();
        match state.engine.as_mut() {
            Some(engine) => engine.set_policy(policy),
            None => state.engine = Some(RiskEngine::new(policy, self.config.risk_window)),
        }
        Ok(())
    }

    /// Whether a verified policy is currently active.
    #[must_use]
    pub fn has_policy(&self) -> bool {
        self.read_state().engine.is_some()
    }

    /// Scores `signals` against the active policy's weights. Without a loaded
    /// policy, default per-signal weights apply (and no module filtering).
    #[must_use]
    pub fn evaluate_risk(&self, signals: RiskBitset) -> RiskScore {
        match self.read_state().engine.as_ref() {
            Some(engine) => {
                let p = engine.policy();
                RiskScore::compute(p.filter_signals(signals), &p.config().signal_weights)
            }
            None => RiskScore::compute(signals, &HashMap::new()),
        }
    }

    /// Maps `signals` to the composite [`TrustLevel`] under the active policy's
    /// thresholds, or [`TrustLevel::Unspecified`] when no config is loaded.
    ///
    /// Unlike [`evaluate_risk`](Self::evaluate_risk), which always yields a
    /// numeric score (default weights when unconfigured), a trust *level*
    /// requires configured thresholds, so it reports `Unspecified` until a
    /// policy is active.
    #[must_use]
    pub fn trust_level_for(&self, signals: RiskBitset) -> TrustLevel {
        match self.read_state().engine.as_ref() {
            Some(engine) => {
                let p = engine.policy();
                let score =
                    RiskScore::compute(p.filter_signals(signals), &p.config().signal_weights).score;
                p.trust_level_for_score(score)
            }
            None => TrustLevel::Unspecified,
        }
    }

    /// Fuses `signals` through the local risk engine (Phase 2). Returns `None`
    /// until a policy is loaded.
    ///
    /// Takes `&self` (the sliding anomaly-detection window is updated under the
    /// exclusive lock), so it is sound on a shared instance.
    pub fn fuse_risk(&self, signals: RiskBitset) -> Option<FusedRisk> {
        self.write_state().engine.as_mut().map(|e| e.fuse(signals))
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
        // Snapshot the guard under the read lock, then release it before the
        // (relatively slow) zstd compression so reloads aren't blocked on it.
        let privacy_guard = self.read_state().privacy_guard.clone();
        let mut batch = EventBatch::new(
            privacy_guard,
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

    /// Raw Ed25519 verify of `signature` over exactly `config_bytes` with
    /// `public_key` — a general-purpose primitive for callers that hold the
    /// signed bytes and signature directly.
    ///
    /// Note: this is **not** how a [`proto::SignedConfig`] is authenticated.
    /// [`KsealCore::load_config`] verifies the full canonical envelope
    /// (`version || ttl_seconds || key_id || config_bytes`, see
    /// [`crypto::verify_config_envelope`]); passing a `SignedConfig`'s
    /// `config_bytes`/`signature` here would not match, by design.
    #[must_use]
    pub fn verify_config_signature(
        config_bytes: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> bool {
        crypto::verify_ed25519(public_key, config_bytes, signature)
    }

    /// The active policy's opt-in re-attestation cadence in seconds, or `0` when
    /// no policy is loaded or continuous mode is disabled.
    ///
    /// The platform SDKs read this to decide whether to start a background
    /// heartbeat. Because it defaults to `0`, the SDK performs no scheduling —
    /// and therefore no network I/O — until a config explicitly opts in.
    #[must_use]
    pub fn reattest_interval_secs(&self) -> u32 {
        self.read_state()
            .engine
            .as_ref()
            .map_or(0, |e| e.policy().reattest_interval_secs())
    }

    /// Maps `signals` to the host-facing [`Decision`] under the active policy,
    /// mirroring the server's `risk.Decision`. Returns [`Decision::Allow`] when
    /// no policy is loaded (nothing to enforce).
    ///
    /// This lets the SDK surface the same `observe → step-up → block` posture to
    /// its `onTrustDecision` hook during continuous monitoring without
    /// re-implementing — or diverging from — the authoritative server rule.
    #[must_use]
    pub fn decision(&self, signals: RiskBitset) -> Decision {
        match self.read_state().engine.as_ref() {
            Some(engine) => {
                let p = engine.policy();
                let score =
                    RiskScore::compute(p.filter_signals(signals), &p.config().signal_weights).score;
                policy::decision(p.trust_level_for_score(score), p.default_mode())
            }
            None => Decision::Allow,
        }
    }

    /// Atomically resolves both the composite [`TrustLevel`] and the host-facing
    /// [`Decision`] for `signals` under a single read of the active policy,
    /// returning `(Unspecified, Allow)` when no policy is loaded.
    ///
    /// The platform SDKs deliver this pair to `onTrustDecision` together. Doing
    /// the level and decision derivation under one lock acquisition guarantees
    /// they reflect the *same* policy snapshot — calling
    /// [`trust_level_for`](Self::trust_level_for) and [`decision`](Self::decision)
    /// separately could otherwise straddle a concurrent
    /// [`load_config`](Self::load_config) and surface a mismatched pair
    /// (e.g. `(HIGH_RISK, ALLOW)`).
    #[must_use]
    pub fn decision_with_level(&self, signals: RiskBitset) -> (TrustLevel, Decision) {
        match self.read_state().engine.as_ref() {
            Some(engine) => {
                let p = engine.policy();
                let score =
                    RiskScore::compute(p.filter_signals(signals), &p.config().signal_weights).score;
                let level = p.trust_level_for_score(score);
                (level, policy::decision(level, p.default_mode()))
            }
            None => (TrustLevel::Unspecified, Decision::Allow),
        }
    }

    /// Applies a server-issued [`SignedKillSwitch`] (protobuf bytes), updating
    /// the [`is_killed`](Self::is_killed) state, and returns the resulting
    /// killed flag.
    ///
    /// Fail-safe by construction: the state only transitions on a
    /// signature-verified command. An undecodable payload or an invalid
    /// signature is a no-op that preserves the current state, so an absent or
    /// forged command can never disable the app. A verified `DISABLE` kills; a
    /// verified `ENABLE`/`UNSPECIFIED` clears the kill (e.g. a build-scoped
    /// re-enable resolved by the server).
    ///
    /// Anti-rollback: each scope `(tenant_id, app_id, build_hash)` carries a
    /// monotonically increasing `version`. A verified command whose version is
    /// below the highest already accepted for its scope is rejected as a replay
    /// — a no-op that preserves the current state. The version is covered by the
    /// authenticated preimage, so an attacker cannot forge a newer one, and
    /// equal versions are accepted as idempotent re-applies of the same command.
    /// Scopes track versions independently, so a low-version command for one
    /// scope is still honored even if another scope has advanced.
    pub fn apply_kill_switch(&self, signed_bytes: &[u8]) -> bool {
        let Ok(ks) = SignedKillSwitch::decode(signed_bytes) else {
            return self.is_killed();
        };
        if !crypto::verify_kill_switch(&self.config.config_public_key, &ks) {
            return self.is_killed();
        }
        let scope = (ks.tenant_id, ks.app_id, ks.build_hash);
        let mut state = self.write_state();
        if state
            .kill_switch_versions
            .get(&scope)
            .is_some_and(|&last| ks.version < last)
        {
            return state.killed;
        }
        state.kill_switch_versions.insert(scope, ks.version);
        let killed = ks.command == KillSwitchCommand::Disable as i32;
        state.killed = killed;
        killed
    }

    /// Whether a verified server kill switch is currently disabling the app.
    /// Defaults to `false`; see [`apply_kill_switch`](Self::apply_kill_switch).
    #[must_use]
    pub fn is_killed(&self) -> bool {
        self.read_state().killed
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
        let (version, ttl_seconds, key_id) = (1i64, 3600i64, "k1");
        let signature = sk
            .sign(&crypto::signed_config_preimage(
                version,
                ttl_seconds,
                key_id,
                &config_bytes,
            ))
            .to_bytes()
            .to_vec();
        SignedConfig {
            config_bytes,
            signature,
            key_id: key_id.into(),
            version,
            ttl_seconds,
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
        let core = core_with(&sk);
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
        let core = core_with(&wrong);
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
    fn set_privacy_guard_replaces_default() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let core = core_with(&sk);
        // Install a guard that only permits RootRisk events.
        core.set_privacy_guard(PrivacyGuard::new(
            [EventType::RootRisk],
            RiskBitset::from_raw(u64::MAX),
            true,
        ));
        let denied = core.create_event(EventInput {
            event_type: EventType::Debugger,
            risk_bits: RiskBitset::DEBUGGER,
            confidence: Confidence::Low,
            app_build_hash: "b".into(),
            policy_hash: "p".into(),
            tenant_scoped_install_key_hash: "h".into(),
            coarse_time_bucket: 1_700_000_000,
            country_or_region: None,
        });
        let wire = core.batch_and_compress(vec![denied]).unwrap();
        let batch = transport::decompress_batch(&wire, None).unwrap();
        assert!(
            batch.events.is_empty(),
            "guard must drop denied event types"
        );
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
        assert!(!KsealCore::verify_config_signature(
            b"other",
            &sig,
            sk.verifying_key().as_bytes()
        ));
    }

    /// A single shared `&KsealCore` is read from many threads while another
    /// thread reloads config — exercising the internal synchronization that
    /// makes the FFI handle sound to alias. The borrow checker also enforces
    /// here that `KsealCore: Sync` (otherwise `thread::scope` would reject the
    /// shared reference).
    #[test]
    fn concurrent_reads_during_reload_are_sound() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let core = core_with(&sk);
        let signed = signed_policy(&sk);
        std::thread::scope(|s| {
            // Writer: repeatedly reload the (monotonic, same-version) config.
            s.spawn(|| {
                for _ in 0..200 {
                    // Same version reloads are accepted (>= cached version).
                    let _ = core.load_config_at(&signed, 1_000);
                }
            });
            // Readers: evaluate risk and build/compress telemetry concurrently.
            for _ in 0..4 {
                s.spawn(|| {
                    for _ in 0..200 {
                        let _ = core.evaluate_risk(RiskBitset::ROOT | RiskBitset::DEBUGGER);
                        let _ = core.trust_level_for(RiskBitset::ROOT);
                        let _ = core.has_policy();
                    }
                });
            }
        });
        // After the storm a policy is active and scoring uses its weights.
        assert!(core.has_policy());
        assert_eq!(core.evaluate_risk(RiskBitset::ROOT).score, 25);
    }

    /// `KsealCore` must be `Send + Sync` so the FFI handle can be shared across
    /// threads (the mobile SDKs hand the same pointer to concurrent callers).
    #[test]
    fn core_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<KsealCore>();
    }

    /// Builds a signed config in `mode` with a `reattest_interval_secs` cadence
    /// and thresholds/weights that let tests drive specific trust levels.
    fn signed_policy_full(
        sk: &SigningKey,
        mode: EnforcementMode,
        reattest_interval_secs: u32,
    ) -> Vec<u8> {
        let mut weights = HashMap::new();
        weights.insert(0, 100); // ROOT -> high
        weights.insert(4, 50); //  DEBUGGER -> medium
        let mut thresholds = HashMap::new();
        thresholds.insert("MEDIUM_RISK".to_string(), 40u32);
        thresholds.insert("HIGH_RISK".to_string(), 90u32);
        thresholds.insert("CRITICAL".to_string(), 130u32);
        let policy = PolicyConfig {
            default_mode: mode as i32,
            signal_weights: weights,
            risk_thresholds: thresholds,
            policy_hash: "ph".into(),
            reattest_interval_secs,
            ..Default::default()
        };
        let config_bytes = policy.encode_to_vec();
        let (version, ttl_seconds, key_id) = (1i64, 3600i64, "k1");
        let signature = sk
            .sign(&crypto::signed_config_preimage(
                version,
                ttl_seconds,
                key_id,
                &config_bytes,
            ))
            .to_bytes()
            .to_vec();
        SignedConfig {
            config_bytes,
            signature,
            key_id: key_id.into(),
            version,
            ttl_seconds,
        }
        .encode_to_vec()
    }

    fn signed_kill_switch(sk: &SigningKey, command: KillSwitchCommand) -> Vec<u8> {
        let mut ks = SignedKillSwitch {
            tenant_id: "tenant".into(),
            app_id: "app".into(),
            build_hash: "build".into(),
            command: command as i32,
            version: 3,
            issued_at: 1_700_000_000,
            reason: "test".into(),
            signature: Vec::new(),
            key_id: "k1".into(),
        };
        ks.signature = sk
            .sign(&crypto::kill_switch_preimage(&ks))
            .to_bytes()
            .to_vec();
        ks.encode_to_vec()
    }

    fn signed_kill_switch_scoped(
        sk: &SigningKey,
        command: KillSwitchCommand,
        version: i64,
        build_hash: &str,
    ) -> Vec<u8> {
        let mut ks = SignedKillSwitch {
            tenant_id: "tenant".into(),
            app_id: "app".into(),
            build_hash: build_hash.into(),
            command: command as i32,
            version,
            issued_at: 1_700_000_000,
            reason: "test".into(),
            signature: Vec::new(),
            key_id: "k1".into(),
        };
        ks.signature = sk
            .sign(&crypto::kill_switch_preimage(&ks))
            .to_bytes()
            .to_vec();
        ks.encode_to_vec()
    }

    #[test]
    fn reattest_interval_secs_reflects_policy() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let core = core_with(&sk);
        // No policy loaded -> continuous mode off.
        assert_eq!(core.reattest_interval_secs(), 0);
        core.load_config_at(
            &signed_policy_full(&sk, EnforcementMode::Observe, 900),
            100,
        )
        .unwrap();
        assert_eq!(core.reattest_interval_secs(), 900);
    }

    #[test]
    fn decision_mirrors_active_policy() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        // No policy -> nothing to enforce.
        let core = core_with(&sk);
        assert_eq!(core.decision(RiskBitset::ROOT), Decision::Allow);
        assert_eq!(
            core.decision_with_level(RiskBitset::ROOT),
            (crate::proto::TrustLevel::Unspecified, Decision::Allow)
        );

        // Block mode: ROOT (100) -> HIGH_RISK -> Deny; DEBUGGER (50) -> MEDIUM -> StepUp.
        let core = core_with(&sk);
        core.load_config_at(&signed_policy_full(&sk, EnforcementMode::Block, 0), 100)
            .unwrap();
        assert_eq!(core.decision(RiskBitset::ROOT), Decision::Deny);
        assert_eq!(core.decision(RiskBitset::DEBUGGER), Decision::StepUp);
        assert_eq!(core.decision(RiskBitset::empty()), Decision::Allow);

        // decision_with_level returns the same decision as decision(), plus the
        // matching level, from a single policy read.
        use crate::proto::TrustLevel;
        assert_eq!(
            core.decision_with_level(RiskBitset::ROOT),
            (TrustLevel::HighRisk, Decision::Deny)
        );
        assert_eq!(
            core.decision_with_level(RiskBitset::DEBUGGER),
            (TrustLevel::MediumRisk, Decision::StepUp)
        );
        assert_eq!(
            core.decision_with_level(RiskBitset::empty()),
            (TrustLevel::Trusted, Decision::Allow)
        );

        // Observe mode never denies.
        let core = core_with(&sk);
        core.load_config_at(&signed_policy_full(&sk, EnforcementMode::Observe, 0), 100)
            .unwrap();
        assert_eq!(core.decision(RiskBitset::ROOT), Decision::Allow);
    }

    #[test]
    fn kill_switch_is_fail_safe() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let core = core_with(&sk);
        // Default: not killed.
        assert!(!core.is_killed());

        // Undecodable / absent payload: no-op (stays not killed).
        assert!(!core.apply_kill_switch(&[0xff, 0xff, 0xff]));
        assert!(!core.is_killed());

        // A signature made by a different key never disables the app.
        let attacker = SigningKey::from_bytes(&[2u8; 32]);
        assert!(!core.apply_kill_switch(&signed_kill_switch(&attacker, KillSwitchCommand::Disable)));
        assert!(!core.is_killed());

        // A validly-signed DISABLE kills.
        assert!(core.apply_kill_switch(&signed_kill_switch(&sk, KillSwitchCommand::Disable)));
        assert!(core.is_killed());

        // A forged payload can't clear an active kill either.
        assert!(core.apply_kill_switch(&signed_kill_switch(&attacker, KillSwitchCommand::Enable)));
        assert!(core.is_killed());

        // A validly-signed ENABLE clears the kill (server re-enable).
        assert!(!core.apply_kill_switch(&signed_kill_switch(&sk, KillSwitchCommand::Enable)));
        assert!(!core.is_killed());
    }

    #[test]
    fn kill_switch_rejects_rollback() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let core = core_with(&sk);

        // DISABLE at version 5 for the build scope -> killed.
        assert!(core.apply_kill_switch(&signed_kill_switch_scoped(
            &sk,
            KillSwitchCommand::Disable,
            5,
            "build",
        )));
        assert!(core.is_killed());

        // A higher-version ENABLE (6) is accepted and lifts the kill.
        assert!(!core.apply_kill_switch(&signed_kill_switch_scoped(
            &sk,
            KillSwitchCommand::Enable,
            6,
            "build",
        )));
        assert!(!core.is_killed());

        // Replaying the old DISABLE (version 5) is rejected as a rollback: the
        // verified-but-stale command is a no-op and the app stays enabled.
        assert!(!core.apply_kill_switch(&signed_kill_switch_scoped(
            &sk,
            KillSwitchCommand::Disable,
            5,
            "build",
        )));
        assert!(!core.is_killed());

        // The same version (6) is idempotent and still applies; a genuinely new
        // DISABLE must advance the version (7) to take effect.
        assert!(core.apply_kill_switch(&signed_kill_switch_scoped(
            &sk,
            KillSwitchCommand::Disable,
            7,
            "build",
        )));
        assert!(core.is_killed());

        // A different scope (build2) tracks its version independently: a
        // version-1 ENABLE is honored even though "build" has advanced to 7.
        assert!(!core.apply_kill_switch(&signed_kill_switch_scoped(
            &sk,
            KillSwitchCommand::Enable,
            1,
            "build2",
        )));
        assert!(!core.is_killed());
    }
}
