//! End-to-end integration tests exercising the public `kseal-core` surface
//! across module boundaries.

use ed25519_dalek::{Signer, SigningKey};
use kseal_core::config::ConfigCache;
use kseal_core::crypto::{self, verify_request_proof};
use kseal_core::events::{build_event, EventBatch, EventInput, PrivacyGuard, RejectReason};
use kseal_core::policy::Policy;
use kseal_core::proto::{
    Compression, Confidence, EnforcementMode, EventType, Platform, PolicyConfig, PolicyRule,
    SignedConfig, TrustLevel,
};
use kseal_core::risk::RiskBitset;
use kseal_core::transport::{self, RetryPolicy};
use kseal_core::{CoreConfig, KsealCore};
use prost::Message;
use std::collections::HashMap;

fn weights() -> HashMap<u32, u32> {
    let mut w = HashMap::new();
    w.insert(0, 25); // ROOT
    w.insert(4, 30); // DEBUGGER
    w.insert(5, 60); // HOOKING
    w.insert(8, 20); // NETWORK_MITM
    w
}

fn thresholds() -> HashMap<String, u32> {
    let mut t = HashMap::new();
    t.insert("LOW_RISK".into(), 10);
    t.insert("MEDIUM_RISK".into(), 40);
    t.insert("HIGH_RISK".into(), 70);
    t.insert("CRITICAL".into(), 100);
    t
}

fn rule(id: &str, mask: RiskBitset, min_score: u32, action: EnforcementMode) -> PolicyRule {
    PolicyRule {
        id: id.into(),
        risk_mask: mask.as_u64(),
        min_score,
        action: action as i32,
        description: String::new(),
    }
}

fn policy_config() -> PolicyConfig {
    PolicyConfig {
        rules: vec![
            rule("block-hooking", RiskBitset::HOOKING, 0, EnforcementMode::Block),
            rule(
                "stepup-debugger",
                RiskBitset::DEBUGGER,
                25,
                EnforcementMode::StepUp,
            ),
            rule(
                "observe-mitm",
                RiskBitset::NETWORK_MITM,
                0,
                EnforcementMode::Observe,
            ),
        ],
        risk_thresholds: thresholds(),
        default_mode: EnforcementMode::Observe as i32,
        modules_enabled: vec![],
        signal_weights: weights(),
        policy_hash: "policy-hash".into(),
    }
}

fn signed_config(sk: &SigningKey, version: i64, ttl: i64) -> SignedConfig {
    let config_bytes = policy_config().encode_to_vec();
    let signature = sk.sign(&config_bytes).to_bytes().to_vec();
    SignedConfig {
        config_bytes,
        signature,
        key_id: "key-1".into(),
        version,
        ttl_seconds: ttl,
    }
}

// --- Policy evaluation across rule combinations -----------------------------

#[test]
fn policy_evaluation_rule_combinations() {
    let p = Policy::new(policy_config());

    // Highest-priority rule wins even with multiple matches.
    let d = p.evaluate(RiskBitset::HOOKING | RiskBitset::DEBUGGER | RiskBitset::NETWORK_MITM);
    assert_eq!(d.mode, EnforcementMode::Block);
    assert_eq!(d.matched_rule_id.as_deref(), Some("block-hooking"));

    // Debugger below its min_score (30 >= 25) → step up.
    let d = p.evaluate(RiskBitset::DEBUGGER);
    assert_eq!(d.mode, EnforcementMode::StepUp);

    // Network MITM only → observe rule.
    let d = p.evaluate(RiskBitset::NETWORK_MITM);
    assert_eq!(d.mode, EnforcementMode::Observe);
    assert_eq!(d.matched_rule_id.as_deref(), Some("observe-mitm"));

    // No matching signal → default mode, no rule.
    let d = p.evaluate(RiskBitset::PROXY);
    assert_eq!(d.mode, EnforcementMode::Observe);
    assert_eq!(d.matched_rule_id, None);
}

#[test]
fn policy_min_score_boundary() {
    // A rule requiring exactly the debugger weight fires; one above it does not.
    let mut cfg = policy_config();
    cfg.rules = vec![rule(
        "exact",
        RiskBitset::DEBUGGER,
        30,
        EnforcementMode::StepUp,
    )];
    let p = Policy::new(cfg.clone());
    assert_eq!(p.evaluate(RiskBitset::DEBUGGER).mode, EnforcementMode::StepUp);

    cfg.rules = vec![rule(
        "too-high",
        RiskBitset::DEBUGGER,
        31,
        EnforcementMode::StepUp,
    )];
    let p = Policy::new(cfg);
    // Falls through to default OBSERVE.
    assert_eq!(p.evaluate(RiskBitset::DEBUGGER).mode, EnforcementMode::Observe);
}

#[test]
fn trust_level_thresholds_full_range() {
    let p = Policy::new(policy_config());
    assert_eq!(p.trust_level_for_score(0), TrustLevel::Trusted);
    assert_eq!(p.trust_level_for_score(9), TrustLevel::Trusted);
    assert_eq!(p.trust_level_for_score(10), TrustLevel::LowRisk);
    assert_eq!(p.trust_level_for_score(40), TrustLevel::MediumRisk);
    assert_eq!(p.trust_level_for_score(70), TrustLevel::HighRisk);
    assert_eq!(p.trust_level_for_score(1_000), TrustLevel::Critical);
}

// --- Risk scoring edge cases ------------------------------------------------

#[test]
fn risk_scoring_edge_cases() {
    let w = weights();

    // Empty → zero, high confidence (unambiguously clean).
    let clean = RiskBitset::empty();
    assert_eq!(clean.weighted_score(&w), 0);
    assert_eq!(clean.confidence(), Confidence::High);

    // Unknown high bit uses the default weight and survives round-trips.
    let unknown = RiskBitset::from_raw(1 << 40);
    assert_eq!(unknown.weighted_score(&w), kseal_core::risk::DEFAULT_SIGNAL_WEIGHT);
    assert_eq!(unknown.as_u64(), 1 << 40);

    // Single signal → low confidence; multiple → escalating.
    assert_eq!(RiskBitset::ROOT.confidence(), Confidence::Low);
    assert_eq!(
        (RiskBitset::ROOT | RiskBitset::DEBUGGER).confidence(),
        Confidence::Medium
    );
}

// --- Event batching + compression roundtrip ---------------------------------

#[test]
fn event_batch_privacy_guard_and_roundtrip() {
    // Only ROOT_RISK events allowed; only ROOT bit may be exported; no country.
    let guard = PrivacyGuard::new([EventType::RootRisk], RiskBitset::ROOT, false);
    let mut batch = EventBatch::new(guard, 8, "1.2.3", Platform::Ios);

    let allowed = build_event(EventInput {
        event_type: EventType::RootRisk,
        risk_bits: RiskBitset::ROOT | RiskBitset::NETWORK_MITM,
        confidence: Confidence::Medium,
        app_build_hash: "build".into(),
        policy_hash: "policy".into(),
        tenant_scoped_install_key_hash: "khash".into(),
        coarse_time_bucket: 1_700_000_000,
        country_or_region: Some("US".into()),
    });
    batch.add(allowed).unwrap();

    // A disallowed type is denied.
    let denied = build_event(EventInput {
        event_type: EventType::Debugger,
        risk_bits: RiskBitset::DEBUGGER,
        confidence: Confidence::Low,
        app_build_hash: "build".into(),
        policy_hash: "policy".into(),
        tenant_scoped_install_key_hash: "khash".into(),
        coarse_time_bucket: 1_700_000_000,
        country_or_region: None,
    });
    assert_eq!(batch.add(denied), Err(RejectReason::Denied));

    let sealed = batch.seal(Compression::Zstd);
    assert_eq!(sealed.events.len(), 1);
    // Privacy guard masked NETWORK_MITM and stripped the country.
    assert_eq!(sealed.events[0].risk_bits, RiskBitset::ROOT.as_u64());
    assert_eq!(sealed.events[0].country_or_region, None);

    // Compression roundtrip (with and without a shared dictionary).
    let wire = transport::compress_batch(&sealed, transport::DEFAULT_ZSTD_LEVEL, None).unwrap();
    assert_eq!(transport::decompress_batch(&wire, None).unwrap(), sealed);

    let dict = b"shared-zstd-dictionary".to_vec();
    let wire_d =
        transport::compress_batch(&sealed, transport::DEFAULT_ZSTD_LEVEL, Some(&dict)).unwrap();
    assert_eq!(transport::decompress_batch(&wire_d, Some(&dict)).unwrap(), sealed);
}

#[test]
fn retry_policy_backoff() {
    let p = RetryPolicy::default();
    assert!(p.delay_ms(0) <= p.delay_ms(1));
    assert!(p.delay_ms(100) <= p.max_delay_ms);
    assert!(p.should_retry(0));
    assert!(!p.should_retry(p.max_retries));
}

// --- Request-proof generation / verification --------------------------------

#[test]
fn request_proof_generation_and_verification() {
    let key = b"hardware-bound-instance-key";
    let request_hash = crypto::sha256(b"POST /transfer {to:bob,amount:500}");
    let nonce = crypto::generate_nonce(crypto::DEFAULT_NONCE_LEN).unwrap();

    let proof = crypto::generate_request_proof(key, "token-123", &request_hash, &nonce, 42);
    assert_eq!(proof.trust_token_id, "token-123");
    assert_eq!(proof.monotonic_sequence, 42);
    assert!(verify_request_proof(key, &proof));

    // Tampering with any bound field invalidates the proof.
    let mut wrong_seq = proof.clone();
    wrong_seq.monotonic_sequence = 43;
    assert!(!verify_request_proof(key, &wrong_seq));

    let mut wrong_hash = proof.clone();
    wrong_hash.request_hash[0] ^= 0xff;
    assert!(!verify_request_proof(key, &wrong_hash));

    assert!(!verify_request_proof(b"attacker-key", &proof));
}

// --- Config signature verification: valid / invalid / expired ---------------

#[test]
fn config_signature_valid_invalid_expired() {
    let sk = SigningKey::from_bytes(&[11u8; 32]);
    let pk = sk.verifying_key();

    // Valid signature decodes and caches.
    let signed = signed_config(&sk, 1, 3600);
    let cached = kseal_core::config::verify_and_decode(&signed, pk.as_bytes(), 1_000).unwrap();
    assert_eq!(cached.version, 1);
    assert!(!cached.is_expired(2_000));
    // Expired after TTL.
    assert!(cached.is_expired(1_000 + 3600));

    // Invalid signature (wrong key) is rejected.
    let other = SigningKey::from_bytes(&[12u8; 32]);
    assert!(kseal_core::config::verify_and_decode(&signed, other.verifying_key().as_bytes(), 0)
        .is_err());

    // Tampered config bytes invalidate the signature.
    let mut tampered = signed.clone();
    tampered.config_bytes.push(0);
    assert!(kseal_core::config::verify_and_decode(&tampered, pk.as_bytes(), 0).is_err());
}

#[test]
fn config_cache_rejects_rollback_and_tracks_refresh() {
    let sk = SigningKey::from_bytes(&[13u8; 32]);
    let pk = sk.verifying_key();
    let mut cache = ConfigCache::new();

    cache.update(&signed_config(&sk, 5, 100), pk.as_bytes(), 0).unwrap();
    assert!(!cache.needs_refresh(50));
    assert!(cache.needs_refresh(100));

    // Rollback to an older version is rejected; cached version stays.
    assert!(cache.update(&signed_config(&sk, 4, 100), pk.as_bytes(), 0).is_err());
    assert_eq!(cache.current().unwrap().version, 5);
}

// --- Full core lifecycle ----------------------------------------------------

#[test]
fn core_lifecycle_end_to_end() {
    let sk = SigningKey::from_bytes(&[21u8; 32]);
    let mut core = KsealCore::new(CoreConfig {
        config_public_key: sk.verifying_key().as_bytes().to_vec(),
        proof_key: b"proof-key".to_vec(),
        platform: Platform::Android,
        ..Default::default()
    });

    // No policy yet → default-weight scoring still works.
    assert!(!core.has_policy());
    let pre = core.evaluate_risk(RiskBitset::ROOT);
    assert_eq!(pre.score, kseal_core::risk::DEFAULT_SIGNAL_WEIGHT);

    // Load the signed config and re-evaluate with policy weights.
    core.load_config_at(&signed_config(&sk, 1, 3600).encode_to_vec(), 1_000)
        .unwrap();
    assert!(core.has_policy());
    let score = core.evaluate_risk(RiskBitset::HOOKING | RiskBitset::DEBUGGER);
    assert_eq!(score.score, 90); // 60 + 30

    // Phase 2 fusion caps the local response at step-up even though policy says block.
    let fused = core.fuse_risk(RiskBitset::HOOKING).unwrap();
    assert_eq!(fused.local_response, EnforcementMode::StepUp);
    assert_eq!(fused.level, TrustLevel::MediumRisk); // score 60
    assert!(fused.anomaly);

    // Build → batch → compress → decode roundtrip via the public API.
    let event = core.create_event(EventInput {
        event_type: EventType::RootRisk,
        risk_bits: RiskBitset::ROOT,
        confidence: Confidence::Low,
        app_build_hash: "b".into(),
        policy_hash: "policy-hash".into(),
        tenant_scoped_install_key_hash: "k".into(),
        coarse_time_bucket: 1_700_000_000,
        country_or_region: None,
    });
    let wire = core.batch_and_compress(vec![event]).unwrap();
    let batch = transport::decompress_batch(&wire, None).unwrap();
    assert_eq!(batch.events.len(), 1);
    assert_eq!(batch.sdk_version, kseal_core::VERSION);

    // Request proof bound to the instance key verifies.
    let proof = core.generate_request_proof("tok", b"reqhash", b"nonce", 1);
    assert!(verify_request_proof(b"proof-key", &proof));
}
