//! Criterion benchmarks for the kseal-core hot paths.
//!
//! Groups cover the latency-critical operations called on the device during a
//! request: policy evaluation, telemetry serialization + zstd compression,
//! HMAC request-proof generation, Ed25519 config-signature verification, and
//! core initialization (relevant to the < 40ms startup budget). Run with
//! `cargo bench`; numbers are reported in the PR description.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use ed25519_dalek::{Signer, SigningKey};
use kseal_core::crypto::{self, verify_request_proof};
use kseal_core::events::{build_event, EventInput};
use kseal_core::policy::Policy;
use kseal_core::proto::{
    Compression, Confidence, EnforcementMode, EventType, Platform, PolicyConfig, PolicyRule,
    SignedConfig,
};
use kseal_core::risk::RiskBitset;
use kseal_core::transport;
use kseal_core::{CoreConfig, KsealCore};
use prost::Message;
use std::collections::HashMap;

fn weights() -> HashMap<u32, u32> {
    let mut w = HashMap::new();
    for bit in 0..16u32 {
        w.insert(bit, 10 + bit);
    }
    w
}

fn policy_config() -> PolicyConfig {
    let rules = (0..8u32)
        .map(|i| PolicyRule {
            id: format!("rule-{i}"),
            risk_mask: 1u64 << i,
            min_score: 5,
            action: EnforcementMode::StepUp as i32,
            description: String::new(),
        })
        .collect();
    let mut thresholds = HashMap::new();
    thresholds.insert("LOW_RISK".into(), 10);
    thresholds.insert("MEDIUM_RISK".into(), 40);
    thresholds.insert("HIGH_RISK".into(), 70);
    PolicyConfig {
        rules,
        risk_thresholds: thresholds,
        default_mode: EnforcementMode::Observe as i32,
        modules_enabled: vec![],
        signal_weights: weights(),
        policy_hash: "policy-hash".into(),
    }
}

fn sample_event() -> kseal_core::proto::TelemetryEvent {
    build_event(EventInput {
        event_type: EventType::RootRisk,
        risk_bits: RiskBitset::ROOT | RiskBitset::DEBUGGER,
        confidence: Confidence::Medium,
        app_build_hash: "app-build-hash-abc123".into(),
        policy_hash: "policy-hash".into(),
        tenant_scoped_install_key_hash: "tenant-install-key-hash".into(),
        coarse_time_bucket: 1_700_000_000,
        country_or_region: Some("US".into()),
    })
}

fn bench_policy_eval(c: &mut Criterion) {
    let policy = Policy::new(policy_config());
    let bits = RiskBitset::ROOT | RiskBitset::DEBUGGER | RiskBitset::NETWORK_MITM;
    c.bench_function("policy_evaluate", |b| {
        b.iter(|| black_box(policy.evaluate(black_box(bits))))
    });
}

fn bench_event_batch_compress(c: &mut Criterion) {
    let core = KsealCore::new(CoreConfig::default());
    let events: Vec<_> = (0..10).map(|_| sample_event()).collect();
    c.bench_function("batch_and_compress_10", |b| {
        b.iter_batched(
            || events.clone(),
            |evs| black_box(core.batch_and_compress(evs).unwrap()),
            BatchSize::SmallInput,
        )
    });
}

fn bench_request_proof(c: &mut Criterion) {
    let key = b"hardware-bound-instance-key-0001";
    let request_hash = crypto::sha256(b"POST /transfer {to:bob,amount:500}");
    let nonce = crypto::generate_nonce(crypto::DEFAULT_NONCE_LEN).unwrap();
    c.bench_function("request_proof_generate", |b| {
        b.iter(|| {
            black_box(crypto::generate_request_proof(
                black_box(key),
                "token-123",
                &request_hash,
                &nonce,
                42,
            ))
        })
    });
    let proof = crypto::generate_request_proof(key, "token-123", &request_hash, &nonce, 42);
    c.bench_function("request_proof_verify", |b| {
        b.iter(|| black_box(verify_request_proof(black_box(key), black_box(&proof))))
    });
}

fn bench_config_verify(c: &mut Criterion) {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let pk = sk.verifying_key();
    let config_bytes = policy_config().encode_to_vec();
    let (version, ttl_seconds, key_id) = (1i64, 3600i64, "key-1");
    let signature = sk
        .sign(&kseal_core::crypto::signed_config_preimage(
            version,
            ttl_seconds,
            key_id,
            &config_bytes,
        ))
        .to_bytes()
        .to_vec();
    let signed = SignedConfig {
        config_bytes,
        signature,
        key_id: key_id.into(),
        version,
        ttl_seconds,
    };
    let pk_bytes = pk.to_bytes();
    c.bench_function("config_verify_and_decode_ed25519", |b| {
        b.iter(|| {
            black_box(kseal_core::config::verify_and_decode(
                black_box(&signed),
                &pk_bytes,
                1_000,
            ))
        })
    });
}

fn bench_core_init(c: &mut Criterion) {
    let cfg = CoreConfig {
        config_public_key: vec![0u8; 32],
        proof_key: b"proof-key".to_vec(),
        platform: Platform::Android,
        ..Default::default()
    };
    c.bench_function("core_new", |b| {
        b.iter_batched(
            || cfg.clone(),
            |c| black_box(KsealCore::new(c)),
            BatchSize::SmallInput,
        )
    });
}

fn bench_decompress(c: &mut Criterion) {
    let core = KsealCore::new(CoreConfig::default());
    let events: Vec<_> = (0..10).map(|_| sample_event()).collect();
    let wire = core.batch_and_compress(events).unwrap();
    c.bench_function("decompress_batch_10", |b| {
        b.iter(|| black_box(transport::decompress_batch(black_box(&wire), None).unwrap()))
    });
    let _ = Compression::Zstd; // keep the wire format explicit in this bench TU
}

criterion_group!(
    benches,
    bench_policy_eval,
    bench_event_batch_compress,
    bench_decompress,
    bench_request_proof,
    bench_config_verify,
    bench_core_init,
);
criterion_main!(benches);
