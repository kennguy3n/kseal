//! Criterion benchmark harness for kseal-core hot paths.
//!
//! Individual benchmark groups are added alongside the modules they exercise
//! (policy evaluation, telemetry compression, request-proof generation, config
//! signature verification). This file wires the harness; groups register here.

use criterion::{criterion_group, criterion_main, Criterion};

fn version_smoke(c: &mut Criterion) {
    c.bench_function("version", |b| {
        b.iter(|| criterion::black_box(kseal_core::VERSION))
    });
}

criterion_group!(benches, version_smoke);
criterion_main!(benches);
