//! Generates Rust types from the kseal protobuf schemas using prost-build.
//!
//! The protobuf files are the single source of truth and live at the repo root
//! under `proto/`. We only compile the message-bearing schemas (the SDK does
//! not need the gRPC service definitions, which are server-side concerns).

use std::path::{Path, PathBuf};

/// Walks up from `start` to find the ancestor that contains `proto/kseal/v1`,
/// so the build doesn't depend on a fixed directory depth.
fn find_proto_root(start: &Path) -> PathBuf {
    for dir in start.ancestors() {
        let candidate = dir.join("proto");
        if candidate.join("kseal/v1/common.proto").is_file() {
            return candidate;
        }
    }
    panic!(
        "could not locate the kseal `proto/` directory above {}",
        start.display()
    );
}

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto_root = find_proto_root(&manifest_dir);

    let protos = [
        "kseal/v1/common.proto",
        "kseal/v1/telemetry.proto",
        "kseal/v1/trust.proto",
        "kseal/v1/config.proto",
        "kseal/v1/registry.proto",
        "kseal/v1/webhook.proto",
        "kseal/v1/ingest.proto",
    ];

    let proto_paths: Vec<PathBuf> = protos.iter().map(|p| proto_root.join(p)).collect();

    for p in &proto_paths {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    println!("cargo:rerun-if-changed={}", proto_root.display());

    prost_build::Config::new()
        .compile_protos(&proto_paths, &[&proto_root])
        .expect("failed to compile kseal protobuf schemas");
}
