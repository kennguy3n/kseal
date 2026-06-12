//! Generates Rust types from the kseal protobuf schemas using prost-build.
//!
//! The protobuf files are the single source of truth and live at the repo root
//! under `proto/`. We only compile the message-bearing schemas (the SDK does
//! not need the gRPC service definitions, which are server-side concerns).

use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // kseal-core -> rust-core -> sdk -> repo root.
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("repo root")
        .to_path_buf();
    let proto_root = repo_root.join("proto");

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
