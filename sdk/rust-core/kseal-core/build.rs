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

/// Collects every message-bearing `.proto` in `dir`, excluding the `*_service.proto`
/// gRPC service definitions (server-side concerns the SDK doesn't compile). Returns
/// a deterministically ordered list so codegen output is stable across builds.
fn message_protos(dir: &Path) -> Vec<PathBuf> {
    let mut protos: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("failed to read proto dir {}: {e}", dir.display()))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            name.ends_with(".proto") && !name.ends_with("_service.proto")
        })
        .collect();
    protos.sort();
    protos
}

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto_root = find_proto_root(&manifest_dir);
    let proto_dir = proto_root.join("kseal/v1");

    // Auto-discover message protos so adding a new schema needs no build.rs edit.
    let proto_paths = message_protos(&proto_dir);
    assert!(
        !proto_paths.is_empty(),
        "no message protos found under {}",
        proto_dir.display()
    );

    // Rerun if any individual proto changes, or if a file is added/removed.
    for p in &proto_paths {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    println!("cargo:rerun-if-changed={}", proto_dir.display());

    prost_build::Config::new()
        .compile_protos(&proto_paths, &[&proto_root])
        .expect("failed to compile kseal protobuf schemas");
}
