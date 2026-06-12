//! Generates `include/kseal.h` from the FFI surface using cbindgen.

use std::path::PathBuf;

fn main() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = crate_dir.join("include");
    std::fs::create_dir_all(&out_dir).expect("create include dir");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    // Generation is best-effort: a clean build without cbindgen's config should
    // still succeed so downstream crates can link the static library.
    match cbindgen::generate(&crate_dir) {
        Ok(bindings) => {
            let header = out_dir.join("kseal.h");
            if !bindings.write_to_file(&header) {
                println!(
                    "cargo:warning=cbindgen wrote no changes or failed to write {}",
                    header.display()
                );
            }
        }
        Err(e) => {
            println!("cargo:warning=cbindgen header generation skipped: {e}");
        }
    }
}
