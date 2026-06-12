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
            // write_to_file returns whether the contents changed (false means the
            // existing header was already up to date) — not an error signal, so
            // we intentionally don't treat false as a failure.
            let _changed = bindings.write_to_file(out_dir.join("kseal.h"));
        }
        Err(e) => {
            println!("cargo:warning=cbindgen header generation skipped: {e}");
        }
    }
}
