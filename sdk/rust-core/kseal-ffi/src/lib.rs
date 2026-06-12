//! C ABI FFI surface for the kseal trust core.
//!
//! These `extern "C"` functions are the boundary consumed by the Android NDK
//! (via JNI) and iOS (via the generated `kseal.h` header). The full surface —
//! core lifecycle, risk evaluation, request-proof generation, config
//! verification, and telemetry compression — is built on top of `kseal-core`.

use std::os::raw::c_char;

/// Returns a static, NUL-terminated C string with the core version.
///
/// # Safety
/// The returned pointer is valid for the lifetime of the process and must not
/// be freed by the caller.
#[no_mangle]
pub extern "C" fn kseal_version() -> *const c_char {
    // SAFETY: the byte string is static and NUL-terminated.
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}
