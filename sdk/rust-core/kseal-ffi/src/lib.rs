//! C ABI FFI surface for the kseal trust core.
//!
//! These `extern "C"` functions are the boundary consumed by the Android NDK
//! (via JNI) and iOS (via the generated `kseal.h` header). The full surface —
//! core lifecycle, risk evaluation, request-proof generation, config
//! verification, and telemetry compression — is built on top of `kseal-core`.
//!
//! ## Conventions
//!
//! - A [`KsealCore`] lives behind an opaque [`CoreHandle`] pointer created by
//!   [`kseal_core_new`] and released by [`kseal_core_free`].
//! - Variable-length output is returned as a length-prefixed [`Buffer`]; the
//!   caller **must** release it with [`kseal_buffer_free`]. Every allocation
//!   handed across the boundary has a matching free, so there are no leaks.
//! - Status functions return a [`Status`] (`Ok` is 0; failures are
//!   negative). `out` parameters are written only on `Ok`.
//! - Byte inputs are `(ptr, len)` pairs; C strings are NUL-terminated UTF-8.
//!   A null pointer with length 0 is treated as an empty slice.

use kseal_core::events::{EventInput, PrivacyGuard};
use kseal_core::proto::{Confidence, EventType, Platform, RequestProof, TelemetryEvent, TrustLevel};
use kseal_core::risk::RiskBitset;
use kseal_core::{transport, CoreConfig, KsealCore};
use prost::Message;
use std::os::raw::c_char;

/// Status codes returned across the FFI boundary. `Ok` is 0; every failure is a
/// distinct negative value so C callers can branch on the cause.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Operation succeeded; any `out` parameter has been written.
    Ok = 0,
    /// A required pointer argument was null.
    ErrNull = -1,
    /// A protobuf payload failed to decode.
    ErrDecode = -2,
    /// An argument was invalid (e.g. non-UTF-8 string, config rejected).
    ErrInvalid = -3,
    /// A cryptographic operation failed.
    ErrCrypto = -4,
    /// Serialization/compression on the transport path failed.
    ErrTransport = -5,
}

/// Opaque handle wrapping a [`KsealCore`]. Created/destroyed via
/// [`kseal_core_new`] / [`kseal_core_free`]; never inspect its fields from C.
pub struct CoreHandle {
    core: KsealCore,
}

/// Owned, length-prefixed byte buffer handed to the caller.
///
/// Release with [`kseal_buffer_free`]. `data` is null and lengths are 0 for an
/// empty result.
#[repr(C)]
pub struct Buffer {
    /// Pointer to `len` bytes (heap-allocated by Rust), or null when empty.
    pub data: *mut u8,
    /// Number of valid bytes.
    pub len: usize,
    /// Allocation capacity (needed to reconstruct and free the buffer).
    pub cap: usize,
}

impl Buffer {
    fn empty() -> Self {
        Self {
            data: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    fn from_vec(mut v: Vec<u8>) -> Self {
        if v.is_empty() {
            return Self::empty();
        }
        let data = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        std::mem::forget(v);
        Self { data, len, cap }
    }
}

/// A borrowed, length-prefixed view of caller-owned bytes (e.g. one serialized
/// event in [`kseal_batch_and_compress`]).
#[repr(C)]
pub struct BytesView {
    /// Pointer to `len` bytes owned by the caller.
    pub data: *const u8,
    /// Number of bytes.
    pub len: usize,
}

/// Borrows `(ptr, len)` as a slice. Null with len 0 is an empty slice; null
/// with len > 0 is rejected (`None`).
///
/// # Safety
/// `ptr` must be valid for `len` bytes when non-null.
unsafe fn as_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts(ptr, len))
}

/// Borrows a NUL-terminated UTF-8 C string. Returns `None` for null or invalid
/// UTF-8.
///
/// # Safety
/// `ptr`, when non-null, must point to a valid NUL-terminated string.
unsafe fn as_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    std::ffi::CStr::from_ptr(ptr).to_str().ok()
}

/// Like [`as_str`] but maps null to an empty string and rejects only invalid
/// UTF-8.
///
/// # Safety
/// Same as [`as_str`].
unsafe fn as_str_or_empty<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return Some("");
    }
    std::ffi::CStr::from_ptr(ptr).to_str().ok()
}

/// Returns a static, NUL-terminated C string with the FFI crate version.
///
/// # Safety
/// The returned pointer is valid for the lifetime of the process and must not
/// be freed by the caller.
#[no_mangle]
pub extern "C" fn kseal_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// Creates a new core instance.
///
/// `config_public_key` is the Ed25519 key (32 bytes) used to verify signed
/// configs; `proof_key` is the instance HMAC key for request proofs. `platform`
/// is a [`Platform`] discriminant. A permissive privacy guard is used; the
/// platform SDK installs the tenant's guard out of band. `max_batch_events`,
/// `risk_window`, and `zstd_level` of 0 select sensible defaults.
///
/// Returns null only on allocation failure or invalid key pointers.
///
/// # Safety
/// The key pointers must each be valid for their stated lengths (or null with
/// length 0). The returned handle must be released with [`kseal_core_free`].
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kseal_core_new(
    config_public_key: *const u8,
    config_public_key_len: usize,
    proof_key: *const u8,
    proof_key_len: usize,
    platform: i32,
    max_batch_events: usize,
    risk_window: usize,
    zstd_level: i32,
) -> *mut CoreHandle {
    let pk = match as_slice(config_public_key, config_public_key_len) {
        Some(s) => s.to_vec(),
        None => return std::ptr::null_mut(),
    };
    let proof = match as_slice(proof_key, proof_key_len) {
        Some(s) => s.to_vec(),
        None => return std::ptr::null_mut(),
    };
    let config = CoreConfig {
        config_public_key: pk,
        proof_key: proof,
        platform: Platform::try_from(platform).unwrap_or(Platform::Unspecified),
        privacy_guard: PrivacyGuard::permissive(),
        max_batch_events: if max_batch_events == 0 { 64 } else { max_batch_events },
        risk_window: if risk_window == 0 {
            kseal_core::risk_engine::DEFAULT_WINDOW
        } else {
            risk_window
        },
        zstd_level: if zstd_level == 0 {
            transport::DEFAULT_ZSTD_LEVEL
        } else {
            zstd_level
        },
        ..CoreConfig::default()
    };
    Box::into_raw(Box::new(CoreHandle {
        core: KsealCore::new(config),
    }))
}

/// Releases a core handle created by [`kseal_core_new`]. Null is a no-op.
///
/// # Safety
/// `handle` must be a pointer previously returned by [`kseal_core_new`] and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn kseal_core_free(handle: *mut CoreHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Verifies and installs a signed config from protobuf bytes.
///
/// # Safety
/// `handle` must be valid; `bytes` must be valid for `len`.
#[no_mangle]
pub unsafe extern "C" fn kseal_load_config(
    handle: *mut CoreHandle,
    bytes: *const u8,
    len: usize,
) -> Status {
    let Some(handle) = handle.as_mut() else {
        return Status::ErrNull;
    };
    let Some(slice) = as_slice(bytes, len) else {
        return Status::ErrNull;
    };
    match handle.core.load_config(slice) {
        Ok(()) => Status::Ok,
        Err(kseal_core::Error::Decode(_)) => Status::ErrDecode,
        Err(kseal_core::Error::Crypto(_)) => Status::ErrCrypto,
        Err(_) => Status::ErrInvalid,
    }
}

/// Computes the weighted risk score and confidence for `risk_bits`.
///
/// Writes the score to `out_score` and the [`Confidence`] discriminant to
/// `out_confidence`.
///
/// # Safety
/// `handle` must be valid; `out_score` and `out_confidence` must be valid,
/// writable pointers.
#[no_mangle]
pub unsafe extern "C" fn kseal_evaluate_risk(
    handle: *const CoreHandle,
    risk_bits: u64,
    out_score: *mut u32,
    out_confidence: *mut i32,
) -> Status {
    let Some(handle) = handle.as_ref() else {
        return Status::ErrNull;
    };
    if out_score.is_null() || out_confidence.is_null() {
        return Status::ErrNull;
    }
    let score = handle.core.evaluate_risk(RiskBitset::from_raw(risk_bits));
    out_score.write(score.score);
    out_confidence.write(score.confidence as i32);
    Status::Ok
}

/// Returns the composite [`TrustLevel`] discriminant for `risk_bits` under the
/// active policy thresholds, or [`TrustLevel::Unspecified`] (0) when no policy
/// is loaded. Returns a negative [`Status`] value for a null handle.
///
/// Note: unlike [`kseal_evaluate_risk`], which always returns a numeric score
/// (using default weights when no policy is loaded), a trust *level* requires
/// configured thresholds. Without a loaded policy this reports `Unspecified`
/// even though `kseal_evaluate_risk` would still yield a non-zero score.
///
/// # Safety
/// `handle` must be valid.
#[no_mangle]
pub unsafe extern "C" fn kseal_compute_risk_level(handle: *const CoreHandle, risk_bits: u64) -> i32 {
    let Some(handle) = handle.as_ref() else {
        return Status::ErrNull as i32;
    };
    let bits = RiskBitset::from_raw(risk_bits);
    let score = handle.core.evaluate_risk(bits).score;
    let level = match handle.core.policy() {
        Some(p) => p.trust_level_for_score(score),
        None => TrustLevel::Unspecified,
    };
    level as i32
}

/// Builds a [`TelemetryEvent`] and writes its serialized protobuf bytes to `out`.
///
/// `country` may be null (omitted). String pointers must be valid UTF-8.
///
/// # Safety
/// `handle` and `out` must be valid; the C-string pointers must be valid
/// NUL-terminated UTF-8 (or null where permitted).
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kseal_create_event(
    handle: *const CoreHandle,
    event_type: i32,
    risk_bits: u64,
    confidence: i32,
    build_hash: *const c_char,
    policy_hash: *const c_char,
    install_key_hash: *const c_char,
    coarse_time_bucket: i64,
    country: *const c_char,
    out: *mut Buffer,
) -> Status {
    let Some(handle) = handle.as_ref() else {
        return Status::ErrNull;
    };
    if out.is_null() {
        return Status::ErrNull;
    }
    let (Some(build), Some(policy), Some(install)) = (
        as_str_or_empty(build_hash),
        as_str_or_empty(policy_hash),
        as_str_or_empty(install_key_hash),
    ) else {
        return Status::ErrInvalid;
    };
    let country = if country.is_null() {
        None
    } else {
        match as_str(country) {
            Some(c) => Some(c.to_string()),
            None => return Status::ErrInvalid,
        }
    };
    let event = handle.core.create_event(EventInput {
        event_type: EventType::try_from(event_type).unwrap_or(EventType::Unspecified),
        risk_bits: RiskBitset::from_raw(risk_bits),
        confidence: Confidence::try_from(confidence).unwrap_or(Confidence::Unspecified),
        app_build_hash: build.to_string(),
        policy_hash: policy.to_string(),
        tenant_scoped_install_key_hash: install.to_string(),
        coarse_time_bucket,
        country_or_region: country,
    });
    out.write(Buffer::from_vec(event.encode_to_vec()));
    Status::Ok
}

/// Privacy-guards and compresses serialized [`TelemetryEvent`]s into the
/// protobuf+zstd wire payload, written to `out`.
///
/// `events` points to `count` [`BytesView`]s, each a serialized `TelemetryEvent`.
///
/// # Safety
/// `handle` and `out` must be valid; `events` must point to `count` valid
/// `BytesView`s, each with a valid `(data, len)`.
#[no_mangle]
pub unsafe extern "C" fn kseal_batch_and_compress(
    handle: *const CoreHandle,
    events: *const BytesView,
    count: usize,
    out: *mut Buffer,
) -> Status {
    let Some(handle) = handle.as_ref() else {
        return Status::ErrNull;
    };
    if out.is_null() || (events.is_null() && count > 0) {
        return Status::ErrNull;
    }
    let views = if count == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(events, count)
    };
    let mut decoded = Vec::with_capacity(count);
    for view in views {
        let Some(bytes) = as_slice(view.data, view.len) else {
            return Status::ErrNull;
        };
        match TelemetryEvent::decode(bytes) {
            Ok(ev) => decoded.push(ev),
            Err(_) => return Status::ErrDecode,
        }
    }
    match handle.core.batch_and_compress(decoded) {
        Ok(wire) => {
            out.write(Buffer::from_vec(wire));
            Status::Ok
        }
        Err(_) => Status::ErrTransport,
    }
}

/// Generates a [`RequestProof`] and writes its serialized protobuf bytes to `out`.
///
/// # Safety
/// `handle` and `out` must be valid; `token_id` must be valid UTF-8; the
/// `request_hash`/`nonce` pointers must be valid for their lengths.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kseal_generate_request_proof(
    handle: *const CoreHandle,
    token_id: *const c_char,
    request_hash: *const u8,
    request_hash_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    seq: i64,
    out: *mut Buffer,
) -> Status {
    let Some(handle) = handle.as_ref() else {
        return Status::ErrNull;
    };
    if out.is_null() || token_id.is_null() {
        return Status::ErrNull;
    }
    let Some(token) = as_str(token_id) else {
        return Status::ErrInvalid;
    };
    let (Some(rh), Some(nc)) = (
        as_slice(request_hash, request_hash_len),
        as_slice(nonce, nonce_len),
    ) else {
        return Status::ErrNull;
    };
    let proof: RequestProof = handle.core.generate_request_proof(token, rh, nc, seq);
    out.write(Buffer::from_vec(proof.encode_to_vec()));
    Status::Ok
}

/// Verifies an Ed25519 signature over `config` bytes with `public_key`.
///
/// Returns 1 (valid), 0 (invalid), or a negative [`Status`] value on bad
/// args.
///
/// # Safety
/// All pointers must be valid for their stated lengths (or null with length 0).
#[no_mangle]
pub unsafe extern "C" fn kseal_verify_config_signature(
    config: *const u8,
    config_len: usize,
    signature: *const u8,
    signature_len: usize,
    public_key: *const u8,
    public_key_len: usize,
) -> i32 {
    let (Some(cfg), Some(sig), Some(pk)) = (
        as_slice(config, config_len),
        as_slice(signature, signature_len),
        as_slice(public_key, public_key_len),
    ) else {
        return Status::ErrNull as i32;
    };
    i32::from(KsealCore::verify_config_signature(cfg, sig, pk))
}

/// Compresses `data` with zstd at `level` (0 → default) into `out`.
///
/// # Safety
/// `data` must be valid for `len`; `out` must be valid.
#[no_mangle]
pub unsafe extern "C" fn kseal_compress(
    data: *const u8,
    len: usize,
    level: i32,
    out: *mut Buffer,
) -> Status {
    if out.is_null() {
        return Status::ErrNull;
    }
    let Some(slice) = as_slice(data, len) else {
        return Status::ErrNull;
    };
    let level = if level == 0 { transport::DEFAULT_ZSTD_LEVEL } else { level };
    match transport::compress(slice, level, None) {
        Ok(v) => {
            out.write(Buffer::from_vec(v));
            Status::Ok
        }
        Err(_) => Status::ErrTransport,
    }
}

/// Decompresses zstd `data` into `out`.
///
/// # Safety
/// `data` must be valid for `len`; `out` must be valid.
#[no_mangle]
pub unsafe extern "C" fn kseal_decompress(
    data: *const u8,
    len: usize,
    out: *mut Buffer,
) -> Status {
    if out.is_null() {
        return Status::ErrNull;
    }
    let Some(slice) = as_slice(data, len) else {
        return Status::ErrNull;
    };
    // FFI input is untrusted; cap output to guard against decompression bombs.
    match transport::decompress_limited(slice, None, transport::DEFAULT_MAX_DECOMPRESSED) {
        Ok(v) => {
            out.write(Buffer::from_vec(v));
            Status::Ok
        }
        Err(_) => Status::ErrTransport,
    }
}

/// Fills `out` with `len` cryptographically secure random bytes (a nonce).
///
/// # Safety
/// `out` must be valid.
#[no_mangle]
pub unsafe extern "C" fn kseal_generate_nonce(len: usize, out: *mut Buffer) -> Status {
    if out.is_null() {
        return Status::ErrNull;
    }
    match kseal_core::crypto::generate_nonce(len) {
        Ok(v) => {
            out.write(Buffer::from_vec(v));
            Status::Ok
        }
        Err(_) => Status::ErrCrypto,
    }
}

/// Releases a [`Buffer`] previously produced by this library. Empty/null
/// buffers are a no-op. Double-free is undefined behavior.
///
/// # Safety
/// `buffer` must have been produced by this library and not already freed.
#[no_mangle]
pub unsafe extern "C" fn kseal_buffer_free(buffer: Buffer) {
    if !buffer.data.is_null() && buffer.cap > 0 {
        drop(Vec::from_raw_parts(buffer.data, buffer.len, buffer.cap));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use kseal_core::proto::{EnforcementMode, PolicyConfig, SignedConfig};
    use prost::Message;
    use std::collections::HashMap;
    use std::ffi::CString;

    unsafe fn take_buffer(buf: Buffer) -> Vec<u8> {
        if buf.data.is_null() {
            return Vec::new();
        }
        let v = std::slice::from_raw_parts(buf.data, buf.len).to_vec();
        kseal_buffer_free(buf);
        v
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    fn signed_config_bytes(sk: &SigningKey) -> Vec<u8> {
        let mut weights = HashMap::new();
        weights.insert(0, 25u32); // ROOT
        weights.insert(4, 30u32); // DEBUGGER
        let mut thresholds = HashMap::new();
        thresholds.insert("MEDIUM_RISK".to_string(), 40u32);
        let policy = PolicyConfig {
            default_mode: EnforcementMode::Observe as i32,
            signal_weights: weights,
            risk_thresholds: thresholds,
            policy_hash: "ph".into(),
            ..Default::default()
        };
        let config_bytes = policy.encode_to_vec();
        let signature = sk.sign(&config_bytes).to_bytes().to_vec();
        SignedConfig {
            config_bytes,
            signature,
            key_id: "k".into(),
            version: 1,
            ttl_seconds: 3600,
        }
        .encode_to_vec()
    }

    unsafe fn new_core(sk: &SigningKey) -> *mut CoreHandle {
        let pk = sk.verifying_key().to_bytes();
        let proof = b"instance-key";
        kseal_core_new(
            pk.as_ptr(),
            pk.len(),
            proof.as_ptr(),
            proof.len(),
            Platform::Android as i32,
            16,
            8,
            0,
        )
    }

    #[test]
    fn full_ffi_round_trip_no_leaks() {
        unsafe {
            let sk = signing_key();
            let handle = new_core(&sk);
            assert!(!handle.is_null());

            // Load config.
            let cfg = signed_config_bytes(&sk);
            assert_eq!(kseal_load_config(handle, cfg.as_ptr(), cfg.len()), Status::Ok);

            // Evaluate risk: ROOT (25) + DEBUGGER (30) = 55.
            let bits = RiskBitset::ROOT | RiskBitset::DEBUGGER;
            let mut score = 0u32;
            let mut conf = 0i32;
            assert_eq!(
                kseal_evaluate_risk(handle, bits.as_u64(), &mut score, &mut conf),
                Status::Ok
            );
            assert_eq!(score, 55);
            assert_eq!(conf, Confidence::Medium as i32);

            // Composite level for score 55 ≥ MEDIUM_RISK threshold 40.
            assert_eq!(
                kseal_compute_risk_level(handle, bits.as_u64()),
                TrustLevel::MediumRisk as i32
            );

            // Create an event.
            let build = CString::new("build").unwrap();
            let policy = CString::new("policy").unwrap();
            let install = CString::new("install").unwrap();
            let mut ev_buf = Buffer::empty();
            assert_eq!(
                kseal_create_event(
                    handle,
                    EventType::RootRisk as i32,
                    RiskBitset::ROOT.as_u64(),
                    Confidence::Low as i32,
                    build.as_ptr(),
                    policy.as_ptr(),
                    install.as_ptr(),
                    1_700_000_000,
                    std::ptr::null(),
                    &mut ev_buf,
                ),
                Status::Ok
            );
            let ev_bytes = take_buffer(ev_buf);
            assert!(!ev_bytes.is_empty());

            // Batch + compress, then decompress and check the event survived.
            let views = [BytesView {
                data: ev_bytes.as_ptr(),
                len: ev_bytes.len(),
            }];
            let mut wire_buf = Buffer::empty();
            assert_eq!(
                kseal_batch_and_compress(handle, views.as_ptr(), views.len(), &mut wire_buf),
                Status::Ok
            );
            let wire = take_buffer(wire_buf);
            let batch = transport::decompress_batch(&wire, None).unwrap();
            assert_eq!(batch.events.len(), 1);
            assert_eq!(batch.events[0].risk_bits, RiskBitset::ROOT.as_u64());

            // Request proof round-trips through the C ABI.
            let token = CString::new("tok-1").unwrap();
            let rh = kseal_core::crypto::sha256(b"POST /pay");
            let nonce = [9u8; 16];
            let mut proof_buf = Buffer::empty();
            assert_eq!(
                kseal_generate_request_proof(
                    handle,
                    token.as_ptr(),
                    rh.as_ptr(),
                    rh.len(),
                    nonce.as_ptr(),
                    nonce.len(),
                    7,
                    &mut proof_buf,
                ),
                Status::Ok
            );
            let proof_bytes = take_buffer(proof_buf);
            let proof = RequestProof::decode(proof_bytes.as_slice()).unwrap();
            assert!(kseal_core::crypto::verify_request_proof(b"instance-key", &proof));
            assert_eq!(proof.monotonic_sequence, 7);

            kseal_core_free(handle);
        }
    }

    #[test]
    fn compress_decompress_through_ffi() {
        unsafe {
            let data = b"kseal kseal kseal kseal kseal kseal kseal kseal";
            let mut c = Buffer::empty();
            assert_eq!(kseal_compress(data.as_ptr(), data.len(), 0, &mut c), Status::Ok);
            let compressed = take_buffer(c);
            let mut d = Buffer::empty();
            assert_eq!(
                kseal_decompress(compressed.as_ptr(), compressed.len(), &mut d),
                Status::Ok
            );
            assert_eq!(take_buffer(d), data);
        }
    }

    #[test]
    fn verify_config_signature_via_ffi() {
        unsafe {
            let sk = signing_key();
            let msg = b"config-bytes";
            let sig = sk.sign(msg).to_bytes();
            let pk = sk.verifying_key().to_bytes();
            assert_eq!(
                kseal_verify_config_signature(
                    msg.as_ptr(),
                    msg.len(),
                    sig.as_ptr(),
                    sig.len(),
                    pk.as_ptr(),
                    pk.len()
                ),
                1
            );
            // Tampered message → 0.
            let bad = b"config-bytez";
            assert_eq!(
                kseal_verify_config_signature(
                    bad.as_ptr(),
                    bad.len(),
                    sig.as_ptr(),
                    sig.len(),
                    pk.as_ptr(),
                    pk.len()
                ),
                0
            );
        }
    }

    #[test]
    fn null_handle_returns_error() {
        unsafe {
            assert_eq!(
                kseal_load_config(std::ptr::null_mut(), std::ptr::null(), 0),
                Status::ErrNull
            );
            assert_eq!(
                kseal_compute_risk_level(std::ptr::null(), 0),
                Status::ErrNull as i32
            );
            kseal_core_free(std::ptr::null_mut()); // no-op, must not crash
        }
    }

    #[test]
    fn request_proof_null_token_is_err_null() {
        unsafe {
            let sk = signing_key();
            let handle = new_core(&sk);
            let mut out = Buffer::empty();
            // Null token_id must report ErrNull (a null-pointer bug), not ErrInvalid.
            assert_eq!(
                kseal_generate_request_proof(
                    handle,
                    std::ptr::null(),
                    b"h".as_ptr(),
                    1,
                    b"n".as_ptr(),
                    1,
                    1,
                    &mut out,
                ),
                Status::ErrNull
            );
            kseal_core_free(handle);
        }
    }

    #[test]
    fn nonce_generation_via_ffi() {
        unsafe {
            let mut buf = Buffer::empty();
            assert_eq!(kseal_generate_nonce(16, &mut buf), Status::Ok);
            assert_eq!(buf.len, 16);
            take_buffer(buf);
        }
    }
}
