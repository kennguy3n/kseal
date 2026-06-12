//! kseal device trust core.
//!
//! This crate implements the device-side trust logic shared by the Android and
//! iOS SDKs: policy evaluation, risk scoring, privacy-minimized telemetry,
//! config signature verification, and per-request proof generation. It contains
//! no platform-specific probe code — that lives in the platform SDKs and feeds
//! signals into this core as a packed [`risk::RiskBitset`].
//!
//! The protobuf wire types are generated from `proto/` at build time (see
//! `build.rs`) and re-exported under [`proto`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Protobuf-generated wire types (`kseal.v1`).
pub mod proto {
    #![allow(missing_docs)]
    include!(concat!(env!("OUT_DIR"), "/kseal.v1.rs"));
}

/// Crate-wide error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A protobuf message failed to decode.
    #[error("decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    /// A protobuf message failed to encode.
    #[error("encode error: {0}")]
    Encode(#[from] prost::EncodeError),
    /// A cryptographic verification or operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// Configuration was missing, malformed, or expired.
    #[error("config error: {0}")]
    Config(String),
}

/// Convenience result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Crate version string, surfaced to telemetry as the SDK version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
