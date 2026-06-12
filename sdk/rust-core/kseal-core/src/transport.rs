//! Wire serialization, zstd compression, and retry policy.
//!
//! Telemetry batches go on the wire as **protobuf + zstd**. A shared, pre-trained
//! zstd dictionary can be supplied so even small batches compress hard (see
//! ARCHITECTURE.md → Compression). The [`RetryPolicy`] describes capped
//! exponential backoff; it computes delays only — the actual scheduling lives
//! in the platform transport.

use crate::proto::TelemetryBatch;
use crate::{Error, Result};
use prost::Message;
use std::io::{Read, Write};

/// Default zstd level: a balance of ratio and the sub-millisecond budget for a
/// small batch. Callers may override for cold/background flushes.
pub const DEFAULT_ZSTD_LEVEL: i32 = 3;

/// Serializes a [`TelemetryBatch`] to canonical protobuf bytes.
#[must_use]
pub fn serialize_batch(batch: &TelemetryBatch) -> Vec<u8> {
    batch.encode_to_vec()
}

/// Decodes protobuf bytes back into a [`TelemetryBatch`].
///
/// # Errors
/// [`Error::Decode`] if the bytes are not a valid `TelemetryBatch`.
pub fn deserialize_batch(bytes: &[u8]) -> Result<TelemetryBatch> {
    Ok(TelemetryBatch::decode(bytes)?)
}

/// Compresses `data` with zstd at `level`, optionally using a shared `dictionary`.
///
/// # Errors
/// [`Error::Transport`] on any zstd failure.
pub fn compress(data: &[u8], level: i32, dictionary: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut encoder = match dictionary {
        Some(dict) => zstd::Encoder::with_dictionary(Vec::new(), level, dict),
        None => zstd::Encoder::new(Vec::new(), level),
    }
    .map_err(|e| Error::Transport(format!("zstd init: {e}")))?;
    encoder
        .write_all(data)
        .map_err(|e| Error::Transport(format!("zstd write: {e}")))?;
    encoder
        .finish()
        .map_err(|e| Error::Transport(format!("zstd finish: {e}")))
}

/// Decompresses zstd `data`, optionally using the shared `dictionary` it was
/// compressed with.
///
/// # Errors
/// [`Error::Transport`] on truncated/corrupt input or a dictionary mismatch.
pub fn decompress(data: &[u8], dictionary: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match dictionary {
        Some(dict) => {
            let mut dec = zstd::Decoder::with_dictionary(data, dict)
                .map_err(|e| Error::Transport(format!("zstd init: {e}")))?;
            dec.read_to_end(&mut out)
                .map_err(|e| Error::Transport(format!("zstd read: {e}")))?;
        }
        None => {
            let mut dec = zstd::Decoder::new(data)
                .map_err(|e| Error::Transport(format!("zstd init: {e}")))?;
            dec.read_to_end(&mut out)
                .map_err(|e| Error::Transport(format!("zstd read: {e}")))?;
        }
    }
    Ok(out)
}

/// Serializes and compresses a batch in one step (the wire form).
///
/// # Errors
/// Propagates compression failures from [`compress`].
pub fn compress_batch(
    batch: &TelemetryBatch,
    level: i32,
    dictionary: Option<&[u8]>,
) -> Result<Vec<u8>> {
    compress(&serialize_batch(batch), level, dictionary)
}

/// Decompresses and decodes a wire-form batch.
///
/// # Errors
/// Propagates decompression and decode failures.
pub fn decompress_batch(bytes: &[u8], dictionary: Option<&[u8]>) -> Result<TelemetryBatch> {
    deserialize_batch(&decompress(bytes, dictionary)?)
}

/// Capped exponential-backoff parameters for telemetry/config retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Delay before the first retry, in milliseconds.
    pub base_delay_ms: u64,
    /// Upper bound on any single delay, in milliseconds.
    pub max_delay_ms: u64,
    /// Per-attempt growth factor.
    pub multiplier: u32,
    /// Maximum number of retries (excluding the initial attempt).
    pub max_retries: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            base_delay_ms: 200,
            max_delay_ms: 30_000,
            multiplier: 2,
            max_retries: 5,
        }
    }
}

impl RetryPolicy {
    /// Delay before retry `attempt` (0-based: attempt 0 is the first retry),
    /// = `min(base * multiplier^attempt, max)`. All arithmetic saturates.
    #[must_use]
    pub fn delay_ms(&self, attempt: u32) -> u64 {
        let factor = u64::from(self.multiplier).saturating_pow(attempt);
        self.base_delay_ms.saturating_mul(factor).min(self.max_delay_ms)
    }

    /// Whether another retry is permitted after `attempt` failures.
    #[must_use]
    pub fn should_retry(&self, attempt: u32) -> bool {
        attempt < self.max_retries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Compression, Platform, TelemetryEvent};

    fn batch(n: usize) -> TelemetryBatch {
        let events = (0..n)
            .map(|i| TelemetryEvent {
                risk_bits: 1 << (i % 16),
                app_build_hash: "build-hash-aaaaaaaaaaaaaaaa".into(),
                policy_hash: "policy-hash-bbbbbbbbbbbbbbbb".into(),
                tenant_scoped_install_key_hash: "kkkkkkkkkkkkkkkkkkkkkkkk".into(),
                coarse_time_bucket: 1_700_000_000 + i as i64,
                ..Default::default()
            })
            .collect();
        TelemetryBatch {
            events,
            sdk_version: "1.0.0".into(),
            compression: Compression::Zstd as i32,
            compression_dictionary_id: String::new(),
            platform: Platform::Android as i32,
        }
    }

    #[test]
    fn compress_roundtrip_no_dict() {
        let b = batch(10);
        let wire = compress_batch(&b, DEFAULT_ZSTD_LEVEL, None).unwrap();
        let back = decompress_batch(&wire, None).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn compress_roundtrip_with_dict() {
        let dict = b"kseal-telemetry-shared-dictionary-sample-tokens".to_vec();
        let b = batch(10);
        let wire = compress_batch(&b, DEFAULT_ZSTD_LEVEL, Some(&dict)).unwrap();
        let back = decompress_batch(&wire, Some(&dict)).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn compression_reduces_repetitive_payload() {
        let b = batch(50);
        let raw = serialize_batch(&b);
        let wire = compress(&raw, DEFAULT_ZSTD_LEVEL, None).unwrap();
        assert!(wire.len() < raw.len(), "expected compression to shrink payload");
    }

    #[test]
    fn corrupt_input_errors_cleanly() {
        // Truncated / non-zstd bytes must surface an Error, not panic.
        assert!(decompress(b"not a zstd frame", None).is_err());
        let wire = compress(b"hello world hello world", DEFAULT_ZSTD_LEVEL, None).unwrap();
        assert!(decompress(&wire[..wire.len() / 2], None).is_err());
    }

    #[test]
    fn retry_backoff_is_capped_and_exponential() {
        let p = RetryPolicy {
            base_delay_ms: 100,
            max_delay_ms: 1000,
            multiplier: 2,
            max_retries: 4,
        };
        assert_eq!(p.delay_ms(0), 100);
        assert_eq!(p.delay_ms(1), 200);
        assert_eq!(p.delay_ms(2), 400);
        assert_eq!(p.delay_ms(3), 800);
        assert_eq!(p.delay_ms(4), 1000); // capped
        assert_eq!(p.delay_ms(50), 1000); // saturates, still capped
        assert!(p.should_retry(3));
        assert!(!p.should_retry(4));
    }
}
