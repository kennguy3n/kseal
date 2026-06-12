//! Signed-config parsing, verification, and TTL caching.
//!
//! Config is fetched from a CDN as a [`proto::SignedConfig`] and verified
//! offline against a pinned Ed25519 public key before use. A verified config is
//! cached with its TTL so the SDK never needs a launch-time network call; the
//! cache exposes staleness/expiry so callers can refresh lazily.
//!
//! # Security: what the signature covers
//!
//! The Ed25519 signature authenticates the **whole envelope**, not just the
//! policy bytes. Verification recomputes the canonical, domain-separated,
//! length-prefixed preimage in [`crypto::signed_config_preimage`] —
//! `DOMAIN || version || ttl_seconds || key_id || config_bytes` — so all of
//! `version` (the rollback anchor), `ttl_seconds` (the staleness anchor),
//! `key_id`, and `config_bytes` are covered by one signature. The wire shape of
//! `SignedConfig` is unchanged; only the bytes the signature is computed over
//! changed, and the Go server (S1) mirrors the identical layout when it signs
//! (cross-checked by a shared golden vector).
//!
//! This closes the earlier CDN/cache tamper vector: an attacker can no longer
//! inflate `version` to lock out future legitimate updates, nor inflate
//! `ttl_seconds` to pin a stale policy — any change to those fields invalidates
//! the signature.
//!
//! The TTL is still clamped to [`MAX_TTL_SECONDS`] as an **operational** bound
//! (not a security one now): even a validly-signed but misconfigured oversized
//! TTL is capped so the SDK refreshes within a bounded window, upholding the
//! "reject stale config" guarantee in `PROPOSAL.md`.

use crate::crypto::verify_config_envelope;
use crate::policy::Policy;
use crate::proto::{PolicyConfig, SignedConfig};
use crate::{Error, Result};
use prost::Message;

/// Upper bound applied to the unauthenticated `SignedConfig.ttl_seconds`.
///
/// The TTL is not covered by the config signature (see the [module
/// docs](self)), so it is clamped to this maximum (24h) as defense-in-depth:
/// even a tampered or absurdly large TTL forces a refresh within a bounded
/// window. Legitimate TTLs at or below this value are unaffected; negative
/// TTLs are clamped to `0` (immediately stale). This aligns with the "rapid
/// signed config updates" posture in `PROPOSAL.md`.
pub const MAX_TTL_SECONDS: i64 = 24 * 60 * 60;

/// A verified, cached policy config plus the metadata needed to age it out.
#[derive(Debug, Clone)]
pub struct CachedConfig {
    /// The decoded, signature-verified policy.
    pub policy: Policy,
    /// Monotonic config version for the (tenant, app).
    pub version: i64,
    /// Identifier of the signing key that produced this config.
    pub key_id: String,
    /// Unix seconds at which this config was loaded/verified.
    pub loaded_at: i64,
    /// Client-side cache lifetime in seconds.
    pub ttl_seconds: i64,
}

impl CachedConfig {
    /// Unix-seconds instant at which this cache entry expires.
    #[must_use]
    pub fn expires_at(&self) -> i64 {
        self.loaded_at.saturating_add(self.ttl_seconds)
    }

    /// Whether the cache entry has passed its TTL as of `now` (unix seconds).
    #[must_use]
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expires_at()
    }

    /// Remaining lifetime in seconds (`0` once expired).
    #[must_use]
    pub fn remaining_ttl(&self, now: i64) -> i64 {
        self.expires_at().saturating_sub(now).max(0)
    }
}

/// Verifies a [`SignedConfig`] and decodes its embedded [`PolicyConfig`].
///
/// # Errors
/// - [`Error::Crypto`] if the Ed25519 signature over the canonical envelope
///   preimage (`version || ttl_seconds || key_id || config_bytes`) is invalid.
/// - [`Error::Decode`] if the embedded `PolicyConfig` fails to decode.
pub fn verify_and_decode(
    signed: &SignedConfig,
    public_key: &[u8],
    now: i64,
) -> Result<CachedConfig> {
    if !verify_config_envelope(
        public_key,
        signed.version,
        signed.ttl_seconds,
        &signed.key_id,
        &signed.config_bytes,
        &signed.signature,
    ) {
        return Err(Error::Crypto("config signature verification failed".into()));
    }
    let policy_config = PolicyConfig::decode(signed.config_bytes.as_slice())?;
    Ok(CachedConfig {
        policy: Policy::new(policy_config),
        version: signed.version,
        key_id: signed.key_id.clone(),
        loaded_at: now,
        // `ttl_seconds` is not covered by the signature; clamp it to a bounded
        // window so a tampered TTL cannot pin a stale config (see module docs).
        ttl_seconds: signed.ttl_seconds.clamp(0, MAX_TTL_SECONDS),
    })
}

/// Holds the currently active [`CachedConfig`] and enforces monotonic updates.
#[derive(Debug, Default, Clone)]
pub struct ConfigCache {
    current: Option<CachedConfig>,
}

impl ConfigCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The active cached config, if any.
    #[must_use]
    pub fn current(&self) -> Option<&CachedConfig> {
        self.current.as_ref()
    }

    /// Verifies and installs `signed` as the active config.
    ///
    /// Rejects a config whose `version` is older than the cached one (a
    /// rollback attempt) with [`Error::Config`]. On success returns a reference
    /// to the newly cached config.
    ///
    /// # Errors
    /// Propagates verification/decoding failures and rejects version rollbacks.
    pub fn update(
        &mut self,
        signed: &SignedConfig,
        public_key: &[u8],
        now: i64,
    ) -> Result<&CachedConfig> {
        if let Some(existing) = &self.current {
            if signed.version < existing.version {
                return Err(Error::Config(format!(
                    "config rollback rejected: incoming version {} < cached {}",
                    signed.version, existing.version
                )));
            }
        }
        let cached = verify_and_decode(signed, public_key, now)?;
        self.current = Some(cached);
        Ok(self.current.as_ref().expect("just set"))
    }

    /// Whether a refresh is warranted: no config yet, or the cached one expired.
    #[must_use]
    pub fn needs_refresh(&self, now: i64) -> bool {
        self.current.as_ref().map_or(true, |c| c.is_expired(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::EnforcementMode;
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn make_signed(version: i64, ttl: i64, sk: &SigningKey) -> SignedConfig {
        let policy = PolicyConfig {
            default_mode: EnforcementMode::Observe as i32,
            policy_hash: "ph".to_string(),
            ..Default::default()
        };
        let config_bytes = policy.encode_to_vec();
        let key_id = "k1".to_string();
        // Sign the canonical envelope preimage (not bare config_bytes) so the
        // signature covers version/ttl_seconds/key_id too — mirrors S1.
        let preimage =
            crate::crypto::signed_config_preimage(version, ttl, &key_id, &config_bytes);
        let signature = sk.sign(&preimage).to_bytes().to_vec();
        SignedConfig {
            config_bytes,
            signature,
            key_id,
            version,
            ttl_seconds: ttl,
        }
    }

    #[test]
    fn verifies_and_decodes_valid_config() {
        let sk = signing_key();
        let signed = make_signed(1, 3600, &sk);
        let cached = verify_and_decode(&signed, sk.verifying_key().as_bytes(), 1000).unwrap();
        assert_eq!(cached.version, 1);
        assert_eq!(cached.expires_at(), 1000 + 3600);
        assert!(!cached.is_expired(2000));
        assert!(cached.is_expired(1000 + 3600));
    }

    #[test]
    fn rejects_bad_signature() {
        let sk = signing_key();
        let mut signed = make_signed(1, 60, &sk);
        signed.signature[0] ^= 0xff;
        let err = verify_and_decode(&signed, sk.verifying_key().as_bytes(), 0).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn rejects_tampered_version() {
        // Envelope signing closes the old vector: flipping `version` after
        // signing must now fail verification (previously it would pass because
        // only `config_bytes` was signed).
        let sk = signing_key();
        let mut signed = make_signed(1, 3600, &sk);
        signed.version = 999; // attacker inflates the rollback anchor
        let err = verify_and_decode(&signed, sk.verifying_key().as_bytes(), 0).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn rejects_tampered_ttl() {
        let sk = signing_key();
        let mut signed = make_signed(1, 60, &sk);
        signed.ttl_seconds = i64::MAX; // attacker tries to pin a stale config
        let err = verify_and_decode(&signed, sk.verifying_key().as_bytes(), 0).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn rejects_tampered_key_id() {
        let sk = signing_key();
        let mut signed = make_signed(1, 60, &sk);
        signed.key_id = "rotated".to_string();
        let err = verify_and_decode(&signed, sk.verifying_key().as_bytes(), 0).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn cache_rejects_rollback() {
        let sk = signing_key();
        let pk = sk.verifying_key();
        let mut cache = ConfigCache::new();
        cache
            .update(&make_signed(5, 60, &sk), pk.as_bytes(), 0)
            .unwrap();
        let err = cache
            .update(&make_signed(4, 60, &sk), pk.as_bytes(), 0)
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
        assert_eq!(cache.current().unwrap().version, 5);
    }

    #[test]
    fn ttl_is_clamped_to_max() {
        let sk = signing_key();
        // A tampered/absurd TTL must not pin the config beyond MAX_TTL_SECONDS.
        let signed = make_signed(1, i64::MAX, &sk);
        let cached = verify_and_decode(&signed, sk.verifying_key().as_bytes(), 1000).unwrap();
        assert_eq!(cached.ttl_seconds, MAX_TTL_SECONDS);
        assert_eq!(cached.expires_at(), 1000 + MAX_TTL_SECONDS);
        assert!(cached.is_expired(1000 + MAX_TTL_SECONDS));
    }

    #[test]
    fn negative_ttl_is_immediately_stale() {
        let sk = signing_key();
        let signed = make_signed(1, -42, &sk);
        let cached = verify_and_decode(&signed, sk.verifying_key().as_bytes(), 1000).unwrap();
        assert_eq!(cached.ttl_seconds, 0);
        assert!(cached.is_expired(1000));
    }

    #[test]
    fn needs_refresh_tracks_expiry() {
        let sk = signing_key();
        let pk = sk.verifying_key();
        let mut cache = ConfigCache::new();
        assert!(cache.needs_refresh(0));
        cache
            .update(&make_signed(1, 100, &sk), pk.as_bytes(), 0)
            .unwrap();
        assert!(!cache.needs_refresh(50));
        assert!(cache.needs_refresh(100));
    }
}
