//! Signed-config parsing, verification, and TTL caching.
//!
//! Config is fetched from a CDN as a [`proto::SignedConfig`] and verified
//! offline against a pinned Ed25519 public key before use. A verified config is
//! cached with its TTL so the SDK never needs a launch-time network call; the
//! cache exposes staleness/expiry so callers can refresh lazily.

use crate::crypto::verify_ed25519;
use crate::policy::Policy;
use crate::proto::{PolicyConfig, SignedConfig};
use crate::{Error, Result};
use prost::Message;

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
        (self.expires_at() - now).max(0)
    }
}

/// Verifies a [`SignedConfig`] and decodes its embedded [`PolicyConfig`].
///
/// # Errors
/// - [`Error::Crypto`] if the Ed25519 signature over `config_bytes` is invalid.
/// - [`Error::Decode`] if the embedded `PolicyConfig` fails to decode.
pub fn verify_and_decode(
    signed: &SignedConfig,
    public_key: &[u8],
    now: i64,
) -> Result<CachedConfig> {
    if !verify_ed25519(public_key, &signed.config_bytes, &signed.signature) {
        return Err(Error::Crypto("config signature verification failed".into()));
    }
    let policy_config = PolicyConfig::decode(signed.config_bytes.as_slice())?;
    Ok(CachedConfig {
        policy: Policy::new(policy_config),
        version: signed.version,
        key_id: signed.key_id.clone(),
        loaded_at: now,
        ttl_seconds: signed.ttl_seconds,
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
        let signature = sk.sign(&config_bytes).to_bytes().to_vec();
        SignedConfig {
            config_bytes,
            signature,
            key_id: "k1".to_string(),
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
    fn cache_rejects_rollback() {
        let sk = signing_key();
        let pk = sk.verifying_key();
        let mut cache = ConfigCache::new();
        cache.update(&make_signed(5, 60, &sk), pk.as_bytes(), 0).unwrap();
        let err = cache
            .update(&make_signed(4, 60, &sk), pk.as_bytes(), 0)
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
        assert_eq!(cache.current().unwrap().version, 5);
    }

    #[test]
    fn needs_refresh_tracks_expiry() {
        let sk = signing_key();
        let pk = sk.verifying_key();
        let mut cache = ConfigCache::new();
        assert!(cache.needs_refresh(0));
        cache.update(&make_signed(1, 100, &sk), pk.as_bytes(), 0).unwrap();
        assert!(!cache.needs_refresh(50));
        assert!(cache.needs_refresh(100));
    }
}
