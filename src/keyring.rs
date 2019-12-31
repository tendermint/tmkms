//! Signing keyring. Presently specialized for Ed25519.

pub mod ecdsa;
pub mod ed25519;
pub mod format;
pub mod providers;

pub use self::{format::Format, providers::SigningProvider};
use crate::{
    chain,
    config::provider::ProviderConfig,
    error::{Error, ErrorKind::*},
    prelude::*,
};
use std::collections::BTreeMap as Map;
use subtle_encoding;
use tendermint::TendermintKey;

/// File encoding for software-backed secret keys
pub type SecretKeyEncoding = subtle_encoding::Base64;

/// Signing keyring
pub struct KeyRing {
    /// ECDSA (secp256k1) keys in the keyring
    ecdsa_keys: Map<TendermintKey, ecdsa::Signer>,

    /// Ed25519 keys in the keyring
    ed25519_keys: Map<TendermintKey, ed25519::Signer>,

    /// Formatting configuration when displaying keys (e.g. bech32)
    format: Format,
}

impl KeyRing {
    /// Create a new keyring
    pub fn new(format: Format) -> Self {
        Self {
            ecdsa_keys: Map::new(),
            ed25519_keys: Map::new(),
            format,
        }
    }

    /// Add an ECDSA key to the keyring, returning an error if we already
    /// have a signer registered for the given public key.
    pub fn add_ecdsa(&mut self, signer: ecdsa::Signer) -> Result<(), Error> {
        let provider = signer.provider();
        let public_key = signer.public_key();
        let public_key_serialized = self.format.serialize(public_key);
        let key_type = match public_key {
            TendermintKey::AccountKey(_) => "account",
            TendermintKey::ConsensusKey(_) => "consensus",
        };

        info!(
            "[keyring:{}] added ECDSA {} key {}",
            provider, key_type, public_key_serialized
        );

        if let Some(other) = self.ecdsa_keys.insert(public_key, signer) {
            fail!(
                InvalidKey,
                "[keyring:{}] duplicate ECDSA key {} already registered as {}",
                provider,
                public_key_serialized,
                other.provider(),
            )
        } else {
            Ok(())
        }
    }

    /// Add an Ed25519 key to the keyring, returning an error if we already
    /// have a signer registered for the given public key.
    pub fn add_ed25519(&mut self, signer: ed25519::Signer) -> Result<(), Error> {
        let provider = signer.provider();
        let public_key = signer.public_key();
        let public_key_serialized = self.format.serialize(public_key);
        let key_type = match public_key {
            TendermintKey::AccountKey(_) => "account",
            TendermintKey::ConsensusKey(_) => "consensus",
        };

        info!(
            "[keyring:{}] added Ed25519 {} key {}",
            provider, key_type, public_key_serialized
        );

        if let Some(other) = self.ed25519_keys.insert(public_key, signer) {
            fail!(
                InvalidKey,
                "[keyring:{}] duplicate Ed25519 key {} already registered as {}",
                provider,
                public_key_serialized,
                other.provider(),
            )
        } else {
            Ok(())
        }
    }

    /// Get the default Ed25519 public key for this keyring
    pub fn default_ed25519_pubkey(&self) -> Result<TendermintKey, Error> {
        let mut keys = self.ed25519_keys.keys();

        if keys.len() == 1 {
            Ok(*keys.next().unwrap())
        } else {
            fail!(InvalidKey, "expected only one key in keyring");
        }
    }

    /// Sign a message using the ECDSA secret key associated with the given
    /// public key (if it is in our keyring)
    pub fn sign_ecdsa(
        &self,
        public_key: Option<&TendermintKey>,
        msg: &[u8],
    ) -> Result<ecdsa::Signature, Error> {
        let signer = match public_key {
            Some(public_key) => self.ecdsa_keys.get(public_key).ok_or_else(|| {
                format_err!(InvalidKey, "not in keyring: {}", public_key.to_bech32(""))
            })?,
            None => {
                let mut vals = self.ecdsa_keys.values();

                if vals.len() > 1 {
                    fail!(SigningError, "expected only one key in keyring");
                } else {
                    vals.next()
                        .ok_or_else(|| format_err!(InvalidKey, "keyring is empty"))?
                }
            }
        };

        signer.sign(msg)
    }

    /// Sign a message using the Ed25519 secret key associated with the given
    /// public key (if it is in our keyring)
    pub fn sign_ed25519(
        &self,
        public_key: Option<&TendermintKey>,
        msg: &[u8],
    ) -> Result<ed25519::Signature, Error> {
        let signer = match public_key {
            Some(public_key) => self.ed25519_keys.get(public_key).ok_or_else(|| {
                format_err!(InvalidKey, "not in keyring: {}", public_key.to_bech32(""))
            })?,
            None => {
                let mut vals = self.ed25519_keys.values();

                if vals.len() > 1 {
                    fail!(SigningError, "expected only one key in keyring");
                } else {
                    vals.next()
                        .ok_or_else(|| format_err!(InvalidKey, "keyring is empty"))?
                }
            }
        };

        signer.sign(msg)
    }
}

/// Initialize the keyring from the configuration file
pub fn load_config(registry: &mut chain::Registry, config: &ProviderConfig) -> Result<(), Error> {
    #[cfg(feature = "softsign")]
    ed25519::softsign::init(registry, &config.softsign)?;

    #[cfg(feature = "yubihsm")]
    ed25519::yubihsm::init(registry, &config.yubihsm)?;

    #[cfg(feature = "ledgertm")]
    ed25519::ledgertm::init(registry, &config.ledgertm)?;

    Ok(())
}
