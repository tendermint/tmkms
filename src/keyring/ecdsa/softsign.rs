//! libsecp256k1 software-based signer
//!
//! This is mainly intended for testing/CI. Ideally validators will use HSMs.

use super::{SecretKey, Signer};
use crate::{
    chain,
    config::provider::softsign::{KeyFormat, SoftsignConfig},
    error::{Error, ErrorKind::*},
    keyring::SigningProvider,
    prelude::*,
};
use signatory::public_key::PublicKeyed;
use signatory_secp256k1::EcdsaSigner;
use std::{convert::TryFrom, fs};
use subtle_encoding::base64;
use tendermint::TendermintKey;
use zeroize::Zeroizing;

/// Create software-backed ECDSA signer objects from the given configuration
pub fn init(chain_registry: &mut chain::Registry, configs: &[SoftsignConfig]) -> Result<(), Error> {
    if configs.is_empty() {
        return Ok(());
    }

    if configs.len() != 1 {
        fail!(
            ConfigError,
            "expected one [providers.softsign] in config, found: {}",
            configs.len()
        );
    }

    let config = &configs[0];
    let key_format = config.key_format.as_ref().cloned().unwrap_or_default();

    let secret_key: SecretKey = match key_format {
        KeyFormat::Base64 => {
            let secret_key_base64 =
                Zeroizing::new(fs::read_to_string(&config.path).map_err(|e| {
                    format_err!(
                        ConfigError,
                        "couldn't read key from {}: {}",
                        &config.path.as_ref().display(),
                        e
                    )
                })?);

            // TODO(tarcieri): constant-time string trimming
            let secret_key_bytes = Zeroizing::new(
                base64::decode(secret_key_base64.trim_end().as_bytes()).map_err(|e| {
                    format_err!(
                        ConfigError,
                        "can't decode key from {}: {}",
                        config.path.as_ref().display(),
                        e
                    )
                })?,
            );

            SecretKey::try_from(secret_key_bytes.as_ref()).map_err(|e| {
                format_err!(
                    ConfigError,
                    "can't decode key from {}: {}",
                    config.path.as_ref().display(),
                    e
                )
            })?
        }
        other => fail!(
            ConfigError,
            "unsupported encoding `{}` for ECDSA key: {}",
            other,
            config.path.as_ref().display()
        ),
    };

    let provider = EcdsaSigner::from(&secret_key);
    let public_key = provider.public_key().map_err(|_| Error::from(InvalidKey))?;
    let consensus_pubkey = TendermintKey::ConsensusKey(public_key.into());

    let signer = Signer::new(
        SigningProvider::SoftSign,
        consensus_pubkey,
        Box::new(provider),
    );

    for chain_id in &config.chain_ids {
        chain_registry
            .get_chain_mut(chain_id)?
            .keyring
            .add_ecdsa(signer.clone())?;
    }

    Ok(())
}
