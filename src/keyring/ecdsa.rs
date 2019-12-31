//! ECDSA (secp256k1) signing keys

pub use signatory::ecdsa::curve::secp256k1::{FixedSignature as Signature, PublicKey, SecretKey};

pub mod signer;
#[cfg(feature = "softsign")]
pub mod softsign;

pub use self::signer::Signer;
