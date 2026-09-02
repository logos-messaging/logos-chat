use ed25519_dalek::{self, Signer};
use rand_core::OsRng;
use std::fmt::Debug;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("verification failed of the Ed25519 Signature")]
pub struct SignatureVerificationError {}

/// A 64-byte XEdDSA signature over an Ed25519-compatible curve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519Signature([u8; 64]);

impl Ed25519Signature {
    pub fn empty() -> Self {
        Self([0u8; 64])
    }
}

impl AsRef<[u8; 64]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8; 64] {
        &self.0
    }
}

impl From<[u8; 64]> for Ed25519Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone)]
pub struct Ed25519SigningKey(ed25519_dalek::SigningKey);

impl Ed25519SigningKey {
    pub fn generate() -> Self {
        Self(ed25519_dalek::SigningKey::generate(&mut OsRng))
    }

    /// Rebuilds the key from the 32-byte seed an Ed25519 private key is.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// The seed [`Self::from_seed`] rebuilds this key from.
    #[allow(non_snake_case)] // All caps makes this standout more in reviews.
    pub fn DANGER_to_seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> Ed25519Signature {
        self.0.sign(msg).to_bytes().into()
    }

    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        self.0.verifying_key().into()
    }
}

impl Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Ed25519SigningKey")
            .field(&"[redacted]")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ed25519VerifyingKey(ed25519_dalek::VerifyingKey);

impl Ed25519VerifyingKey {
    pub fn verify(
        &self,
        msg: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<(), SignatureVerificationError> {
        let inner_signature = signature.0;
        self.0
            .verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&inner_signature))
            .map_err(|_| SignatureVerificationError {})
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignatureVerificationError> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| SignatureVerificationError {})
    }
}

impl From<ed25519_dalek::VerifyingKey> for Ed25519VerifyingKey {
    fn from(value: ed25519_dalek::VerifyingKey) -> Self {
        Ed25519VerifyingKey(value)
    }
}

impl AsRef<[u8]> for Ed25519VerifyingKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seed a key hands out rebuilds that same key.
    #[test]
    fn seed_round_trip() {
        let key = Ed25519SigningKey::generate();
        assert_eq!(
            Ed25519SigningKey::from_seed(&key.DANGER_to_seed()).verifying_key(),
            key.verifying_key()
        );
    }
}
