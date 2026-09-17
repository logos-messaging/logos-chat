//! Who is who.
//!
//! ```text
//! SignerKey       an installation: the key it signs under
//! ParticipantId   a participant: the user an installation acts for
//! ```
//!
//! The model and the reasoning behind it: `docs/adr/0003-identity-model.md`.

use std::fmt;

use crypto::Ed25519VerifyingKey;

/// Who signed: the Ed25519 key a message's signatures verify under.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SignerKey(Ed25519VerifyingKey);
pub type SignerRef<'a> = &'a SignerKey;

impl SignerKey {
    /// The key's bytes — the id the registries are keyed on.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// The key itself, for verifying a signature under it.
    pub fn verifying_key(&self) -> &Ed25519VerifyingKey {
        &self.0
    }
}

impl From<Ed25519VerifyingKey> for SignerKey {
    fn from(key: Ed25519VerifyingKey) -> Self {
        Self(key)
    }
}

/// Not every byte string names a signer: exactly 32 bytes forming a valid
/// Ed25519 key.
impl TryFrom<&[u8]> for SignerKey {
    type Error = SignerError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.try_into().map_err(|_| SignerError::NotAKey)?;
        Ed25519VerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| SignerError::NotAKey)
    }
}

impl fmt::Display for SignerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.as_bytes()))
    }
}

impl fmt::Debug for SignerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signer")
            .field(&hex::encode(self.as_bytes()))
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignerError {
    #[error("not an Ed25519 verifying key")]
    NotAKey,
}

/// The participant an installation acts for. Opaque to the core; the client decides
/// what it encodes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ParticipantId(Vec<u8>);

impl ParticipantId {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<&[u8]> for ParticipantId {
    fn from(value: &[u8]) -> Self {
        Self(value.into())
    }
}

impl fmt::Display for ParticipantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.as_bytes()))
    }
}
