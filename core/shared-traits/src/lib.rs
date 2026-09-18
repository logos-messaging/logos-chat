use crypto::{Ed25519Signature, Ed25519VerifyingKey};
use std::fmt;

/// Who signed: the Ed25519 key a message's signatures verify under.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signer(Ed25519VerifyingKey);
pub type SignerRef<'a> = &'a Signer;

impl Signer {
    /// The key's bytes — the device id the registries and directory are keyed on.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// The key itself, for verifying a signature under it.
    pub fn verifying_key(&self) -> &Ed25519VerifyingKey {
        &self.0
    }
}

impl From<Ed25519VerifyingKey> for Signer {
    fn from(key: Ed25519VerifyingKey) -> Self {
        Self(key)
    }
}

/// Not every byte string names a signer: exactly 32 bytes forming a valid
/// Ed25519 key.
impl TryFrom<&[u8]> for Signer {
    type Error = SignerError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.try_into().map_err(|_| SignerError::NotAKey)?;
        Ed25519VerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| SignerError::NotAKey)
    }
}

impl fmt::Display for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.as_bytes()))
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignerError {
    #[error("not an Ed25519 verifying key")]
    NotAKey,
}

/// Represents an external Identity
/// Implement this to provide an Authentication model for users/installations
pub trait IdentityProvider {
    fn signer(&self) -> SignerRef<'_>;
    fn participant_id(&self) -> ParticipantId;

    // Display name is not garenteed to be consistent. It should only be used to
    // provded a more readable identifier for the account.
    fn display_name(&self) -> String;
    fn sign(&self, payload: &[u8]) -> Ed25519Signature;
}
