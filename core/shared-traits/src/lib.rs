use crypto::{Ed25519Signature, Ed25519VerifyingKey};
use std::fmt;

/// Who signed: the signature key the group's ciphersuite verifies under.
///
/// Always public — never secret key material.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signer(Vec<u8>);
pub type SignerRef<'a> = &'a Signer;

impl Signer {
    /// The key's bytes — the device id the registries and directory are keyed on.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Ed25519VerifyingKey> for Signer {
    fn from(key: Ed25519VerifyingKey) -> Self {
        Self(key.as_ref().to_vec())
    }
}

/// Any bytes: which signature scheme they belong to is the ciphersuite's
/// business, and MLS checks the key itself.
impl From<&[u8]> for Signer {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

/// Parses the hex form `Display` writes. Temporary, for causal history's string ids.
impl TryFrom<&str> for Signer {
    type Error = SignerError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        hex::decode(value)
            .map(Self)
            .map_err(|_| SignerError::NotHex)
    }
}

impl fmt::Display for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.as_bytes()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExternalIdentifier(Vec<u8>);

impl ExternalIdentifier {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// The key's bytes — the device id the registries and directory are keyed on.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<&[u8]> for ExternalIdentifier {
    fn from(value: &[u8]) -> Self {
        Self(value.into())
    }
}

impl fmt::Display for ExternalIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.as_bytes()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignerError {
    #[error("not an Ed25519 verifying key")]
    NotAKey,
    #[error("not a hex-encoded signer")]
    NotHex,
}

/// Represents an external Identity
/// Implement this to provide an Authentication model for users/installations
pub trait IdentityProvider {
    fn signer(&self) -> SignerRef<'_>;
    fn external_id(&self) -> ExternalIdentifier;

    // Display name is not garenteed to be consistent. It should only be used to
    // provded a more readable identifier for the account.
    fn display_name(&self) -> String;
    fn sign(&self, payload: &[u8]) -> Ed25519Signature;
}
