//! Who is who.
//!
//! ```text
//! SignerKey                           an installation: the key it signs under
//! ParticipantId                       a participant: the user an installation acts for
//! Signer { signer_key, participant_id }   one installation of one participant, in a conversation
//!   │  AuthService
//!   └──► AuthenticatedMember          a member the service vouched for
//! ```
//!
//! The model and the reasoning behind it: `docs/adr/0003-identity-model.md`.

use std::fmt;

use crypto::Ed25519VerifyingKey;

use crate::service_traits::{AuthResult, AuthService};

/// Who signed: the signature key the group's ciphersuite verifies under.
///
/// Always public — never secret key material.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SignerKey(Vec<u8>);
pub type SignerRef<'a> = &'a SignerKey;

impl SignerKey {
    /// The key's bytes — the id the registries are keyed on.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Ed25519VerifyingKey> for SignerKey {
    fn from(key: Ed25519VerifyingKey) -> Self {
        Self::from(&key)
    }
}

impl From<&Ed25519VerifyingKey> for SignerKey {
    fn from(key: &Ed25519VerifyingKey) -> Self {
        Self::from(key.as_ref())
    }
}

/// Any bytes: which signature scheme they belong to is the ciphersuite's
/// business, and MLS checks the key itself.
impl From<&[u8]> for SignerKey {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

/// Parses the hex form `Display` writes. Temporary, for causal history's string ids.
impl TryFrom<&str> for SignerKey {
    type Error = SignerError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        hex::decode(value)
            .map(Self)
            .map_err(|_| SignerError::NotHex)
    }
}

impl fmt::Display for SignerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.as_bytes()))
    }
}

impl fmt::Debug for SignerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SignerKey")
            .field(&hex::encode(self.as_bytes()))
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignerError {
    #[error("not an Ed25519 verifying key")]
    NotAKey,
    #[error("not a hex-encoded signer")]
    NotHex,
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

/// Identity of a entity in a conversation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signer {
    /// Installation specific signing key
    pub signer: SignerKey,
    /// The participant this signer acts for.
    pub participant_id: ParticipantId,
}

impl Signer {
    pub(crate) fn from_leaf(signature_key: &[u8], credential: &[u8]) -> Self {
        Self {
            signer: SignerKey::from(signature_key),
            participant_id: ParticipantId::from(credential),
        }
    }

    pub(crate) fn auth_status<A: AuthService>(&self, auth: &A) -> AuthStatus {
        match auth.validate_signer(self.signer.clone(), self.participant_id.clone()) {
            Ok(result) => result.into(),
            Err(error) => {
                tracing::warn!(signer = %self.signer, %error, "auth service could not decide");
                AuthStatus::Unknown
            }
        }
    }

    pub(crate) fn require_valid<A: AuthService>(self, auth: &A) -> Option<AuthenticatedMember> {
        match self.auth_status(auth) {
            AuthStatus::Valid => Some(AuthenticatedMember(self)),
            status => {
                tracing::warn!(signer = %self.signer, ?status, "member failed auth");
                None
            }
        }
    }
}

/// The auth service's verdict on a member, as of when it was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthStatus {
    Valid,
    /// Was valid; withdrawn since.
    Revoked,
    /// Never valid for this signer.
    Invalid,
    /// The service could not decide. Not a verdict.
    Unknown,
}

impl From<AuthResult> for AuthStatus {
    fn from(result: AuthResult) -> Self {
        match result {
            AuthResult::Valid => Self::Valid,
            AuthResult::Revoked => Self::Revoked,
            AuthResult::Invalid => Self::Invalid,
        }
    }
}

/// A member the auth service found valid.
///
/// [`Signer::require_valid`] is the only constructor, so holding one
/// is proof the check passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedMember(Signer);

impl AuthenticatedMember {
    pub fn signer(&self) -> &SignerKey {
        &self.0.signer
    }

    pub fn participant_id(&self) -> &ParticipantId {
        &self.0.participant_id
    }
}
