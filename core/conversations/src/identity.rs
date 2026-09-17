//! Who is who.
//!
//! ```text
//! Signer                              an installation: the key it signs under
//! ParticipantId                       a participant: the user an installation acts for
//! Member { signer, participant_id }   one installation of one participant, in a conversation
//!   │  AuthService
//!   └──► AuthenticatedMember          a member the service vouched for
//! ```

use std::fmt;

use crypto::Ed25519VerifyingKey;

use crate::service_traits::{AuthResult, AuthService};

/// Who signed: the signature key the group's ciphersuite verifies under.
///
/// Always public — never secret key material.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signer(Vec<u8>);
pub type SignerRef<'a> = &'a Signer;

impl Signer {
    /// The key's bytes — the id the registries are keyed on.
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

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
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
pub struct Member {
    /// Installation specific signing key
    pub signer: Signer,
    /// The participant this signer acts for.
    pub participant_id: ParticipantId,
}

impl Member {
    pub(crate) fn from_leaf(signature_key: &[u8], credential: &[u8]) -> Self {
        Self {
            signer: Signer::from(signature_key),
            participant_id: ParticipantId::from(credential),
        }
    }

    pub(crate) fn auth_status<A: AuthService>(&self, auth: &A) -> AuthStatus {
        match auth.validate_member(self.signer.clone(), self.participant_id.clone()) {
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
/// [`Member::require_valid`] is the only constructor, so holding one
/// is proof the check passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedMember(Member);

impl AuthenticatedMember {
    pub fn signer(&self) -> &Signer {
        &self.0.signer
    }

    pub fn participant_id(&self) -> &ParticipantId {
        &self.0.participant_id
    }
}
