//! Who is in a conversation.
//!
//! ```text
//! Convo has ──► Member { signer, external_id }    one MLS leaf
//!                │  AuthService
//!                └──► AuthenticatedMember         a member the service vouched for
//! ```

use shared_traits::{ExternalIdentifier, Signer};

use crate::service_traits::{AuthResult, AuthService};

/// Identity of a entity in a conversation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Member {
    /// Installation specific signing key
    pub signer: Signer,
    /// The identifier for the external identity.
    pub external_id: ExternalIdentifier,
}

impl Member {
    pub(crate) fn from_leaf(signature_key: &[u8], credential: &[u8]) -> Self {
        Self {
            signer: Signer::from(signature_key),
            external_id: ExternalIdentifier::from(credential),
        }
    }

    pub(crate) fn auth_status<A: AuthService>(&self, auth: &A) -> AuthStatus {
        match auth.validate_external_identifier(self.signer.clone(), self.external_id.clone()) {
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

    pub fn external_id(&self) -> &ExternalIdentifier {
        &self.0.external_id
    }
}
