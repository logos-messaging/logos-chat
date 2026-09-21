use libchat::{ParticipantId, SignerKey};
use logos_account::AccountAddr;

use crate::errors::ClientError;

/// One installation in a conversation, and the account it acts for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    pub signer_key: SignerKey,
    pub account: AccountAddr,
}

impl TryFrom<libchat::Signer> for Signer {
    type Error = ClientError;

    fn try_from(value: libchat::Signer) -> Result<Self, Self::Error> {
        Ok(Signer {
            account: account_of(&value.participant_id)?,
            signer_key: value.signer,
        })
    }
}

/// A member the core's auth service vouched for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedMember(Signer);

impl AuthenticatedMember {
    pub fn signer(&self) -> &SignerKey {
        &self.0.signer_key
    }

    pub fn account(&self) -> &AccountAddr {
        &self.0.account
    }
}

impl TryFrom<libchat::AuthenticatedMember> for AuthenticatedMember {
    type Error = ClientError;

    fn try_from(value: libchat::AuthenticatedMember) -> Result<Self, Self::Error> {
        Ok(AuthenticatedMember(Signer {
            signer_key: value.signer().clone(),
            account: account_of(value.participant_id())?,
        }))
    }
}

impl From<AuthenticatedMember> for Signer {
    fn from(value: AuthenticatedMember) -> Self {
        value.0
    }
}

/// An account address as the core's participant id.
pub(crate) fn account_id(account: &AccountAddr) -> ParticipantId {
    ParticipantId::from(account.to_bytes())
}

/// The account a participant id names.
fn account_of(participant_id: &ParticipantId) -> Result<AccountAddr, ClientError> {
    AccountAddr::try_from(participant_id.as_bytes())
        .map_err(|_| ClientError::InvalidAccountAddress(participant_id.to_string()))
}

#[cfg(test)]
mod tests {
    use crypto::Ed25519SigningKey;

    use super::*;

    fn signer() -> SignerKey {
        SignerKey::from(Ed25519SigningKey::generate().verifying_key())
    }

    #[test]
    fn a_participant_id_yields_its_account() {
        let signer = signer();
        let account = AccountAddr::try_from(Ed25519SigningKey::generate().verifying_key().as_ref())
            .expect("a generated key is an address");
        let member = libchat::Signer {
            signer: signer.clone(),
            participant_id: account_id(&account),
        };

        let decoded = Signer::try_from(member).expect("decodes");
        assert_eq!(decoded.account, account);
        assert_eq!(decoded.signer_key, signer);
    }

    #[test]
    fn a_participant_id_that_is_not_an_account_is_rejected() {
        let member = libchat::Signer {
            signer: signer(),
            participant_id: ParticipantId::from(b"saro".as_slice()),
        };

        assert!(Signer::try_from(member).is_err());
    }
}
