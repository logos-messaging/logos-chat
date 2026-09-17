use libchat::{ExternalIdentifier, Signer};
use logos_account::AccountAddr;

use crate::delegate::DelegateCredential;
use crate::errors::ClientError;

/// One device in a conversation, and the account it acts for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub signer: Signer,
    pub account: AccountAddr,
}

impl TryFrom<libchat::Member> for Member {
    type Error = ClientError;

    fn try_from(value: libchat::Member) -> Result<Self, Self::Error> {
        Ok(Member {
            account: account_of(&value.external_id)?,
            signer: value.signer,
        })
    }
}

/// A member the core's auth service vouched for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedMember(Member);

impl AuthenticatedMember {
    pub fn signer(&self) -> &Signer {
        &self.0.signer
    }

    pub fn account(&self) -> &AccountAddr {
        &self.0.account
    }
}

impl TryFrom<libchat::AuthenticatedMember> for AuthenticatedMember {
    type Error = ClientError;

    fn try_from(value: libchat::AuthenticatedMember) -> Result<Self, Self::Error> {
        Ok(AuthenticatedMember(Member {
            signer: value.signer().clone(),
            account: account_of(value.external_id())?,
        }))
    }
}

impl From<AuthenticatedMember> for Member {
    fn from(value: AuthenticatedMember) -> Self {
        value.0
    }
}

/// An account address as the core's external id.
pub(crate) fn account_id(account: &str) -> Result<ExternalIdentifier, ClientError> {
    let addr: AccountAddr = account
        .parse()
        .map_err(|e| ClientError::AccountResolution(format!("{account}: {e}")))?;
    Ok(ExternalIdentifier::from(addr.to_bytes()))
}

/// The account a delegate credential names.
fn account_of(external_id: &ExternalIdentifier) -> Result<AccountAddr, ClientError> {
    DelegateCredential::try_from(external_id.to_bytes())?
        .account_addr()
        .and_then(|addr| addr.parse().ok())
        .ok_or(ClientError::BadlyFormedCredential)
}

#[cfg(test)]
mod tests {
    use crypto::Ed25519SigningKey;

    use super::*;

    fn member(credential: DelegateCredential) -> libchat::Member {
        libchat::Member {
            signer: Signer::from(credential.delegate_id().clone()),
            external_id: ExternalIdentifier::from(credential.serialize().as_slice()),
        }
    }

    #[test]
    fn a_credential_yields_its_account() {
        let device = Ed25519SigningKey::generate().verifying_key();
        let account = AccountAddr::try_from(Ed25519SigningKey::generate().verifying_key().as_ref())
            .expect("a generated key is an address");
        let credential = DelegateCredential::associated(&device, &account.to_string());

        let decoded = Member::try_from(member(credential)).expect("decodes");
        assert_eq!(decoded.account, account);
        assert_eq!(decoded.signer, Signer::from(device));
    }

    #[test]
    fn a_credential_without_an_account_is_rejected() {
        let device = Ed25519SigningKey::generate().verifying_key();
        let credential = DelegateCredential::unassociated(&device);

        assert!(Member::try_from(member(credential)).is_err());
    }
}
