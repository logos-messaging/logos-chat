use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use libchat::{AuthResult, AuthService, IdentityProvider, ParticipantId, Signer, SignerRef, trunc};
use logos_account::AccountAddr;

use crate::errors::ClientError;
use crate::members::account_id;

/// A key generated for one installation, waiting for its account to endorse
/// it. Held in memory only: nothing persists it.
/// [`complete`](Self::complete) pairs it with that account once endorsed.
pub struct PendingInstallation {
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
}

impl PendingInstallation {
    pub fn generate() -> Self {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// The signer the account must endorse.
    pub fn endorsement_request(&self) -> Signer {
        Signer::from(self.verifying_key.clone())
    }

    /// This key as an installation of `account`. Nothing is checked here:
    /// [`ChatClientBuilder`](crate::ChatClientBuilder) confirms the
    /// endorsement when it builds.
    pub fn complete(self, account: AccountAddr) -> Installation {
        Installation {
            signer: self.endorsement_request(),
            signing_key: self.signing_key,
            account,
        }
    }
}

/// An installation paired with its account: the identity a
/// [`ChatClient`](crate::ChatClient) runs as.
pub struct Installation {
    signing_key: Ed25519SigningKey,
    /// The public key, which is what this installation signs under.
    signer: Signer,
    account: AccountAddr,
}

impl Installation {
    pub fn account(&self) -> &AccountAddr {
        &self.account
    }

    /// `Ok` only if `auth` confirms the account endorses this installation.
    pub(crate) fn validate(&self, auth: &impl AuthService) -> Result<(), ClientError> {
        match auth.validate_member(self.signer.clone(), self.participant_id()) {
            Ok(AuthResult::Valid) => Ok(()),
            Ok(verdict) => Err(ClientError::NotEndorsed(format!("{verdict:?}"))),
            Err(e) => Err(ClientError::NotEndorsed(format!(
                "auth service could not decide: {e}"
            ))),
        }
    }
}

impl IdentityProvider for Installation {
    fn signer(&self) -> SignerRef<'_> {
        &self.signer
    }

    fn participant_id(&self) -> ParticipantId {
        account_id(&self.account)
    }

    fn display_name(&self) -> String {
        trunc(&self.signer.to_string())
    }

    fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.signing_key.sign(payload)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;
    use integration_tests_core::AcceptAllAuth;

    #[derive(Debug)]
    struct RejectAll;

    impl AuthService for RejectAll {
        type Error = Infallible;

        fn validate_member(
            &self,
            _signer: Signer,
            _participant_id: ParticipantId,
        ) -> Result<AuthResult, Self::Error> {
            Ok(AuthResult::Invalid)
        }

        fn signers_for_participant(
            &self,
            _ident: &ParticipantId,
        ) -> Result<Vec<Signer>, Self::Error> {
            Ok(Vec::new())
        }
    }

    fn account() -> AccountAddr {
        AccountAddr::try_from(Ed25519SigningKey::generate().verifying_key().as_ref())
            .expect("a generated key is an address")
    }

    #[test]
    fn an_installation_signs_as_its_key_for_its_account() {
        let pending = PendingInstallation::generate();
        let signer = pending.endorsement_request();
        let account = account();

        let installation = pending.complete(account.clone());
        assert_eq!(installation.signer(), &signer);
        assert_eq!(installation.participant_id(), account_id(&account));
    }

    #[test]
    fn validation_follows_the_auth_service() {
        let installation = PendingInstallation::generate().complete(account());

        assert!(installation.validate(&AcceptAllAuth::default()).is_ok());
        assert!(matches!(
            installation.validate(&RejectAll),
            Err(ClientError::NotEndorsed(_))
        ));
    }
}
